// userland/corinth/src/helix.rs
//
// HELIX — Adaptive Parallel Build Scheduler
//
// Architecture:
//   BuildJob: one (GeneSequence, OptimizationFocus) unit of work
//   WorkQueue: fixed-size MPSC queue (ring buffer, lock-free via atomic head/tail)
//   WorkerSlot: logical worker (maps to a thread or async task in full impl)
//     - pulls next job from queue
//     - runs CrucibleEngine.mutate + CorinthCompiler.synthesize
//     - reports telemetry back to scheduler
//   ThermalGovernor: watches aggregate thermal readings,
//     adjusts active_workers and overrides OptimizationFocus if hot
//
// Dependency ordering:
//   Topological sort of Alchemist's selection graph
//   (Kahn's algorithm — BFS-based, zero allocation)
//   Packages with no unsatisfied deps go into the queue first
//
// Work stealing:
//   Each WorkerSlot has a local deque (small fixed array)
//   When local deque is empty, steals from the busiest other worker
//   Implemented as a simple scan — no lock needed with single-threaded sim

#![allow(dead_code)]

use crate::dna::OptimizationFocus;

pub const MAX_WORKERS: usize = 8;
pub const QUEUE_CAPACITY: usize = 256;
pub const MAX_BUILD_JOBS: usize = 256;
pub const LOCAL_DEQUE: usize = 16;
pub const THROTTLE_TEMP: u8 = 85; // °C: start reducing workers
pub const CRITICAL_TEMP: u8 = 95; // °C: emergency single-worker mode

// ─────────────────────────────────────────────
// BUILD JOB
// ─────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
pub struct BuildJob {
    pub pkg_var: u16, // variable ID from Alchemist registry
    pub name_hash: u64,
    pub version_idx: u16,
    pub focus: OptimizationFocus,
    pub ir_offset: u32, // offset into shared IR arena
    pub ir_len: u32,
    pub dep_count: u8, // number of unsatisfied dependencies
    pub priority: i32, // higher = build sooner
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum JobStatus {
    Pending,
    InProgress { worker_id: u8 },
    Done { inode: u32 },
    Failed { reason: BuildFailure },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BuildFailure {
    SynthesisFailed,
    MutationFailed,
    OutputTooSmall,
    Throttled,
}

// ─────────────────────────────────────────────
// LOCK-FREE WORK QUEUE (ring buffer)
// Single producer (scheduler) / multi consumer (workers)
// ─────────────────────────────────────────────

pub struct WorkQueue {
    pub jobs: [BuildJob; QUEUE_CAPACITY],
    pub head: usize, // consumer reads from head
    pub tail: usize, // producer writes to tail
    pub count: usize,
}

impl WorkQueue {
    pub const fn new() -> Self {
        const EMPTY: BuildJob = BuildJob {
            pkg_var: 0,
            name_hash: 0,
            version_idx: 0,
            focus: OptimizationFocus::MaximumThroughput,
            ir_offset: 0,
            ir_len: 0,
            dep_count: 0,
            priority: 0,
        };
        Self {
            jobs: [EMPTY; QUEUE_CAPACITY],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    pub fn push(&mut self, job: BuildJob) -> bool {
        if self.count >= QUEUE_CAPACITY {
            return false;
        }
        self.jobs[self.tail % QUEUE_CAPACITY] = job;
        self.tail += 1;
        self.count += 1;
        true
    }

    pub fn pop(&mut self) -> Option<BuildJob> {
        if self.count == 0 {
            return None;
        }
        let job = self.jobs[self.head % QUEUE_CAPACITY];
        self.head += 1;
        self.count -= 1;
        Some(job)
    }

    /// Pop highest-priority job (O(N) scan — queue is small)
    pub fn pop_priority(&mut self) -> Option<BuildJob> {
        if self.count == 0 {
            return None;
        }
        let mut best_prio = i32::MIN;
        let mut best_slot = 0usize;
        for i in 0..self.count {
            let slot = (self.head + i) % QUEUE_CAPACITY;
            if self.jobs[slot].priority > best_prio {
                best_prio = self.jobs[slot].priority;
                best_slot = slot;
            }
        }
        let job = self.jobs[best_slot];
        // Fill gap by moving tail item
        let tail_slot = (self.head + self.count - 1) % QUEUE_CAPACITY;
        self.jobs[best_slot] = self.jobs[tail_slot];
        self.count -= 1;
        Some(job)
    }
}

// ─────────────────────────────────────────────
// THERMAL GOVERNOR
// ─────────────────────────────────────────────

pub struct ThermalGovernor {
    pub readings: [u8; MAX_WORKERS],
    pub active_workers: usize,
    pub override_focus: Option<OptimizationFocus>,
    pub throttle_events: u32,
    pub emergency_events: u32,
    pub current_peak: u8,
}

impl ThermalGovernor {
    pub fn new(max_workers: usize) -> Self {
        Self {
            readings: [0u8; MAX_WORKERS],
            active_workers: max_workers.min(MAX_WORKERS),
            override_focus: None,
            throttle_events: 0,
            emergency_events: 0,
            current_peak: 0,
        }
    }

    pub fn update(&mut self, worker_id: usize, temp_c: u8) {
        if worker_id < MAX_WORKERS {
            self.readings[worker_id] = temp_c;
        }
        self.current_peak = *self.readings.iter().max().unwrap_or(&0);
        self.govern();
    }

    fn govern(&mut self) {
        if self.current_peak >= CRITICAL_TEMP {
            // Emergency: single worker, thermal efficiency only
            if self.active_workers > 1 {
                self.active_workers = 1;
                self.emergency_events += 1;
            }
            self.override_focus = Some(OptimizationFocus::ThermalEfficiency);
        } else if self.current_peak >= THROTTLE_TEMP {
            // Throttle: halve workers, switch focus
            let new_w = (self.active_workers / 2).max(1);
            if new_w < self.active_workers {
                self.throttle_events += 1;
            }
            self.active_workers = new_w;
            self.override_focus = Some(OptimizationFocus::ThermalEfficiency);
        } else {
            // Cool: restore max workers, remove override
            self.override_focus = None;
        }
    }

    pub fn effective_focus(&self, requested: OptimizationFocus) -> OptimizationFocus {
        self.override_focus.unwrap_or(requested)
    }
}

// ─────────────────────────────────────────────
// WORKER SLOT
// ─────────────────────────────────────────────

pub struct WorkerSlot {
    pub id: u8,
    pub active: bool,
    pub local_deque: [Option<BuildJob>; LOCAL_DEQUE],
    pub deque_len: usize,
    pub jobs_done: u32,
    pub jobs_stolen: u32,
    pub last_temp: u8,
}

impl WorkerSlot {
    pub const fn new(id: u8) -> Self {
        Self {
            id,
            active: false,
            local_deque: [None; LOCAL_DEQUE],
            deque_len: 0,
            jobs_done: 0,
            jobs_stolen: 0,
            last_temp: 0,
        }
    }

    pub fn push_local(&mut self, job: BuildJob) -> bool {
        if self.deque_len >= LOCAL_DEQUE {
            return false;
        }
        self.local_deque[self.deque_len] = Some(job);
        self.deque_len += 1;
        true
    }

    pub fn pop_local(&mut self) -> Option<BuildJob> {
        if self.deque_len == 0 {
            return None;
        }
        self.deque_len -= 1;
        self.local_deque[self.deque_len].take()
    }

    /// Steal one job from another worker's local deque (take from the front)
    pub fn steal_from(&mut self, victim: &mut WorkerSlot) -> Option<BuildJob> {
        if victim.deque_len == 0 {
            return None;
        }
        let stolen = victim.local_deque[0].take()?;
        // Shift victim's deque
        for i in 0..victim.deque_len - 1 {
            victim.local_deque[i] = victim.local_deque[i + 1].take();
        }
        victim.deque_len -= 1;
        self.jobs_stolen += 1;
        Some(stolen)
    }
}

// ─────────────────────────────────────────────
// TOPOLOGICAL SORT (Kahn's algorithm)
// Turns Alchemist's selection into a build order
// where every package is built after all its deps
// ─────────────────────────────────────────────

pub struct TopoSorter {
    pub in_degree: [u8; MAX_BUILD_JOBS],
    pub order: [u16; MAX_BUILD_JOBS],
    pub order_len: usize,
}

impl TopoSorter {
    pub fn new() -> Self {
        Self {
            in_degree: [0u8; MAX_BUILD_JOBS],
            order: [0u16; MAX_BUILD_JOBS],
            order_len: 0,
        }
    }

    /// `edges[i]` = slice of package indices that package i depends on
    /// Returns true if the graph is acyclic (valid dep graph)
    pub fn sort(
        &mut self,
        n: usize,
        edges: &[[u16; 16]; MAX_BUILD_JOBS],
        edge_lens: &[u8; MAX_BUILD_JOBS],
    ) -> bool {
        if n > MAX_BUILD_JOBS {
            return false;
        }
        self.in_degree.fill(0);
        self.order.fill(0);
        self.order_len = 0;

        // Build in-degree
        for i in 0..n {
            if usize::from(edge_lens[i]) > edges[i].len() {
                return false;
            }
            for j in 0..edge_lens[i] as usize {
                let dep = edges[i][j] as usize;
                if dep >= n {
                    return false;
                }
                self.in_degree[i] = self.in_degree[i].saturating_add(1);
            }
        }

        // BFS from zero-indegree nodes
        let mut queue = [0u16; MAX_BUILD_JOBS];
        let mut qh = 0;
        let mut qt = 0;
        for i in 0..n {
            if self.in_degree[i] == 0 {
                queue[qt % MAX_BUILD_JOBS] = i as u16;
                qt += 1;
            }
        }

        while qh < qt {
            let node = queue[qh % MAX_BUILD_JOBS] as usize;
            qh += 1;
            if self.order_len < MAX_BUILD_JOBS {
                self.order[self.order_len] = node as u16;
                self.order_len += 1;
            }
            // Decrement in-degree of all nodes that depend on `node`
            for i in 0..n {
                for j in 0..edge_lens[i] as usize {
                    if edges[i][j] as usize == node {
                        self.in_degree[i] = self.in_degree[i].saturating_sub(1);
                        if self.in_degree[i] == 0 {
                            queue[qt % MAX_BUILD_JOBS] = i as u16;
                            qt += 1;
                        }
                    }
                }
            }
        }

        self.order_len == n // false = cycle detected
    }
}

// ─────────────────────────────────────────────
// HELIX SCHEDULER
// ─────────────────────────────────────────────

pub struct HelixScheduler {
    pub queue: WorkQueue,
    pub workers: [WorkerSlot; MAX_WORKERS],
    pub governor: ThermalGovernor,
    pub topo: TopoSorter,
    pub job_status: [JobStatus; MAX_BUILD_JOBS],
    pub job_count: usize,
    pub total_built: u32,
    pub total_fail: u32,
    pub max_workers: usize,
}

impl HelixScheduler {
    pub fn new(max_workers: usize) -> Self {
        const EMPTY_WORKER: WorkerSlot = WorkerSlot::new(0);
        let workers = core::array::from_fn(|i| WorkerSlot {
            id: i as u8,
            active: i < max_workers.min(MAX_WORKERS),
            ..EMPTY_WORKER
        });
        Self {
            queue: WorkQueue::new(),
            workers,
            governor: ThermalGovernor::new(max_workers),
            topo: TopoSorter::new(),
            job_status: [JobStatus::Pending; MAX_BUILD_JOBS],
            job_count: 0,
            total_built: 0,
            total_fail: 0,
            max_workers: max_workers.min(MAX_WORKERS),
        }
    }

    pub fn enqueue(&mut self, job: BuildJob) -> bool {
        if self.job_count >= MAX_BUILD_JOBS {
            return false;
        }
        self.job_status[self.job_count] = JobStatus::Pending;
        self.job_count += 1;
        self.queue.push(job)
    }

    /// Dispatch next job to a free worker (or steal from busy one)
    pub fn dispatch(&mut self) -> Option<(u8, BuildJob)> {
        // Find free active worker
        let active = self.governor.active_workers;
        let worker_id =
            (0..active).find(|&w| self.workers[w].active && self.workers[w].deque_len == 0)?;

        // Try global queue first
        let mut job = self.queue.pop_priority().or_else(|| {
            // Work stealing: find busiest worker
            let busiest = (0..active)
                .filter(|&w| w != worker_id)
                .max_by_key(|&w| self.workers[w].deque_len)?;
            // We need two mutable borrows — use index trick
            let (lo, hi) = if worker_id < busiest {
                let (a, b) = self.workers.split_at_mut(busiest);
                (&mut a[worker_id], &mut b[0])
            } else {
                let (a, b) = self.workers.split_at_mut(worker_id);
                (&mut b[0], &mut a[busiest])
            };
            if worker_id < busiest {
                lo.steal_from(hi)
            } else {
                hi.steal_from(lo)
            }
        })?;

        // Apply thermal override to focus
        job.focus = self.governor.effective_focus(job.focus);
        self.workers[worker_id].push_local(job);
        Some((worker_id as u8, job))
    }

    /// Report thermal reading from a worker
    pub fn report_thermal(&mut self, worker_id: usize, temp_c: u8) {
        if worker_id < MAX_WORKERS {
            self.workers[worker_id].last_temp = temp_c;
        }
        self.governor.update(worker_id, temp_c);
    }

    /// Mark a job complete
    pub fn complete(&mut self, worker_id: usize, inode: u32) {
        self.workers[worker_id].pop_local();
        self.workers[worker_id].jobs_done += 1;
        self.total_built += 1;
        if let Some(slot) = self
            .job_status
            .iter_mut()
            .find(|s| matches!(s, JobStatus::InProgress { worker_id: w } if *w == worker_id as u8))
        {
            *slot = JobStatus::Done { inode };
        }
    }

    pub fn stats(&self) -> HelixStats {
        HelixStats {
            total_built: self.total_built,
            total_failed: self.total_fail,
            active_workers: self.governor.active_workers as u8,
            peak_temp: self.governor.current_peak,
            throttle_events: self.governor.throttle_events,
            queue_depth: self.queue.count as u32,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct HelixStats {
    pub total_built: u32,
    pub total_failed: u32,
    pub active_workers: u8,
    pub peak_temp: u8,
    pub throttle_events: u32,
    pub queue_depth: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn governor_halves_workers_at_throttle_temp() {
        let mut gov = ThermalGovernor::new(4);
        gov.update(0, THROTTLE_TEMP);
        assert_eq!(gov.active_workers, 2);
        assert_eq!(
            gov.override_focus,
            Some(OptimizationFocus::ThermalEfficiency)
        );
    }

    #[test]
    fn governor_emergency_single_worker_at_critical_temp() {
        let mut gov = ThermalGovernor::new(8);
        gov.update(0, CRITICAL_TEMP);
        assert_eq!(gov.active_workers, 1);
    }

    #[test]
    fn topo_sorter_handles_linear_chain() {
        let mut topo = TopoSorter::new();
        let mut edges = [[0u16; 16]; MAX_BUILD_JOBS];
        let mut elens = [0u8; MAX_BUILD_JOBS];
        // 0 depends on 1, 1 depends on 2
        edges[0][0] = 1;
        elens[0] = 1;
        edges[1][0] = 2;
        elens[1] = 1;
        assert!(topo.sort(3, &edges, &elens));
        // 2 should come first in build order
        assert_eq!(topo.order[0], 2);
    }
}
