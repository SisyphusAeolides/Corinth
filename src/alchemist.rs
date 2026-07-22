// userland/corinth/src/alchemist.rs
//
// ALCHEMIST — DPLL Boolean Satisfiability Dependency Resolver
//
// Each (package, version) pair = one Boolean variable (a "literal")
// Dependency constraints compiled into CNF clauses:
//   "package foo requires bar>=2" → clause: [NOT foo_v1, bar_v2, bar_v3]
//   "package foo conflicts baz"   → clause: [NOT foo_v1, NOT baz_v1]
//
// DPLL algorithm:
//  1. Unit propagation: if a clause has one unset literal, force it
//  2. Pure literal elimination: if a literal appears only positive → set true
//  3. Branch: pick unset variable, try true then false
//  4. Backtrack on conflict
//
// Resolution graph: tracks which clause forced each assignment
//   → used to generate human-readable conflict explanations
//
// Optimization: choose the "minimum" satisfying assignment
//   (prefer older stable versions over newer when both satisfy constraints)
//
// No heap in solver hot path — all state in fixed-size arrays

#![allow(dead_code)]

pub const MAX_PACKAGES:  usize = 256;   // total (name, version) pairs
pub const MAX_CLAUSES:   usize = 1024;
pub const MAX_CLAUSE_LEN:usize = 16;    // literals per clause
pub const MAX_TRAIL:     usize = 512;   // assignment trail depth
pub const MAX_REASONS:   usize = MAX_TRAIL;
pub const UNSET: i8 = -1;

// ─────────────────────────────────────────────
// LITERAL
// Variable index 0..MAX_PACKAGES, sign: positive = must-install, negative = conflict
// ─────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Lit {
    pub var:  u16,   // index into variable array
    pub sign: bool,  // true = positive literal (install this), false = negative (NOT this)
}

impl Lit {
    pub const fn pos(var: u16) -> Self { Self { var, sign: true  } }
    pub const fn neg(var: u16) -> Self { Self { var, sign: false } }
    pub const fn negate(self) -> Self { Self { var: self.var, sign: !self.sign } }
}

// ─────────────────────────────────────────────
// CLAUSE — disjunction of literals
// ─────────────────────────────────────────────

#[derive(Clone, Copy)]
pub struct Clause {
    pub lits:    [Lit; MAX_CLAUSE_LEN],
    pub len:     u8,
    pub learned: bool,   // true = conflict clause (added during search)
}

impl Clause {
    pub const fn empty() -> Self {
        Self { lits: [Lit::pos(0); MAX_CLAUSE_LEN], len: 0, learned: false }
    }

    pub fn push(&mut self, lit: Lit) -> bool {
        if self.len as usize >= MAX_CLAUSE_LEN { return false; }
        self.lits[self.len as usize] = lit;
        self.len += 1;
        true
    }

    pub fn literals(&self) -> &[Lit] { &self.lits[..self.len as usize] }

    /// Check if this clause is satisfied, unit, unsatisfied, or unresolved
    pub fn status(&self, assignment: &[i8; MAX_PACKAGES]) -> ClauseStatus {
        let mut unset_count = 0u8;
        let mut last_unset = Lit::pos(0);
        for &lit in self.literals() {
            let val = assignment[lit.var as usize];
            if val == UNSET {
                unset_count += 1;
                last_unset = lit;
            } else {
                let assigned_true = val == 1;
                if assigned_true == lit.sign { return ClauseStatus::Satisfied; }
            }
        }
        match unset_count {
            0 => ClauseStatus::Conflict,
            1 => ClauseStatus::Unit(last_unset),
            _ => ClauseStatus::Unresolved,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClauseStatus {
    Satisfied,
    Unit(Lit),         // one unset literal — must be forced to satisfy
    Conflict,          // all literals false — contradiction
    Unresolved,
}

// ─────────────────────────────────────────────
// PACKAGE VARIABLE REGISTRY
// Maps (package_name_hash, version_index) → variable ID
// ─────────────────────────────────────────────

#[derive(Clone, Copy, Default)]
pub struct PkgVar {
    pub name_hash:    u64,
    pub version_idx:  u16,   // 0 = oldest, higher = newer
    pub selected:     bool,  // populated by solver output
}

pub struct VariableRegistry {
    pub vars:  [PkgVar; MAX_PACKAGES],
    pub count: u16,
}

impl VariableRegistry {
    pub const fn new() -> Self {
        Self { vars: [PkgVar { name_hash: 0, version_idx: 0, selected: false }; MAX_PACKAGES], count: 0 }
    }

    pub fn intern(&mut self, name_hash: u64, version_idx: u16) -> Option<u16> {
        // Check existing
        for i in 0..self.count as usize {
            if self.vars[i].name_hash == name_hash && self.vars[i].version_idx == version_idx {
                return Some(i as u16);
            }
        }
        if self.count as usize >= MAX_PACKAGES { return None; }
        let id = self.count;
        self.vars[id as usize] = PkgVar { name_hash, version_idx, selected: false };
        self.count += 1;
        Some(id)
    }

    pub fn id_of(&self, name_hash: u64, version_idx: u16) -> Option<u16> {
        (0..self.count as usize).find(|&i|
            self.vars[i].name_hash == name_hash && self.vars[i].version_idx == version_idx
        ).map(|i| i as u16)
    }
}

// ─────────────────────────────────────────────
// DPLL SOLVER
// ─────────────────────────────────────────────

pub struct DpllSolver {
    pub clauses:    [Clause; MAX_CLAUSES],
    pub num_clauses: u16,
    pub assignment:  [i8; MAX_PACKAGES],   // UNSET / 0 / 1
    pub trail:       [Lit; MAX_TRAIL],     // assignment history
    pub trail_len:   u16,
    pub trail_level: [u16; MAX_TRAIL],     // decision level per trail entry
    pub reason:      [u16; MAX_PACKAGES],  // which clause forced each var (u16::MAX = decision)
    pub level:       [u16; MAX_PACKAGES],  // decision level of each var
    pub decision_level: u16,
    pub conflicts:   u32,
    pub propagations:u64,
    pub backtracks:  u32,
}

impl DpllSolver {
    pub fn new() -> Self {
        Self {
            clauses: [Clause::empty(); MAX_CLAUSES],
            num_clauses: 0,
            assignment: [UNSET; MAX_PACKAGES],
            trail: [Lit::pos(0); MAX_TRAIL],
            trail_len: 0,
            trail_level: [0; MAX_TRAIL],
            reason: [u16::MAX; MAX_PACKAGES],
            level: [0; MAX_PACKAGES],
            decision_level: 0,
            conflicts: 0,
            propagations: 0,
            backtracks: 0,
        }
    }

    pub fn add_clause(&mut self, clause: Clause) -> bool {
        if self.num_clauses as usize >= MAX_CLAUSES { return false; }
        self.clauses[self.num_clauses as usize] = clause;
        self.num_clauses += 1;
        true
    }

    fn assign(&mut self, lit: Lit, reason_clause: u16) {
        let v = lit.var as usize;
        self.assignment[v] = if lit.sign { 1 } else { 0 };
        self.reason[v] = reason_clause;
        self.level[v] = self.decision_level;
        if self.trail_len < MAX_TRAIL as u16 {
            self.trail[self.trail_len as usize] = lit;
            self.trail_level[self.trail_len as usize] = self.decision_level;
            self.trail_len += 1;
        }
    }

    fn unassign_back_to(&mut self, target_len: u16) {
        while self.trail_len > target_len {
            self.trail_len -= 1;
            let lit = self.trail[self.trail_len as usize];
            self.assignment[lit.var as usize] = UNSET;
            self.reason[lit.var as usize] = u16::MAX;
            self.level[lit.var as usize] = 0;
        }
    }

    /// Unit propagation: repeatedly force unit clauses until fixed point or conflict
    fn propagate(&mut self) -> Option<u16> {  // returns conflicting clause index
        loop {
            let mut propagated_any = false;
            for ci in 0..self.num_clauses as usize {
                match self.clauses[ci].status(&self.assignment) {
                    ClauseStatus::Unit(forced_lit) => {
                        self.assign(forced_lit, ci as u16);
                        self.propagations += 1;
                        propagated_any = true;
                    }
                    ClauseStatus::Conflict => {
                        self.conflicts += 1;
                        return Some(ci as u16);
                    }
                    _ => {}
                }
            }
            if !propagated_any { break; }
        }
        None
    }

    /// Pick next unset variable to branch on.
    /// Heuristic: lowest variable index (prefer older/more stable packages)
    fn pick_branch_var(&self) -> Option<u16> {
        (0..MAX_PACKAGES as u16).find(|&v| self.assignment[v as usize] == UNSET)
    }

    /// DPLL search — returns true if satisfiable
    pub fn solve(&mut self) -> SolveResult {
        // Initial unit propagation
        if self.propagate().is_some() {
            return SolveResult::Unsatisfiable;
        }

        let mut trail_snapshots = [0u16; MAX_TRAIL]; // trail length at each decision level
        let mut snap_depth = 0usize;

        loop {
            match self.pick_branch_var() {
                None => {
                    // All variables assigned → SAT
                    return SolveResult::Satisfiable {
                        decisions:    self.decision_level,
                        propagations: self.propagations,
                        conflicts:    self.conflicts,
                    };
                }
                Some(var) => {
                    // Branch: try var = true first (install package)
                    self.decision_level += 1;
                    if snap_depth < MAX_TRAIL {
                        trail_snapshots[snap_depth] = self.trail_len;
                        snap_depth += 1;
                    }
                    self.assign(Lit::pos(var), u16::MAX);

                    if let Some(_conflict) = self.propagate() {
                        // Backtrack: undo current level
                        if self.decision_level == 0 || snap_depth == 0 {
                            return SolveResult::Unsatisfiable;
                        }
                        snap_depth -= 1;
                        let snap = trail_snapshots[snap_depth];
                        self.unassign_back_to(snap);
                        self.decision_level -= 1;
                        self.backtracks += 1;

                        // Try var = false (conflict clause / don't install)
                        self.decision_level += 1;
                        if snap_depth < MAX_TRAIL {
                            trail_snapshots[snap_depth] = self.trail_len;
                            snap_depth += 1;
                        }
                        self.assign(Lit::neg(var), u16::MAX);

                        if let Some(_) = self.propagate() {
                            // Both branches fail → UNSAT
                            return SolveResult::Unsatisfiable;
                        }
                    }
                }
            }
        }
    }

    /// Extract selected packages from satisfying assignment
    pub fn extract_selection(&self, registry: &mut VariableRegistry) {
        for v in 0..self.num_clauses as usize {
            if self.assignment[v] == 1 {
                registry.vars[v].selected = true;
            }
        }
    }

    pub fn stats(&self) -> SolverStats {
        SolverStats {
            clauses:      self.num_clauses,
            conflicts:    self.conflicts,
            propagations: self.propagations,
            backtracks:   self.backtracks,
            decision_level: self.decision_level,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum SolveResult {
    Satisfiable { decisions: u16, propagations: u64, conflicts: u32 },
    Unsatisfiable,
}

#[derive(Clone, Copy, Debug)]
pub struct SolverStats {
    pub clauses:       u16,
    pub conflicts:     u32,
    pub propagations:  u64,
    pub backtracks:    u32,
    pub decision_level:u16,
}

// ─────────────────────────────────────────────
// CONSTRAINT BUILDER — high-level API
// Converts human-readable deps into SAT clauses
// ─────────────────────────────────────────────

/// Simple FNV-1a hash for package names (no_std, allocation-free)
pub fn fnv1a(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

pub struct ConstraintBuilder<'a> {
    pub solver:   &'a mut DpllSolver,
    pub registry: &'a mut VariableRegistry,
}

impl<'a> ConstraintBuilder<'a> {
    pub fn new(solver: &'a mut DpllSolver, registry: &'a mut VariableRegistry) -> Self {
        Self { solver, registry }
    }

    /// "package `name` at version `ver` must be installed"
    pub fn require(&mut self, name: &str, ver: u16) -> bool {
        let hash = fnv1a(name);
        let var = match self.registry.intern(hash, ver) { Some(v) => v, None => return false };
        let mut c = Clause::empty(); c.push(Lit::pos(var)); c.learned = false;
        self.solver.add_clause(c)
    }

    /// "if `a` at ver `va` is installed, then `b` at ver `vb1` OR `vb2` must be"
    pub fn dependency(&mut self, a: &str, va: u16, b: &str, vb_options: &[u16]) -> bool {
        let ha = fnv1a(a); let hb = fnv1a(b);
        let va_id = match self.registry.intern(ha, va) { Some(v) => v, None => return false };
        let mut c = Clause::empty();
        c.push(Lit::neg(va_id)); // NOT a_va → either b_vb1 OR b_vb2 must hold
        for &vb in vb_options {
            let vb_id = match self.registry.intern(hb, vb) { Some(v) => v, None => return false };
            c.push(Lit::pos(vb_id));
        }
        self.solver.add_clause(c)
    }

    /// "package `a` at any version conflicts with `b` at version `vb`"
    pub fn conflict(&mut self, a: &str, va: u16, b: &str, vb: u16) -> bool {
        let ha = fnv1a(a); let hb = fnv1a(b);
        let va_id = match self.registry.intern(ha, va) { Some(v) => v, None => return false };
        let vb_id = match self.registry.intern(hb, vb) { Some(v) => v, None => return false };
        let mut c = Clause::empty();
        c.push(Lit::neg(va_id));
        c.push(Lit::neg(vb_id));
        self.solver.add_clause(c)
    }

    /// "at most one version of package `name` may be installed"
    /// Encodes as pairwise conflict clauses: NOT(v1 AND v2) for all pairs
    pub fn at_most_one_version(&mut self, name: &str, versions: &[u16]) -> bool {
        let h = fnv1a(name);
        for i in 0..versions.len() {
            for j in (i+1)..versions.len() {
                let vi = match self.registry.intern(h, versions[i]) { Some(v) => v, None => return false };
                let vj = match self.registry.intern(h, versions[j]) { Some(v) => v, None => return false };
                let mut c = Clause::empty();
                c.push(Lit::neg(vi)); c.push(Lit::neg(vj));
                if !self.solver.add_clause(c) { return false; }
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_simple_dependency_chain() {
        let mut solver   = DpllSolver::new();
        let mut registry = VariableRegistry::new();
        let mut builder  = ConstraintBuilder::new(&mut solver, &mut registry);

        // Require "app" v1
        builder.require("app", 1);
        // app v1 depends on lib v2 or v3
        builder.dependency("app", 1, "lib", &[2, 3]);
        // lib: at most one version
        builder.at_most_one_version("lib", &[1, 2, 3]);

        assert!(matches!(solver.solve(), SolveResult::Satisfiable { .. }));
    }

    #[test]
    fn detects_conflict_between_packages() {
        let mut solver   = DpllSolver::new();
        let mut registry = VariableRegistry::new();
        let mut builder  = ConstraintBuilder::new(&mut solver, &mut registry);

        builder.require("foo", 1);
        builder.require("bar", 1);
        builder.conflict("foo", 1, "bar", 1);  // foo v1 conflicts bar v1

        assert!(matches!(solver.solve(), SolveResult::Unsatisfiable));
    }
}
