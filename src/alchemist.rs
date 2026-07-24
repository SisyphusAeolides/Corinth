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

pub const MAX_PACKAGES: usize = 256; // total (name, version) pairs
pub const MAX_CLAUSES: usize = 1024;
pub const MAX_CLAUSE_LEN: usize = 16; // literals per clause
pub const MAX_TRAIL: usize = 512; // assignment trail depth
pub const MAX_REASONS: usize = MAX_TRAIL;
pub const UNSET: i8 = -1;

// ─────────────────────────────────────────────
// LITERAL
// Variable index 0..MAX_PACKAGES, sign: positive = must-install, negative = conflict
// ─────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Lit {
    pub var: u16,   // index into variable array
    pub sign: bool, // true = positive literal (install this), false = negative (NOT this)
}

impl Lit {
    pub const fn pos(var: u16) -> Self {
        Self { var, sign: true }
    }
    pub const fn neg(var: u16) -> Self {
        Self { var, sign: false }
    }
    pub const fn negate(self) -> Self {
        Self {
            var: self.var,
            sign: !self.sign,
        }
    }
}

// ─────────────────────────────────────────────
// CLAUSE — disjunction of literals
// ─────────────────────────────────────────────

#[derive(Clone, Copy)]
pub struct Clause {
    pub lits: [Lit; MAX_CLAUSE_LEN],
    pub len: u8,
    pub learned: bool, // true = conflict clause (added during search)
}

impl Clause {
    pub const fn empty() -> Self {
        Self {
            lits: [Lit::pos(0); MAX_CLAUSE_LEN],
            len: 0,
            learned: false,
        }
    }

    pub fn push(&mut self, lit: Lit) -> bool {
        if self.len as usize >= MAX_CLAUSE_LEN {
            return false;
        }
        self.lits[self.len as usize] = lit;
        self.len += 1;
        true
    }

    pub fn literals(&self) -> &[Lit] {
        &self.lits[..self.len as usize]
    }

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
                if assigned_true == lit.sign {
                    return ClauseStatus::Satisfied;
                }
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
    Unit(Lit), // one unset literal — must be forced to satisfy
    Conflict,  // all literals false — contradiction
    Unresolved,
}

// ─────────────────────────────────────────────
// PACKAGE VARIABLE REGISTRY
// Maps (package_name_hash, version_index) → variable ID
// ─────────────────────────────────────────────

#[derive(Clone, Copy, Default, Debug, Eq, PartialEq)]
pub struct PkgVar {
    pub name_hash: u64,
    pub version_idx: u16, // 0 = oldest, higher = newer
    pub selected: bool,   // populated by solver output
}

pub struct VariableRegistry {
    pub vars: [PkgVar; MAX_PACKAGES],
    pub count: u16,
}

impl VariableRegistry {
    pub const fn new() -> Self {
        Self {
            vars: [PkgVar {
                name_hash: 0,
                version_idx: 0,
                selected: false,
            }; MAX_PACKAGES],
            count: 0,
        }
    }

    pub fn intern(&mut self, name_hash: u64, version_idx: u16) -> Option<u16> {
        // Check existing
        for i in 0..self.count as usize {
            if self.vars[i].name_hash == name_hash && self.vars[i].version_idx == version_idx {
                return Some(i as u16);
            }
        }
        if self.count as usize >= MAX_PACKAGES {
            return None;
        }
        let id = self.count;
        self.vars[id as usize] = PkgVar {
            name_hash,
            version_idx,
            selected: false,
        };
        self.count += 1;
        Some(id)
    }

    pub fn id_of(&self, name_hash: u64, version_idx: u16) -> Option<u16> {
        (0..self.count as usize)
            .find(|&i| {
                self.vars[i].name_hash == name_hash && self.vars[i].version_idx == version_idx
            })
            .map(|i| i as u16)
    }
}

// ─────────────────────────────────────────────
// DPLL SOLVER
// ─────────────────────────────────────────────

pub struct DpllSolver {
    pub clauses: [Clause; MAX_CLAUSES],
    pub num_clauses: u16,
    active_variables: [bool; MAX_PACKAGES],
    pub assignment: [i8; MAX_PACKAGES], // UNSET / 0 / 1
    pub trail: [Lit; MAX_TRAIL],        // assignment history
    pub trail_len: u16,
    pub trail_level: [u16; MAX_TRAIL], // decision level per trail entry
    pub reason: [u16; MAX_PACKAGES],   // which clause forced each var (u16::MAX = decision)
    pub level: [u16; MAX_PACKAGES],    // decision level of each var
    pub decision_level: u16,
    pub conflicts: u32,
    pub propagations: u64,
    pub backtracks: u32,
}

impl DpllSolver {
    pub fn new() -> Self {
        Self {
            clauses: [Clause::empty(); MAX_CLAUSES],
            num_clauses: 0,
            active_variables: [false; MAX_PACKAGES],
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
        if self.num_clauses as usize >= MAX_CLAUSES
            || usize::from(clause.len) > MAX_CLAUSE_LEN
            || clause
                .lits
                .iter()
                .take(usize::from(clause.len))
                .any(|literal| usize::from(literal.var) >= MAX_PACKAGES)
        {
            return false;
        }
        for literal in clause.lits.iter().take(usize::from(clause.len)) {
            self.active_variables[usize::from(literal.var)] = true;
        }
        self.clauses[self.num_clauses as usize] = clause;
        self.num_clauses += 1;
        true
    }

    /// Rolls an append-only constraint transaction back to an earlier clause
    /// boundary and reconstructs the exact active-variable domain.
    fn truncate_clauses(&mut self, count: u16) {
        if count >= self.num_clauses {
            return;
        }
        let old_count = self.num_clauses;
        self.clauses[usize::from(count)..usize::from(old_count)].fill(Clause::empty());
        self.num_clauses = count;
        self.active_variables.fill(false);
        for clause in self.clauses.iter().take(usize::from(count)) {
            for literal in clause.literals() {
                self.active_variables[usize::from(literal.var)] = true;
            }
        }
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
    fn propagate(&mut self) -> Option<u16> {
        // returns conflicting clause index
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
            if !propagated_any {
                break;
            }
        }
        None
    }

    /// Pick next unset variable to branch on.
    /// Heuristic: lowest variable index (prefer older/more stable packages)
    fn pick_branch_var(&self) -> Option<u16> {
        self.active_variables
            .iter()
            .zip(self.assignment.iter())
            .position(|(active, assignment)| *active && *assignment == UNSET)
            .map(|variable| variable as u16)
    }

    /// DPLL search — returns true if satisfiable
    pub fn solve(&mut self) -> SolveResult {
        self.reset_search();

        let mut decisions = [DecisionFrame::EMPTY; MAX_PACKAGES];
        let mut decision_count = 0usize;

        loop {
            if self.propagate().is_some() {
                let mut resumed = false;
                while decision_count != 0 {
                    let frame_index = decision_count - 1;
                    let frame = decisions[frame_index];
                    self.unassign_back_to(frame.trail_start);
                    self.backtracks = self.backtracks.saturating_add(1);
                    if !frame.tried_positive {
                        decisions[frame_index].tried_positive = true;
                        self.decision_level = decision_count as u16;
                        self.assign(Lit::pos(frame.variable), u16::MAX);
                        resumed = true;
                        break;
                    }
                    decisions[frame_index] = DecisionFrame::EMPTY;
                    decision_count -= 1;
                    self.decision_level = decision_count as u16;
                }
                if resumed {
                    continue;
                }
                return SolveResult::Unsatisfiable;
            }

            let Some(variable) = self.pick_branch_var() else {
                return SolveResult::Satisfiable {
                    decisions: self.decision_level,
                    propagations: self.propagations,
                    conflicts: self.conflicts,
                };
            };
            if decision_count == decisions.len() {
                return SolveResult::Unsatisfiable;
            }
            decisions[decision_count] = DecisionFrame {
                variable,
                trail_start: self.trail_len,
                tried_positive: false,
            };
            decision_count += 1;
            self.decision_level = decision_count as u16;
            // Package variables default to absent. Required packages and
            // dependency clauses force only the minimum necessary positive
            // frontier; the positive branch is explored on conflict.
            self.assign(Lit::neg(variable), u16::MAX);
        }
    }

    /// Extract selected packages from satisfying assignment
    pub fn extract_selection(&self, registry: &mut VariableRegistry) {
        let count = usize::from(registry.count).min(MAX_PACKAGES);
        for (variable, package) in registry.vars[..count].iter_mut().enumerate() {
            package.selected = self.assignment[variable] == 1;
        }
    }

    fn reset_search(&mut self) {
        self.assignment.fill(UNSET);
        self.trail.fill(Lit::pos(0));
        self.trail_len = 0;
        self.trail_level.fill(0);
        self.reason.fill(u16::MAX);
        self.level.fill(0);
        self.decision_level = 0;
        self.conflicts = 0;
        self.propagations = 0;
        self.backtracks = 0;
    }

    pub fn stats(&self) -> SolverStats {
        SolverStats {
            clauses: self.num_clauses,
            conflicts: self.conflicts,
            propagations: self.propagations,
            backtracks: self.backtracks,
            decision_level: self.decision_level,
        }
    }
}

#[derive(Clone, Copy)]
struct DecisionFrame {
    variable: u16,
    trail_start: u16,
    tried_positive: bool,
}

impl DecisionFrame {
    const EMPTY: Self = Self {
        variable: 0,
        trail_start: 0,
        tried_positive: false,
    };
}

#[derive(Clone, Copy, Debug)]
pub enum SolveResult {
    Satisfiable {
        decisions: u16,
        propagations: u64,
        conflicts: u32,
    },
    Unsatisfiable,
}

#[derive(Clone, Copy, Debug)]
pub struct SolverStats {
    pub clauses: u16,
    pub conflicts: u32,
    pub propagations: u64,
    pub backtracks: u32,
    pub decision_level: u16,
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
    pub solver: &'a mut DpllSolver,
    pub registry: &'a mut VariableRegistry,
}

#[derive(Clone, Copy)]
struct ConstraintCheckpoint {
    registry_count: u16,
    clause_count: u16,
}

impl<'a> ConstraintBuilder<'a> {
    pub fn new(solver: &'a mut DpllSolver, registry: &'a mut VariableRegistry) -> Self {
        Self { solver, registry }
    }

    /// "package `name` at version `ver` must be installed"
    pub fn require(&mut self, name: &str, ver: u16) -> bool {
        let checkpoint = self.checkpoint();
        let success = (|| {
            let var = self.registry.intern(fnv1a(name), ver)?;
            let mut clause = Clause::empty();
            clause.push(Lit::pos(var)).then_some(())?;
            clause.learned = false;
            self.solver.add_clause(clause).then_some(())
        })()
        .is_some();
        self.finish(checkpoint, success)
    }

    /// "if `a` at ver `va` is installed, then `b` at ver `vb1` OR `vb2` must be"
    pub fn dependency(&mut self, a: &str, va: u16, b: &str, vb_options: &[u16]) -> bool {
        if vb_options.is_empty()
            || vb_options.len() >= MAX_CLAUSE_LEN
            || !strictly_increasing(vb_options)
        {
            return false;
        }
        let checkpoint = self.checkpoint();
        let success = (|| {
            let va_id = self.registry.intern(fnv1a(a), va)?;
            let dependency_hash = fnv1a(b);
            let mut clause = Clause::empty();
            clause.push(Lit::neg(va_id)).then_some(())?;
            // Intern newest-to-oldest. With absence-first branching, the
            // oldest acceptable version is the last unresolved literal and
            // becomes the forced choice without installing optional versions.
            for &version in vb_options.iter().rev() {
                let dependency = self.registry.intern(dependency_hash, version)?;
                clause.push(Lit::pos(dependency)).then_some(())?;
            }
            self.solver.add_clause(clause).then_some(())
        })()
        .is_some();
        self.finish(checkpoint, success)
    }

    /// "package `a` at any version conflicts with `b` at version `vb`"
    pub fn conflict(&mut self, a: &str, va: u16, b: &str, vb: u16) -> bool {
        let checkpoint = self.checkpoint();
        let success = (|| {
            let va_id = self.registry.intern(fnv1a(a), va)?;
            let vb_id = self.registry.intern(fnv1a(b), vb)?;
            let mut clause = Clause::empty();
            clause.push(Lit::neg(va_id)).then_some(())?;
            clause.push(Lit::neg(vb_id)).then_some(())?;
            self.solver.add_clause(clause).then_some(())
        })()
        .is_some();
        self.finish(checkpoint, success)
    }

    /// "at most one version of package `name` may be installed"
    /// Encodes as pairwise conflict clauses: NOT(v1 AND v2) for all pairs
    pub fn at_most_one_version(&mut self, name: &str, versions: &[u16]) -> bool {
        if !strictly_increasing(versions) {
            return false;
        }
        let checkpoint = self.checkpoint();
        let success = (|| {
            let hash = fnv1a(name);
            for i in 0..versions.len() {
                for j in (i + 1)..versions.len() {
                    let left = self.registry.intern(hash, versions[i])?;
                    let right = self.registry.intern(hash, versions[j])?;
                    let mut clause = Clause::empty();
                    clause.push(Lit::neg(left)).then_some(())?;
                    clause.push(Lit::neg(right)).then_some(())?;
                    self.solver.add_clause(clause).then_some(())?;
                }
            }
            Some(())
        })()
        .is_some();
        self.finish(checkpoint, success)
    }

    fn checkpoint(&self) -> ConstraintCheckpoint {
        ConstraintCheckpoint {
            registry_count: self.registry.count,
            clause_count: self.solver.num_clauses,
        }
    }

    fn finish(&mut self, checkpoint: ConstraintCheckpoint, success: bool) -> bool {
        if success {
            return true;
        }
        self.solver.truncate_clauses(checkpoint.clause_count);
        let old_count = self.registry.count;
        self.registry.vars[usize::from(checkpoint.registry_count)..usize::from(old_count)]
            .fill(PkgVar::default());
        self.registry.count = checkpoint.registry_count;
        false
    }
}

fn strictly_increasing(values: &[u16]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clause(literals: &[Lit]) -> Clause {
        let mut clause = Clause::empty();
        for literal in literals {
            assert!(clause.push(*literal));
        }
        clause
    }

    #[test]
    fn resolves_simple_dependency_chain() {
        let mut solver = DpllSolver::new();
        let mut registry = VariableRegistry::new();
        let mut builder = ConstraintBuilder::new(&mut solver, &mut registry);

        // Require "app" v1
        builder.require("app", 1);
        // app v1 depends on lib v2 or v3
        builder.dependency("app", 1, "lib", &[2, 3]);
        // lib: at most one version
        builder.at_most_one_version("lib", &[1, 2, 3]);

        assert!(matches!(solver.solve(), SolveResult::Satisfiable { .. }));
        solver.extract_selection(&mut registry);
        assert!(registry.vars[registry.id_of(fnv1a("app"), 1).unwrap() as usize].selected);
        assert!(registry.vars[registry.id_of(fnv1a("lib"), 2).unwrap() as usize].selected);
        assert!(!registry.vars[registry.id_of(fnv1a("lib"), 3).unwrap() as usize].selected);
    }

    #[test]
    fn detects_conflict_between_packages() {
        let mut solver = DpllSolver::new();
        let mut registry = VariableRegistry::new();
        let mut builder = ConstraintBuilder::new(&mut solver, &mut registry);

        builder.require("foo", 1);
        builder.require("bar", 1);
        builder.conflict("foo", 1, "bar", 1); // foo v1 conflicts bar v1

        assert!(matches!(solver.solve(), SolveResult::Unsatisfiable));
    }

    #[test]
    fn branches_only_over_variables_present_in_clauses() {
        let mut solver = DpllSolver::new();
        assert!(solver.add_clause(clause(&[Lit::pos(200)])));

        assert!(matches!(
            solver.solve(),
            SolveResult::Satisfiable { decisions: 0, .. },
        ));
        assert_eq!(solver.assignment[200], 1);
        assert!(solver.assignment[..200].iter().all(|value| *value == UNSET));
        assert!(solver.assignment[201..].iter().all(|value| *value == UNSET));
    }

    #[test]
    fn extraction_clears_stale_state_across_the_registry_domain() {
        let mut registry = VariableRegistry::new();
        assert_eq!(registry.intern(fnv1a("a"), 1), Some(0));
        assert_eq!(registry.intern(fnv1a("b"), 1), Some(1));
        assert_eq!(registry.intern(fnv1a("c"), 1), Some(2));
        registry.vars[..usize::from(registry.count)]
            .iter_mut()
            .for_each(|package| package.selected = true);

        let mut solver = DpllSolver::new();
        assert!(solver.add_clause(clause(&[Lit::pos(2)])));
        assert!(matches!(solver.solve(), SolveResult::Satisfiable { .. }));
        solver.extract_selection(&mut registry);

        assert!(!registry.vars[0].selected);
        assert!(!registry.vars[1].selected);
        assert!(registry.vars[2].selected);
    }

    #[test]
    fn dependency_rejects_empty_and_truncating_alternative_sets() {
        let mut solver = DpllSolver::new();
        let mut registry = VariableRegistry::new();
        let mut builder = ConstraintBuilder::new(&mut solver, &mut registry);

        assert!(!builder.dependency("app", 1, "lib", &[]));
        assert_eq!(builder.solver.num_clauses, 0);
        assert_eq!(builder.registry.count, 0);

        let oversized = [1_u16; MAX_CLAUSE_LEN];
        assert!(!builder.dependency("app", 1, "lib", &oversized));
        assert_eq!(builder.solver.num_clauses, 0);
        assert_eq!(builder.registry.count, 0);

        let maximum = core::array::from_fn::<_, { MAX_CLAUSE_LEN - 1 }, _>(|index| index as u16);
        assert!(builder.dependency("app", 1, "lib", &maximum));
        assert_eq!(builder.solver.clauses[0].len as usize, MAX_CLAUSE_LEN);
    }

    #[test]
    fn satisfiable_search_backtracks_across_multiple_decision_levels() {
        let gate = 0;
        let left = 1;
        let right = 2;
        let mut solver = DpllSolver::new();
        for constraint in [
            clause(&[Lit::pos(gate), Lit::pos(left), Lit::pos(right)]),
            clause(&[Lit::pos(gate), Lit::pos(left), Lit::neg(right)]),
            clause(&[Lit::pos(gate), Lit::neg(left), Lit::pos(right)]),
            clause(&[Lit::pos(gate), Lit::neg(left), Lit::neg(right)]),
        ] {
            assert!(solver.add_clause(constraint));
        }

        assert!(matches!(solver.solve(), SolveResult::Satisfiable { .. }));
        assert_eq!(solver.assignment[gate as usize], 1);
        assert!(solver.backtracks >= 3);
        assert!(
            solver.clauses[..usize::from(solver.num_clauses)]
                .iter()
                .all(|constraint| constraint.status(&solver.assignment) == ClauseStatus::Satisfied)
        );
    }

    #[test]
    fn rejects_a_clause_with_an_out_of_domain_variable() {
        let mut solver = DpllSolver::new();
        assert!(!solver.add_clause(clause(&[Lit::pos(MAX_PACKAGES as u16)])));
        assert_eq!(solver.num_clauses, 0);
    }

    #[test]
    fn clause_capacity_failure_rolls_back_a_multi_clause_constraint_exactly() {
        let mut solver = DpllSolver::new();
        let seed = clause(&[Lit::pos(0)]);
        for _ in 0..MAX_CLAUSES - 1 {
            assert!(solver.add_clause(seed));
        }
        let mut registry = VariableRegistry::new();
        let mut builder = ConstraintBuilder::new(&mut solver, &mut registry);

        assert!(!builder.at_most_one_version("volatile", &[1, 2, 3]));
        assert_eq!(builder.solver.num_clauses as usize, MAX_CLAUSES - 1);
        assert_eq!(builder.registry.count, 0);
        assert!(matches!(
            builder.solver.solve(),
            SolveResult::Satisfiable { .. }
        ));
        assert_eq!(builder.solver.assignment[0], 1);
    }

    #[test]
    fn registry_exhaustion_rolls_back_partial_dependency_interning() {
        let mut solver = DpllSolver::new();
        let mut registry = VariableRegistry::new();
        assert_eq!(registry.intern(fnv1a("app"), 1), Some(0));
        for version in 1..MAX_PACKAGES as u16 - 1 {
            assert!(registry.intern(fnv1a("occupied"), version).is_some());
        }
        assert_eq!(registry.count as usize, MAX_PACKAGES - 1);
        let before = registry.vars;
        let mut builder = ConstraintBuilder::new(&mut solver, &mut registry);

        assert!(!builder.dependency("app", 1, "lib", &[1, 2]));
        assert_eq!(builder.registry.count as usize, MAX_PACKAGES - 1);
        assert_eq!(builder.registry.vars, before);
        assert_eq!(builder.solver.num_clauses, 0);
    }

    #[test]
    fn failed_single_clause_constraint_does_not_leave_an_orphan_variable() {
        let mut solver = DpllSolver::new();
        for _ in 0..MAX_CLAUSES {
            assert!(solver.add_clause(clause(&[Lit::pos(0)])));
        }
        let mut registry = VariableRegistry::new();
        let mut builder = ConstraintBuilder::new(&mut solver, &mut registry);

        assert!(!builder.require("orphan", 1));
        assert_eq!(builder.registry.count, 0);
        assert_eq!(builder.solver.num_clauses as usize, MAX_CLAUSES);
    }

    #[test]
    fn optional_conflict_only_packages_remain_absent() {
        let mut solver = DpllSolver::new();
        let mut registry = VariableRegistry::new();
        let mut builder = ConstraintBuilder::new(&mut solver, &mut registry);
        assert!(builder.conflict("foo", 1, "bar", 1));
        assert!(matches!(solver.solve(), SolveResult::Satisfiable { .. }));
        solver.extract_selection(&mut registry);
        assert!(!registry.vars[registry.id_of(fnv1a("foo"), 1).unwrap() as usize].selected);
        assert!(!registry.vars[registry.id_of(fnv1a("bar"), 1).unwrap() as usize].selected);
    }

    #[test]
    fn unordered_or_duplicate_version_domains_are_rejected_without_mutation() {
        let mut solver = DpllSolver::new();
        let mut registry = VariableRegistry::new();
        let mut builder = ConstraintBuilder::new(&mut solver, &mut registry);
        assert!(!builder.dependency("app", 1, "lib", &[2, 2]));
        assert!(!builder.dependency("app", 1, "lib", &[3, 2]));
        assert!(!builder.at_most_one_version("lib", &[1, 1]));
        assert_eq!(builder.registry.count, 0);
        assert_eq!(builder.solver.num_clauses, 0);
    }
}
