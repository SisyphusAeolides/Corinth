//! Bounded signed package constraints and deterministic SAT planning.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
    vec,
    vec::Vec,
};
use core::fmt;
use serde::{Deserialize, Serialize};

use crate::alchemist::{Clause, DpllSolver, Lit, MAX_CLAUSE_LEN, MAX_PACKAGES, SolveResult};

pub const MAX_PACKAGE_REQUIREMENTS: usize = 64;
pub const MAX_PACKAGE_CONSTRAINTS: usize = 64;
pub const MAX_PACKAGE_CAPABILITIES: usize = 64;
pub const MAX_REQUIREMENT_ALTERNATIVES: usize = 16;
pub const MAX_CONSTRAINT_VERSIONS: usize = 64;

/// One package or virtual capability accepted by a dependency or conflict.
///
/// Repository publication expands ecosystem-specific ranges into the exact
/// retained versions accepted by this snapshot. An empty version set accepts
/// any retained version of the named package or capability.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageConstraint {
    pub name: String,
    #[serde(default)]
    pub versions: Vec<String>,
}

/// A dependency clause. At least one alternative must be selected whenever
/// the package carrying this requirement is selected.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageRequirement {
    pub alternatives: Vec<PackageConstraint>,
}

/// A virtual capability supplied by a package. If `version` is omitted, the
/// package's own version is used when matching an exact-version constraint.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageCapability {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependencyMetadata {
    pub requirements: Vec<PackageRequirement>,
    pub provides: Vec<PackageCapability>,
    pub conflicts: Vec<PackageConstraint>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolutionCandidate {
    pub package: String,
    pub version: String,
    pub sequence: u64,
    pub metadata: DependencyMetadata,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependencyPlan {
    /// Original candidate indexes selected by the solver.
    pub selected: Vec<usize>,
    /// Selected original candidate indexes in dependency-first order.
    pub order: Vec<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DependencyError {
    Invalid(String),
    Capacity(String),
    Unsatisfiable,
    Cycle(Vec<String>),
}

impl fmt::Display for DependencyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(value) => write!(formatter, "invalid dependency metadata: {value}"),
            Self::Capacity(value) => write!(formatter, "dependency graph exceeds bounds: {value}"),
            Self::Unsatisfiable => formatter.write_str("package dependency graph is unsatisfiable"),
            Self::Cycle(packages) => {
                write!(
                    formatter,
                    "package dependency cycle: {}",
                    packages.join(" -> ")
                )
            }
        }
    }
}

impl std::error::Error for DependencyError {}

pub fn package_requirement(name: impl Into<String>) -> PackageRequirement {
    PackageRequirement {
        alternatives: vec![PackageConstraint {
            name: name.into(),
            versions: Vec::new(),
        }],
    }
}

pub fn package_capability(name: impl Into<String>) -> PackageCapability {
    PackageCapability {
        name: name.into(),
        version: None,
    }
}

pub fn validate_dependency_metadata(
    requirements: &[PackageRequirement],
    provides: &[PackageCapability],
    conflicts: &[PackageConstraint],
) -> Result<(), DependencyError> {
    if requirements.len() > MAX_PACKAGE_REQUIREMENTS
        || provides.len() > MAX_PACKAGE_CAPABILITIES
        || conflicts.len() > MAX_PACKAGE_CONSTRAINTS
    {
        return Err(DependencyError::Capacity(
            "per-package requirement, capability, or conflict count".into(),
        ));
    }
    let mut requirement_keys = BTreeSet::new();
    for requirement in requirements {
        if requirement.alternatives.is_empty()
            || requirement.alternatives.len() > MAX_REQUIREMENT_ALTERNATIVES
        {
            return Err(DependencyError::Invalid(
                "dependency alternatives are empty or oversized".into(),
            ));
        }
        let mut alternatives = BTreeSet::new();
        for alternative in &requirement.alternatives {
            validate_constraint(alternative)?;
            if !alternatives.insert(alternative.clone()) {
                return Err(DependencyError::Invalid(
                    "duplicate dependency alternative".into(),
                ));
            }
        }
        if !requirement_keys.insert(alternatives) {
            return Err(DependencyError::Invalid(
                "duplicate dependency requirement".into(),
            ));
        }
    }
    let mut capability_keys = BTreeSet::new();
    for capability in provides {
        if !valid_name(&capability.name)
            || capability
                .version
                .as_deref()
                .is_some_and(|version| !valid_version(version))
            || !capability_keys.insert(capability.clone())
        {
            return Err(DependencyError::Invalid(
                "invalid or duplicate package capability".into(),
            ));
        }
    }
    let mut conflict_keys = BTreeSet::new();
    for conflict in conflicts {
        validate_constraint(conflict)?;
        if !conflict_keys.insert(conflict.clone()) {
            return Err(DependencyError::Invalid(
                "duplicate package conflict".into(),
            ));
        }
    }
    Ok(())
}

pub fn solve_dependency_graph(
    candidates: &[ResolutionCandidate],
    required: usize,
    fixed: &[usize],
) -> Result<DependencyPlan, DependencyError> {
    if candidates.is_empty() || required >= candidates.len() {
        return Err(DependencyError::Invalid(
            "required candidate is outside the graph".into(),
        ));
    }
    if candidates.len() > MAX_PACKAGES {
        return Err(DependencyError::Capacity(format!(
            "{} candidates exceeds {MAX_PACKAGES}",
            candidates.len()
        )));
    }
    validate_candidates(candidates, fixed)?;

    let mut canonical = (0..candidates.len()).collect::<Vec<_>>();
    canonical.sort_by(|left, right| {
        let left = &candidates[*left];
        let right = &candidates[*right];
        left.package
            .cmp(&right.package)
            .then(left.sequence.cmp(&right.sequence))
            .then(left.version.cmp(&right.version))
    });
    let mut variable_for_candidate = vec![0_u16; candidates.len()];
    for (variable, candidate) in canonical.iter().copied().enumerate() {
        variable_for_candidate[candidate] = variable as u16;
    }

    let mut solver = DpllSolver::new();
    add_unit(&mut solver, variable_for_candidate[required])?;
    for candidate in fixed {
        add_unit(&mut solver, variable_for_candidate[*candidate])?;
    }

    let mut package_domains = BTreeMap::<&str, Vec<usize>>::new();
    for candidate in &canonical {
        package_domains
            .entry(candidates[*candidate].package.as_str())
            .or_default()
            .push(*candidate);
    }
    for domain in package_domains.values() {
        for (offset, left) in domain.iter().enumerate() {
            for right in domain.iter().skip(offset + 1) {
                add_binary_conflict(
                    &mut solver,
                    variable_for_candidate[*left],
                    variable_for_candidate[*right],
                )?;
            }
        }
    }

    for (candidate_index, candidate) in candidates.iter().enumerate() {
        let variable = variable_for_candidate[candidate_index];
        for requirement in &candidate.metadata.requirements {
            let options = canonical
                .iter()
                .copied()
                .filter(|option| {
                    requirement
                        .alternatives
                        .iter()
                        .any(|constraint| candidate_satisfies(&candidates[*option], constraint))
                })
                .collect::<Vec<_>>();
            if options.len() + 1 > MAX_CLAUSE_LEN {
                return Err(DependencyError::Capacity(format!(
                    "{} dependency options for {}",
                    options.len(),
                    candidate.package
                )));
            }
            let mut clause = Clause::empty();
            if !clause.push(Lit::neg(variable)) {
                return Err(DependencyError::Capacity("dependency clause".into()));
            }
            for option in options {
                if !clause.push(Lit::pos(variable_for_candidate[option])) {
                    return Err(DependencyError::Capacity("dependency clause".into()));
                }
            }
            if !solver.add_clause(clause) {
                return Err(DependencyError::Capacity("dependency clauses".into()));
            }
        }
        for conflict in &candidate.metadata.conflicts {
            for other in canonical.iter().copied().filter(|other| {
                *other != candidate_index && candidate_satisfies(&candidates[*other], conflict)
            }) {
                add_binary_conflict(&mut solver, variable, variable_for_candidate[other])?;
            }
        }
    }

    if !matches!(solver.solve(), SolveResult::Satisfiable { .. }) {
        return Err(DependencyError::Unsatisfiable);
    }
    let mut selected = canonical
        .iter()
        .copied()
        .filter(|candidate| solver.assignment[variable_for_candidate[*candidate] as usize] == 1)
        .collect::<Vec<_>>();
    selected.sort_by(|left, right| {
        candidate_key(&candidates[*left]).cmp(&candidate_key(&candidates[*right]))
    });
    let order = dependency_order(candidates, &selected)?;
    Ok(DependencyPlan { selected, order })
}

fn validate_candidates(
    candidates: &[ResolutionCandidate],
    fixed: &[usize],
) -> Result<(), DependencyError> {
    let mut identities = BTreeSet::new();
    let mut sequences = BTreeSet::new();
    for candidate in candidates {
        if !valid_name(&candidate.package) || !valid_version(&candidate.version) {
            return Err(DependencyError::Invalid(
                "invalid candidate identity".into(),
            ));
        }
        if !identities.insert((candidate.package.clone(), candidate.version.clone()))
            || !sequences.insert((candidate.package.clone(), candidate.sequence))
        {
            return Err(DependencyError::Invalid(
                "duplicate candidate version or sequence".into(),
            ));
        }
        validate_dependency_metadata(
            &candidate.metadata.requirements,
            &candidate.metadata.provides,
            &candidate.metadata.conflicts,
        )?;
    }
    let mut fixed_set = BTreeSet::new();
    if fixed
        .iter()
        .any(|candidate| *candidate >= candidates.len() || !fixed_set.insert(*candidate))
    {
        return Err(DependencyError::Invalid(
            "fixed candidate set is invalid".into(),
        ));
    }
    Ok(())
}

fn dependency_order(
    candidates: &[ResolutionCandidate],
    selected: &[usize],
) -> Result<Vec<usize>, DependencyError> {
    let selected_set = selected.iter().copied().collect::<BTreeSet<_>>();
    let mut dependencies = BTreeMap::<usize, Vec<usize>>::new();
    for candidate_index in selected {
        let candidate = &candidates[*candidate_index];
        let mut edges = BTreeSet::new();
        for requirement in &candidate.metadata.requirements {
            let dependency = selected
                .iter()
                .copied()
                .filter(|option| {
                    requirement
                        .alternatives
                        .iter()
                        .any(|constraint| candidate_satisfies(&candidates[*option], constraint))
                })
                .max_by(|left, right| {
                    candidates[*left]
                        .sequence
                        .cmp(&candidates[*right].sequence)
                        .then(candidates[*right].package.cmp(&candidates[*left].package))
                })
                .ok_or(DependencyError::Unsatisfiable)?;
            if dependency != *candidate_index && selected_set.contains(&dependency) {
                edges.insert(dependency);
            }
        }
        dependencies.insert(*candidate_index, edges.into_iter().collect());
    }

    let mut state = vec![0_u8; candidates.len()];
    let mut stack = Vec::new();
    let mut order = Vec::with_capacity(selected.len());
    let mut roots = selected.to_vec();
    roots.sort_by(|left, right| {
        candidate_key(&candidates[*left]).cmp(&candidate_key(&candidates[*right]))
    });
    for candidate in roots {
        visit_candidate(
            candidate,
            candidates,
            &dependencies,
            &mut state,
            &mut stack,
            &mut order,
        )?;
    }
    Ok(order)
}

fn visit_candidate(
    candidate: usize,
    candidates: &[ResolutionCandidate],
    dependencies: &BTreeMap<usize, Vec<usize>>,
    state: &mut [u8],
    stack: &mut Vec<usize>,
    order: &mut Vec<usize>,
) -> Result<(), DependencyError> {
    match state[candidate] {
        2 => return Ok(()),
        1 => {
            let start = stack
                .iter()
                .position(|entry| *entry == candidate)
                .unwrap_or(0);
            let mut cycle = stack[start..]
                .iter()
                .map(|entry| candidates[*entry].package.clone())
                .collect::<Vec<_>>();
            cycle.push(candidates[candidate].package.clone());
            return Err(DependencyError::Cycle(cycle));
        }
        _ => {}
    }
    state[candidate] = 1;
    stack.push(candidate);
    if let Some(edges) = dependencies.get(&candidate) {
        let mut edges = edges.clone();
        edges.sort_by(|left, right| {
            candidate_key(&candidates[*left]).cmp(&candidate_key(&candidates[*right]))
        });
        for dependency in edges {
            visit_candidate(dependency, candidates, dependencies, state, stack, order)?;
        }
    }
    stack.pop();
    state[candidate] = 2;
    order.push(candidate);
    Ok(())
}

fn add_unit(solver: &mut DpllSolver, variable: u16) -> Result<(), DependencyError> {
    let mut clause = Clause::empty();
    if !clause.push(Lit::pos(variable)) || !solver.add_clause(clause) {
        return Err(DependencyError::Capacity("required package clauses".into()));
    }
    Ok(())
}

fn add_binary_conflict(
    solver: &mut DpllSolver,
    left: u16,
    right: u16,
) -> Result<(), DependencyError> {
    let mut clause = Clause::empty();
    if !clause.push(Lit::neg(left)) || !clause.push(Lit::neg(right)) || !solver.add_clause(clause) {
        return Err(DependencyError::Capacity("package conflict clauses".into()));
    }
    Ok(())
}

pub(crate) fn candidate_satisfies(
    candidate: &ResolutionCandidate,
    constraint: &PackageConstraint,
) -> bool {
    package_satisfies_constraint(
        &candidate.package,
        &candidate.version,
        &candidate.metadata.provides,
        constraint,
    )
}

pub(crate) fn package_satisfies_constraint(
    package: &str,
    version: &str,
    provides: &[PackageCapability],
    constraint: &PackageConstraint,
) -> bool {
    let implicit = (package == constraint.name).then_some(version);
    implicit
        .into_iter()
        .chain(provides.iter().filter_map(|capability| {
            (capability.name == constraint.name)
                .then_some(capability.version.as_deref().unwrap_or(version))
        }))
        .any(|version| {
            constraint.versions.is_empty() || constraint.versions.iter().any(|item| item == version)
        })
}

fn validate_constraint(constraint: &PackageConstraint) -> Result<(), DependencyError> {
    if !valid_name(&constraint.name)
        || constraint.versions.len() > MAX_CONSTRAINT_VERSIONS
        || constraint
            .versions
            .iter()
            .any(|version| !valid_version(version))
        || constraint
            .versions
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(DependencyError::Invalid(format!(
            "invalid package constraint: {}",
            constraint.name
        )));
    }
    Ok(())
}

fn candidate_key(candidate: &ResolutionCandidate) -> (&str, u64, &str) {
    (&candidate.package, candidate.sequence, &candidate.version)
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            !byte.is_ascii_control()
                && !byte.is_ascii_whitespace()
                && !matches!(byte, b'/' | b'\\' | b'@')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(
        package: &str,
        version: &str,
        sequence: u64,
        requirements: Vec<PackageRequirement>,
    ) -> ResolutionCandidate {
        ResolutionCandidate {
            package: package.into(),
            version: version.into(),
            sequence,
            metadata: DependencyMetadata {
                requirements,
                provides: Vec::new(),
                conflicts: Vec::new(),
            },
        }
    }

    #[test]
    fn selects_latest_satisfying_dependency_and_orders_it_first() {
        let candidates = vec![
            candidate("app", "1.0.0", 1, vec![package_requirement("lib")]),
            candidate("lib", "1.0.0", 1, vec![]),
            candidate("lib", "2.0.0", 2, vec![]),
        ];
        let plan = solve_dependency_graph(&candidates, 0, &[]).unwrap();
        assert_eq!(plan.selected, vec![0, 2]);
        assert_eq!(plan.order, vec![2, 0]);
    }

    #[test]
    fn exact_versions_alternatives_and_capabilities_are_solved() {
        let mut app = candidate(
            "app",
            "1.0.0",
            1,
            vec![PackageRequirement {
                alternatives: vec![
                    PackageConstraint {
                        name: "ssl-api".into(),
                        versions: vec!["3".into()],
                    },
                    PackageConstraint {
                        name: "compat-ssl".into(),
                        versions: Vec::new(),
                    },
                ],
            }],
        );
        app.metadata.conflicts.push(PackageConstraint {
            name: "broken-provider".into(),
            versions: Vec::new(),
        });
        let mut openssl = candidate("openssl", "3.4.0", 2, vec![]);
        openssl.metadata.provides.push(PackageCapability {
            name: "ssl-api".into(),
            version: Some("3".into()),
        });
        let broken = candidate("broken-provider", "1.0.0", 1, vec![]);
        let candidates = vec![app, openssl, broken];
        let plan = solve_dependency_graph(&candidates, 0, &[]).unwrap();
        assert_eq!(plan.selected, vec![0, 1]);
        assert_eq!(plan.order, vec![1, 0]);
    }

    #[test]
    fn fixed_conflict_is_unsatisfiable() {
        let mut app = candidate("app", "1.0.0", 1, vec![]);
        app.metadata.conflicts.push(PackageConstraint {
            name: "legacy".into(),
            versions: Vec::new(),
        });
        let candidates = vec![app, candidate("legacy", "1.0.0", 1, vec![])];
        assert_eq!(
            solve_dependency_graph(&candidates, 0, &[1]),
            Err(DependencyError::Unsatisfiable)
        );
    }

    #[test]
    fn dependency_cycles_are_rejected_after_sat_selection() {
        let candidates = vec![
            candidate("alpha", "1.0.0", 1, vec![package_requirement("beta")]),
            candidate("beta", "1.0.0", 1, vec![package_requirement("alpha")]),
        ];
        assert!(matches!(
            solve_dependency_graph(&candidates, 0, &[]),
            Err(DependencyError::Cycle(_))
        ));
    }

    #[test]
    fn oversized_option_domains_fail_closed() {
        let mut candidates = vec![candidate(
            "app",
            "1.0.0",
            1,
            vec![package_requirement("lib")],
        )];
        for sequence in 1..=MAX_CLAUSE_LEN {
            candidates.push(candidate(
                "lib",
                &format!("{sequence}.0.0"),
                sequence as u64,
                vec![],
            ));
        }
        assert!(matches!(
            solve_dependency_graph(&candidates, 0, &[]),
            Err(DependencyError::Capacity(_))
        ));
    }

    #[test]
    fn exact_versions_preserve_foreign_epoch_and_revision_syntax() {
        let version = "2:1.4.0~rc1-3.fc44";
        let candidates = vec![
            candidate(
                "app",
                "1.0.0",
                1,
                vec![PackageRequirement {
                    alternatives: vec![PackageConstraint {
                        name: "runtime".into(),
                        versions: vec![version.into()],
                    }],
                }],
            ),
            candidate("runtime", version, 1, vec![]),
        ];
        assert!(solve_dependency_graph(&candidates, 0, &[]).is_ok());

        let mut invalid = candidates;
        invalid[1].version = "bad version".into();
        assert!(matches!(
            solve_dependency_graph(&invalid, 0, &[]),
            Err(DependencyError::Invalid(_))
        ));
    }
}
