//! Deterministic application compatibility route selection.

use alloc::{collections::BTreeSet, string::String, vec::Vec};
use core::fmt;

pub const ROUTE_POLICY_FORMAT: u32 = 1;
pub const MAX_ROUTE_CAPABILITIES: usize = 64;
pub const ROUTE_COUNT: usize = 5;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(rename_all = "kebab-case"))]
pub enum ApplicationRoute {
    Native,
    Rebuilt,
    CompatibilityRuntime,
    Container,
    ManagedVm,
}

pub const ROUTE_PREFERENCE: [ApplicationRoute; ROUTE_COUNT] = [
    ApplicationRoute::Native,
    ApplicationRoute::Rebuilt,
    ApplicationRoute::CompatibilityRuntime,
    ApplicationRoute::Container,
    ApplicationRoute::ManagedVm,
];

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(rename_all = "kebab-case"))]
pub enum IsolationBoundary {
    Process,
    Namespace,
    VirtualMachine,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(deny_unknown_fields))]
pub struct WorkloadRoutePolicy {
    pub format: u32,
    pub workload: String,
    pub proprietary: bool,
    pub permitted_routes: Vec<ApplicationRoute>,
    pub required_capabilities: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(deny_unknown_fields))]
pub struct RouteCandidate {
    pub route: ApplicationRoute,
    pub provider: String,
    pub available: bool,
    pub qualified: bool,
    pub isolation: IsolationBoundary,
    pub capabilities: Vec<String>,
    pub evidence_sha256: Option<String>,
    pub fallback_reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteSelection {
    pub workload: String,
    pub route: ApplicationRoute,
    pub provider: String,
    pub isolation: IsolationBoundary,
    pub evidence_sha256: String,
    pub fallback_reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteError {
    InvalidPolicy,
    InvalidCandidate,
    DuplicateCandidate,
    Unsupported { workload: String },
}

impl fmt::Display for RouteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy => formatter.write_str("invalid workload route policy"),
            Self::InvalidCandidate => formatter.write_str("invalid application route candidate"),
            Self::DuplicateCandidate => formatter.write_str("duplicate application route candidate"),
            Self::Unsupported { workload } => {
                write!(formatter, "no qualified execution route for {workload}")
            }
        }
    }
}

pub fn select_route(
    policy: &WorkloadRoutePolicy,
    candidates: &[RouteCandidate],
) -> Result<RouteSelection, RouteError> {
    policy.validate()?;
    let mut routes = BTreeSet::new();
    for candidate in candidates {
        candidate.validate()?;
        if !routes.insert(candidate.route) {
            return Err(RouteError::DuplicateCandidate);
        }
    }

    for preferred in ROUTE_PREFERENCE {
        if !policy.permitted_routes.contains(&preferred) {
            continue;
        }
        let Some(candidate) = candidates.iter().find(|candidate| candidate.route == preferred) else {
            continue;
        };
        if !candidate.available || !candidate.qualified {
            continue;
        }
        if !policy
            .required_capabilities
            .iter()
            .all(|required| candidate.capabilities.contains(required))
        {
            continue;
        }
        let evidence_sha256 = candidate
            .evidence_sha256
            .clone()
            .ok_or(RouteError::InvalidCandidate)?;
        return Ok(RouteSelection {
            workload: policy.workload.clone(),
            route: candidate.route,
            provider: candidate.provider.clone(),
            isolation: candidate.isolation,
            evidence_sha256,
            fallback_reason: candidate.fallback_reason.clone(),
        });
    }

    Err(RouteError::Unsupported {
        workload: policy.workload.clone(),
    })
}

impl WorkloadRoutePolicy {
    pub fn validate(&self) -> Result<(), RouteError> {
        if self.format != ROUTE_POLICY_FORMAT
            || !valid_identifier(&self.workload)
            || self.permitted_routes.is_empty()
            || self.permitted_routes.len() > ROUTE_COUNT
            || self.required_capabilities.len() > MAX_ROUTE_CAPABILITIES
        {
            return Err(RouteError::InvalidPolicy);
        }
        let mut previous_index = None;
        for route in &self.permitted_routes {
            let index = route_index(*route);
            if previous_index.is_some_and(|previous| previous >= index) {
                return Err(RouteError::InvalidPolicy);
            }
            if self.proprietary && *route == ApplicationRoute::Rebuilt {
                return Err(RouteError::InvalidPolicy);
            }
            previous_index = Some(index);
        }
        let mut capabilities = BTreeSet::new();
        if self.required_capabilities.iter().any(|capability| {
            !valid_identifier(capability) || !capabilities.insert(capability.as_str())
        }) {
            return Err(RouteError::InvalidPolicy);
        }
        Ok(())
    }
}

impl RouteCandidate {
    pub fn validate(&self) -> Result<(), RouteError> {
        if !valid_identifier(&self.provider)
            || self.capabilities.len() > MAX_ROUTE_CAPABILITIES
            || self.available != self.evidence_sha256.is_some()
                && self.qualified
            || self
                .evidence_sha256
                .as_deref()
                .is_some_and(|digest| !valid_digest(digest))
        {
            return Err(RouteError::InvalidCandidate);
        }
        if self.qualified && (!self.available || self.evidence_sha256.is_none()) {
            return Err(RouteError::InvalidCandidate);
        }
        let mut capabilities = BTreeSet::new();
        if self.capabilities.iter().any(|capability| {
            !valid_identifier(capability) || !capabilities.insert(capability.as_str())
        }) {
            return Err(RouteError::InvalidCandidate);
        }
        let expected_isolation = match self.route {
            ApplicationRoute::Native
            | ApplicationRoute::Rebuilt
            | ApplicationRoute::CompatibilityRuntime => IsolationBoundary::Process,
            ApplicationRoute::Container => IsolationBoundary::Namespace,
            ApplicationRoute::ManagedVm => IsolationBoundary::VirtualMachine,
        };
        if self.isolation != expected_isolation {
            return Err(RouteError::InvalidCandidate);
        }
        match self.route {
            ApplicationRoute::Native => {
                if self.fallback_reason.is_some() {
                    return Err(RouteError::InvalidCandidate);
                }
            }
            _ => {
                if self
                    .fallback_reason
                    .as_deref()
                    .is_none_or(|reason| reason.trim().is_empty() || reason.len() > 512)
                {
                    return Err(RouteError::InvalidCandidate);
                }
            }
        }
        Ok(())
    }
}

const fn route_index(route: ApplicationRoute) -> u8 {
    match route {
        ApplicationRoute::Native => 0,
        ApplicationRoute::Rebuilt => 1,
        ApplicationRoute::CompatibilityRuntime => 2,
        ApplicationRoute::Container => 3,
        ApplicationRoute::ManagedVm => 4,
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'+' | b'-' | b'_' | b'.' | b':')
        })
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{string::ToString, vec};

    fn digest() -> String {
        "a".repeat(64)
    }

    fn policy() -> WorkloadRoutePolicy {
        WorkloadRoutePolicy {
            format: ROUTE_POLICY_FORMAT,
            workload: "office-suite".to_string(),
            proprietary: false,
            permitted_routes: ROUTE_PREFERENCE.to_vec(),
            required_capabilities: vec!["wayland".to_string(), "persistent-home".to_string()],
        }
    }

    fn candidate(route: ApplicationRoute, qualified: bool) -> RouteCandidate {
        RouteCandidate {
            route,
            provider: match route {
                ApplicationRoute::Native => "native-package",
                ApplicationRoute::Rebuilt => "source-rebuild",
                ApplicationRoute::CompatibilityRuntime => "linux-runtime",
                ApplicationRoute::Container => "oci-runtime",
                ApplicationRoute::ManagedVm => "linux-vm",
            }
            .to_string(),
            available: true,
            qualified,
            isolation: match route {
                ApplicationRoute::Container => IsolationBoundary::Namespace,
                ApplicationRoute::ManagedVm => IsolationBoundary::VirtualMachine,
                _ => IsolationBoundary::Process,
            },
            capabilities: vec!["wayland".to_string(), "persistent-home".to_string()],
            evidence_sha256: Some(digest()),
            fallback_reason: (route != ApplicationRoute::Native)
                .then(|| "native route is not yet qualified".to_string()),
        }
    }

    #[test]
    fn selects_first_qualified_route_in_canonical_order() {
        let candidates = vec![
            candidate(ApplicationRoute::ManagedVm, true),
            candidate(ApplicationRoute::Native, false),
            candidate(ApplicationRoute::Container, true),
        ];
        let selected = select_route(&policy(), &candidates).unwrap();
        assert_eq!(selected.route, ApplicationRoute::Container);
    }

    #[test]
    fn missing_capability_forces_a_later_route() {
        let native = RouteCandidate {
            capabilities: vec!["wayland".to_string()],
            ..candidate(ApplicationRoute::Native, true)
        };
        let vm = candidate(ApplicationRoute::ManagedVm, true);
        let selected = select_route(&policy(), &[native, vm]).unwrap();
        assert_eq!(selected.route, ApplicationRoute::ManagedVm);
    }

    #[test]
    fn proprietary_workload_cannot_claim_a_source_rebuild() {
        let mut value = policy();
        value.proprietary = true;
        assert_eq!(value.validate(), Err(RouteError::InvalidPolicy));
    }

    #[test]
    fn fallback_route_requires_a_user_visible_reason() {
        let mut value = candidate(ApplicationRoute::Container, true);
        value.fallback_reason = None;
        assert_eq!(value.validate(), Err(RouteError::InvalidCandidate));
    }

    #[test]
    fn managed_vm_requires_a_virtual_machine_boundary() {
        let mut value = candidate(ApplicationRoute::ManagedVm, true);
        value.isolation = IsolationBoundary::Namespace;
        assert_eq!(value.validate(), Err(RouteError::InvalidCandidate));
    }

    #[test]
    fn unsupported_workload_fails_predictably() {
        let result = select_route(&policy(), &[candidate(ApplicationRoute::Native, false)]);
        assert_eq!(
            result,
            Err(RouteError::Unsupported {
                workload: "office-suite".to_string()
            })
        );
    }
}
