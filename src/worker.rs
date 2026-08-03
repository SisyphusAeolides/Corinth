//! Fail-closed contracts for dynamic compatibility workers.

use alloc::{collections::BTreeSet, string::String, vec::Vec};
use core::fmt;

pub const WORKER_REQUEST_FORMAT: u32 = 1;
pub const MAX_WORKER_INPUTS: usize = 256;
pub const MAX_WORKER_TOOLS: usize = 64;
pub const MAX_WORKER_OUTPUTS: usize = 256;
pub const MAX_NETWORK_RESOURCES: usize = 64;
pub const MAX_WORKER_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
pub const MAX_NETWORK_RESOURCE_BYTES: u64 = 512 * 1024 * 1024;
pub const MINIMUM_REPRODUCIBILITY_RUNS: u8 = 2;
pub const MAXIMUM_REPRODUCIBILITY_RUNS: u8 = 4;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(rename_all = "kebab-case"))]
pub enum WorkerCapability {
    ReadInputs,
    ExecuteTools,
    WriteOutputs,
    FixedOutputNetwork,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(deny_unknown_fields))]
pub struct WorkerInput {
    pub path: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(deny_unknown_fields))]
pub struct WorkerTool {
    pub path: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(deny_unknown_fields))]
pub struct WorkerOutput {
    pub path: String,
    pub maximum_size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(deny_unknown_fields))]
pub struct FixedNetworkResource {
    pub url: String,
    pub sha256: String,
    pub maximum_size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(
    feature = "host-store",
    serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)
)]
pub enum WorkerNetwork {
    Denied,
    FixedOutput {
        resources: Vec<FixedNetworkResource>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(deny_unknown_fields))]
pub struct WorkerRequest {
    pub format: u32,
    pub request_id: String,
    pub ecosystem: String,
    pub capabilities: Vec<WorkerCapability>,
    pub inputs: Vec<WorkerInput>,
    pub tools: Vec<WorkerTool>,
    pub outputs: Vec<WorkerOutput>,
    pub network: WorkerNetwork,
    pub reproducibility_runs: u8,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(deny_unknown_fields))]
pub struct WorkerOutputEvidence {
    pub path: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(deny_unknown_fields))]
pub struct WorkerRunEvidence {
    pub measurement_sha256: String,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub outputs: Vec<WorkerOutputEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(deny_unknown_fields))]
pub struct ReproducibilityEvidence {
    pub request_sha256: String,
    pub runs: Vec<WorkerRunEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkerError {
    InvalidIdentity,
    InvalidCapabilities,
    InvalidInput,
    InvalidTool,
    InvalidOutput,
    InvalidNetwork,
    InvalidReproducibility,
    OutputMismatch,
    NonReproducible,
}

impl fmt::Display for WorkerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidIdentity => "invalid compatibility worker identity",
            Self::InvalidCapabilities => "invalid compatibility worker capability set",
            Self::InvalidInput => "invalid compatibility worker input",
            Self::InvalidTool => "invalid compatibility worker tool",
            Self::InvalidOutput => "invalid compatibility worker output",
            Self::InvalidNetwork => "invalid compatibility worker network boundary",
            Self::InvalidReproducibility => "invalid compatibility worker reproducibility policy",
            Self::OutputMismatch => "compatibility worker output differs from its declaration",
            Self::NonReproducible => "compatibility worker runs are not byte-identical",
        };
        formatter.write_str(message)
    }
}

impl WorkerRequest {
    pub fn validate(&self) -> Result<(), WorkerError> {
        if self.format != WORKER_REQUEST_FORMAT
            || !valid_identifier(&self.request_id)
            || !valid_identifier(&self.ecosystem)
        {
            return Err(WorkerError::InvalidIdentity);
        }
        if !(MINIMUM_REPRODUCIBILITY_RUNS..=MAXIMUM_REPRODUCIBILITY_RUNS)
            .contains(&self.reproducibility_runs)
        {
            return Err(WorkerError::InvalidReproducibility);
        }

        let capabilities = self.capabilities.iter().copied().collect::<BTreeSet<_>>();
        if capabilities.len() != self.capabilities.len()
            || !capabilities.contains(&WorkerCapability::ReadInputs)
            || !capabilities.contains(&WorkerCapability::ExecuteTools)
            || !capabilities.contains(&WorkerCapability::WriteOutputs)
        {
            return Err(WorkerError::InvalidCapabilities);
        }
        let network_capability = capabilities.contains(&WorkerCapability::FixedOutputNetwork);
        if network_capability != matches!(&self.network, WorkerNetwork::FixedOutput { .. }) {
            return Err(WorkerError::InvalidCapabilities);
        }

        if self.inputs.is_empty() || self.inputs.len() > MAX_WORKER_INPUTS {
            return Err(WorkerError::InvalidInput);
        }
        let mut input_paths = BTreeSet::new();
        for input in &self.inputs {
            if !safe_relative(&input.path)
                || !input_paths.insert(input.path.as_str())
                || !valid_digest(&input.sha256)
                || input.size == 0
                || input.size > MAX_WORKER_FILE_BYTES
            {
                return Err(WorkerError::InvalidInput);
            }
        }

        if self.tools.is_empty() || self.tools.len() > MAX_WORKER_TOOLS {
            return Err(WorkerError::InvalidTool);
        }
        let mut tool_paths = BTreeSet::new();
        for tool in &self.tools {
            if !safe_relative(&tool.path)
                || !tool_paths.insert(tool.path.as_str())
                || !valid_digest(&tool.sha256)
            {
                return Err(WorkerError::InvalidTool);
            }
        }

        if self.outputs.is_empty() || self.outputs.len() > MAX_WORKER_OUTPUTS {
            return Err(WorkerError::InvalidOutput);
        }
        let mut output_paths = BTreeSet::new();
        for output in &self.outputs {
            if !safe_relative(&output.path)
                || input_paths.contains(output.path.as_str())
                || tool_paths.contains(output.path.as_str())
                || !output_paths.insert(output.path.as_str())
                || output.maximum_size == 0
                || output.maximum_size > MAX_WORKER_FILE_BYTES
            {
                return Err(WorkerError::InvalidOutput);
            }
        }

        match &self.network {
            WorkerNetwork::Denied => {}
            WorkerNetwork::FixedOutput { resources } => {
                if resources.is_empty() || resources.len() > MAX_NETWORK_RESOURCES {
                    return Err(WorkerError::InvalidNetwork);
                }
                let mut urls = BTreeSet::new();
                for resource in resources {
                    if !resource.url.starts_with("https://")
                        || !urls.insert(resource.url.as_str())
                        || !valid_digest(&resource.sha256)
                        || resource.maximum_size == 0
                        || resource.maximum_size > MAX_NETWORK_RESOURCE_BYTES
                    {
                        return Err(WorkerError::InvalidNetwork);
                    }
                }
            }
        }
        Ok(())
    }
}

impl ReproducibilityEvidence {
    pub fn validate(&self, request: &WorkerRequest) -> Result<(), WorkerError> {
        request.validate()?;
        if !valid_digest(&self.request_sha256)
            || self.runs.len() < request.reproducibility_runs as usize
            || self.runs.len() > MAXIMUM_REPRODUCIBILITY_RUNS as usize
        {
            return Err(WorkerError::InvalidReproducibility);
        }
        let declarations = request
            .outputs
            .iter()
            .map(|output| (output.path.as_str(), output.maximum_size))
            .collect::<alloc::collections::BTreeMap<_, _>>();

        let mut canonical: Option<WorkerRunEvidence> = None;
        for run in &self.runs {
            if !valid_digest(&run.measurement_sha256)
                || !valid_digest(&run.stdout_sha256)
                || !valid_digest(&run.stderr_sha256)
            {
                return Err(WorkerError::InvalidReproducibility);
            }
            let mut outputs = run.outputs.clone();
            outputs.sort();
            if outputs.len() != declarations.len() {
                return Err(WorkerError::OutputMismatch);
            }
            let mut seen = BTreeSet::new();
            for output in &outputs {
                let Some(maximum_size) = declarations.get(output.path.as_str()) else {
                    return Err(WorkerError::OutputMismatch);
                };
                if !seen.insert(output.path.as_str())
                    || !valid_digest(&output.sha256)
                    || output.size > *maximum_size
                {
                    return Err(WorkerError::OutputMismatch);
                }
            }
            let normalized = WorkerRunEvidence {
                measurement_sha256: run.measurement_sha256.clone(),
                stdout_sha256: run.stdout_sha256.clone(),
                stderr_sha256: run.stderr_sha256.clone(),
                outputs,
            };
            if let Some(first) = &canonical {
                if first != &normalized {
                    return Err(WorkerError::NonReproducible);
                }
            } else {
                canonical = Some(normalized);
            }
        }
        Ok(())
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_' | b'.' | b':')
        })
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn safe_relative(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4096
        && !value.starts_with('/')
        && !value.contains('\\')
        && value
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{string::ToString, vec};

    fn digest(byte: char) -> String {
        core::iter::repeat_n(byte, 64).collect()
    }

    fn request() -> WorkerRequest {
        WorkerRequest {
            format: WORKER_REQUEST_FORMAT,
            request_id: "arch-pkgbuild-coreutils".to_string(),
            ecosystem: "arch".to_string(),
            capabilities: vec![
                WorkerCapability::ReadInputs,
                WorkerCapability::ExecuteTools,
                WorkerCapability::WriteOutputs,
            ],
            inputs: vec![WorkerInput {
                path: "inputs/PKGBUILD".to_string(),
                sha256: digest('a'),
                size: 1024,
            }],
            tools: vec![WorkerTool {
                path: "tools/bash".to_string(),
                sha256: digest('b'),
            }],
            outputs: vec![WorkerOutput {
                path: "outputs/recipe.toml".to_string(),
                maximum_size: 4096,
            }],
            network: WorkerNetwork::Denied,
            reproducibility_runs: 2,
        }
    }

    fn run() -> WorkerRunEvidence {
        WorkerRunEvidence {
            measurement_sha256: digest('c'),
            stdout_sha256: digest('d'),
            stderr_sha256: digest('e'),
            outputs: vec![WorkerOutputEvidence {
                path: "outputs/recipe.toml".to_string(),
                sha256: digest('f'),
                size: 2048,
            }],
        }
    }

    #[test]
    fn denies_undeclared_network_access() {
        let mut value = request();
        value
            .capabilities
            .push(WorkerCapability::FixedOutputNetwork);
        assert_eq!(value.validate(), Err(WorkerError::InvalidCapabilities));
    }

    #[test]
    fn accepts_digest_bound_fixed_output_network() {
        let mut value = request();
        value
            .capabilities
            .push(WorkerCapability::FixedOutputNetwork);
        value.network = WorkerNetwork::FixedOutput {
            resources: vec![FixedNetworkResource {
                url: "https://example.invalid/source.tar.xz".to_string(),
                sha256: digest('1'),
                maximum_size: 1024,
            }],
        };
        assert_eq!(value.validate(), Ok(()));
    }

    #[test]
    fn rejects_output_aliasing_an_input() {
        let mut value = request();
        value.outputs[0].path = value.inputs[0].path.clone();
        assert_eq!(value.validate(), Err(WorkerError::InvalidOutput));
    }

    #[test]
    fn requires_byte_identical_repeated_runs() {
        let value = request();
        let first = run();
        let mut second = first.clone();
        second.outputs[0].sha256 = digest('0');
        let evidence = ReproducibilityEvidence {
            request_sha256: digest('9'),
            runs: vec![first, second],
        };
        assert_eq!(evidence.validate(&value), Err(WorkerError::NonReproducible));
    }

    #[test]
    fn accepts_identical_repeated_runs() {
        let value = request();
        let result = run();
        let evidence = ReproducibilityEvidence {
            request_sha256: digest('9'),
            runs: vec![result.clone(), result],
        };
        assert_eq!(evidence.validate(&value), Ok(()));
    }
}
