use crate::dna::{OptimizationFocus, ValidatedGeneSequence};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetArchitecture {
    X86_64Sisyphus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SynthesisTelemetry {
    pub thermal_celsius: u8,
}

pub trait LoweringBackend {
    fn lower(
        &self,
        architecture: TargetArchitecture,
        ir: &[u8],
        focus: OptimizationFocus,
        output: &mut [u8],
    ) -> Result<usize, SynthesisError>;
}

pub trait ArtifactPublisher {
    fn publish(
        &self,
        package_name: &str,
        version_hash: u64,
        machine_code: &[u8],
    ) -> Result<u32, SynthesisError>;
}

pub struct CorinthCompiler {
    pub target_architecture: TargetArchitecture,
    pub thermal_limit_celsius: u8,
}

impl CorinthCompiler {
    pub const fn new() -> Self {
        Self {
            target_architecture: TargetArchitecture::X86_64Sisyphus,
            thermal_limit_celsius: 90,
        }
    }

    /// Lowers a validated IR artifact into bounded caller-owned storage and
    /// publishes only the initialized machine-code prefix.
    pub fn synthesize<B: LoweringBackend, P: ArtifactPublisher>(
        &self,
        gene: ValidatedGeneSequence<'_>,
        telemetry: SynthesisTelemetry,
        output: &mut [u8],
        backend: &B,
        publisher: &P,
    ) -> Result<u32, SynthesisError> {
        let sequence = gene.sequence();
        let preferred = if telemetry.thermal_celsius >= self.thermal_limit_celsius {
            OptimizationFocus::ThermalEfficiency
        } else {
            OptimizationFocus::MaximumThroughput
        };
        let focus = if sequence.allowed_mutations.contains(&preferred) {
            preferred
        } else {
            sequence
                .allowed_mutations
                .first()
                .copied()
                .ok_or(SynthesisError::NoAllowedMutation)?
        };
        let written =
            backend.lower(self.target_architecture, sequence.ir_payload, focus, output)?;
        if written == 0 || written > output.len() {
            return Err(SynthesisError::InvalidMachineCodeLength);
        }
        publisher.publish(
            sequence.package_name,
            sequence.version_hash,
            &output[..written],
        )
    }
}

impl Default for CorinthCompiler {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SynthesisError {
    NoAllowedMutation,
    OutputTooSmall,
    InvalidMachineCodeLength,
    BackendUnavailable,
    PublicationUnavailable,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dna::GeneSequence;
    use core::cell::Cell;

    struct Backend {
        selected: Cell<Option<OptimizationFocus>>,
    }

    impl LoweringBackend for Backend {
        fn lower(
            &self,
            _architecture: TargetArchitecture,
            _ir: &[u8],
            focus: OptimizationFocus,
            output: &mut [u8],
        ) -> Result<usize, SynthesisError> {
            if output.len() < 2 {
                return Err(SynthesisError::OutputTooSmall);
            }
            self.selected.set(Some(focus));
            output[..2].copy_from_slice(&[0x90, 0xc3]);
            Ok(2)
        }
    }

    struct Publisher;

    impl ArtifactPublisher for Publisher {
        fn publish(
            &self,
            _package_name: &str,
            _version_hash: u64,
            machine_code: &[u8],
        ) -> Result<u32, SynthesisError> {
            assert_eq!(machine_code, [0x90, 0xc3]);
            Ok(7)
        }
    }

    #[test]
    fn thermal_pressure_selects_an_allowed_efficiency_mutation() {
        let mutations = [
            OptimizationFocus::MaximumThroughput,
            OptimizationFocus::ThermalEfficiency,
        ];
        let gene = GeneSequence {
            package_name: "test",
            version_hash: 1,
            ir_payload: b"ir",
            causal_dependencies: &[],
            allowed_mutations: &mutations,
        }
        .validate()
        .unwrap();
        let backend = Backend {
            selected: Cell::new(None),
        };
        let mut output = [0_u8; 8];
        let inode = CorinthCompiler::new()
            .synthesize(
                gene,
                SynthesisTelemetry {
                    thermal_celsius: 95,
                },
                &mut output,
                &backend,
                &Publisher,
            )
            .unwrap();
        assert_eq!(inode, 7);
        assert_eq!(
            backend.selected.get(),
            Some(OptimizationFocus::ThermalEfficiency)
        );
    }
}
