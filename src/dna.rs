pub const MAXIMUM_PACKAGE_NAME_BYTES: usize = 128;
pub const MAXIMUM_IR_BYTES: usize = 1024 * 1024;
pub const MAXIMUM_DEPENDENCIES: usize = 16;
pub const MAXIMUM_MUTATION_FOCI: usize = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OptimizationFocus {
    MaximumThroughput,
    ThermalEfficiency,
    MemoryCompression,
}

/// Borrowed, allocation-free genetic intermediate representation manifest.
///
/// Payload ownership stays with measured package storage. Corinth validates
/// all bounds before a future compiler backend may consume the sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GeneSequence<'artifact> {
    pub package_name: &'artifact str,
    pub version_hash: u64,
    pub ir_payload: &'artifact [u8],
    pub causal_dependencies: &'artifact [&'artifact str],
    pub allowed_mutations: &'artifact [OptimizationFocus],
}

impl<'artifact> GeneSequence<'artifact> {
    pub fn validate(self) -> Result<ValidatedGeneSequence<'artifact>, GeneError> {
        if self.package_name.is_empty()
            || self.package_name.len() > MAXIMUM_PACKAGE_NAME_BYTES
            || self.version_hash == 0
            || self.ir_payload.is_empty()
            || self.ir_payload.len() > MAXIMUM_IR_BYTES
            || self.causal_dependencies.len() > MAXIMUM_DEPENDENCIES
            || self.allowed_mutations.len() > MAXIMUM_MUTATION_FOCI
        {
            return Err(GeneError::InvalidManifest);
        }
        for dependency in self.causal_dependencies {
            if dependency.is_empty() || dependency.len() > MAXIMUM_PACKAGE_NAME_BYTES {
                return Err(GeneError::InvalidDependency);
            }
        }
        for (index, dependency) in self.causal_dependencies.iter().enumerate() {
            if self.causal_dependencies[..index].contains(dependency) {
                return Err(GeneError::DuplicateDependency);
            }
        }
        Ok(ValidatedGeneSequence { sequence: self })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedGeneSequence<'artifact> {
    sequence: GeneSequence<'artifact>,
}

impl<'artifact> ValidatedGeneSequence<'artifact> {
    pub const fn sequence(self) -> GeneSequence<'artifact> {
        self.sequence
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeneError {
    InvalidManifest,
    InvalidDependency,
    DuplicateDependency,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_a_bounded_borrowed_ir_recipe() {
        let dependencies = ["slope-net"];
        let mutations = [OptimizationFocus::ThermalEfficiency];
        let sequence = GeneSequence {
            package_name: "corinth",
            version_hash: 0x1234,
            ir_payload: b"BC\xc0\xde",
            causal_dependencies: &dependencies,
            allowed_mutations: &mutations,
        };
        assert_eq!(sequence.validate().unwrap().sequence(), sequence);
    }

    #[test]
    fn rejects_duplicate_causal_dependencies() {
        let dependencies = ["slope-net", "slope-net"];
        let sequence = GeneSequence {
            package_name: "corinth",
            version_hash: 1,
            ir_payload: b"ir",
            causal_dependencies: &dependencies,
            allowed_mutations: &[],
        };
        assert_eq!(sequence.validate(), Err(GeneError::DuplicateDependency));
    }
}
