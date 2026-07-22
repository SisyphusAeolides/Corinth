use crate::dna::ValidatedGeneSequence;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MatrixCommandKind {
    BeginService = 0,
    AddDependency = 1,
    CommitService = 2,
    AbortService = 3,
}

/// Fixed-size command suitable for a bounded SPSC control ring.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct MatrixCommand {
    pub kind: MatrixCommandKind,
    pub inode: u32,
    pub subject_hash: u64,
    pub object_hash: u64,
}

pub trait MatrixCommandSink {
    fn submit(&mut self, command: MatrixCommand) -> Result<(), IntegrationError>;
}

/// Emits an atomic Arachne update protocol without directly mutating PID 1.
pub fn integrate_into_matrix<S: MatrixCommandSink>(
    gene: ValidatedGeneSequence<'_>,
    inode: u32,
    sink: &mut S,
) -> Result<(), IntegrationError> {
    if inode == 0 {
        return Err(IntegrationError::InvalidInode);
    }
    let sequence = gene.sequence();
    let subject = stable_name_hash(sequence.package_name);
    sink.submit(MatrixCommand {
        kind: MatrixCommandKind::BeginService,
        inode,
        subject_hash: subject,
        object_hash: sequence.causal_dependencies.len() as u64,
    })?;
    for dependency in sequence.causal_dependencies {
        if let Err(error) = sink.submit(MatrixCommand {
            kind: MatrixCommandKind::AddDependency,
            inode,
            subject_hash: subject,
            object_hash: stable_name_hash(dependency),
        }) {
            let _ = sink.submit(MatrixCommand {
                kind: MatrixCommandKind::AbortService,
                inode,
                subject_hash: subject,
                object_hash: 0,
            });
            return Err(error);
        }
    }
    sink.submit(MatrixCommand {
        kind: MatrixCommandKind::CommitService,
        inode,
        subject_hash: subject,
        object_hash: 0,
    })
}

pub const fn stable_name_hash(name: &str) -> u64 {
    let bytes = name.as_bytes();
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    let mut index = 0;
    while index < bytes.len() {
        hash ^= bytes[index] as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        index += 1;
    }
    hash
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegrationError {
    InvalidInode,
    TransportUnavailable,
    QueueFull,
    Rejected,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dna::{GeneSequence, OptimizationFocus};

    struct Capture {
        commands: [Option<MatrixCommand>; 4],
        length: usize,
    }

    impl MatrixCommandSink for Capture {
        fn submit(&mut self, command: MatrixCommand) -> Result<(), IntegrationError> {
            self.commands[self.length] = Some(command);
            self.length += 1;
            Ok(())
        }
    }

    #[test]
    fn emits_begin_edges_and_commit_in_order() {
        let dependencies = ["slope-net"];
        let mutations = [OptimizationFocus::MaximumThroughput];
        let gene = GeneSequence {
            package_name: "corinth",
            version_hash: 1,
            ir_payload: b"ir",
            causal_dependencies: &dependencies,
            allowed_mutations: &mutations,
        }
        .validate()
        .unwrap();
        let mut capture = Capture {
            commands: [None; 4],
            length: 0,
        };
        integrate_into_matrix(gene, 7, &mut capture).unwrap();
        assert_eq!(capture.length, 3);
        assert_eq!(
            capture.commands[0].unwrap().kind,
            MatrixCommandKind::BeginService
        );
        assert_eq!(
            capture.commands[1].unwrap().kind,
            MatrixCommandKind::AddDependency
        );
        assert_eq!(
            capture.commands[2].unwrap().kind,
            MatrixCommandKind::CommitService
        );
    }
}
