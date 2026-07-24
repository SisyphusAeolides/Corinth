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
            return abort_after_failure(sink, inode, subject, error);
        }
    }
    if let Err(error) = sink.submit(MatrixCommand {
        kind: MatrixCommandKind::CommitService,
        inode,
        subject_hash: subject,
        object_hash: 0,
    }) {
        return abort_after_failure(sink, inode, subject, error);
    }
    Ok(())
}

fn abort_after_failure<S: MatrixCommandSink>(
    sink: &mut S,
    inode: u32,
    subject_hash: u64,
    operation_error: IntegrationError,
) -> Result<(), IntegrationError> {
    sink.submit(MatrixCommand {
        kind: MatrixCommandKind::AbortService,
        inode,
        subject_hash,
        object_hash: 0,
    })
    .map_err(|_| IntegrationError::RollbackFailed)?;
    Err(operation_error)
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
    RollbackFailed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dna::{GeneSequence, OptimizationFocus};

    struct Capture {
        commands: [Option<MatrixCommand>; 5],
        length: usize,
        fail_kind: Option<MatrixCommandKind>,
        fail_abort: bool,
    }

    impl MatrixCommandSink for Capture {
        fn submit(&mut self, command: MatrixCommand) -> Result<(), IntegrationError> {
            self.commands[self.length] = Some(command);
            self.length += 1;
            if self.fail_abort && command.kind == MatrixCommandKind::AbortService {
                return Err(IntegrationError::TransportUnavailable);
            }
            if self.fail_kind == Some(command.kind) {
                return Err(IntegrationError::Rejected);
            }
            Ok(())
        }
    }

    fn gene<'artifact>(
        dependencies: &'artifact [&'artifact str],
        mutations: &'artifact [OptimizationFocus],
    ) -> ValidatedGeneSequence<'artifact> {
        GeneSequence {
            package_name: "corinth",
            version_hash: 1,
            ir_payload: b"ir",
            causal_dependencies: dependencies,
            allowed_mutations: mutations,
        }
        .validate()
        .unwrap()
    }

    #[test]
    fn emits_begin_edges_and_commit_in_order() {
        let dependencies = ["slope-net"];
        let mutations = [OptimizationFocus::MaximumThroughput];
        let mut capture = Capture {
            commands: [None; 5],
            length: 0,
            fail_kind: None,
            fail_abort: false,
        };
        integrate_into_matrix(gene(&dependencies, &mutations), 7, &mut capture).unwrap();
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

    #[test]
    fn commit_rejection_aborts_the_open_transaction() {
        let mutations = [OptimizationFocus::MaximumThroughput];
        let mut capture = Capture {
            commands: [None; 5],
            length: 0,
            fail_kind: Some(MatrixCommandKind::CommitService),
            fail_abort: false,
        };

        assert_eq!(
            integrate_into_matrix(gene(&[], &mutations), 7, &mut capture),
            Err(IntegrationError::Rejected),
        );
        assert_eq!(capture.length, 3);
        assert_eq!(
            capture.commands[0].unwrap().kind,
            MatrixCommandKind::BeginService,
        );
        assert_eq!(
            capture.commands[1].unwrap().kind,
            MatrixCommandKind::CommitService,
        );
        assert_eq!(
            capture.commands[2].unwrap().kind,
            MatrixCommandKind::AbortService,
        );
    }

    #[test]
    fn dependency_rejection_aborts_the_open_transaction() {
        let dependencies = ["slope-net"];
        let mutations = [OptimizationFocus::MaximumThroughput];
        let mut capture = Capture {
            commands: [None; 5],
            length: 0,
            fail_kind: Some(MatrixCommandKind::AddDependency),
            fail_abort: false,
        };

        assert_eq!(
            integrate_into_matrix(gene(&dependencies, &mutations), 7, &mut capture),
            Err(IntegrationError::Rejected),
        );
        assert_eq!(capture.length, 3);
        assert_eq!(
            capture.commands[2].unwrap().kind,
            MatrixCommandKind::AbortService,
        );
    }

    #[test]
    fn rollback_failure_is_not_reported_as_successful_cleanup() {
        let mutations = [OptimizationFocus::MaximumThroughput];
        let mut capture = Capture {
            commands: [None; 5],
            length: 0,
            fail_kind: Some(MatrixCommandKind::CommitService),
            fail_abort: true,
        };

        assert_eq!(
            integrate_into_matrix(gene(&[], &mutations), 7, &mut capture),
            Err(IntegrationError::RollbackFailed),
        );
        assert_eq!(
            capture.commands[2].unwrap().kind,
            MatrixCommandKind::AbortService,
        );
    }
}
