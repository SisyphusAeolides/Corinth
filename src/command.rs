//! Strict native command grammar for the Corinth package service.
//!
//! Commands stage bounded, authority-checked ledger transactions. Publishing
//! an artifact requires a durable package store and Arach's measured-image
//! registry; this module deliberately exposes the staged result separately so
//! callers cannot confuse planning with installation.

use slope::env::QuantumArgv;

use crate::alchemist::fnv1a;
use crate::pkg::{PackageError, PackageLedger, ResolvedPackage, TransactionReceipt};
use crate::registry::builtin_package;

pub use crate::registry::MAX_PACKAGE_NAME_BYTES;

pub const PACKAGE_VERSION_INDEX: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackageVerb {
    Install,
    Remove,
    Update,
    Search,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackageCommand<'a> {
    pub verb: PackageVerb,
    pub package: &'a [u8],
    pub package_hash: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandResult {
    Staged(TransactionReceipt),
    Search { known: bool },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandError {
    Usage,
    UnknownVerb,
    InvalidPackageName,
    PackageUnavailable,
    Package(PackageError),
}

/// Parses exactly one native package command.
///
/// Shell expansion, environment substitution, and path interpretation are
/// intentionally absent. A package identity is a bounded ASCII atom, not a
/// host path or an executable command line.
pub fn parse<'a>(arguments: &[&'a [u8]]) -> Result<PackageCommand<'a>, CommandError> {
    if arguments.len() != 3 || arguments[0] != b"corinth" {
        return Err(CommandError::Usage);
    }
    let verb = match arguments[1] {
        b"install" => PackageVerb::Install,
        b"remove" => PackageVerb::Remove,
        b"update" => PackageVerb::Update,
        b"search" => PackageVerb::Search,
        _ => return Err(CommandError::UnknownVerb),
    };
    let package = arguments[2];
    if !valid_package_name(package) {
        return Err(CommandError::InvalidPackageName);
    }
    Ok(PackageCommand {
        verb,
        package,
        package_hash: fnv1a(
            core::str::from_utf8(package).map_err(|_| CommandError::InvalidPackageName)?,
        ),
    })
}

pub fn parse_argv(argv: &QuantumArgv) -> Result<PackageCommand<'static>, CommandError> {
    let (Some(program), Some(verb), Some(package)) = (argv.get(0), argv.get(1), argv.get(2)) else {
        return Err(CommandError::Usage);
    };
    if argv.len() != 3 {
        return Err(CommandError::Usage);
    }
    parse(&[program, verb, package])
}

/// Stages a transaction in the caller-supplied ledger. The caller must bind
/// the resulting receipt to verified artifact storage before describing the
/// package as installed.
pub fn execute(
    command: PackageCommand<'_>,
    ledger: &mut PackageLedger,
) -> Result<CommandResult, CommandError> {
    match command.verb {
        PackageVerb::Search => Ok(CommandResult::Search {
            known: builtin_package(command.package).is_some(),
        }),
        PackageVerb::Install => {
            let Some(package) = builtin_package(command.package) else {
                return Err(CommandError::PackageUnavailable);
            };
            let authority = ledger.authority();
            let mut transaction = ledger.begin(authority).map_err(CommandError::Package)?;
            transaction
                .install(ResolvedPackage {
                    name_hash: package.package_hash,
                    version_idx: package.version_index,
                })
                .map_err(CommandError::Package)?;
            ledger
                .commit(transaction)
                .map(CommandResult::Staged)
                .map_err(CommandError::Package)
        }
        PackageVerb::Remove => {
            let version = ledger
                .version_of(command.package_hash)
                .ok_or(CommandError::Package(PackageError::PackageNotInstalled))?;
            let authority = ledger.authority();
            let mut transaction = ledger.begin(authority).map_err(CommandError::Package)?;
            transaction
                .remove(command.package_hash, version)
                .map_err(CommandError::Package)?;
            ledger
                .commit(transaction)
                .map(CommandResult::Staged)
                .map_err(CommandError::Package)
        }
        PackageVerb::Update => {
            let Some(package) = builtin_package(command.package) else {
                return Err(CommandError::PackageUnavailable);
            };
            let version = ledger
                .version_of(command.package_hash)
                .ok_or(CommandError::Package(PackageError::PackageNotInstalled))?;
            if package.version_index <= version {
                return Err(CommandError::Package(
                    PackageError::VersionPreconditionFailed,
                ));
            }
            let authority = ledger.authority();
            let mut transaction = ledger.begin(authority).map_err(CommandError::Package)?;
            transaction
                .upgrade(command.package_hash, version, package.version_index)
                .map_err(CommandError::Package)?;
            ledger
                .commit(transaction)
                .map(CommandResult::Staged)
                .map_err(CommandError::Package)
        }
    }
}

fn valid_package_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= MAX_PACKAGE_NAME_BYTES
        && name.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_four_native_package_verbs() {
        for (verb, expected) in [
            (b"install" as &[u8], PackageVerb::Install),
            (b"remove", PackageVerb::Remove),
            (b"update", PackageVerb::Update),
            (b"search", PackageVerb::Search),
        ] {
            let parsed = parse(&[b"corinth", verb, b"crest"]).unwrap();
            assert_eq!(parsed.verb, expected);
            assert_eq!(parsed.package_hash, fnv1a("crest"));
        }
    }

    #[test]
    fn rejects_paths_shell_syntax_and_unrecognized_verbs() {
        assert_eq!(
            parse(&[b"corinth", b"install", b"../crest"]),
            Err(CommandError::InvalidPackageName)
        );
        assert_eq!(
            parse(&[b"corinth", b"run", b"crest"]),
            Err(CommandError::UnknownVerb)
        );
        assert_eq!(parse(&[b"install", b"crest"]), Err(CommandError::Usage));
    }

    #[test]
    fn stages_install_and_remove_without_fabricating_an_update() {
        let mut ledger = PackageLedger::new();
        let install = parse(&[b"corinth", b"install", b"crest"]).unwrap();
        let CommandResult::Staged(receipt) = execute(install, &mut ledger).unwrap() else {
            panic!("install must stage a transaction")
        };
        assert_eq!(
            (receipt.installed, receipt.removed, receipt.upgraded),
            (1, 0, 0)
        );

        let update = parse(&[b"corinth", b"update", b"crest"]).unwrap();
        assert_eq!(
            execute(update, &mut ledger),
            Err(CommandError::Package(
                PackageError::VersionPreconditionFailed
            ))
        );

        let remove = parse(&[b"corinth", b"remove", b"crest"]).unwrap();
        let CommandResult::Staged(receipt) = execute(remove, &mut ledger).unwrap() else {
            panic!("remove must stage a transaction")
        };
        assert_eq!(
            (receipt.installed, receipt.removed, receipt.upgraded),
            (0, 1, 0)
        );
    }

    #[test]
    fn search_reports_the_measured_build_catalog_only() {
        let crest = parse(&[b"corinth", b"search", b"crest"]).unwrap();
        assert_eq!(
            execute(crest, &mut PackageLedger::new()),
            Ok(CommandResult::Search { known: true })
        );
        let unknown = parse(&[b"corinth", b"search", b"unknown"]).unwrap();
        assert_eq!(
            execute(unknown, &mut PackageLedger::new()),
            Ok(CommandResult::Search { known: false })
        );
    }

    #[test]
    fn install_rejects_an_unrooted_package_identity() {
        let unknown = parse(&[b"corinth", b"install", b"unknown"]).unwrap();
        assert_eq!(
            execute(unknown, &mut PackageLedger::new()),
            Err(CommandError::PackageUnavailable)
        );
    }
}
