//! Signed, immutable ingress for supported upstream package ecosystems.
//!
//! Discovery and installation authority remain separate. A resolver may find
//! a candidate in AUR, an Arch, CRUX, Fedora, Debian, Alpine, or Gentoo
//! repository, a locked Nix export, or crates.io, but this module accepts it
//! only after a signed ingress lock has reduced every mutable reference to a
//! full Git object or SHA-256 digest.

use alloc::{format, string::String, string::ToString, vec, vec::Vec};
use core::fmt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Component, Path};

use crate::arch_import::{
    ArchPackageMetadata, ArchSource, ArchSourceKind, ImportedRecipe, RecipeTargetPolicy,
    parse_pkgbuild,
};
use crate::foreign_import::{
    ForeignImportError, build_foreign_recipe, parse_alpine_apkbuild, parse_crux_pkgfile,
    parse_debian_control, parse_fedora_spec, parse_gentoo_ebuild, parse_nix_export,
};
use crate::hardware::{
    RecipeCargoClosure, RecipeCargoPackage, RecipeSource, metadata_sha256, parse_recipe,
    source_lock_sha256, validate_cargo_lock_closure,
};

pub const UNIVERSAL_IMPORT_FORMAT: u32 = 1;
pub const UNIVERSAL_IMPORT_RECEIPT_FORMAT: u32 = 1;
pub const MAXIMUM_UNIVERSAL_LOCK_BYTES: usize = 4 * 1024 * 1024;
pub const MAXIMUM_UPSTREAM_METADATA_BYTES: usize = 512 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UniversalEcosystem {
    Arch,
    Aur,
    Fedora,
    Debian,
    Alpine,
    Gentoo,
    Crux,
    Nix,
    Cargo,
}

impl UniversalEcosystem {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Arch => "arch",
            Self::Aur => "aur",
            Self::Fedora => "fedora",
            Self::Debian => "debian",
            Self::Alpine => "alpine",
            Self::Gentoo => "gentoo",
            Self::Crux => "crux",
            Self::Nix => "nix",
            Self::Cargo => "cargo",
        }
    }

    pub const fn requires_companion_source_lock(self) -> bool {
        matches!(
            self,
            Self::Crux | Self::Fedora | Self::Debian | Self::Alpine | Self::Gentoo
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum UniversalOrigin {
    Git {
        repository: String,
        revision: String,
        metadata_path: String,
        metadata_sha256: String,
        #[serde(default)]
        source_lock_path: Option<String>,
        #[serde(default)]
        source_lock_sha256: Option<String>,
        #[serde(default)]
        submodules: bool,
    },
    CratesIo {
        version: String,
        release: u32,
        checksum: String,
        summary: String,
        license: String,
        architectures: Vec<String>,
        #[serde(default)]
        depends: Vec<String>,
        #[serde(default)]
        makedepends: Vec<String>,
        #[serde(default)]
        provides: Vec<String>,
        #[serde(default)]
        conflicts: Vec<String>,
        cargo_lock: String,
        cargo_lock_sha256: String,
        packages: Vec<RecipeCargoPackage>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UniversalImportLock {
    pub format: u32,
    pub ecosystem: UniversalEcosystem,
    pub package: String,
    pub origin: UniversalOrigin,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UniversalImportedRecipe {
    pub recipe: ImportedRecipe,
    pub upstream_evidence_sha256: String,
    pub package: String,
    pub version: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct UniversalImportReceipt {
    pub format: u32,
    pub ecosystem: String,
    pub package: String,
    pub version: String,
    pub ingress_lock_sha256: String,
    pub upstream_evidence_sha256: String,
    pub recipe_metadata_sha256: String,
    pub recipe_source_lock_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UniversalImportError {
    TooLarge,
    Parse(String),
    InvalidLock(String),
    InvalidRepository(String),
    UnsafePath(String),
    MissingSourceLock,
    UnexpectedSourceLock,
    DigestMismatch { path: String },
    PackageMismatch { expected: String, actual: String },
    Arch(String),
    Foreign(String),
    Serialization(String),
}

impl fmt::Display for UniversalImportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for UniversalImportError {}

pub fn parse_universal_import_lock(
    bytes: &[u8],
) -> Result<UniversalImportLock, UniversalImportError> {
    if bytes.is_empty() || bytes.len() > MAXIMUM_UNIVERSAL_LOCK_BYTES {
        return Err(UniversalImportError::TooLarge);
    }
    let lock: UniversalImportLock =
        toml::from_slice(bytes).map_err(|error| UniversalImportError::Parse(error.to_string()))?;
    validate_universal_import_lock(&lock)?;
    Ok(lock)
}

pub fn serialize_universal_import_lock(
    lock: &UniversalImportLock,
) -> Result<Vec<u8>, UniversalImportError> {
    validate_universal_import_lock(lock)?;
    toml::to_string(lock)
        .map(String::into_bytes)
        .map_err(|error| UniversalImportError::Serialization(error.to_string()))
}

pub fn validate_universal_import_lock(
    lock: &UniversalImportLock,
) -> Result<(), UniversalImportError> {
    if lock.format != UNIVERSAL_IMPORT_FORMAT || !valid_package_atom(&lock.package) {
        return Err(UniversalImportError::InvalidLock(
            "invalid format or package identity".into(),
        ));
    }
    match (&lock.ecosystem, &lock.origin) {
        (
            UniversalEcosystem::Arch
            | UniversalEcosystem::Aur
            | UniversalEcosystem::Fedora
            | UniversalEcosystem::Debian
            | UniversalEcosystem::Alpine
            | UniversalEcosystem::Gentoo
            | UniversalEcosystem::Crux
            | UniversalEcosystem::Nix,
            UniversalOrigin::Git {
                repository,
                revision,
                metadata_path,
                metadata_sha256,
                source_lock_path,
                source_lock_sha256,
                submodules,
            },
        ) => {
            if !valid_https_git(repository)
                || !valid_revision(revision)
                || !valid_digest(metadata_sha256)
                || *submodules
            {
                return Err(UniversalImportError::InvalidLock(
                    "Git origin is not immutable".into(),
                ));
            }
            validate_relative_path(metadata_path)?;
            match lock.ecosystem {
                ecosystem if ecosystem.requires_companion_source_lock() => {
                    let path = source_lock_path
                        .as_deref()
                        .ok_or(UniversalImportError::MissingSourceLock)?;
                    validate_relative_path(path)?;
                    if path == metadata_path {
                        return Err(UniversalImportError::InvalidLock(
                            "metadata and source-lock paths must be distinct".into(),
                        ));
                    }
                    if !source_lock_sha256.as_deref().is_some_and(valid_digest) {
                        return Err(UniversalImportError::MissingSourceLock);
                    }
                }
                _ if source_lock_path.is_some() || source_lock_sha256.is_some() => {
                    return Err(UniversalImportError::UnexpectedSourceLock);
                }
                _ => {}
            }
        }
        (
            UniversalEcosystem::Cargo,
            UniversalOrigin::CratesIo {
                version,
                release,
                checksum,
                summary,
                license,
                architectures,
                depends,
                makedepends,
                provides,
                conflicts,
                cargo_lock,
                cargo_lock_sha256,
                packages,
            },
        ) => {
            if !valid_version(version)
                || *release == 0
                || !valid_digest(checksum)
                || summary.trim().is_empty()
                || license.trim().is_empty()
                || architectures.is_empty()
                || architectures.iter().any(|value| !valid_architecture(value))
                || depends
                    .iter()
                    .chain(makedepends)
                    .chain(provides)
                    .chain(conflicts)
                    .any(|value| !valid_package_atom(value))
                || cargo_lock.is_empty()
                || cargo_lock.len() > MAXIMUM_UNIVERSAL_LOCK_BYTES
                || !valid_digest(cargo_lock_sha256)
                || hex_digest(&Sha256::digest(cargo_lock.as_bytes())) != *cargo_lock_sha256
            {
                return Err(UniversalImportError::InvalidLock(
                    "crates.io origin is not a complete immutable package".into(),
                ));
            }
            validate_cargo_lock_closure(cargo_lock, packages, &lock.package, version)
                .map_err(|error| UniversalImportError::InvalidLock(error.to_string()))?;
        }
        _ => {
            return Err(UniversalImportError::InvalidLock(
                "ecosystem and origin kind do not agree".into(),
            ));
        }
    }
    Ok(())
}

pub fn git_origin(lock: &UniversalImportLock) -> Option<(&str, &str, bool)> {
    match &lock.origin {
        UniversalOrigin::Git {
            repository,
            revision,
            submodules,
            ..
        } => Some((repository, revision, *submodules)),
        UniversalOrigin::CratesIo { .. } => None,
    }
}

pub fn crates_io_acquisition_source(lock: &UniversalImportLock) -> Option<RecipeSource> {
    let UniversalOrigin::CratesIo {
        version, checksum, ..
    } = &lock.origin
    else {
        return None;
    };
    Some(RecipeSource {
        kind: "crates-io".into(),
        url: Some(crates_io_url(&lock.package, version)),
        revision: None,
        checksum: Some(checksum.clone()),
        package: Some(lock.package.clone()),
        version: Some(version.clone()),
        destination: None,
        submodules: false,
    })
}

pub fn import_universal_lock(
    lock: &UniversalImportLock,
    repository_root: Option<&Path>,
    policy: &RecipeTargetPolicy,
) -> Result<UniversalImportedRecipe, UniversalImportError> {
    validate_universal_import_lock(lock)?;
    let (metadata, upstream_evidence_sha256) = match (&lock.ecosystem, &lock.origin) {
        (
            UniversalEcosystem::Arch | UniversalEcosystem::Aur,
            UniversalOrigin::Git {
                metadata_path,
                metadata_sha256,
                ..
            },
        ) => {
            let bytes = read_locked_file(repository_root, metadata_path, metadata_sha256)?;
            (
                parse_pkgbuild(&bytes)
                    .map_err(|error| UniversalImportError::Arch(error.to_string()))?,
                metadata_sha256.clone(),
            )
        }
        (
            UniversalEcosystem::Crux,
            UniversalOrigin::Git {
                metadata_path,
                metadata_sha256,
                source_lock_path,
                source_lock_sha256,
                ..
            },
        ) => {
            let pkgfile = read_locked_file(repository_root, metadata_path, metadata_sha256)?;
            let source_lock = read_locked_file(
                repository_root,
                source_lock_path
                    .as_deref()
                    .ok_or(UniversalImportError::MissingSourceLock)?,
                source_lock_sha256
                    .as_deref()
                    .ok_or(UniversalImportError::MissingSourceLock)?,
            )?;
            (
                parse_crux_pkgfile(&pkgfile, &source_lock).map_err(map_foreign_error)?,
                metadata_sha256.clone(),
            )
        }
        (
            UniversalEcosystem::Fedora
            | UniversalEcosystem::Debian
            | UniversalEcosystem::Alpine
            | UniversalEcosystem::Gentoo,
            UniversalOrigin::Git {
                metadata_path,
                metadata_sha256,
                source_lock_path,
                source_lock_sha256,
                ..
            },
        ) => {
            let foreign_metadata =
                read_locked_file(repository_root, metadata_path, metadata_sha256)?;
            let source_lock = read_locked_file(
                repository_root,
                source_lock_path
                    .as_deref()
                    .ok_or(UniversalImportError::MissingSourceLock)?,
                source_lock_sha256
                    .as_deref()
                    .ok_or(UniversalImportError::MissingSourceLock)?,
            )?;
            let metadata = match lock.ecosystem {
                UniversalEcosystem::Fedora => parse_fedora_spec(&foreign_metadata, &source_lock),
                UniversalEcosystem::Debian => parse_debian_control(&foreign_metadata, &source_lock),
                UniversalEcosystem::Alpine => {
                    parse_alpine_apkbuild(&foreign_metadata, &source_lock)
                }
                UniversalEcosystem::Gentoo => {
                    let filename = Path::new(metadata_path)
                        .file_name()
                        .and_then(|name| name.to_str())
                        .ok_or_else(|| UniversalImportError::UnsafePath(metadata_path.clone()))?;
                    parse_gentoo_ebuild(filename, &foreign_metadata, &source_lock)
                }
                _ => unreachable!("foreign ecosystem match is exhaustive"),
            }
            .map_err(map_foreign_error)?;
            (metadata, metadata_sha256.clone())
        }
        (
            UniversalEcosystem::Nix,
            UniversalOrigin::Git {
                metadata_path,
                metadata_sha256,
                ..
            },
        ) => {
            let manifest = read_locked_file(repository_root, metadata_path, metadata_sha256)?;
            (
                parse_nix_export(&manifest).map_err(map_foreign_error)?,
                metadata_sha256.clone(),
            )
        }
        (UniversalEcosystem::Cargo, UniversalOrigin::CratesIo { .. }) => cargo_metadata(lock)?,
        _ => {
            return Err(UniversalImportError::InvalidLock(
                "ecosystem and origin kind do not agree".into(),
            ));
        }
    };
    if metadata.name != lock.package {
        return Err(UniversalImportError::PackageMismatch {
            expected: lock.package.clone(),
            actual: metadata.name,
        });
    }
    let package = metadata.name.clone();
    let version = metadata.version.clone();
    let mut recipe = build_foreign_recipe(&metadata, policy).map_err(map_foreign_error)?;
    if lock.ecosystem == UniversalEcosystem::Cargo {
        recipe = attach_cargo_closure(lock, recipe)?;
    }
    Ok(UniversalImportedRecipe {
        recipe,
        upstream_evidence_sha256,
        package,
        version,
    })
}

pub fn build_universal_import_receipt(
    lock_bytes: &[u8],
    lock: &UniversalImportLock,
    imported: &UniversalImportedRecipe,
) -> UniversalImportReceipt {
    UniversalImportReceipt {
        format: UNIVERSAL_IMPORT_RECEIPT_FORMAT,
        ecosystem: lock.ecosystem.name().into(),
        package: imported.package.clone(),
        version: imported.version.clone(),
        ingress_lock_sha256: hex_digest(&Sha256::digest(lock_bytes)),
        upstream_evidence_sha256: imported.upstream_evidence_sha256.clone(),
        recipe_metadata_sha256: imported.recipe.metadata_sha256.clone(),
        recipe_source_lock_sha256: imported.recipe.source_lock_sha256.clone(),
    }
}

pub fn serialize_universal_import_receipt(
    receipt: &UniversalImportReceipt,
) -> Result<Vec<u8>, UniversalImportError> {
    toml::to_string(receipt)
        .map(String::into_bytes)
        .map_err(|error| UniversalImportError::Serialization(error.to_string()))
}

fn cargo_metadata(
    lock: &UniversalImportLock,
) -> Result<(ArchPackageMetadata, String), UniversalImportError> {
    let UniversalOrigin::CratesIo {
        version,
        release,
        checksum,
        summary,
        license,
        architectures,
        depends,
        makedepends,
        provides,
        conflicts,
        ..
    } = &lock.origin
    else {
        return Err(UniversalImportError::InvalidLock(
            "Cargo lock has a non-Cargo origin".into(),
        ));
    };
    let url = crates_io_url(&lock.package, version);
    Ok((
        ArchPackageMetadata {
            name: lock.package.clone(),
            version: version.clone(),
            release: *release,
            summary: summary.clone(),
            license: license.clone(),
            architectures: architectures.clone(),
            sources: vec![ArchSource {
                kind: ArchSourceKind::CratesIo,
                url,
                revision: None,
                checksum: Some(checksum.clone()),
                package: Some(lock.package.clone()),
                version: Some(version.clone()),
            }],
            depends: depends.clone(),
            makedepends: makedepends.clone(),
            provides: provides.clone(),
            conflicts: conflicts.clone(),
        },
        checksum.clone(),
    ))
}

fn attach_cargo_closure(
    lock: &UniversalImportLock,
    imported: ImportedRecipe,
) -> Result<ImportedRecipe, UniversalImportError> {
    let UniversalOrigin::CratesIo {
        version,
        cargo_lock,
        packages,
        ..
    } = &lock.origin
    else {
        return Err(UniversalImportError::InvalidLock(
            "Cargo ingress has a non-Cargo origin".into(),
        ));
    };
    let mut document = parse_recipe(&imported.bytes)
        .map_err(|error| UniversalImportError::Serialization(error.to_string()))?;
    if document.build.system != "cargo"
        || document.policy.network
        || document.build.commands.iter().any(|command| {
            !command
                .split_ascii_whitespace()
                .any(|word| word == "--locked")
        })
    {
        return Err(UniversalImportError::InvalidLock(
            "Cargo target policy must be offline and use --locked".into(),
        ));
    }
    for package in packages {
        document.source.push(RecipeSource {
            kind: "crates-io".into(),
            url: Some(crates_io_url(&package.name, &package.version)),
            revision: None,
            checksum: Some(package.checksum.clone()),
            package: Some(package.name.clone()),
            version: Some(package.version.clone()),
            destination: Some(format!(
                ".corinth-vendor/{}-{}",
                package.name, package.version
            )),
            submodules: false,
        });
    }
    document.cargo_closure = Some(RecipeCargoClosure {
        lock: cargo_lock.clone(),
        packages: packages.clone(),
    });
    validate_cargo_lock_closure(cargo_lock, packages, &lock.package, version)
        .map_err(|error| UniversalImportError::InvalidLock(error.to_string()))?;
    let bytes = toml::to_string(&document)
        .map(String::into_bytes)
        .map_err(|error| UniversalImportError::Serialization(error.to_string()))?;
    Ok(ImportedRecipe {
        metadata_sha256: metadata_sha256(&bytes),
        source_lock_sha256: source_lock_sha256(&document.source),
        bytes,
    })
}

fn read_locked_file(
    repository_root: Option<&Path>,
    relative: &str,
    expected_sha256: &str,
) -> Result<Vec<u8>, UniversalImportError> {
    let root = repository_root.ok_or_else(|| {
        UniversalImportError::InvalidRepository("repository checkout is missing".into())
    })?;
    let root_metadata = fs::symlink_metadata(root)
        .map_err(|error| UniversalImportError::InvalidRepository(error.to_string()))?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(UniversalImportError::InvalidRepository(
            "repository root is not a regular directory".into(),
        ));
    }
    let mut path = root.to_path_buf();
    for component in Path::new(relative).components() {
        let Component::Normal(name) = component else {
            return Err(UniversalImportError::UnsafePath(relative.into()));
        };
        path.push(name);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| UniversalImportError::InvalidRepository(error.to_string()))?;
        if metadata.file_type().is_symlink() {
            return Err(UniversalImportError::UnsafePath(relative.into()));
        }
    }
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| UniversalImportError::InvalidRepository(error.to_string()))?;
    if !metadata.is_file() || metadata.len() > MAXIMUM_UPSTREAM_METADATA_BYTES as u64 {
        return Err(UniversalImportError::InvalidRepository(format!(
            "upstream metadata is not a bounded regular file: {relative}"
        )));
    }
    let bytes = fs::read(&path)
        .map_err(|error| UniversalImportError::InvalidRepository(error.to_string()))?;
    if hex_digest(&Sha256::digest(&bytes)) != expected_sha256 {
        return Err(UniversalImportError::DigestMismatch {
            path: relative.into(),
        });
    }
    Ok(bytes)
}

fn validate_relative_path(value: &str) -> Result<(), UniversalImportError> {
    let path = Path::new(value);
    if value.is_empty()
        || value.len() > 4096
        || path.components().count() > 32
        || !path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(UniversalImportError::UnsafePath(value.into()));
    }
    Ok(())
}

fn valid_package_atom(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-' | b'_'))
}

fn valid_architecture(value: &str) -> bool {
    matches!(value, "any" | "x86-64" | "aarch64" | "riscv64")
}

fn valid_revision(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_https_git(value: &str) -> bool {
    value.starts_with("https://")
        && value.ends_with(".git")
        && !value.contains(char::is_whitespace)
        && !value.contains('@')
        && !value.contains('#')
}

fn crates_io_url(package: &str, version: &str) -> String {
    format!("https://static.crates.io/crates/{package}/{package}-{version}.crate")
}

fn map_foreign_error(error: ForeignImportError) -> UniversalImportError {
    UniversalImportError::Foreign(error.to_string())
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch_import::parse_target_policy;
    use crate::hardware::parse_recipe;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn digest(bytes: &[u8]) -> String {
        hex_digest(&Sha256::digest(bytes))
    }

    fn temporary_directory(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "corinth-universal-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    fn policy(package: &str, system: &str) -> RecipeTargetPolicy {
        parse_target_policy(
            format!(
                "format = 1\npackage = \"{package}\"\narchitecture = \"x86-64\"\nscope = \"system\"\npublish_authority = \"arach-native\"\nbuild_system = \"{system}\"\nbuild_commands = [\"cargo build --release --locked\"]\noutputs = [\"target/release/{package}\"]\nnetwork = false\nsandbox = true\nreproducible = true\n"
            )
            .as_bytes(),
        )
        .unwrap()
    }

    fn fixed_output_manifest() -> Vec<u8> {
        b"format = 1\n\n[package]\nname = \"demo\"\nversion = \"1.0.0\"\nrelease = 1\nsummary = \"demo\"\nlicense = \"MIT\"\narchitectures = [\"x86-64\"]\ndepends = []\nmakedepends = []\nprovides = []\nconflicts = []\n\n[[source]]\nkind = \"archive\"\nurl = \"https://example.org/demo.tar.gz\"\nsha256 = \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\n"
            .to_vec()
    }

    #[test]
    fn pinned_aur_repository_becomes_one_canonical_recipe() {
        let root = temporary_directory("aur");
        let pkgbuild = b"pkgname=demo\npkgver=1.2.3\npkgrel=1\npkgdesc='demo'\narch=('x86_64')\nlicense=('MIT')\nsource=('https://example.org/demo.tar.gz')\nsha256sums=('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')\ndepends=()\nmakedepends=()\nprovides=()\nconflicts=()\n";
        fs::write(root.join("PKGBUILD"), pkgbuild).unwrap();
        let lock = UniversalImportLock {
            format: UNIVERSAL_IMPORT_FORMAT,
            ecosystem: UniversalEcosystem::Aur,
            package: "demo".into(),
            origin: UniversalOrigin::Git {
                repository: "https://aur.archlinux.org/demo.git".into(),
                revision: "0123456789abcdef0123456789abcdef01234567".into(),
                metadata_path: "PKGBUILD".into(),
                metadata_sha256: digest(pkgbuild),
                source_lock_path: None,
                source_lock_sha256: None,
                submodules: false,
            },
        };
        let imported = import_universal_lock(&lock, Some(&root), &policy("demo", "cargo")).unwrap();
        let recipe = parse_recipe(&imported.recipe.bytes).unwrap();
        assert_eq!(recipe.package.name, "demo");
        assert_eq!(recipe.package.version, "1.2.3");
        assert_eq!(recipe.source[0].kind, "archive");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn crates_io_lock_retains_typed_source_identity() {
        let checksum = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let dependency_checksum =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let cargo_lock = format!(
            "version = 4\n\n[[package]]\nname = \"demo\"\nversion = \"2.0.0\"\ndependencies = [\"helper\"]\n\n[[package]]\nname = \"helper\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{dependency_checksum}\"\n"
        );
        let lock = UniversalImportLock {
            format: UNIVERSAL_IMPORT_FORMAT,
            ecosystem: UniversalEcosystem::Cargo,
            package: "demo".into(),
            origin: UniversalOrigin::CratesIo {
                version: "2.0.0".into(),
                release: 1,
                checksum: checksum.into(),
                summary: "demo crate".into(),
                license: "MIT".into(),
                architectures: vec!["x86-64".into()],
                depends: vec![],
                makedepends: vec![],
                provides: vec![],
                conflicts: vec![],
                cargo_lock: cargo_lock.clone(),
                cargo_lock_sha256: digest(cargo_lock.as_bytes()),
                packages: vec![RecipeCargoPackage {
                    name: "helper".into(),
                    version: "1.0.0".into(),
                    checksum: dependency_checksum.into(),
                }],
            },
        };
        let source = crates_io_acquisition_source(&lock).unwrap();
        assert_eq!(source.kind, "crates-io");
        assert_eq!(source.package.as_deref(), Some("demo"));
        assert_eq!(source.version.as_deref(), Some("2.0.0"));
        let imported = import_universal_lock(&lock, None, &policy("demo", "cargo")).unwrap();
        let recipe = parse_recipe(&imported.recipe.bytes).unwrap();
        assert_eq!(recipe.source[0].kind, "crates-io");
        assert_eq!(recipe.source[0].checksum.as_deref(), Some(checksum));
        assert_eq!(recipe.source.len(), 2);
        assert_eq!(
            recipe.source[1].destination.as_deref(),
            Some(".corinth-vendor/helper-1.0.0")
        );
        assert_eq!(recipe.cargo_closure.unwrap().packages.len(), 1);
    }

    #[test]
    fn github_nix_and_crux_origins_remeasure_every_metadata_file() {
        let root = temporary_directory("foreign");
        let manifest = fixed_output_manifest();
        fs::write(root.join("fixed-output.toml"), &manifest).unwrap();
        let nix = UniversalImportLock {
            format: UNIVERSAL_IMPORT_FORMAT,
            ecosystem: UniversalEcosystem::Nix,
            package: "demo".into(),
            origin: UniversalOrigin::Git {
                repository: "https://github.com/example/nix-export.git".into(),
                revision: "0123456789abcdef0123456789abcdef01234567".into(),
                metadata_path: "fixed-output.toml".into(),
                metadata_sha256: digest(&manifest),
                source_lock_path: None,
                source_lock_sha256: None,
                submodules: false,
            },
        };
        let imported = import_universal_lock(&nix, Some(&root), &policy("demo", "cargo")).unwrap();
        assert_eq!(imported.version, "1.0.0");

        let pkgfile = b"name=demo\nversion=1.0.0\nrelease=1\nsource=(https://example.org/demo.tar.gz)\ndepends=()\nbuild() { false; }\n";
        fs::write(root.join("Pkgfile"), pkgfile).unwrap();
        let crux = UniversalImportLock {
            format: UNIVERSAL_IMPORT_FORMAT,
            ecosystem: UniversalEcosystem::Crux,
            package: "demo".into(),
            origin: UniversalOrigin::Git {
                repository: "https://github.com/example/crux-port.git".into(),
                revision: "89abcdef0123456789abcdef0123456789abcdef".into(),
                metadata_path: "Pkgfile".into(),
                metadata_sha256: digest(pkgfile),
                source_lock_path: Some("fixed-output.toml".into()),
                source_lock_sha256: Some(digest(&manifest)),
                submodules: false,
            },
        };
        let imported = import_universal_lock(&crux, Some(&root), &policy("demo", "cargo")).unwrap();
        assert_eq!(imported.version, "1.0.0");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn signed_foreign_git_origins_translate_every_static_ecosystem() {
        let root = temporary_directory("foreign-static");
        let source_lock = fixed_output_manifest();
        fs::write(root.join("sources.toml"), &source_lock).unwrap();
        let checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let alpine = format!(
            "pkgname=demo\npkgver=1.0.0\npkgrel=1\npkgdesc=demo\narch=x86_64\nlicense=MIT\nsource=https://example.org/demo.tar.gz\nsha256sums={checksum}\nbuild() {{ false; }}\n"
        );
        let inputs = [
            (
                UniversalEcosystem::Fedora,
                "demo.spec",
                b"Name: demo\nVersion: 1.0.0\nRelease: 1\nSummary: demo\nLicense: MIT\nExclusiveArch: x86_64\nSource0: https://example.org/demo.tar.gz\n%description\ndemo\n"
                    .as_slice(),
            ),
            (
                UniversalEcosystem::Debian,
                "debian/control",
                b"Source: demo\n\nPackage: demo\nArchitecture: amd64\nVersion: 1.0.0\nDescription: demo\n bounded metadata\n"
                    .as_slice(),
            ),
            (
                UniversalEcosystem::Alpine,
                "APKBUILD",
                alpine.as_bytes(),
            ),
            (
                UniversalEcosystem::Gentoo,
                "demo-1.0.0.ebuild",
                b"EAPI=8\nDESCRIPTION=demo\nHOMEPAGE=https://example.org\nLICENSE=MIT\nKEYWORDS=~amd64\nSLOT=0\nSRC_URI=https://example.org/demo.tar.gz\nsrc_compile() { false; }\n"
                    .as_slice(),
            ),
        ];
        for (ecosystem, metadata_path, metadata) in inputs {
            let path = root.join(metadata_path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, metadata).unwrap();
            let lock = UniversalImportLock {
                format: UNIVERSAL_IMPORT_FORMAT,
                ecosystem,
                package: "demo".into(),
                origin: UniversalOrigin::Git {
                    repository: format!("https://example.org/{}.git", ecosystem.name()),
                    revision: "0123456789abcdef0123456789abcdef01234567".into(),
                    metadata_path: metadata_path.into(),
                    metadata_sha256: digest(metadata),
                    source_lock_path: Some("sources.toml".into()),
                    source_lock_sha256: Some(digest(&source_lock)),
                    submodules: false,
                },
            };
            let imported =
                import_universal_lock(&lock, Some(&root), &policy("demo", "cargo")).unwrap();
            let recipe = parse_recipe(&imported.recipe.bytes).unwrap();
            assert_eq!(recipe.package.name, "demo");
            assert_eq!(recipe.package.version, "1.0.0");
            assert_eq!(recipe.source.len(), 1);
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn foreign_git_origins_require_both_source_lock_identity_fields() {
        for ecosystem in [
            UniversalEcosystem::Fedora,
            UniversalEcosystem::Debian,
            UniversalEcosystem::Alpine,
            UniversalEcosystem::Gentoo,
        ] {
            let mut lock = UniversalImportLock {
                format: UNIVERSAL_IMPORT_FORMAT,
                ecosystem,
                package: "demo".into(),
                origin: UniversalOrigin::Git {
                    repository: format!("https://example.org/{}.git", ecosystem.name()),
                    revision: "0123456789abcdef0123456789abcdef01234567".into(),
                    metadata_path: "metadata".into(),
                    metadata_sha256: "a".repeat(64),
                    source_lock_path: None,
                    source_lock_sha256: None,
                    submodules: false,
                },
            };
            assert_eq!(
                validate_universal_import_lock(&lock),
                Err(UniversalImportError::MissingSourceLock)
            );
            if let UniversalOrigin::Git {
                source_lock_path, ..
            } = &mut lock.origin
            {
                *source_lock_path = Some("sources.toml".into());
            }
            assert_eq!(
                validate_universal_import_lock(&lock),
                Err(UniversalImportError::MissingSourceLock)
            );
        }
    }

    #[test]
    fn serialized_lock_schema_is_strict_and_transport_is_separate() {
        let bytes = b"format = 1\necosystem = \"aur\"\npackage = \"demo\"\n\n[origin]\nkind = \"git\"\nrepository = \"https://aur.archlinux.org/demo.git\"\nrevision = \"0123456789abcdef0123456789abcdef01234567\"\nmetadata_path = \"PKGBUILD\"\nmetadata_sha256 = \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\nsubmodules = false\n";
        let lock = parse_universal_import_lock(bytes).unwrap();
        let serialized = serialize_universal_import_lock(&lock).unwrap();
        assert_eq!(parse_universal_import_lock(&serialized).unwrap(), lock);
        assert_eq!(lock.ecosystem, UniversalEcosystem::Aur);
        assert_eq!(
            git_origin(&lock).unwrap().0,
            "https://aur.archlinux.org/demo.git"
        );
        let mut submodules = lock.clone();
        if let UniversalOrigin::Git { submodules, .. } = &mut submodules.origin {
            *submodules = true;
        }
        assert!(matches!(
            validate_universal_import_lock(&submodules),
            Err(UniversalImportError::InvalidLock(_))
        ));

        let unknown = [bytes.as_slice(), b"unknown = true\n"].concat();
        assert!(matches!(
            parse_universal_import_lock(&unknown),
            Err(UniversalImportError::Parse(_))
        ));
    }

    #[test]
    fn metadata_drift_and_path_escape_fail_before_parsing() {
        let root = temporary_directory("drift");
        fs::write(root.join("PKGBUILD"), b"changed").unwrap();
        let lock = UniversalImportLock {
            format: UNIVERSAL_IMPORT_FORMAT,
            ecosystem: UniversalEcosystem::Arch,
            package: "demo".into(),
            origin: UniversalOrigin::Git {
                repository: "https://github.com/example/demo.git".into(),
                revision: "0123456789abcdef0123456789abcdef01234567".into(),
                metadata_path: "PKGBUILD".into(),
                metadata_sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .into(),
                source_lock_path: None,
                source_lock_sha256: None,
                submodules: false,
            },
        };
        assert!(matches!(
            import_universal_lock(&lock, Some(&root), &policy("demo", "cargo")),
            Err(UniversalImportError::DigestMismatch { .. })
        ));
        let mut escaped = lock;
        if let UniversalOrigin::Git { metadata_path, .. } = &mut escaped.origin {
            *metadata_path = "../PKGBUILD".into();
        }
        assert!(matches!(
            validate_universal_import_lock(&escaped),
            Err(UniversalImportError::UnsafePath(_))
        ));
        fs::remove_dir_all(root).unwrap();
    }
}
