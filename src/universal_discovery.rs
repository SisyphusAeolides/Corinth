//! Mutable provider discovery with an immutable output boundary.
//!
//! This module may resolve a branch, tag, or provider HEAD, but its only
//! product is an unsigned ingress candidate containing a full Git commit and
//! SHA-256 measurements. It cannot emit a recipe or authorize installation.

use alloc::{format, string::String, string::ToString, vec};
use core::fmt;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Component, Path};
use std::process::{Command, Stdio};

use crate::hardware::HardwareProvisioner;
use crate::universal_import::{
    MAXIMUM_UPSTREAM_METADATA_BYTES, UNIVERSAL_IMPORT_FORMAT, UniversalEcosystem,
    UniversalImportLock, UniversalOrigin, validate_universal_import_lock,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitDiscoveryRequest {
    pub ecosystem: UniversalEcosystem,
    pub package: String,
    pub repository: String,
    pub reference: String,
    pub metadata_path: String,
    pub source_lock_path: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiscoveryError {
    InvalidRequest(String),
    ResolutionFailed(String),
    AmbiguousReference(String),
    AcquisitionFailed(String),
    UnsafePath(String),
    MetadataUnavailable(String),
    InvalidCandidate(String),
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for DiscoveryError {}

pub fn aur_discovery_request(package: &str, reference: &str) -> GitDiscoveryRequest {
    GitDiscoveryRequest {
        ecosystem: UniversalEcosystem::Aur,
        package: package.into(),
        repository: format!("https://aur.archlinux.org/{package}.git"),
        reference: reference.into(),
        metadata_path: "PKGBUILD".into(),
        source_lock_path: None,
    }
}

pub fn arch_discovery_request(package: &str, reference: &str) -> GitDiscoveryRequest {
    GitDiscoveryRequest {
        ecosystem: UniversalEcosystem::Arch,
        package: package.into(),
        repository: format!(
            "https://gitlab.archlinux.org/archlinux/packaging/packages/{package}.git"
        ),
        reference: reference.into(),
        metadata_path: "PKGBUILD".into(),
        source_lock_path: None,
    }
}

pub fn discover_git_candidate(
    request: &GitDiscoveryRequest,
    provisioner: &HardwareProvisioner,
) -> Result<UniversalImportLock, DiscoveryError> {
    validate_git_discovery_request(request)?;
    let revision = resolve_git_reference(&request.repository, &request.reference)?;
    let repository = provisioner
        .acquire_recipe_repository(&request.repository, &revision, false)
        .map_err(|error| DiscoveryError::AcquisitionFailed(error.to_string()))?;
    build_git_candidate(request, &revision, &repository)
}

pub fn build_git_candidate(
    request: &GitDiscoveryRequest,
    revision: &str,
    repository_root: &Path,
) -> Result<UniversalImportLock, DiscoveryError> {
    validate_git_discovery_request(request)?;
    if !valid_revision(revision) {
        return Err(DiscoveryError::InvalidRequest(
            "resolved Git object is not a full commit identity".into(),
        ));
    }
    let metadata_sha256 = measure_repository_file(repository_root, &request.metadata_path)?;
    let source_lock_sha256 = request
        .source_lock_path
        .as_deref()
        .map(|path| measure_repository_file(repository_root, path))
        .transpose()?;
    let candidate = UniversalImportLock {
        format: UNIVERSAL_IMPORT_FORMAT,
        ecosystem: request.ecosystem,
        package: request.package.clone(),
        origin: UniversalOrigin::Git {
            repository: request.repository.clone(),
            revision: revision.into(),
            metadata_path: request.metadata_path.clone(),
            metadata_sha256,
            source_lock_path: request.source_lock_path.clone(),
            source_lock_sha256,
            submodules: false,
        },
    };
    validate_universal_import_lock(&candidate)
        .map_err(|error| DiscoveryError::InvalidCandidate(error.to_string()))?;
    Ok(candidate)
}

pub fn validate_git_discovery_request(request: &GitDiscoveryRequest) -> Result<(), DiscoveryError> {
    if matches!(request.ecosystem, UniversalEcosystem::Cargo) {
        return Err(DiscoveryError::InvalidRequest(
            "Cargo discovery requires a complete registry dependency graph".into(),
        ));
    }
    if !valid_package(&request.package)
        || !valid_repository(&request.repository)
        || !valid_reference(&request.reference)
    {
        return Err(DiscoveryError::InvalidRequest(
            "package, repository, or reference is invalid".into(),
        ));
    }
    validate_relative_path(&request.metadata_path)?;
    match request.ecosystem {
        UniversalEcosystem::Crux => {
            let path = request.source_lock_path.as_deref().ok_or_else(|| {
                DiscoveryError::InvalidRequest("CRUX discovery requires a source lock".into())
            })?;
            validate_relative_path(path)?;
        }
        _ if request.source_lock_path.is_some() => {
            return Err(DiscoveryError::InvalidRequest(
                "only CRUX discovery accepts a separate source lock".into(),
            ));
        }
        _ => {}
    }
    if request.ecosystem == UniversalEcosystem::Aur
        && request.repository != format!("https://aur.archlinux.org/{}.git", request.package)
    {
        return Err(DiscoveryError::InvalidRequest(
            "AUR repository identity must be derived from the package".into(),
        ));
    }
    if request.ecosystem == UniversalEcosystem::Arch
        && request.repository
            != format!(
                "https://gitlab.archlinux.org/archlinux/packaging/packages/{}.git",
                request.package
            )
    {
        return Err(DiscoveryError::InvalidRequest(
            "Arch repository identity must be derived from the package".into(),
        ));
    }
    Ok(())
}

pub fn resolve_git_reference(repository: &str, reference: &str) -> Result<String, DiscoveryError> {
    if !valid_repository(repository) || !valid_reference(reference) {
        return Err(DiscoveryError::InvalidRequest(
            "repository or reference is invalid".into(),
        ));
    }
    if valid_revision(reference) {
        return Ok(reference.into());
    }
    let mut arguments = vec!["ls-remote", repository];
    let peeled_reference;
    if reference == "HEAD" || reference.starts_with("refs/heads/") {
        arguments.push(reference);
    } else {
        arguments.push(reference);
        peeled_reference = format!("{reference}^{{}}");
        arguments.push(&peeled_reference);
    }
    let output = Command::new("git")
        .args(&arguments)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "/bin/false")
        .env("GIT_ALLOW_PROTOCOL", "https")
        .stdin(Stdio::null())
        .output()
        .map_err(|error| DiscoveryError::ResolutionFailed(error.to_string()))?;
    if !output.status.success() {
        return Err(DiscoveryError::ResolutionFailed(
            "git provider query failed".into(),
        ));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| DiscoveryError::ResolutionFailed("Git output is not UTF-8".into()))?;
    parse_ls_remote(reference, &stdout)
}

fn parse_ls_remote(reference: &str, output: &str) -> Result<String, DiscoveryError> {
    let mut direct = None;
    let mut peeled = None;
    for line in output.lines() {
        let mut fields = line.split_ascii_whitespace();
        let revision = fields.next().unwrap_or_default();
        let name = fields.next().unwrap_or_default();
        if fields.next().is_some() || !valid_revision(revision) {
            return Err(DiscoveryError::ResolutionFailed(
                "provider returned malformed Git identity".into(),
            ));
        }
        if name == reference {
            if direct.as_deref().is_some_and(|current| current != revision) {
                return Err(DiscoveryError::AmbiguousReference(reference.into()));
            }
            direct = Some(revision.to_string());
        } else if name == format!("{reference}^{{}}") {
            if peeled.as_deref().is_some_and(|current| current != revision) {
                return Err(DiscoveryError::AmbiguousReference(reference.into()));
            }
            peeled = Some(revision.to_string());
        } else {
            return Err(DiscoveryError::ResolutionFailed(
                "provider returned an unexpected Git reference".into(),
            ));
        }
    }
    peeled
        .or(direct)
        .ok_or_else(|| DiscoveryError::ResolutionFailed(reference.into()))
}

fn measure_repository_file(root: &Path, relative: &str) -> Result<String, DiscoveryError> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| DiscoveryError::MetadataUnavailable(error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(DiscoveryError::MetadataUnavailable(
            "checkout root is not a regular directory".into(),
        ));
    }
    validate_relative_path(relative)?;
    let mut path = root.to_path_buf();
    for component in Path::new(relative).components() {
        let Component::Normal(name) = component else {
            return Err(DiscoveryError::UnsafePath(relative.into()));
        };
        path.push(name);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| DiscoveryError::MetadataUnavailable(error.to_string()))?;
        if metadata.file_type().is_symlink() {
            return Err(DiscoveryError::UnsafePath(relative.into()));
        }
    }
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| DiscoveryError::MetadataUnavailable(error.to_string()))?;
    if !metadata.is_file() || metadata.len() > MAXIMUM_UPSTREAM_METADATA_BYTES as u64 {
        return Err(DiscoveryError::MetadataUnavailable(relative.into()));
    }
    let bytes =
        fs::read(path).map_err(|error| DiscoveryError::MetadataUnavailable(error.to_string()))?;
    Ok(hex_digest(&Sha256::digest(bytes)))
}

fn validate_relative_path(value: &str) -> Result<(), DiscoveryError> {
    let path = Path::new(value);
    if value.is_empty()
        || value.len() > 4096
        || path.components().count() > 32
        || !path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(DiscoveryError::UnsafePath(value.into()));
    }
    Ok(())
}

fn valid_repository(value: &str) -> bool {
    value.starts_with("https://")
        && value.ends_with(".git")
        && !value.contains(char::is_whitespace)
        && !value.contains('@')
        && !value.contains('#')
        && !value.starts_with("https://-")
}

fn valid_package(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_reference(value: &str) -> bool {
    if valid_revision(value) || value == "HEAD" {
        return true;
    }
    value.len() <= 512
        && (value.starts_with("refs/heads/") || value.starts_with("refs/tags/"))
        && !value.ends_with('/')
        && !value.ends_with('.')
        && !value.contains("..")
        && !value.contains("//")
        && !value.contains("@{")
        && !value.bytes().any(|byte| {
            byte.is_ascii_control()
                || byte.is_ascii_whitespace()
                || matches!(byte, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
        })
}

fn valid_revision(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
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
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_directory(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "corinth-discovery-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn aur_identity_is_derived_and_candidate_is_fully_measured() {
        let root = temporary_directory("aur");
        fs::write(root.join("PKGBUILD"), b"pkgname=demo\n").unwrap();
        let request = aur_discovery_request("demo", "HEAD");
        let candidate =
            build_git_candidate(&request, "0123456789abcdef0123456789abcdef01234567", &root)
                .unwrap();
        let UniversalOrigin::Git {
            revision,
            metadata_sha256,
            ..
        } = candidate.origin
        else {
            panic!("expected Git origin");
        };
        assert_eq!(revision, "0123456789abcdef0123456789abcdef01234567");
        assert_eq!(metadata_sha256.len(), 64);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn arch_identity_is_derived_from_the_official_packaging_namespace() {
        let request = arch_discovery_request("linux", "HEAD");
        assert_eq!(
            request.repository,
            "https://gitlab.archlinux.org/archlinux/packaging/packages/linux.git"
        );
        assert_eq!(request.metadata_path, "PKGBUILD");
    }

    #[test]
    fn annotated_tag_resolution_prefers_the_peeled_commit() {
        let object = "0123456789abcdef0123456789abcdef01234567";
        let commit = "89abcdef0123456789abcdef0123456789abcdef";
        let output = format!("{object}\trefs/tags/v1\n{commit}\trefs/tags/v1^{{}}\n");
        assert_eq!(parse_ls_remote("refs/tags/v1", &output).unwrap(), commit);
    }

    #[test]
    fn identical_provider_duplicates_preserve_one_identity() {
        let revision = "0123456789abcdef0123456789abcdef01234567";
        let output = format!("{revision}\tHEAD\n{revision}\tHEAD\n");
        assert_eq!(parse_ls_remote("HEAD", &output).unwrap(), revision);
    }

    #[test]
    fn ambiguous_or_unexpected_provider_output_is_rejected() {
        let revision = "0123456789abcdef0123456789abcdef01234567";
        let other = "89abcdef0123456789abcdef0123456789abcdef";
        let duplicate = format!("{revision}\trefs/heads/main\n{other}\trefs/heads/main\n");
        assert!(matches!(
            parse_ls_remote("refs/heads/main", &duplicate),
            Err(DiscoveryError::AmbiguousReference(_))
        ));
        let unexpected = format!("{revision}\trefs/heads/other\n");
        assert!(parse_ls_remote("refs/heads/main", &unexpected).is_err());
    }

    #[test]
    fn crux_requires_two_independent_metadata_measurements() {
        let root = temporary_directory("crux");
        fs::write(root.join("Pkgfile"), b"name=demo\n").unwrap();
        fs::write(root.join("sources.toml"), b"format = 1\n").unwrap();
        let request = GitDiscoveryRequest {
            ecosystem: UniversalEcosystem::Crux,
            package: "demo".into(),
            repository: "https://example.org/ports/demo.git".into(),
            reference: "refs/heads/main".into(),
            metadata_path: "Pkgfile".into(),
            source_lock_path: Some("sources.toml".into()),
        };
        let candidate =
            build_git_candidate(&request, "0123456789abcdef0123456789abcdef01234567", &root)
                .unwrap();
        let UniversalOrigin::Git {
            source_lock_sha256, ..
        } = candidate.origin
        else {
            panic!("expected Git origin");
        };
        assert_eq!(source_lock_sha256.unwrap().len(), 64);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unsafe_refs_paths_and_aur_remotes_fail_closed() {
        let mut request = aur_discovery_request("demo", "refs/heads/main");
        request.metadata_path = "../PKGBUILD".into();
        assert!(validate_git_discovery_request(&request).is_err());
        request.metadata_path = "PKGBUILD".into();
        request.repository = "https://example.org/demo.git".into();
        assert!(validate_git_discovery_request(&request).is_err());
        request.repository = "https://aur.archlinux.org/demo.git".into();
        request.reference = "refs/heads/main..next".into();
        assert!(validate_git_discovery_request(&request).is_err());
    }
}
