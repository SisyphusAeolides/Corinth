//! Signed binary repository support for Corinth.
//!
//! Binary packages are not a shortcut around authority.  The repository index
//! is signed with a scoped `package-index` key, every artifact is fetched over
//! HTTPS, and the downloaded bytes must match the index digest before they are
//! published to the receipt store.

use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use arach_hwd::plan::CorinthVerb;
use arach_hwd::profile::{PackageScope, RepositoryAuthority};
use arach_hwd::signature::Keyring;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::hardware::{
    HardwareBuildReceipt, HardwareError, HostPackageStore, MAX_OUTPUT_BYTES, VerifiedHardwarePlan,
    atomic_write, hex_digest, prepare_private_root, read_bounded,
};

pub const BINARY_INDEX_FORMAT: u32 = 1;
pub const MAX_INDEX_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BinaryRepositoryIndex {
    pub format: u32,
    pub repository: RepositoryAuthority,
    pub key_id: String,
    #[serde(rename = "package")]
    pub packages: Vec<BinaryPackage>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BinaryPackage {
    pub name: String,
    pub version: String,
    pub release: u32,
    pub scope: PackageScope,
    pub repository: RepositoryAuthority,
    pub metadata_sha256: String,
    pub artifact_sha256: String,
    pub source_lock_sha256: String,
    pub url: String,
    pub size: u64,
}

#[derive(Clone, Debug)]
pub struct VerifiedBinaryIndex {
    pub index: BinaryRepositoryIndex,
    pub key_id: String,
    pub index_sha256: String,
}

impl BinaryRepositoryIndex {
    pub fn validate(&self) -> Result<(), HardwareError> {
        if self.format != BINARY_INDEX_FORMAT || self.key_id.is_empty() || self.packages.is_empty()
        {
            return Err(HardwareError::InvalidPlan(
                "invalid binary repository index header".into(),
            ));
        }
        let mut names = std::collections::BTreeSet::new();
        for package in &self.packages {
            if !valid_package_name(&package.name)
                || package.version.trim().is_empty()
                || package.release == 0
                || !names.insert(package.name.clone())
                || !valid_digest(&package.metadata_sha256)
                || !valid_digest(&package.artifact_sha256)
                || !valid_digest(&package.source_lock_sha256)
                || !is_https_url(&package.url)
                || package.size == 0
                || package.size > MAX_OUTPUT_BYTES
            {
                return Err(HardwareError::InvalidPlan(format!(
                    "invalid binary package record: {}",
                    package.name
                )));
            }
            let authority_valid = match package.scope {
                PackageScope::System => package.repository == RepositoryAuthority::ArachNative,
                PackageScope::Driver | PackageScope::Firmware => {
                    package.repository == RepositoryAuthority::ArachHardware
                }
            };
            if !authority_valid || package.repository != self.repository {
                return Err(HardwareError::InvalidPlan(format!(
                    "binary authority mismatch for {}",
                    package.name
                )));
            }
        }
        Ok(())
    }
}

pub fn verify_binary_index(
    bytes: &[u8],
    signature_text: &str,
    keyring: &Keyring,
) -> Result<VerifiedBinaryIndex, HardwareError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_INDEX_BYTES {
        return Err(HardwareError::RecipeTooLarge);
    }
    let key_id = keyring
        .verify_payload(bytes, signature_text, "package-index")
        .map_err(|error| HardwareError::Signature(error.to_string()))?;
    let index: BinaryRepositoryIndex =
        toml::from_slice(bytes).map_err(|error| HardwareError::RecipeParse(error.to_string()))?;
    if index.key_id != key_id {
        return Err(HardwareError::InvalidPlan(
            "binary index key id does not match signature".into(),
        ));
    }
    index.validate()?;
    Ok(VerifiedBinaryIndex {
        index,
        key_id,
        index_sha256: hex_digest(&Sha256::digest(bytes)),
    })
}

/// Downloads one exact index record and returns a receipt suitable for
/// `HostPackageStore::install`.  The caller still decides whether the package
/// is covered by a signed HWD plan before committing it to the live system.
#[derive(Clone, Debug)]
pub struct BinaryProvisioner {
    pub artifact_root: PathBuf,
    pub allow_network: bool,
}

impl BinaryProvisioner {
    pub fn new(artifact_root: PathBuf) -> Result<Self, HardwareError> {
        prepare_private_root(&artifact_root)?;
        Ok(Self {
            artifact_root,
            allow_network: false,
        })
    }

    pub fn fetch(
        &self,
        verified: &VerifiedBinaryIndex,
        name: &str,
        version: Option<&str>,
    ) -> Result<HardwareBuildReceipt, HardwareError> {
        let package = verified
            .index
            .packages
            .iter()
            .find(|package| {
                package.name == name && version.is_none_or(|version| package.version == version)
            })
            .ok_or_else(|| HardwareError::PackageNotFound(name.into()))?;
        let filename = format!(
            "{}-{}-{}.pkg",
            package.name, package.version, package.release
        );
        let destination = self.artifact_root.join(filename);
        if destination.exists() {
            let bytes = read_bounded(&destination, MAX_OUTPUT_BYTES)
                .map_err(|error| HardwareError::SourceUnavailable(error.to_string()))?;
            verify_artifact(&bytes, package)?;
        } else {
            if !self.allow_network {
                return Err(HardwareError::NetworkNotAllowed);
            }
            let temporary = destination.with_extension(format!("download-{}", std::process::id()));
            run_curl(&package.url, &temporary, self.artifact_root.as_path())?;
            let bytes = read_bounded(&temporary, MAX_OUTPUT_BYTES)
                .map_err(|error| HardwareError::SourceUnavailable(error.to_string()))?;
            if bytes.len() as u64 != package.size {
                let _ = fs::remove_file(&temporary);
                return Err(HardwareError::InvalidSource(format!(
                    "binary size mismatch for {}",
                    package.name
                )));
            }
            verify_artifact(&bytes, package)?;
            atomic_write(&destination, &bytes)?;
            fs::remove_file(temporary)?;
        }
        Ok(HardwareBuildReceipt {
            package: package.name.clone(),
            version: package.version.clone(),
            release: package.release,
            source_revision: format!("binary-index:{}", verified.index_sha256),
            metadata_sha256: package.metadata_sha256.clone(),
            source_lock_sha256: package.source_lock_sha256.clone(),
            artifact_sha256: package.artifact_sha256.clone(),
            outputs: vec![destination],
        })
    }

    pub fn install(
        &self,
        store: &HostPackageStore,
        verified: &VerifiedBinaryIndex,
        name: &str,
        version: Option<&str>,
    ) -> Result<HardwareBuildReceipt, HardwareError> {
        let package = verified
            .index
            .packages
            .iter()
            .find(|package| {
                package.name == name && version.is_none_or(|version| package.version == version)
            })
            .ok_or_else(|| HardwareError::PackageNotFound(name.into()))?;
        if package.scope != PackageScope::System {
            return Err(HardwareError::InvalidPlan(
                "driver and firmware binaries require a verified HWD plan".into(),
            ));
        }
        let receipt = self.fetch(verified, name, version)?;
        store.install(std::slice::from_ref(&receipt))?;
        Ok(receipt)
    }

    /// Install all binary records authorized by one already-verified HWD
    /// plan. Every plan field must match the signed repository index.
    pub fn install_plan(
        &self,
        store: &HostPackageStore,
        verified: &VerifiedBinaryIndex,
        plan: &VerifiedHardwarePlan,
    ) -> Result<Vec<HardwareBuildReceipt>, HardwareError> {
        let mut receipts = Vec::with_capacity(plan.plan.package.len());
        for intent in &plan.plan.package {
            if !matches!(intent.verb, CorinthVerb::Install) {
                return Err(HardwareError::InvalidPlan(
                    "binary plan contains an unsupported verb".into(),
                ));
            }
            let package = verified
                .index
                .packages
                .iter()
                .find(|package| package.name == intent.name && package.version == intent.version)
                .ok_or_else(|| HardwareError::PackageNotFound(intent.name.clone()))?;
            if package.scope != intent.scope
                || package.repository != intent.repository
                || package.metadata_sha256 != intent.metadata_sha256
                || package.artifact_sha256 != intent.artifact_sha256
                || package.source_lock_sha256 != intent.source_lock_sha256
            {
                return Err(HardwareError::InvalidPlan(format!(
                    "binary index record does not match HWD intent: {}",
                    intent.name
                )));
            }
            receipts.push(self.fetch(verified, &intent.name, Some(&intent.version))?);
        }
        store.install(&receipts)?;
        Ok(receipts)
    }
}

fn verify_artifact(bytes: &[u8], package: &BinaryPackage) -> Result<(), HardwareError> {
    if bytes.len() as u64 != package.size {
        return Err(HardwareError::InvalidSource(format!(
            "binary size mismatch for {}",
            package.name
        )));
    }
    let actual = hex_digest(&Sha256::digest(bytes));
    if actual != package.artifact_sha256 {
        return Err(HardwareError::ArtifactDigestMismatch {
            package: package.name.clone(),
            expected: package.artifact_sha256.clone(),
            actual,
        });
    }
    Ok(())
}

fn run_curl(url: &str, destination: &Path, directory: &Path) -> Result<(), HardwareError> {
    let status = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https",
            "--tlsv1.2",
            url,
            "--output",
        ])
        .arg(destination)
        .current_dir(directory)
        .stdin(Stdio::null())
        .status()
        .map_err(|error| HardwareError::CommandFailed(error.to_string()))?;
    if !status.success() {
        return Err(HardwareError::CommandFailed("curl failed".into()));
    }
    Ok(())
}

fn valid_package_name(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        })
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        && value.bytes().any(|byte| byte != b'0')
}

fn is_https_url(value: &str) -> bool {
    value.starts_with("https://") && !value.contains(char::is_whitespace)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SERIAL: AtomicU64 = AtomicU64::new(1);

    fn record(scope: PackageScope, repository: RepositoryAuthority) -> BinaryPackage {
        BinaryPackage {
            name: "demo".into(),
            version: "1.0.0".into(),
            release: 1,
            scope,
            repository,
            metadata_sha256: "1".repeat(64),
            artifact_sha256: "2".repeat(64),
            source_lock_sha256: "3".repeat(64),
            url: "https://packages.example.invalid/demo.pkg".into(),
            size: 4,
        }
    }

    fn test_root() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "corinth-binary-test-{}-{}",
            std::process::id(),
            TEST_SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        root
    }

    #[test]
    fn native_index_accepts_only_native_system_records() {
        let index = BinaryRepositoryIndex {
            format: BINARY_INDEX_FORMAT,
            repository: RepositoryAuthority::ArachNative,
            key_id: "native-key".into(),
            packages: vec![record(
                PackageScope::System,
                RepositoryAuthority::ArachNative,
            )],
        };
        assert!(index.validate().is_ok());
        let mut driver = index.clone();
        driver.packages[0] = record(PackageScope::Driver, RepositoryAuthority::ArachHardware);
        assert!(driver.validate().is_err());
    }

    #[test]
    fn index_rejects_duplicate_names_and_untrusted_urls() {
        let mut index = BinaryRepositoryIndex {
            format: BINARY_INDEX_FORMAT,
            repository: RepositoryAuthority::ArachNative,
            key_id: "native-key".into(),
            packages: vec![record(
                PackageScope::System,
                RepositoryAuthority::ArachNative,
            )],
        };
        index.packages.push(index.packages[0].clone());
        assert!(index.validate().is_err());
        index.packages.truncate(1);
        index.packages[0].url = "http://packages.example.invalid/demo.pkg".into();
        assert!(index.validate().is_err());
    }

    #[test]
    fn cached_binary_is_usable_without_network() {
        let root = test_root();
        let artifacts = root.join("artifacts");
        let mut package = record(PackageScope::System, RepositoryAuthority::ArachNative);
        let bytes = b"pkg!";
        package.size = bytes.len() as u64;
        package.artifact_sha256 = hex_digest(&Sha256::digest(bytes));
        let index = VerifiedBinaryIndex {
            index: BinaryRepositoryIndex {
                format: BINARY_INDEX_FORMAT,
                repository: RepositoryAuthority::ArachNative,
                key_id: "native-key".into(),
                packages: vec![package.clone()],
            },
            key_id: "native-key".into(),
            index_sha256: "0".repeat(64),
        };
        fs::create_dir(&artifacts).unwrap();
        fs::set_permissions(&artifacts, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(artifacts.join("demo-1.0.0-1.pkg"), bytes).unwrap();
        let provisioner = BinaryProvisioner::new(artifacts).unwrap();
        let receipt = provisioner.fetch(&index, "demo", None).unwrap();
        assert_eq!(receipt.artifact_sha256, package.artifact_sha256);
        fs::remove_dir_all(root).unwrap();
    }
}
