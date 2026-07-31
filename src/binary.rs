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
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::hardware::{
    HardwareBuildReceipt, HardwareError, HostPackageStore, MAX_OUTPUT_BYTES, VerifiedHardwarePlan,
    atomic_write, hex_digest, prepare_private_root, read_bounded,
};

pub const BINARY_INDEX_FORMAT: u32 = 1;
pub const MAX_INDEX_BYTES: u64 = 4 * 1024 * 1024;
pub const BINARY_PAYLOAD_FORMAT: u16 = 1;
pub const MAX_PAYLOAD_FILES: u32 = 4096;
pub const MAX_PAYLOAD_PATH_BYTES: usize = 4096;
const PAYLOAD_MAGIC: &[u8; 8] = b"ARCPKG01";
const PAYLOAD_HEADER_BYTES: usize = 8 + 2 + 2 + 2 + 4 + 4 + 32 + 32;
static INSTALL_SERIAL: AtomicU64 = AtomicU64::new(1);

/// A regular-file entry in Corinth's native binary payload container.
/// Symlinks, device nodes, hard links, and executable post-install scripts are
/// intentionally not representable in this format.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BinaryPayloadFile {
    pub path: String,
    pub mode: u32,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BinaryPayload {
    pub package: String,
    pub version: String,
    pub release: u32,
    pub metadata_sha256: String,
    pub source_lock_sha256: String,
    pub files: Vec<BinaryPayloadFile>,
}

#[derive(Clone, Debug, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct BinaryInstallReceipt {
    pub package: String,
    pub version: String,
    pub release: u32,
    pub artifact_sha256: String,
    pub files: Vec<InstalledBinaryFile>,
}

#[derive(Clone, Debug, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledBinaryFile {
    pub path: String,
    pub mode: u32,
    pub sha256: String,
}

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
                || !valid_version(&package.version)
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

/// Encode a package payload in Corinth's deterministic native container.
///
/// The index carries metadata, source-lock, and artifact digests.  The
/// payload repeats the first two digests and binds its package identity to
/// those records, so a valid index cannot be paired with an unrelated file
/// tree.  The caller computes `artifact_sha256` over the returned bytes when
/// publishing the index.
pub fn encode_binary_payload(
    package: &BinaryPackage,
    files: &[BinaryPayloadFile],
) -> Result<Vec<u8>, HardwareError> {
    if files.is_empty() || files.len() > MAX_PAYLOAD_FILES as usize {
        return Err(HardwareError::InvalidSource(
            "binary payload has an invalid file count".into(),
        ));
    }
    let metadata = decode_hex_digest(&package.metadata_sha256)?;
    let source_lock = decode_hex_digest(&package.source_lock_sha256)?;
    let name = valid_payload_identity(&package.name, "package name")?;
    let version = valid_payload_version(&package.version)?;
    let name_len = name.len();
    let version_len = version.len();
    if name_len > u16::MAX as usize || version_len > u16::MAX as usize {
        return Err(HardwareError::InvalidSource(
            "binary payload identity is too long".into(),
        ));
    }

    let mut seen = std::collections::BTreeSet::new();
    let mut total = PAYLOAD_HEADER_BYTES
        .checked_add(name_len)
        .and_then(|size| size.checked_add(version_len))
        .ok_or_else(|| HardwareError::InvalidSource("binary payload is too large".into()))?;
    for file in files {
        let path = safe_payload_path(&file.path)?;
        if !seen.insert(path.to_string_lossy().into_owned()) {
            return Err(HardwareError::InvalidSource(format!(
                "duplicate binary payload path: {}",
                file.path
            )));
        }
        if file.mode & !0o7777 != 0 || file.bytes.len() as u64 > MAX_OUTPUT_BYTES {
            return Err(HardwareError::InvalidSource(format!(
                "invalid binary payload file: {}",
                file.path
            )));
        }
        total = total
            .checked_add(2 + 4 + 8 + 32 + path.as_os_str().as_encoded_bytes().len())
            .and_then(|size| size.checked_add(file.bytes.len()))
            .ok_or_else(|| HardwareError::InvalidSource("binary payload is too large".into()))?;
        if total as u64 > MAX_OUTPUT_BYTES {
            return Err(HardwareError::InvalidSource(
                "binary payload exceeds the output limit".into(),
            ));
        }
    }

    let mut output = Vec::with_capacity(total);
    output.extend_from_slice(PAYLOAD_MAGIC);
    output.extend_from_slice(&BINARY_PAYLOAD_FORMAT.to_le_bytes());
    output.extend_from_slice(&(name_len as u16).to_le_bytes());
    output.extend_from_slice(&(version_len as u16).to_le_bytes());
    output.extend_from_slice(&package.release.to_le_bytes());
    output.extend_from_slice(&(files.len() as u32).to_le_bytes());
    output.extend_from_slice(&metadata);
    output.extend_from_slice(&source_lock);
    output.extend_from_slice(name.as_bytes());
    output.extend_from_slice(version.as_bytes());
    for file in files {
        let path = safe_payload_path(&file.path)?;
        let digest: [u8; 32] = Sha256::digest(&file.bytes).into();
        output.extend_from_slice(&(path.as_os_str().as_encoded_bytes().len() as u16).to_le_bytes());
        output.extend_from_slice(&file.mode.to_le_bytes());
        output.extend_from_slice(&(file.bytes.len() as u64).to_le_bytes());
        output.extend_from_slice(&digest);
        output.extend_from_slice(path.as_os_str().as_encoded_bytes());
        output.extend_from_slice(&file.bytes);
    }
    Ok(output)
}

/// Decode and validate a native payload against the exact signed index
/// record.  Validation is complete before any target-root mutation occurs.
pub fn decode_binary_payload(
    bytes: &[u8],
    package: &BinaryPackage,
) -> Result<BinaryPayload, HardwareError> {
    if bytes.len() < PAYLOAD_HEADER_BYTES || bytes.len() as u64 > MAX_OUTPUT_BYTES {
        return Err(HardwareError::InvalidSource(
            "binary payload is truncated or too large".into(),
        ));
    }
    let mut cursor = PayloadCursor { bytes, offset: 0 };
    if cursor.take(8)? != PAYLOAD_MAGIC {
        return Err(HardwareError::InvalidSource(
            "binary payload magic mismatch".into(),
        ));
    }
    if cursor.u16()? != BINARY_PAYLOAD_FORMAT {
        return Err(HardwareError::InvalidSource(
            "unsupported binary payload format".into(),
        ));
    }
    let name_len = cursor.u16()? as usize;
    let version_len = cursor.u16()? as usize;
    let release = cursor.u32()?;
    let file_count = cursor.u32()?;
    if file_count == 0 || file_count > MAX_PAYLOAD_FILES {
        return Err(HardwareError::InvalidSource(
            "binary payload has an invalid file count".into(),
        ));
    }
    let metadata = cursor.array32()?;
    let source_lock = cursor.array32()?;
    let name = cursor.text(name_len, "package name")?;
    let version = cursor.text(version_len, "package version")?;
    if name != package.name || version != package.version || release != package.release {
        return Err(HardwareError::InvalidSource(
            "binary payload identity does not match the index".into(),
        ));
    }
    if hex_digest(&metadata) != package.metadata_sha256
        || hex_digest(&source_lock) != package.source_lock_sha256
    {
        return Err(HardwareError::InvalidSource(
            "binary payload metadata does not match the index".into(),
        ));
    }

    let mut files = Vec::with_capacity(file_count as usize);
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..file_count {
        let path_len = cursor.u16()? as usize;
        if path_len == 0 || path_len > MAX_PAYLOAD_PATH_BYTES {
            return Err(HardwareError::InvalidSource(
                "binary payload path is invalid".into(),
            ));
        }
        let mode = cursor.u32()?;
        let size = cursor.u64()?;
        let expected: [u8; 32] = cursor.array32()?;
        if mode & !0o7777 != 0 || size > MAX_OUTPUT_BYTES {
            return Err(HardwareError::InvalidSource(
                "binary payload file metadata is invalid".into(),
            ));
        }
        let path = cursor.text(path_len, "payload path")?;
        let normalized = safe_payload_path(&path)?.to_string_lossy().into_owned();
        if !seen.insert(normalized.clone()) {
            return Err(HardwareError::InvalidSource(format!(
                "duplicate binary payload path: {normalized}"
            )));
        }
        let data = cursor.bytes(size as usize)?;
        let actual: [u8; 32] = Sha256::digest(data).into();
        if actual != expected {
            return Err(HardwareError::ArtifactDigestMismatch {
                package: package.name.clone(),
                expected: hex_digest(&expected),
                actual: hex_digest(&actual),
            });
        }
        files.push(BinaryPayloadFile {
            path: normalized,
            mode,
            bytes: data.to_vec(),
        });
    }
    if cursor.offset != bytes.len() {
        return Err(HardwareError::InvalidSource(
            "binary payload has trailing bytes".into(),
        ));
    }
    Ok(BinaryPayload {
        package: package.name.clone(),
        version: package.version.clone(),
        release: package.release,
        metadata_sha256: package.metadata_sha256.clone(),
        source_lock_sha256: package.source_lock_sha256.clone(),
        files,
    })
}

struct PayloadCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> PayloadCursor<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], HardwareError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| HardwareError::InvalidSource("binary payload overflow".into()))?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| HardwareError::InvalidSource("binary payload is truncated".into()))?;
        self.offset = end;
        Ok(bytes)
    }

    fn u16(&mut self) -> Result<u16, HardwareError> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().expect("two bytes"),
        ))
    }

    fn u32(&mut self) -> Result<u32, HardwareError> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("four bytes"),
        ))
    }

    fn u64(&mut self) -> Result<u64, HardwareError> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("eight bytes"),
        ))
    }

    fn array32(&mut self) -> Result<[u8; 32], HardwareError> {
        Ok(self.take(32)?.try_into().expect("32 bytes"))
    }

    fn text(&mut self, length: usize, label: &str) -> Result<String, HardwareError> {
        let bytes = self.take(length)?;
        let value = core::str::from_utf8(bytes)
            .map_err(|_| HardwareError::InvalidSource(format!("invalid binary payload {label}")))?
            .to_string();
        if value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
        {
            return Err(HardwareError::InvalidSource(format!(
                "invalid binary payload {label}"
            )));
        }
        Ok(value)
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], HardwareError> {
        self.take(length)
    }
}

fn decode_hex_digest(value: &str) -> Result<[u8; 32], HardwareError> {
    if !valid_digest(value) {
        return Err(HardwareError::InvalidSource(
            "binary payload digest is invalid".into(),
        ));
    }
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(output)
}

fn hex_nibble(byte: u8) -> Result<u8, HardwareError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(HardwareError::InvalidSource(
            "binary payload digest is invalid".into(),
        )),
    }
}

fn valid_payload_identity<'a>(value: &'a str, label: &str) -> Result<&'a str, HardwareError> {
    if value.is_empty()
        || value.len() > u16::MAX as usize
        || value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(HardwareError::InvalidSource(format!(
            "invalid binary payload {label}"
        )));
    }
    Ok(value)
}

fn valid_payload_version(value: &str) -> Result<&str, HardwareError> {
    if !valid_version(value) {
        return Err(HardwareError::InvalidSource(
            "invalid binary payload package version".into(),
        ));
    }
    Ok(value)
}

fn safe_payload_path(value: &str) -> Result<&Path, HardwareError> {
    if value.is_empty() || value.len() > MAX_PAYLOAD_PATH_BYTES || value.contains('\\') {
        return Err(HardwareError::OutputRejected(value.into()));
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
                    | std::path::Component::CurDir
            )
        })
    {
        return Err(HardwareError::OutputRejected(value.into()));
    }
    Ok(path)
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
        self.fetch_bytes(verified, name, version)
            .map(|(receipt, _)| receipt)
    }

    fn fetch_bytes(
        &self,
        verified: &VerifiedBinaryIndex,
        name: &str,
        version: Option<&str>,
    ) -> Result<(HardwareBuildReceipt, Vec<u8>), HardwareError> {
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
        let bytes = if destination.exists() {
            let bytes = read_bounded(&destination, MAX_OUTPUT_BYTES)
                .map_err(|error| HardwareError::SourceUnavailable(error.to_string()))?;
            verify_artifact(&bytes, package)?;
            bytes
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
            bytes
        };
        Ok((
            HardwareBuildReceipt {
                package: package.name.clone(),
                version: package.version.clone(),
                release: package.release,
                source_revision: format!("binary-index:{}", verified.index_sha256),
                metadata_sha256: package.metadata_sha256.clone(),
                source_lock_sha256: package.source_lock_sha256.clone(),
                artifact_sha256: package.artifact_sha256.clone(),
                outputs: vec![destination],
            },
            bytes,
        ))
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

    /// Decode and atomically install a signed native payload into `target`.
    /// The state directory is separate from the live root and records every
    /// owned file, allowing later update/remove operations to refuse modified
    /// files instead of deleting user data.
    pub fn install_to_root(
        &self,
        state: PathBuf,
        target: PathBuf,
        verified: &VerifiedBinaryIndex,
        name: &str,
        version: Option<&str>,
    ) -> Result<BinaryInstallReceipt, HardwareError> {
        self.install_or_update_to_root(state, target, verified, name, version, false)
    }

    pub fn update_to_root(
        &self,
        state: PathBuf,
        target: PathBuf,
        verified: &VerifiedBinaryIndex,
        name: &str,
        version: Option<&str>,
    ) -> Result<BinaryInstallReceipt, HardwareError> {
        self.install_or_update_to_root(state, target, verified, name, version, true)
    }

    fn install_or_update_to_root(
        &self,
        state: PathBuf,
        target: PathBuf,
        verified: &VerifiedBinaryIndex,
        name: &str,
        version: Option<&str>,
        replace: bool,
    ) -> Result<BinaryInstallReceipt, HardwareError> {
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
        let (receipt, bytes) = self.fetch_bytes(verified, name, version)?;
        let payload = decode_binary_payload(&bytes, package)?;
        BinaryInstallStore::open(state, target)?.install_payload(
            &payload,
            &receipt.artifact_sha256,
            replace,
        )
    }

    pub fn remove_from_root(
        &self,
        state: PathBuf,
        target: PathBuf,
        package: &str,
    ) -> Result<(), HardwareError> {
        BinaryInstallStore::open(state, target)?.remove(package)
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

    /// Install driver and firmware payloads authorized by one or more
    /// already-verified HWD plans into a target root.  The binary index is
    /// checked against every plan intent before the first target mutation;
    /// failures roll back packages installed earlier in this call.
    pub fn install_hardware_plan_set_to_root(
        &self,
        state: PathBuf,
        target: PathBuf,
        verified: &VerifiedBinaryIndex,
        plans: &[VerifiedHardwarePlan],
    ) -> Result<Vec<BinaryInstallReceipt>, HardwareError> {
        if plans.is_empty() {
            return Err(HardwareError::InvalidPlan(
                "hardware binary installation requires a non-empty plan set".into(),
            ));
        }
        let mut intents = std::collections::BTreeMap::new();
        for plan in plans {
            for intent in &plan.plan.package {
                if !matches!(intent.verb, CorinthVerb::Install)
                    || !matches!(intent.scope, PackageScope::Driver | PackageScope::Firmware)
                {
                    return Err(HardwareError::InvalidPlan(format!(
                        "binary hardware plan contains a non-driver intent: {}",
                        intent.name
                    )));
                }
                let Some(package) = verified.index.packages.iter().find(|package| {
                    package.name == intent.name && package.version == intent.version
                }) else {
                    return Err(HardwareError::PackageNotFound(intent.name.clone()));
                };
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
                let key = intent.name.clone();
                if let Some(previous) = intents.insert(key.clone(), intent) {
                    if previous.version != intent.version
                        || previous.metadata_sha256 != intent.metadata_sha256
                        || previous.artifact_sha256 != intent.artifact_sha256
                        || previous.source_lock_sha256 != intent.source_lock_sha256
                    {
                        return Err(HardwareError::InvalidPlan(format!(
                            "conflicting package intents across hardware plans: {key}"
                        )));
                    }
                }
            }
        }
        let store = BinaryInstallStore::open(state, target)?;
        let mut installed = Vec::with_capacity(intents.len());
        for intent in intents.into_values() {
            let (receipt, bytes) =
                self.fetch_bytes(verified, &intent.name, Some(&intent.version))?;
            let package = verified
                .index
                .packages
                .iter()
                .find(|package| package.name == intent.name && package.version == intent.version)
                .ok_or_else(|| HardwareError::PackageNotFound(intent.name.clone()))?;
            let payload = decode_binary_payload(&bytes, package)?;
            match store.install_payload(&payload, &receipt.artifact_sha256, false) {
                Ok(result) => installed.push(result),
                Err(error) => {
                    for previous in installed.iter().rev() {
                        let _ = store.remove(&previous.package);
                    }
                    return Err(error);
                }
            }
        }
        Ok(installed)
    }
}

/// Transactional live-root owner for native binary payloads.
#[derive(Clone, Debug)]
pub struct BinaryInstallStore {
    target: PathBuf,
    receipts: PathBuf,
    staging: PathBuf,
}

impl BinaryInstallStore {
    pub fn open(state: PathBuf, target: PathBuf) -> Result<Self, HardwareError> {
        prepare_private_root(&state)?;
        validate_target_root(&target)?;
        let receipts = state.join("binary-installed");
        let staging = state.join("binary-staging");
        create_private_directory(&receipts)?;
        create_private_directory(&staging)?;
        Ok(Self {
            target,
            receipts,
            staging,
        })
    }

    pub fn install_payload(
        &self,
        payload: &BinaryPayload,
        artifact_sha256: &str,
        replace: bool,
    ) -> Result<BinaryInstallReceipt, HardwareError> {
        validate_payload(payload)?;
        if !valid_digest(artifact_sha256) {
            return Err(HardwareError::State(
                "binary artifact digest is invalid".into(),
            ));
        }
        let receipt_path = self.receipt_path(&payload.package)?;
        let previous = self.read_receipt(&receipt_path)?;
        if previous.is_some() && !replace {
            return Err(HardwareError::State(format!(
                "package is already installed: {}",
                payload.package
            )));
        }
        if previous.is_none() && replace {
            return Err(HardwareError::State(format!(
                "package is not installed: {}",
                payload.package
            )));
        }

        let new_files = payload
            .files
            .iter()
            .map(|file| InstalledBinaryFile {
                path: file.path.clone(),
                mode: file.mode,
                sha256: hex_digest(&Sha256::digest(&file.bytes)),
            })
            .collect::<Vec<_>>();
        let old_files = previous
            .as_ref()
            .map(|receipt| receipt.files.as_slice())
            .unwrap_or(&[]);
        self.validate_targets(&new_files, old_files, replace)?;

        let serial = INSTALL_SERIAL.fetch_add(1, Ordering::Relaxed);
        let stage = self.staging.join(format!(
            "{}-{}-{serial}",
            payload.package,
            std::process::id()
        ));
        let backup = self
            .staging
            .join(format!("{}.backup-{serial}", payload.package));
        create_private_directory(&stage)?;
        create_private_directory(&backup)?;
        let mut backups = Vec::new();
        let mut installed = Vec::new();
        let operation = (|| {
            for file in &payload.files {
                let staged = stage.join(&file.path);
                ensure_parent_dirs(&stage, &file.path)?;
                let mut handle = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(file.mode)
                    .open(&staged)?;
                handle.write_all(&file.bytes)?;
                handle.sync_all()?;
                handle.set_permissions(fs::Permissions::from_mode(file.mode))?;
            }

            let old_paths = old_files
                .iter()
                .map(|file| file.path.as_str())
                .collect::<std::collections::BTreeSet<_>>();
            let new_paths = new_files
                .iter()
                .map(|file| file.path.as_str())
                .collect::<std::collections::BTreeSet<_>>();
            for path in old_paths.union(&new_paths) {
                let target = self.target.join(path);
                if target_metadata(&target)?.is_none() {
                    continue;
                }
                let backup_path = backup.join(path);
                ensure_parent_dirs(&backup, path)?;
                fs::rename(&target, &backup_path)?;
                backups.push((target, backup_path));
            }
            for file in &payload.files {
                let target = self.target.join(&file.path);
                ensure_parent_dirs(&self.target, &file.path)?;
                let staged = stage.join(&file.path);
                fs::rename(staged, &target)?;
                installed.push(target);
            }
            let result = BinaryInstallReceipt {
                package: payload.package.clone(),
                version: payload.version.clone(),
                release: payload.release,
                artifact_sha256: artifact_sha256.into(),
                files: new_files,
            };
            write_receipt(&receipt_path, &result)?;
            Ok::<(), HardwareError>(())
        })();

        match operation {
            Ok(()) => {
                let _ = fs::remove_dir_all(stage);
                let _ = fs::remove_dir_all(backup);
                let _ = previous;
                Ok(self
                    .read_receipt(&receipt_path)?
                    .ok_or_else(|| HardwareError::State("installed receipt disappeared".into()))?)
            }
            Err(error) => {
                // The operation owns no untrusted paths after complete payload
                // validation.  Restore old files before exposing the error.
                rollback_files(&installed, &backups);
                let _ = fs::remove_dir_all(stage);
                let _ = fs::remove_dir_all(backup);
                Err(error)
            }
        }
    }

    pub fn remove(&self, package: &str) -> Result<(), HardwareError> {
        let receipt_path = self.receipt_path(package)?;
        let receipt = self
            .read_receipt(&receipt_path)?
            .ok_or_else(|| HardwareError::State(format!("package is not installed: {package}")))?;
        validate_install_receipt(&receipt)?;
        for file in &receipt.files {
            let target = self.target.join(&file.path);
            let Some(metadata) = target_metadata(&target)? else {
                continue;
            };
            if metadata.file_type().is_symlink() {
                return Err(HardwareError::State(format!(
                    "refusing to remove symlink: {}",
                    file.path
                )));
            }
            if digest_file(&target)? != file.sha256 {
                return Err(HardwareError::State(format!(
                    "installed file was modified: {}",
                    file.path
                )));
            }
        }
        let serial = INSTALL_SERIAL.fetch_add(1, Ordering::Relaxed);
        let backup = self.staging.join(format!("{}.remove-{serial}", package));
        create_private_directory(&backup)?;
        let mut moved = Vec::new();
        let retired = receipt_path.with_extension(format!("remove-{serial}"));
        let result = (|| {
            for file in &receipt.files {
                let target = self.target.join(&file.path);
                if target_metadata(&target)?.is_none() {
                    continue;
                }
                let backup_path = backup.join(&file.path);
                ensure_parent_dirs(&backup, &file.path)?;
                fs::rename(&target, &backup_path)?;
                moved.push((target, backup_path));
            }
            fs::rename(&receipt_path, &retired)?;
            fs::remove_file(&retired)?;
            Ok::<(), HardwareError>(())
        })();
        if let Err(error) = result {
            for (target, backup_path) in moved.iter().rev() {
                let _ = fs::rename(backup_path, target);
            }
            if retired.exists() && !receipt_path.exists() {
                let _ = fs::rename(&retired, &receipt_path);
            }
            let _ = fs::remove_dir_all(&backup);
            return Err(error);
        }
        fs::remove_dir_all(backup)?;
        Ok(())
    }

    fn receipt_path(&self, package: &str) -> Result<PathBuf, HardwareError> {
        if !valid_package_name(package) {
            return Err(HardwareError::State("invalid package identity".into()));
        }
        Ok(self.receipts.join(format!("{package}.toml")))
    }

    fn read_receipt(&self, path: &Path) -> Result<Option<BinaryInstallReceipt>, HardwareError> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => Err(
                HardwareError::State("binary receipt is not a regular file".into()),
            ),
            Ok(_) => {
                let bytes = read_bounded(path, MAX_INDEX_BYTES)
                    .map_err(|error| HardwareError::State(error.to_string()))?;
                let receipt: BinaryInstallReceipt = toml::from_slice(&bytes)
                    .map_err(|error| HardwareError::State(error.to_string()))?;
                validate_install_receipt(&receipt)?;
                Ok(Some(receipt))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(HardwareError::State(error.to_string())),
        }
    }

    fn validate_targets(
        &self,
        new_files: &[InstalledBinaryFile],
        old_files: &[InstalledBinaryFile],
        replace: bool,
    ) -> Result<(), HardwareError> {
        let old = old_files
            .iter()
            .map(|file| (file.path.as_str(), file))
            .collect::<std::collections::BTreeMap<_, _>>();
        let new = new_files
            .iter()
            .map(|file| file.path.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        for file in old_files {
            let target = self.target.join(&file.path);
            if target_metadata(&target)?.is_some() && digest_file(&target)? != file.sha256 {
                return Err(HardwareError::State(format!(
                    "installed file was modified: {}",
                    file.path
                )));
            }
        }
        for file in new_files {
            let target = self.target.join(&file.path);
            let Some(metadata) = target_metadata(&target)? else {
                continue;
            };
            if metadata.file_type().is_symlink() {
                return Err(HardwareError::State(format!(
                    "refusing to overwrite symlink: {}",
                    file.path
                )));
            }
            if !replace || !old.contains_key(file.path.as_str()) {
                return Err(HardwareError::State(format!(
                    "binary payload conflicts with existing file: {}",
                    file.path
                )));
            }
        }
        for file in old_files {
            if !new.contains(file.path.as_str()) {
                let target = self.target.join(&file.path);
                if target_metadata(&target)?
                    .is_some_and(|metadata| metadata.file_type().is_symlink())
                {
                    return Err(HardwareError::State(format!(
                        "refusing to remove symlink: {}",
                        file.path
                    )));
                }
            }
        }
        Ok(())
    }
}

fn validate_payload(payload: &BinaryPayload) -> Result<(), HardwareError> {
    if !valid_package_name(&payload.package)
        || !valid_version(&payload.version)
        || payload.release == 0
        || payload.files.is_empty()
        || payload.files.len() > MAX_PAYLOAD_FILES as usize
        || !valid_digest(&payload.metadata_sha256)
        || !valid_digest(&payload.source_lock_sha256)
    {
        return Err(HardwareError::State(
            "invalid binary payload identity".into(),
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for file in &payload.files {
        let path = safe_payload_path(&file.path)?;
        if !seen.insert(path.to_string_lossy().into_owned())
            || file.mode & !0o7777 != 0
            || file.bytes.len() as u64 > MAX_OUTPUT_BYTES
        {
            return Err(HardwareError::State(format!(
                "invalid binary payload file: {}",
                file.path
            )));
        }
    }
    Ok(())
}

fn validate_install_receipt(receipt: &BinaryInstallReceipt) -> Result<(), HardwareError> {
    if !valid_package_name(&receipt.package)
        || !valid_version(&receipt.version)
        || receipt.release == 0
        || !valid_digest(&receipt.artifact_sha256)
        || receipt.files.is_empty()
        || receipt.files.len() > MAX_PAYLOAD_FILES as usize
    {
        return Err(HardwareError::State(
            "invalid binary install receipt".into(),
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for file in &receipt.files {
        let path = safe_payload_path(&file.path)?;
        if !seen.insert(path.to_string_lossy().into_owned())
            || !valid_digest(&file.sha256)
            || file.mode & !0o7777 != 0
        {
            return Err(HardwareError::State(
                "invalid binary install receipt".into(),
            ));
        }
    }
    Ok(())
}

fn validate_target_root(path: &Path) -> Result<(), HardwareError> {
    if !path.is_absolute() {
        return Err(HardwareError::InvalidSource(
            "binary target root must be absolute".into(),
        ));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        HardwareError::InvalidSource(format!("binary target root is unavailable: {error}"))
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(HardwareError::InvalidSource(
            "binary target root must be a directory".into(),
        ));
    }
    Ok(())
}

fn target_metadata(path: &Path) -> Result<Option<fs::Metadata>, HardwareError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(HardwareError::State(error.to_string())),
    }
}

fn create_private_directory(path: &Path) -> Result<(), HardwareError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(HardwareError::State(format!(
                    "private directory is unsafe: {}",
                    path.display()
                )));
            }
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .ok_or_else(|| HardwareError::State("private directory has no parent".into()))?;
            let metadata = fs::symlink_metadata(parent)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(HardwareError::State(
                    "private directory parent is unsafe".into(),
                ));
            }
            fs::DirBuilder::new().mode(0o700).create(path)?;
        }
        Err(error) => return Err(HardwareError::State(error.to_string())),
    }
    Ok(())
}

fn ensure_parent_dirs(root: &Path, relative: &str) -> Result<(), HardwareError> {
    let path = safe_payload_path(relative)?;
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    let mut current = root.to_path_buf();
    for component in parent.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(HardwareError::OutputRejected(relative.into()));
        };
        current.push(name);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if !metadata.is_dir() || metadata.file_type().is_symlink() {
                    return Err(HardwareError::State(format!(
                        "payload parent is unsafe: {}",
                        current.display()
                    )));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::DirBuilder::new().mode(0o755).create(&current)?;
            }
            Err(error) => return Err(HardwareError::State(error.to_string())),
        }
    }
    Ok(())
}

fn write_receipt(path: &Path, receipt: &BinaryInstallReceipt) -> Result<(), HardwareError> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(HardwareError::State("binary receipt path is unsafe".into()));
        }
    }
    let bytes =
        toml::to_string(receipt).map_err(|error| HardwareError::State(error.to_string()))?;
    atomic_write(path, bytes.as_bytes())
}

fn digest_file(path: &Path) -> Result<String, HardwareError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(HardwareError::State(format!(
            "installed path is not a regular file: {}",
            path.display()
        )));
    }
    let bytes = read_bounded(path, MAX_OUTPUT_BYTES)
        .map_err(|error| HardwareError::State(error.to_string()))?;
    Ok(hex_digest(&Sha256::digest(bytes)))
}

fn rollback_files(installed: &[PathBuf], backups: &[(PathBuf, PathBuf)]) {
    for target in installed.iter().rev() {
        let _ = fs::remove_file(target);
    }
    for (target, backup) in backups.iter().rev() {
        if backup.exists() {
            let _ = ensure_parent_dirs(
                target.parent().unwrap_or_else(|| Path::new("/")),
                target
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or_default(),
            );
            let _ = fs::rename(backup, target);
        }
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

fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| !byte.is_ascii_control() && byte != b'/' && byte != b'\\')
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
    use arach_hwd::plan::ProvisionPlan;
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
        index.packages[0].url = "https://packages.example.invalid/demo.pkg".into();
        index.packages[0].version = "../escape".into();
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

    #[test]
    fn payload_round_trip_and_target_lifecycle_are_transactional() {
        let root = test_root();
        let state = root.join("state");
        let target = root.join("target");
        fs::create_dir(&target).unwrap();
        let mut package = record(PackageScope::System, RepositoryAuthority::ArachNative);
        let files = vec![BinaryPayloadFile {
            path: "usr/bin/demo".into(),
            mode: 0o755,
            bytes: b"first".to_vec(),
        }];
        let bytes = encode_binary_payload(&package, &files).unwrap();
        package.size = bytes.len() as u64;
        package.artifact_sha256 = hex_digest(&Sha256::digest(&bytes));
        let payload = decode_binary_payload(&bytes, &package).unwrap();
        assert_eq!(payload.files, files);

        let store = BinaryInstallStore::open(state, target.clone()).unwrap();
        let receipt = store
            .install_payload(&payload, &package.artifact_sha256, false)
            .unwrap();
        assert_eq!(receipt.files.len(), 1);
        assert_eq!(fs::read(target.join("usr/bin/demo")).unwrap(), b"first");

        let mut updated = package.clone();
        updated.release = 2;
        let updated_files = vec![BinaryPayloadFile {
            path: "usr/bin/demo".into(),
            mode: 0o755,
            bytes: b"second".to_vec(),
        }];
        let updated_bytes = encode_binary_payload(&updated, &updated_files).unwrap();
        updated.artifact_sha256 = hex_digest(&Sha256::digest(&updated_bytes));
        let updated_payload = decode_binary_payload(&updated_bytes, &updated).unwrap();
        store
            .install_payload(&updated_payload, &updated.artifact_sha256, true)
            .unwrap();
        assert_eq!(fs::read(target.join("usr/bin/demo")).unwrap(), b"second");

        store.remove("demo").unwrap();
        assert!(!target.join("usr/bin/demo").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn payload_paths_and_existing_files_fail_closed() {
        let mut package = record(PackageScope::System, RepositoryAuthority::ArachNative);
        let traversal = vec![BinaryPayloadFile {
            path: "../escape".into(),
            mode: 0o644,
            bytes: b"bad".to_vec(),
        }];
        assert!(encode_binary_payload(&package, &traversal).is_err());

        let root = test_root();
        let target = root.join("target");
        fs::create_dir(&target).unwrap();
        fs::create_dir_all(target.join("usr/bin")).unwrap();
        fs::write(target.join("usr/bin/demo"), b"owned elsewhere").unwrap();
        let files = vec![BinaryPayloadFile {
            path: "usr/bin/demo".into(),
            mode: 0o755,
            bytes: b"new".to_vec(),
        }];
        let bytes = encode_binary_payload(&package, &files).unwrap();
        package.artifact_sha256 = hex_digest(&Sha256::digest(&bytes));
        let payload = decode_binary_payload(&bytes, &package).unwrap();
        let store = BinaryInstallStore::open(root.join("state"), target).unwrap();
        assert!(
            store
                .install_payload(&payload, &package.artifact_sha256, false)
                .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn signed_hardware_plan_installs_binary_payload_to_target() {
        let root = test_root();
        let artifact_root = root.join("artifacts");
        let target = root.join("target");
        fs::create_dir(&artifact_root).unwrap();
        fs::set_permissions(&artifact_root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(&target).unwrap();

        let mut package = record(PackageScope::Driver, RepositoryAuthority::ArachHardware);
        package.name = "wifi-driver".into();
        package.size = 0;
        let payload = encode_binary_payload(
            &package,
            &[BinaryPayloadFile {
                path: "usr/lib/firmware/wifi.bin".into(),
                mode: 0o644,
                bytes: b"firmware".to_vec(),
            }],
        )
        .unwrap();
        package.size = payload.len() as u64;
        package.artifact_sha256 = hex_digest(&Sha256::digest(&payload));
        fs::write(artifact_root.join("wifi-driver-1.0.0-1.pkg"), &payload).unwrap();

        let intent = arach_hwd::plan::CorinthIntent {
            verb: CorinthVerb::Install,
            name: package.name.clone(),
            version: package.version.clone(),
            scope: package.scope,
            repository: package.repository,
            metadata_sha256: package.metadata_sha256.clone(),
            artifact_sha256: package.artifact_sha256.clone(),
            source_lock_sha256: package.source_lock_sha256.clone(),
        };
        let plan = VerifiedHardwarePlan {
            plan: ProvisionPlan {
                schema: arach_hwd::plan::PLAN_SCHEMA,
                profile_id: "wifi-profile".into(),
                profile_sha256: "4".repeat(64),
                signing_key_id: "hardware-key".into(),
                device_key: "pci:0000:00:00.0".into(),
                driver_abi: "1.0".into(),
                package: vec![intent],
                health: Vec::new(),
                rollback: arach_hwd::profile::RollbackPolicy {
                    remove_packages: vec![package.name.clone()],
                    restore_previous_driver: true,
                    reboot_if_required: false,
                },
                recovery: None,
            },
        };
        let verified = VerifiedBinaryIndex {
            index: BinaryRepositoryIndex {
                format: BINARY_INDEX_FORMAT,
                repository: RepositoryAuthority::ArachHardware,
                key_id: "hardware-index".into(),
                packages: vec![package],
            },
            key_id: "hardware-index".into(),
            index_sha256: "5".repeat(64),
        };
        let mut provisioner = BinaryProvisioner::new(artifact_root).unwrap();
        provisioner.allow_network = false;
        let receipts = provisioner
            .install_hardware_plan_set_to_root(
                root.join("state"),
                target.clone(),
                &verified,
                &[plan],
            )
            .unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(
            fs::read(target.join("usr/lib/firmware/wifi.bin")).unwrap(),
            b"firmware"
        );
        fs::remove_dir_all(root).unwrap();
    }
}
