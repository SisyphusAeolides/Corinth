//! Bounded package-record admission for Corinth.
//!
//! The host forge emits a small canonical `package.toml` record. Corinth
//! parses only that fixed key/value subset, validates every identity and path,
//! and measures immutable artifact bytes with Sisyphus' SHA-256 primitive.
//! Measurement is an admission token; durable storage and service publication
//! remain separate authorities.

use blacklab::oureboros::{MAXIMUM_ARTIFACT_BYTES, sha256};

use crate::alchemist::fnv1a;

pub const PACKAGE_SCHEMA_VERSION: u16 = 1;
pub const MAX_RECORD_BYTES: usize = 4096;
pub const MAX_PACKAGE_NAME_BYTES: usize = 63;
pub const MAX_VERSION_BYTES: usize = 63;
pub const MAX_PATH_BYTES: usize = 127;
pub const MAX_CATALOG_ENTRIES: usize = 128;
pub const MAX_ARTIFACT_BYTES: usize = MAXIMUM_ARTIFACT_BYTES;
pub const NATIVE_TARGET: &str = "x86_64-sisyphus-user";

const FIELD_SCHEMA: u16 = 1 << 0;
const FIELD_SOURCE: u16 = 1 << 1;
const FIELD_CRATE: u16 = 1 << 2;
const FIELD_VERSION: u16 = 1 << 3;
const FIELD_BINARY: u16 = 1 << 4;
const FIELD_SERVICE_CLASS: u16 = 1 << 5;
const FIELD_PACKAGE_VERSION: u16 = 1 << 6;
const FIELD_TARGET: u16 = 1 << 7;
const FIELD_ARTIFACT: u16 = 1 << 8;
const FIELD_ARTIFACT_SHA256: u16 = 1 << 9;
const FIELD_RESOLUTION_LOCK_SHA256: u16 = 1 << 10;
const FIELD_SOURCE_LOCK_SHA256: u16 = 1 << 11;
const REQUIRED_FIELDS: u16 = (1 << 12) - 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryError {
    RecordTooLarge,
    InvalidUtf8,
    EmptyLine,
    InvalidAssignment,
    UnknownField,
    DuplicateField,
    MissingField,
    InvalidInteger,
    IntegerOverflow,
    InvalidString,
    InvalidName,
    InvalidVersion,
    InvalidTarget,
    InvalidArtifactPath,
    InvalidServiceClass,
    InvalidHash,
    InvalidSchema,
    ArtifactEmpty,
    ArtifactTooLarge,
    ArtifactDigestMismatch,
    DuplicatePackage,
    CatalogFull,
}

/// A validated forge record borrowing its immutable source bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackageRecord<'a> {
    pub schema_version: u16,
    pub source: &'a str,
    pub crate_name: &'a str,
    pub version: &'a str,
    pub binary: &'a str,
    pub service_class: u16,
    pub package_version_index: u16,
    pub target: &'a str,
    pub artifact_path: &'a str,
    pub artifact_sha256: [u8; 32],
    pub resolution_lock_sha256: [u8; 32],
    pub source_lock_sha256: [u8; 32],
}

impl PackageRecord<'_> {
    pub fn package_hash(&self) -> u64 {
        fnv1a(self.crate_name)
    }

    pub fn validate(&self) -> Result<(), RegistryError> {
        if self.schema_version != PACKAGE_SCHEMA_VERSION {
            return Err(RegistryError::InvalidSchema);
        }
        if !valid_source(self.source) || !valid_name(self.crate_name) || !valid_name(self.binary) {
            return Err(RegistryError::InvalidName);
        }
        if !valid_version(self.version) {
            return Err(RegistryError::InvalidVersion);
        }
        if self.target != NATIVE_TARGET {
            return Err(RegistryError::InvalidTarget);
        }
        if self.service_class == 0 {
            return Err(RegistryError::InvalidServiceClass);
        }
        if self.artifact_path.len() > MAX_PATH_BYTES
            || !self.artifact_path.starts_with("root/bin/")
            || self.artifact_path[9..] != *self.binary
        {
            return Err(RegistryError::InvalidArtifactPath);
        }
        if self.artifact_sha256 == [0; 32]
            || self.resolution_lock_sha256 == [0; 32]
            || self.source_lock_sha256 == [0; 32]
        {
            return Err(RegistryError::InvalidHash);
        }
        Ok(())
    }
}

/// A record and artifact that passed local measurement. It is not durable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MeasuredPackage<'a> {
    pub record: PackageRecord<'a>,
    pub package_hash: u64,
    pub artifact_len: u32,
}

impl MeasuredPackage<'_> {
    pub const fn version_index(self) -> u16 {
        self.record.package_version_index
    }

    pub const fn service_class(self) -> u16 {
        self.record.service_class
    }
}

/// Parse the canonical subset emitted by `corinth-forge.sh`.
pub fn parse_record<'a>(raw: &'a [u8]) -> Result<PackageRecord<'a>, RegistryError> {
    if raw.is_empty() || raw.len() > MAX_RECORD_BYTES {
        return Err(RegistryError::RecordTooLarge);
    }
    let text = core::str::from_utf8(raw).map_err(|_| RegistryError::InvalidUtf8)?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    if text.is_empty() || text.ends_with('\n') {
        return Err(RegistryError::EmptyLine);
    }

    let mut seen = 0_u16;
    let mut partial = PartialRecord::default();
    for line in text.split('\n') {
        let bytes = line.as_bytes();
        let Some(separator) = bytes.windows(3).position(|window| window == b" = ") else {
            return Err(RegistryError::InvalidAssignment);
        };
        if separator == 0
            || bytes[separator + 3..].contains(&b'=')
            || bytes[..separator]
                .iter()
                .any(|byte| !byte.is_ascii_lowercase() && !byte.is_ascii_digit() && *byte != b'_')
        {
            return Err(RegistryError::InvalidAssignment);
        }
        let key = &bytes[..separator];
        let value = &bytes[separator + 3..];
        let (bit, kind) = field_kind(key).ok_or(RegistryError::UnknownField)?;
        if seen & bit != 0 {
            return Err(RegistryError::DuplicateField);
        }
        seen |= bit;
        match kind {
            FieldKind::Integer(slot) => {
                let value = parse_u16(value)?;
                match slot {
                    IntegerSlot::Schema => partial.schema = Some(value),
                    IntegerSlot::ServiceClass => partial.service_class = Some(value),
                    IntegerSlot::PackageVersion => partial.package_version = Some(value),
                }
            }
            FieldKind::String(slot) => {
                let value = parse_string(value)?;
                match slot {
                    StringSlot::Source => partial.source = Some(value),
                    StringSlot::Crate => partial.crate_name = Some(value),
                    StringSlot::Version => partial.version = Some(value),
                    StringSlot::Binary => partial.binary = Some(value),
                    StringSlot::Target => partial.target = Some(value),
                    StringSlot::Artifact => partial.artifact_path = Some(value),
                }
            }
            FieldKind::Hash(slot) => {
                let value = parse_hash(value)?;
                match slot {
                    HashSlot::Artifact => partial.artifact = Some(value),
                    HashSlot::ResolutionLock => partial.resolution_lock = Some(value),
                    HashSlot::SourceLock => partial.source_lock = Some(value),
                }
            }
        }
    }

    if seen != REQUIRED_FIELDS {
        return Err(RegistryError::MissingField);
    }
    let record = PackageRecord {
        schema_version: partial.schema.ok_or(RegistryError::MissingField)?,
        source: partial.source.ok_or(RegistryError::MissingField)?,
        crate_name: partial.crate_name.ok_or(RegistryError::MissingField)?,
        version: partial.version.ok_or(RegistryError::MissingField)?,
        binary: partial.binary.ok_or(RegistryError::MissingField)?,
        service_class: partial.service_class.ok_or(RegistryError::MissingField)?,
        package_version_index: partial.package_version.ok_or(RegistryError::MissingField)?,
        target: partial.target.ok_or(RegistryError::MissingField)?,
        artifact_path: partial.artifact_path.ok_or(RegistryError::MissingField)?,
        artifact_sha256: partial.artifact.ok_or(RegistryError::MissingField)?,
        resolution_lock_sha256: partial.resolution_lock.ok_or(RegistryError::MissingField)?,
        source_lock_sha256: partial.source_lock.ok_or(RegistryError::MissingField)?,
    };
    record.validate()?;
    Ok(record)
}

/// Measure artifact bytes against a validated record.
pub fn measure_artifact<'a>(
    record: PackageRecord<'a>,
    artifact: &[u8],
) -> Result<MeasuredPackage<'a>, RegistryError> {
    record.validate()?;
    if artifact.is_empty() {
        return Err(RegistryError::ArtifactEmpty);
    }
    if artifact.len() > MAX_ARTIFACT_BYTES {
        return Err(RegistryError::ArtifactTooLarge);
    }
    let actual = sha256(artifact);
    if actual != record.artifact_sha256 {
        return Err(RegistryError::ArtifactDigestMismatch);
    }
    Ok(MeasuredPackage {
        record,
        package_hash: record.package_hash(),
        artifact_len: artifact.len() as u32,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogEntry {
    pub package_hash: u64,
    pub version_index: u16,
    pub artifact_len: u32,
    pub artifact_sha256: [u8; 32],
    pub service_class: u16,
}

impl CatalogEntry {
    const EMPTY: Self = Self {
        package_hash: 0,
        version_index: 0,
        artifact_len: 0,
        artifact_sha256: [0; 32],
        service_class: 0,
    };
}

/// Order-stable, fixed-capacity catalog of measured package records.
pub struct PackageCatalog {
    entries: [CatalogEntry; MAX_CATALOG_ENTRIES],
    count: u16,
}

impl PackageCatalog {
    pub const fn new() -> Self {
        Self {
            entries: [CatalogEntry::EMPTY; MAX_CATALOG_ENTRIES],
            count: 0,
        }
    }

    pub fn entries(&self) -> &[CatalogEntry] {
        &self.entries[..usize::from(self.count)]
    }

    pub fn register<'a>(&mut self, measured: MeasuredPackage<'a>) -> Result<(), RegistryError> {
        let entry = CatalogEntry {
            package_hash: measured.package_hash,
            version_index: measured.version_index(),
            artifact_len: measured.artifact_len,
            artifact_sha256: measured.record.artifact_sha256,
            service_class: measured.service_class(),
        };
        let count = usize::from(self.count);
        let index = self.entries[..count]
            .binary_search_by_key(&(entry.package_hash, entry.version_index), |candidate| {
                (candidate.package_hash, candidate.version_index)
            })
            .unwrap_or_else(|index| index);
        if index < count
            && (
                self.entries[index].package_hash,
                self.entries[index].version_index,
            ) == (entry.package_hash, entry.version_index)
        {
            return Err(RegistryError::DuplicatePackage);
        }
        if count == MAX_CATALOG_ENTRIES {
            return Err(RegistryError::CatalogFull);
        }
        self.entries.copy_within(index..count, index + 1);
        self.entries[index] = entry;
        self.count += 1;
        Ok(())
    }

    pub fn contains(&self, package_hash: u64) -> bool {
        self.entries()
            .binary_search_by_key(&package_hash, |entry| entry.package_hash)
            .is_ok()
    }

    pub fn latest_version(&self, package_hash: u64) -> Option<u16> {
        self.entries()
            .iter()
            .filter(|entry| entry.package_hash == package_hash)
            .map(|entry| entry.version_index)
            .max()
    }
}

impl Default for PackageCatalog {
    fn default() -> Self {
        Self::new()
    }
}

/// Identities rooted in the current measured workspace image. This does not
/// claim that artifact bytes have already been durably installed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuiltinPackage {
    pub name: &'static [u8],
    pub package_hash: u64,
    pub version_index: u16,
    pub service_class: u16,
}

pub fn builtin_package(name: &[u8]) -> Option<BuiltinPackage> {
    let (name, service_class) = match name {
        b"boulder" => (b"boulder" as &'static [u8], 1),
        b"corinth" => (b"corinth" as &'static [u8], 2),
        b"crest" => (b"crest" as &'static [u8], 3),
        b"push" => (b"push" as &'static [u8], 4),
        _ => return None,
    };
    Some(BuiltinPackage {
        name,
        package_hash: fnv1a(core::str::from_utf8(name).expect("builtin ASCII")),
        version_index: 1,
        service_class,
    })
}

#[derive(Default)]
struct PartialRecord<'a> {
    schema: Option<u16>,
    source: Option<&'a str>,
    crate_name: Option<&'a str>,
    version: Option<&'a str>,
    binary: Option<&'a str>,
    service_class: Option<u16>,
    package_version: Option<u16>,
    target: Option<&'a str>,
    artifact_path: Option<&'a str>,
    artifact: Option<[u8; 32]>,
    resolution_lock: Option<[u8; 32]>,
    source_lock: Option<[u8; 32]>,
}

#[derive(Clone, Copy)]
enum FieldKind {
    Integer(IntegerSlot),
    String(StringSlot),
    Hash(HashSlot),
}

#[derive(Clone, Copy)]
enum IntegerSlot {
    Schema,
    ServiceClass,
    PackageVersion,
}

#[derive(Clone, Copy)]
enum StringSlot {
    Source,
    Crate,
    Version,
    Binary,
    Target,
    Artifact,
}

#[derive(Clone, Copy)]
enum HashSlot {
    Artifact,
    ResolutionLock,
    SourceLock,
}

fn field_kind(key: &[u8]) -> Option<(u16, FieldKind)> {
    Some(match key {
        b"schema_version" => (FIELD_SCHEMA, FieldKind::Integer(IntegerSlot::Schema)),
        b"source" => (FIELD_SOURCE, FieldKind::String(StringSlot::Source)),
        b"crate" => (FIELD_CRATE, FieldKind::String(StringSlot::Crate)),
        b"version" => (FIELD_VERSION, FieldKind::String(StringSlot::Version)),
        b"binary" => (FIELD_BINARY, FieldKind::String(StringSlot::Binary)),
        b"service_class" => (
            FIELD_SERVICE_CLASS,
            FieldKind::Integer(IntegerSlot::ServiceClass),
        ),
        b"package_version_index" => (
            FIELD_PACKAGE_VERSION,
            FieldKind::Integer(IntegerSlot::PackageVersion),
        ),
        b"target" => (FIELD_TARGET, FieldKind::String(StringSlot::Target)),
        b"artifact" => (FIELD_ARTIFACT, FieldKind::String(StringSlot::Artifact)),
        b"artifact_sha256" => (FIELD_ARTIFACT_SHA256, FieldKind::Hash(HashSlot::Artifact)),
        b"resolution_lock_sha256" => (
            FIELD_RESOLUTION_LOCK_SHA256,
            FieldKind::Hash(HashSlot::ResolutionLock),
        ),
        b"source_lock_sha256" => (
            FIELD_SOURCE_LOCK_SHA256,
            FieldKind::Hash(HashSlot::SourceLock),
        ),
        _ => return None,
    })
}

fn parse_u16(value: &[u8]) -> Result<u16, RegistryError> {
    if value.is_empty() {
        return Err(RegistryError::InvalidInteger);
    }
    let mut output = 0_u16;
    for byte in value {
        if !byte.is_ascii_digit() {
            return Err(RegistryError::InvalidInteger);
        }
        output = output
            .checked_mul(10)
            .ok_or(RegistryError::IntegerOverflow)?
            .checked_add(u16::from(byte - b'0'))
            .ok_or(RegistryError::IntegerOverflow)?;
    }
    Ok(output)
}

fn parse_string(value: &[u8]) -> Result<&str, RegistryError> {
    if value.len() < 2 || value[0] != b'"' || value[value.len() - 1] != b'"' {
        return Err(RegistryError::InvalidString);
    }
    let inner = &value[1..value.len() - 1];
    if inner
        .iter()
        .any(|byte| !byte.is_ascii_graphic() || matches!(byte, b'"' | b'\\'))
    {
        return Err(RegistryError::InvalidString);
    }
    core::str::from_utf8(inner).map_err(|_| RegistryError::InvalidUtf8)
}

fn parse_hash(value: &[u8]) -> Result<[u8; 32], RegistryError> {
    let text = parse_string(value)?;
    if text.len() != 64 {
        return Err(RegistryError::InvalidHash);
    }
    let mut output = [0_u8; 32];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        let high = hex(pair[0]).ok_or(RegistryError::InvalidHash)?;
        let low = hex(pair[1]).ok_or(RegistryError::InvalidHash)?;
        output[index] = (high << 4) | low;
    }
    if output == [0; 32] {
        return Err(RegistryError::InvalidHash);
    }
    Ok(output)
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn valid_source(source: &str) -> bool {
    !source.is_empty()
        && source.len() <= MAX_PACKAGE_NAME_BYTES
        && source
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'"' | b'\\'))
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_PACKAGE_NAME_BYTES
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn valid_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= MAX_VERSION_BYTES
        && version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write;
    use std::string::String;

    fn record_text(artifact: &[u8]) -> String {
        let digest = sha256(artifact);
        let mut text = String::new();
        write!(
            text,
            "schema_version = 1\nsource = \"crates.io\"\ncrate = \"demo\"\nversion = \"1.2.3\"\nbinary = \"demo\"\nservice_class = 7\npackage_version_index = 1\ntarget = \"x86_64-sisyphus-user\"\nartifact = \"root/bin/demo\"\nartifact_sha256 = \""
        )
        .unwrap();
        for byte in digest {
            write!(text, "{byte:02x}").unwrap();
        }
        text.push_str(
            "\"\nresolution_lock_sha256 = \"0101010101010101010101010101010101010101010101010101010101010101\"\nsource_lock_sha256 = \"0202020202020202020202020202020202020202020202020202020202020202\"\n",
        );
        text
    }

    #[test]
    fn parses_and_measures_the_forge_record() {
        let artifact = b"native package bytes";
        let raw = record_text(artifact);
        let record = parse_record(raw.as_bytes()).unwrap();
        assert_eq!(record.crate_name, "demo");
        let measured = measure_artifact(record, artifact).unwrap();
        assert_eq!(measured.package_hash, fnv1a("demo"));
        assert_eq!(measured.artifact_len, artifact.len() as u32);
    }

    #[test]
    fn rejects_tampering_and_path_escape() {
        let artifact = b"native package bytes";
        let raw = record_text(artifact);
        let record = parse_record(raw.as_bytes()).unwrap();
        assert_eq!(
            measure_artifact(record, b"tampered"),
            Err(RegistryError::ArtifactDigestMismatch)
        );
        let escaped = raw.replace("root/bin/demo", "root/../demo");
        assert_eq!(
            parse_record(escaped.as_bytes()),
            Err(RegistryError::InvalidArtifactPath)
        );
    }

    #[test]
    fn catalog_is_ordered_and_rejects_duplicate_identity() {
        let artifact = b"native package bytes";
        let raw = record_text(artifact);
        let measured = measure_artifact(parse_record(raw.as_bytes()).unwrap(), artifact).unwrap();
        let mut catalog = PackageCatalog::new();
        catalog.register(measured).unwrap();
        assert!(catalog.contains(fnv1a("demo")));
        assert_eq!(catalog.latest_version(fnv1a("demo")), Some(1));
        assert_eq!(
            catalog.register(measured),
            Err(RegistryError::DuplicatePackage)
        );
    }

    #[test]
    fn builtin_catalog_is_identity_only_and_unknown_names_fail_closed() {
        assert_eq!(builtin_package(b"crest").unwrap().version_index, 1);
        assert!(builtin_package(b"unknown").is_none());
    }
}
