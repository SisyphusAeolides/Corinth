//! Signed, sharded authority for the complete Arach recipe corpus.

use alloc::{collections::BTreeSet, format, string::String, vec::Vec};
use core::fmt;
use sha2::{Digest, Sha256};

use crate::indexer::Upstream;

pub const RECIPE_CORPUS_FORMAT: u32 = 1;
pub const PRODUCTION_RECIPE_COUNT: usize = 39_191;
pub const DEFAULT_CORPUS_SHARDS: u16 = 256;
pub const MAXIMUM_CORPUS_ENTRIES: usize = 50_000;
pub const MAXIMUM_CORPUS_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(rename_all = "kebab-case"))]
pub enum RecipeGenerationStrategy {
    StaticImporter,
    DeterministicWorker,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(deny_unknown_fields))]
pub struct RecipeCorpusEntry {
    pub ordinal: u32,
    pub upstream: Upstream,
    pub package: String,
    pub version: String,
    pub architecture: String,
    pub shard: u16,
    pub strategy: RecipeGenerationStrategy,
    pub ingress_lock: String,
    pub ingress_lock_sha256: String,
    pub ingress_signature: String,
    pub ingress_signature_sha256: String,
    pub target_policy: String,
    pub target_policy_sha256: String,
    pub target_signature: String,
    pub target_signature_sha256: String,
    pub recipe: String,
    pub receipt: String,
    pub worker_request: Option<String>,
    pub worker_request_sha256: Option<String>,
    pub fallback_reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(deny_unknown_fields))]
pub struct RecipeCorpusManifest {
    pub format: u32,
    pub distribution: String,
    pub target_count: u32,
    pub shard_count: u16,
    pub architecture: String,
    pub entries: Vec<RecipeCorpusEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(deny_unknown_fields))]
pub struct RecipeCorpusBuildReceipt {
    pub format: u32,
    pub corpus_sha256: String,
    pub target_count: u32,
    pub generated: u32,
    pub worker_required: u32,
    pub blocked: u32,
    pub recipe_merkle_root: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecipeCorpusError {
    TooLarge,
    Parse(String),
    InvalidHeader,
    InvalidCount,
    InvalidEntry,
    NonCanonicalOrder,
    Duplicate,
    InvalidShard,
    InvalidStrategy,
    InvalidPath,
    InvalidDigest,
    InvalidReceipt,
    Serialization(String),
}

impl fmt::Display for RecipeCorpusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(message) | Self::Serialization(message) => formatter.write_str(message),
            other => write!(formatter, "{other:?}"),
        }
    }
}

#[cfg(feature = "host-store")]
impl std::error::Error for RecipeCorpusError {}

impl RecipeCorpusManifest {
    pub fn validate(&self) -> Result<(), RecipeCorpusError> {
        self.validate_with_expected_count(self.target_count as usize)
    }

    pub fn validate_production(&self) -> Result<(), RecipeCorpusError> {
        if self.target_count as usize != PRODUCTION_RECIPE_COUNT
            || self.shard_count != DEFAULT_CORPUS_SHARDS
        {
            return Err(RecipeCorpusError::InvalidCount);
        }
        self.validate_with_expected_count(PRODUCTION_RECIPE_COUNT)
    }

    pub fn validate_with_expected_count(
        &self,
        expected_count: usize,
    ) -> Result<(), RecipeCorpusError> {
        if self.format != RECIPE_CORPUS_FORMAT
            || self.distribution != "ArachOS"
            || !valid_architecture(&self.architecture)
            || self.shard_count == 0
            || !self.shard_count.is_power_of_two()
        {
            return Err(RecipeCorpusError::InvalidHeader);
        }
        if expected_count == 0
            || expected_count > MAXIMUM_CORPUS_ENTRIES
            || self.target_count as usize != expected_count
            || self.entries.len() != expected_count
        {
            return Err(RecipeCorpusError::InvalidCount);
        }

        let mut previous: Option<(Upstream, &str, &str, &str)> = None;
        let mut identities = BTreeSet::new();
        let mut ingress_locks = BTreeSet::new();
        let mut ingress_signatures = BTreeSet::new();
        let mut target_policies = BTreeSet::new();
        let mut target_signatures = BTreeSet::new();
        let mut recipes = BTreeSet::new();
        let mut receipts = BTreeSet::new();
        let mut worker_requests = BTreeSet::new();

        for (index, entry) in self.entries.iter().enumerate() {
            if entry.ordinal as usize != index
                || !valid_package(&entry.package)
                || !valid_version(&entry.version)
                || entry.architecture != self.architecture
            {
                return Err(RecipeCorpusError::InvalidEntry);
            }
            let identity = (
                entry.upstream,
                entry.package.as_str(),
                entry.version.as_str(),
                entry.architecture.as_str(),
            );
            if previous.is_some_and(|value| value >= identity) {
                return Err(RecipeCorpusError::NonCanonicalOrder);
            }
            previous = Some(identity);
            if !identities.insert(identity) {
                return Err(RecipeCorpusError::Duplicate);
            }

            let expected_shard = corpus_shard(
                entry.upstream,
                &entry.package,
                &entry.version,
                &entry.architecture,
                self.shard_count,
            )?;
            if entry.shard != expected_shard {
                return Err(RecipeCorpusError::InvalidShard);
            }

            for digest in [
                &entry.ingress_lock_sha256,
                &entry.ingress_signature_sha256,
                &entry.target_policy_sha256,
                &entry.target_signature_sha256,
            ] {
                if !valid_digest(digest) {
                    return Err(RecipeCorpusError::InvalidDigest);
                }
            }

            validate_path(&entry.ingress_lock, "locks/", ".toml")?;
            validate_path(&entry.ingress_signature, "signatures/", ".sig")?;
            validate_path(&entry.target_policy, "targets/", ".toml")?;
            validate_path(&entry.target_signature, "signatures/", ".sig")?;
            validate_path(&entry.recipe, "recipes/", "/package.toml")?;
            validate_path(&entry.receipt, "receipts/", ".toml")?;

            if !ingress_locks.insert(entry.ingress_lock.as_str())
                || !ingress_signatures.insert(entry.ingress_signature.as_str())
                || !target_policies.insert(entry.target_policy.as_str())
                || !target_signatures.insert(entry.target_signature.as_str())
                || !recipes.insert(entry.recipe.as_str())
                || !receipts.insert(entry.receipt.as_str())
            {
                return Err(RecipeCorpusError::Duplicate);
            }

            match entry.strategy {
                RecipeGenerationStrategy::StaticImporter => {
                    if entry.worker_request.is_some()
                        || entry.worker_request_sha256.is_some()
                        || entry.fallback_reason.is_some()
                    {
                        return Err(RecipeCorpusError::InvalidStrategy);
                    }
                }
                RecipeGenerationStrategy::DeterministicWorker => {
                    let request = entry
                        .worker_request
                        .as_deref()
                        .ok_or(RecipeCorpusError::InvalidStrategy)?;
                    validate_path(request, "workers/", ".json")?;
                    if !worker_requests.insert(request) {
                        return Err(RecipeCorpusError::Duplicate);
                    }
                    if !entry
                        .worker_request_sha256
                        .as_deref()
                        .is_some_and(valid_digest)
                    {
                        return Err(RecipeCorpusError::InvalidDigest);
                    }
                    if entry
                        .fallback_reason
                        .as_deref()
                        .is_none_or(|reason| reason.trim().is_empty() || reason.len() > 512)
                    {
                        return Err(RecipeCorpusError::InvalidStrategy);
                    }
                }
            }
        }
        Ok(())
    }
}

impl RecipeCorpusBuildReceipt {
    pub fn validate(&self) -> Result<(), RecipeCorpusError> {
        if self.format != RECIPE_CORPUS_FORMAT
            || !valid_digest(&self.corpus_sha256)
            || self.target_count == 0
            || self
                .generated
                .checked_add(self.worker_required)
                .and_then(|value| value.checked_add(self.blocked))
                != Some(self.target_count)
        {
            return Err(RecipeCorpusError::InvalidReceipt);
        }
        if self.generated == self.target_count {
            if self.worker_required != 0
                || self.blocked != 0
                || !self
                    .recipe_merkle_root
                    .as_deref()
                    .is_some_and(valid_digest)
            {
                return Err(RecipeCorpusError::InvalidReceipt);
            }
        } else if self.recipe_merkle_root.is_some() {
            return Err(RecipeCorpusError::InvalidReceipt);
        }
        Ok(())
    }

    pub const fn complete(&self) -> bool {
        self.generated == self.target_count && self.worker_required == 0 && self.blocked == 0
    }
}

#[cfg(feature = "host-store")]
pub fn parse_recipe_corpus(bytes: &[u8]) -> Result<RecipeCorpusManifest, RecipeCorpusError> {
    if bytes.is_empty() || bytes.len() > MAXIMUM_CORPUS_BYTES {
        return Err(RecipeCorpusError::TooLarge);
    }
    let manifest: RecipeCorpusManifest = serde_json::from_slice(bytes)
        .map_err(|error| RecipeCorpusError::Parse(error.to_string()))?;
    manifest.validate()?;
    Ok(manifest)
}

#[cfg(feature = "host-store")]
pub fn serialize_recipe_corpus(
    manifest: &RecipeCorpusManifest,
) -> Result<Vec<u8>, RecipeCorpusError> {
    manifest.validate()?;
    serde_json::to_vec(manifest)
        .map_err(|error| RecipeCorpusError::Serialization(error.to_string()))
}

pub fn corpus_shard(
    upstream: Upstream,
    package: &str,
    version: &str,
    architecture: &str,
    shard_count: u16,
) -> Result<u16, RecipeCorpusError> {
    if shard_count == 0 || !shard_count.is_power_of_two() {
        return Err(RecipeCorpusError::InvalidHeader);
    }
    let mut hasher = Sha256::new();
    hasher.update(upstream_name(upstream).as_bytes());
    hasher.update([0]);
    hasher.update(package.as_bytes());
    hasher.update([0]);
    hasher.update(version.as_bytes());
    hasher.update([0]);
    hasher.update(architecture.as_bytes());
    let digest = hasher.finalize();
    let value = u16::from_be_bytes([digest[0], digest[1]]);
    Ok(value & (shard_count - 1))
}

const fn upstream_name(upstream: Upstream) -> &'static str {
    match upstream {
        Upstream::Arch => "arch",
        Upstream::Aur => "aur",
        Upstream::Fedora => "fedora",
        Upstream::Debian => "debian",
        Upstream::Alpine => "alpine",
        Upstream::Gentoo => "gentoo",
        Upstream::Crux => "crux",
        Upstream::Nix => "nix",
        Upstream::Cargo => "cargo",
        Upstream::Github => "github",
    }
}

fn validate_path(value: &str, prefix: &str, suffix: &str) -> Result<(), RecipeCorpusError> {
    if !safe_relative(value) || !value.starts_with(prefix) || !value.ends_with(suffix) {
        return Err(RecipeCorpusError::InvalidPath);
    }
    Ok(())
}

fn valid_architecture(value: &str) -> bool {
    matches!(value, "x86-64" | "aarch64" | "riscv64")
}

fn valid_package(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'+' | b'-' | b'_' | b'.')
        })
}

fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_whitespace())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn safe_relative(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4096
        && !value.starts_with('/')
        && !value.contains('\\')
        && value
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{string::ToString, vec};

    fn digest(byte: char) -> String {
        core::iter::repeat_n(byte, 64).collect()
    }

    fn entry(ordinal: u32, package: &str, strategy: RecipeGenerationStrategy) -> RecipeCorpusEntry {
        let version = "1.0.0";
        let architecture = "x86-64";
        let shard = corpus_shard(Upstream::Arch, package, version, architecture, 8).unwrap();
        RecipeCorpusEntry {
            ordinal,
            upstream: Upstream::Arch,
            package: package.to_string(),
            version: version.to_string(),
            architecture: architecture.to_string(),
            shard,
            strategy,
            ingress_lock: format!("locks/{package}.toml"),
            ingress_lock_sha256: digest('a'),
            ingress_signature: format!("signatures/{package}.lock.sig"),
            ingress_signature_sha256: digest('b'),
            target_policy: format!("targets/{package}.toml"),
            target_policy_sha256: digest('c'),
            target_signature: format!("signatures/{package}.target.sig"),
            target_signature_sha256: digest('d'),
            recipe: format!("recipes/{package}/package.toml"),
            receipt: format!("receipts/{package}.toml"),
            worker_request: (strategy == RecipeGenerationStrategy::DeterministicWorker)
                .then(|| format!("workers/{package}.json")),
            worker_request_sha256: (strategy
                == RecipeGenerationStrategy::DeterministicWorker)
                .then(|| digest('e')),
            fallback_reason: (strategy == RecipeGenerationStrategy::DeterministicWorker)
                .then(|| "static metadata contains dynamic packaging logic".to_string()),
        }
    }

    fn manifest(entries: Vec<RecipeCorpusEntry>) -> RecipeCorpusManifest {
        RecipeCorpusManifest {
            format: RECIPE_CORPUS_FORMAT,
            distribution: "ArachOS".to_string(),
            target_count: entries.len() as u32,
            shard_count: 8,
            architecture: "x86-64".to_string(),
            entries,
        }
    }

    #[test]
    fn accepts_canonical_static_and_worker_entries() {
        let value = manifest(vec![
            entry(0, "alpha", RecipeGenerationStrategy::StaticImporter),
            entry(1, "beta", RecipeGenerationStrategy::DeterministicWorker),
        ]);
        assert_eq!(value.validate_with_expected_count(2), Ok(()));
    }

    #[test]
    fn production_count_is_exact() {
        let value = manifest(vec![entry(
            0,
            "alpha",
            RecipeGenerationStrategy::StaticImporter,
        )]);
        assert_eq!(value.validate_production(), Err(RecipeCorpusError::InvalidCount));
    }

    #[test]
    fn canonical_order_is_required() {
        let value = manifest(vec![
            entry(0, "beta", RecipeGenerationStrategy::StaticImporter),
            entry(1, "alpha", RecipeGenerationStrategy::StaticImporter),
        ]);
        assert_eq!(
            value.validate_with_expected_count(2),
            Err(RecipeCorpusError::NonCanonicalOrder)
        );
    }

    #[test]
    fn shard_assignment_is_verified() {
        let mut value = manifest(vec![entry(
            0,
            "alpha",
            RecipeGenerationStrategy::StaticImporter,
        )]);
        value.entries[0].shard ^= 1;
        assert_eq!(
            value.validate_with_expected_count(1),
            Err(RecipeCorpusError::InvalidShard)
        );
    }

    #[test]
    fn worker_requires_request_and_reason() {
        let mut value = manifest(vec![entry(
            0,
            "alpha",
            RecipeGenerationStrategy::DeterministicWorker,
        )]);
        value.entries[0].fallback_reason = None;
        assert_eq!(
            value.validate_with_expected_count(1),
            Err(RecipeCorpusError::InvalidStrategy)
        );
    }

    #[test]
    fn worker_request_requires_a_digest() {
        let mut value = manifest(vec![entry(
            0,
            "alpha",
            RecipeGenerationStrategy::DeterministicWorker,
        )]);
        value.entries[0].worker_request_sha256 = None;
        assert_eq!(
            value.validate_with_expected_count(1),
            Err(RecipeCorpusError::InvalidDigest)
        );
    }

    #[test]
    fn complete_receipt_requires_a_merkle_root() {
        let receipt = RecipeCorpusBuildReceipt {
            format: RECIPE_CORPUS_FORMAT,
            corpus_sha256: digest('a'),
            target_count: 39_191,
            generated: 39_191,
            worker_required: 0,
            blocked: 0,
            recipe_merkle_root: Some(digest('b')),
        };
        assert_eq!(receipt.validate(), Ok(()));
        assert!(receipt.complete());
    }

    #[test]
    fn partial_receipt_cannot_claim_a_root() {
        let receipt = RecipeCorpusBuildReceipt {
            format: RECIPE_CORPUS_FORMAT,
            corpus_sha256: digest('a'),
            target_count: 39_191,
            generated: 1,
            worker_required: 1,
            blocked: 39_189,
            recipe_merkle_root: Some(digest('b')),
        };
        assert_eq!(receipt.validate(), Err(RecipeCorpusError::InvalidReceipt));
    }
}
