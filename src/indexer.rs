//! Canonical snapshots produced by automatic upstream repository indexers.

use alloc::{collections::BTreeSet, string::String, vec::Vec};
use core::fmt;

pub const INDEX_SNAPSHOT_FORMAT: u32 = 1;
pub const UPSTREAM_COUNT: usize = 10;
pub const MAX_INDEX_ENTRIES: usize = 100_000;
pub const MAX_PACKAGE_NAME_BYTES: usize = 128;
pub const MAX_VERSION_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(rename_all = "kebab-case"))]
pub enum Upstream {
    Arch,
    Aur,
    Fedora,
    Debian,
    Alpine,
    Gentoo,
    Crux,
    Nix,
    Cargo,
    Github,
}

pub const ALL_UPSTREAMS: [Upstream; UPSTREAM_COUNT] = [
    Upstream::Arch,
    Upstream::Aur,
    Upstream::Fedora,
    Upstream::Debian,
    Upstream::Alpine,
    Upstream::Gentoo,
    Upstream::Crux,
    Upstream::Nix,
    Upstream::Cargo,
    Upstream::Github,
];

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(
    feature = "host-store",
    serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)
)]
pub enum SourcePin {
    Git {
        repository: String,
        object_id: String,
    },
    Archive {
        url: String,
        sha256: String,
    },
    Cargo {
        crate_name: String,
        version: String,
        checksum: String,
    },
    NixFixedOutput {
        store_path: String,
        nar_sha256: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(rename_all = "kebab-case"))]
pub enum EntryStatus {
    Active,
    Removed,
    Compromised,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(deny_unknown_fields))]
pub struct UpstreamRoot {
    pub upstream: Upstream,
    pub revision: String,
    pub index_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(deny_unknown_fields))]
pub struct CanonicalRecipe {
    pub recipe_sha256: String,
    pub source_lock_sha256: String,
    pub dependency_closure_sha256: String,
    pub binary_sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(deny_unknown_fields))]
pub struct IndexEntry {
    pub upstream: Upstream,
    pub package: String,
    pub version: String,
    pub status: EntryStatus,
    pub status_reason: Option<String>,
    pub source: SourcePin,
    pub recipe: CanonicalRecipe,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "host-store", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "host-store", serde(deny_unknown_fields))]
pub struct IndexSnapshot {
    pub format: u32,
    pub sequence: u64,
    pub created_unix: u64,
    pub key_id: String,
    pub signature_sha256: String,
    pub upstream_roots: Vec<UpstreamRoot>,
    pub entries: Vec<IndexEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IndexError {
    InvalidHeader,
    InvalidSequence,
    InvalidUpstreamRoots,
    Capacity,
    NonCanonicalOrder,
    InvalidPackage,
    MutableSource,
    InvalidRecipe,
    InvalidTombstone,
}

impl fmt::Display for IndexError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidHeader => "invalid upstream index snapshot header",
            Self::InvalidSequence => "upstream index sequence is not monotonic",
            Self::InvalidUpstreamRoots => "upstream root set is incomplete or invalid",
            Self::Capacity => "upstream index exceeds its bounded capacity",
            Self::NonCanonicalOrder => "upstream index entries are not in canonical order",
            Self::InvalidPackage => "upstream index package identity is invalid",
            Self::MutableSource => "upstream index source is not immutable",
            Self::InvalidRecipe => "upstream index recipe closure is invalid",
            Self::InvalidTombstone => "removed or compromised package tombstone is invalid",
        };
        formatter.write_str(message)
    }
}

impl IndexSnapshot {
    pub fn validate(&self, previous_sequence: Option<u64>) -> Result<(), IndexError> {
        if self.format != INDEX_SNAPSHOT_FORMAT
            || self.sequence == 0
            || self.created_unix == 0
            || !valid_identifier(&self.key_id)
            || !valid_digest(&self.signature_sha256)
        {
            return Err(IndexError::InvalidHeader);
        }
        if previous_sequence.is_some_and(|previous| self.sequence != previous.saturating_add(1)) {
            return Err(IndexError::InvalidSequence);
        }
        validate_upstream_roots(&self.upstream_roots)?;
        if self.entries.len() > MAX_INDEX_ENTRIES {
            return Err(IndexError::Capacity);
        }

        let mut previous_key: Option<(Upstream, &str, &str)> = None;
        for entry in &self.entries {
            let key = (
                entry.upstream,
                entry.package.as_str(),
                entry.version.as_str(),
            );
            if previous_key.is_some_and(|previous| previous >= key) {
                return Err(IndexError::NonCanonicalOrder);
            }
            previous_key = Some(key);
            if !valid_package(&entry.package) || !valid_version(&entry.version) {
                return Err(IndexError::InvalidPackage);
            }
            entry.source.validate()?;
            entry.recipe.validate()?;
            match entry.status {
                EntryStatus::Active => {
                    if entry.status_reason.is_some() || entry.recipe.binary_sha256.is_none() {
                        return Err(IndexError::InvalidTombstone);
                    }
                }
                EntryStatus::Removed | EntryStatus::Compromised => {
                    if entry
                        .status_reason
                        .as_deref()
                        .is_none_or(|reason| reason.trim().is_empty() || reason.len() > 512)
                        || entry.recipe.binary_sha256.is_some()
                    {
                        return Err(IndexError::InvalidTombstone);
                    }
                }
            }
        }
        Ok(())
    }
}

impl SourcePin {
    fn validate(&self) -> Result<(), IndexError> {
        let valid = match self {
            Self::Git {
                repository,
                object_id,
            } => is_https(repository) && valid_revision(object_id),
            Self::Archive { url, sha256 } => is_https(url) && valid_digest(sha256),
            Self::Cargo {
                crate_name,
                version,
                checksum,
            } => valid_package(crate_name) && valid_version(version) && valid_digest(checksum),
            Self::NixFixedOutput {
                store_path,
                nar_sha256,
            } => {
                store_path.starts_with("/nix/store/")
                    && store_path.len() <= 4096
                    && !store_path.contains("..")
                    && valid_digest(nar_sha256)
            }
        };
        if valid {
            Ok(())
        } else {
            Err(IndexError::MutableSource)
        }
    }
}

impl CanonicalRecipe {
    fn validate(&self) -> Result<(), IndexError> {
        if !valid_digest(&self.recipe_sha256)
            || !valid_digest(&self.source_lock_sha256)
            || !valid_digest(&self.dependency_closure_sha256)
            || self
                .binary_sha256
                .as_deref()
                .is_some_and(|digest| !valid_digest(digest))
        {
            return Err(IndexError::InvalidRecipe);
        }
        Ok(())
    }
}

fn validate_upstream_roots(roots: &[UpstreamRoot]) -> Result<(), IndexError> {
    if roots.len() != UPSTREAM_COUNT {
        return Err(IndexError::InvalidUpstreamRoots);
    }
    let expected = ALL_UPSTREAMS.into_iter().collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    let mut previous = None;
    for root in roots {
        if previous.is_some_and(|upstream| upstream >= root.upstream)
            || !actual.insert(root.upstream)
            || !valid_revision(&root.revision)
            || !valid_digest(&root.index_sha256)
        {
            return Err(IndexError::InvalidUpstreamRoots);
        }
        previous = Some(root.upstream);
    }
    if actual != expected {
        return Err(IndexError::InvalidUpstreamRoots);
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_' | b'.' | b':')
        })
}

fn valid_package(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PACKAGE_NAME_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'_' | b'.'))
}

fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_VERSION_BYTES
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte == 0)
}

fn valid_revision(value: &str) -> bool {
    (40..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_https(value: &str) -> bool {
    value.starts_with("https://") && value.len() <= 4096 && !value.contains(char::is_whitespace)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, string::ToString, vec};

    fn digest(byte: char) -> String {
        core::iter::repeat_n(byte, 64).collect()
    }

    fn roots() -> Vec<UpstreamRoot> {
        ALL_UPSTREAMS
            .into_iter()
            .enumerate()
            .map(|(index, upstream)| UpstreamRoot {
                upstream,
                revision: digest(char::from_digit((index % 10) as u32, 10).unwrap()),
                index_sha256: digest('a'),
            })
            .collect()
    }

    fn recipe(binary: Option<String>) -> CanonicalRecipe {
        CanonicalRecipe {
            recipe_sha256: digest('b'),
            source_lock_sha256: digest('c'),
            dependency_closure_sha256: digest('d'),
            binary_sha256: binary,
        }
    }

    fn active_entry(upstream: Upstream, package: &str) -> IndexEntry {
        IndexEntry {
            upstream,
            package: package.to_string(),
            version: "1.0.0".to_string(),
            status: EntryStatus::Active,
            status_reason: None,
            source: SourcePin::Git {
                repository: format!("https://example.invalid/{package}.git"),
                object_id: digest('e'),
            },
            recipe: recipe(Some(digest('f'))),
        }
    }

    fn snapshot() -> IndexSnapshot {
        IndexSnapshot {
            format: INDEX_SNAPSHOT_FORMAT,
            sequence: 2,
            created_unix: 1,
            key_id: "corinth-index-2026".to_string(),
            signature_sha256: digest('1'),
            upstream_roots: roots(),
            entries: vec![active_entry(Upstream::Arch, "base")],
        }
    }

    #[test]
    fn accepts_complete_monotonic_snapshot() {
        assert_eq!(snapshot().validate(Some(1)), Ok(()));
    }

    #[test]
    fn requires_every_upstream_root() {
        let mut value = snapshot();
        value.upstream_roots.pop();
        assert_eq!(
            value.validate(Some(1)),
            Err(IndexError::InvalidUpstreamRoots)
        );
    }

    #[test]
    fn rejects_non_monotonic_sequence() {
        assert_eq!(
            snapshot().validate(Some(2)),
            Err(IndexError::InvalidSequence)
        );
    }

    #[test]
    fn rejects_mutable_git_reference() {
        let mut value = snapshot();
        value.entries[0].source = SourcePin::Git {
            repository: "https://example.invalid/base.git".to_string(),
            object_id: "main".to_string(),
        };
        assert_eq!(value.validate(Some(1)), Err(IndexError::MutableSource));
    }

    #[test]
    fn compromised_entry_becomes_a_non_installable_tombstone() {
        let mut value = snapshot();
        value.entries[0].status = EntryStatus::Compromised;
        value.entries[0].status_reason = Some("upstream signing key compromised".to_string());
        value.entries[0].recipe.binary_sha256 = None;
        assert_eq!(value.validate(Some(1)), Ok(()));
    }

    #[test]
    fn tombstone_cannot_publish_a_binary() {
        let mut value = snapshot();
        value.entries[0].status = EntryStatus::Removed;
        value.entries[0].status_reason = Some("removed upstream".to_string());
        assert_eq!(value.validate(Some(1)), Err(IndexError::InvalidTombstone));
    }

    #[test]
    fn entries_must_be_in_canonical_order() {
        let mut value = snapshot();
        value.entries = vec![
            active_entry(Upstream::Debian, "zlib"),
            active_entry(Upstream::Arch, "base"),
        ];
        assert_eq!(value.validate(Some(1)), Err(IndexError::NonCanonicalOrder));
    }
}
