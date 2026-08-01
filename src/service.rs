//! Signed repository resolution and the standard Corinth package lifecycle.
//!
//! The service configuration is signed package-index metadata. It names every
//! repository that participates in resolution and binds each remote object by
//! SHA-256. Native Arach packages always outrank imported source packages.
//! Mutable provider discovery remains an administrative operation: the normal
//! lifecycle accepts only immutable ingress locks already admitted by a signed
//! source catalog.

use alloc::{boxed::Box, format, string::String, string::ToString, vec::Vec};
use arach_hwd::facts::CpuArchitecture;
use arach_hwd::plan::CompilerTarget;
use arach_hwd::profile::{CompilerPolicy, PackageScope, RepositoryAuthority};
use arach_hwd::scan::scan_system;
use arach_hwd::signature::Keyring;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::arch_import::{RecipeTargetPolicy, parse_target_policy};
use crate::binary::{
    BinaryInstallReceipt, BinaryInstallStore, BinaryProvisioner, VerifiedBinaryIndex,
    verify_binary_index,
};
use crate::hardware::{
    HardwareError, HardwareProvisioner, atomic_write, metadata_sha256, prepare_private_root,
};
use crate::universal_import::{
    UniversalEcosystem, crates_io_acquisition_source, git_origin, import_universal_lock,
    parse_universal_import_lock,
};

pub const SERVICE_CONFIG_FORMAT: u32 = 1;
pub const SOURCE_CATALOG_FORMAT: u32 = 1;
pub const SERVICE_RECEIPT_FORMAT: u32 = 1;
const SERVICE_JOURNAL_FORMAT: u32 = 1;
const MAX_SERVICE_DOCUMENT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_SIGNATURE_BYTES: u64 = 16 * 1024;
const MAX_PROVIDER_COUNT: usize = 256;
const MAX_CATALOG_PACKAGES: usize = 100_000;
const MAX_NAME_BYTES: usize = 128;
const MAX_VERSION_BYTES: usize = 256;
static RESOURCE_SERIAL: AtomicU64 = AtomicU64::new(1);

pub const DEFAULT_SERVICE_CONFIG: &str = "/etc/corinth/service.toml";
pub const DEFAULT_SERVICE_SIGNATURE: &str = "/etc/corinth/service.toml.sig";
pub const DEFAULT_SERVICE_KEYRING: &str = "/etc/arach/hwd/keys.toml";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    pub format: u32,
    pub key_id: String,
    pub generation: u64,
    pub channel: String,
    pub expires_unix: u64,
    pub state: PathBuf,
    pub work: PathBuf,
    pub artifacts: PathBuf,
    pub root: PathBuf,
    pub allow_network: bool,
    pub compiler: CompilerPolicy,
    #[serde(rename = "native", default)]
    pub native_repositories: Vec<NativeRepository>,
    #[serde(rename = "source", default)]
    pub source_repositories: Vec<SourceRepository>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRepository {
    pub name: String,
    pub priority: i32,
    pub generation: u64,
    pub channel: String,
    pub architectures: Vec<String>,
    pub index: String,
    pub index_sha256: String,
    pub signature: String,
    pub signature_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRepository {
    pub name: String,
    pub priority: i32,
    pub generation: u64,
    pub channel: String,
    pub architectures: Vec<String>,
    pub catalog: String,
    pub catalog_sha256: String,
    pub signature: String,
    pub signature_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCatalog {
    pub format: u32,
    pub key_id: String,
    pub name: String,
    pub channel: String,
    pub generation: u64,
    pub expires_unix: u64,
    #[serde(rename = "package", default)]
    pub packages: Vec<SourceCatalogPackage>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCatalogPackage {
    pub name: String,
    pub version: String,
    pub release: u32,
    pub sequence: u64,
    pub ecosystem: UniversalEcosystem,
    pub architectures: Vec<String>,
    pub ingress_lock: String,
    pub ingress_lock_sha256: String,
    pub ingress_signature: String,
    pub ingress_signature_sha256: String,
    pub target_policy: String,
    pub target_policy_sha256: String,
    pub target_signature: String,
    pub target_signature_sha256: String,
    pub recipe_sha256: String,
    pub source_lock_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceReceipt {
    pub format: u32,
    pub package: String,
    pub version: String,
    pub release: u32,
    pub provider: String,
    pub channel: String,
    pub service_generation: u64,
    pub service_config_sha256: String,
    pub provider_generation: u64,
    pub package_sequence: u64,
    pub artifact_sha256: String,
    pub origin: ServiceOrigin,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "route", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ServiceOrigin {
    Native {
        index_sha256: String,
        metadata_sha256: String,
        source_lock_sha256: String,
    },
    Source {
        ecosystem: UniversalEcosystem,
        catalog_sha256: String,
        ingress_lock_sha256: String,
        target_policy_sha256: String,
        recipe_sha256: String,
        source_lock_sha256: String,
        compiler_sha256: String,
    },
}

impl ServiceOrigin {
    fn route_name(&self) -> &'static str {
        match self {
            Self::Native { .. } => "native",
            Self::Source { .. } => "source",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolutionSummary {
    pub package: String,
    pub version: String,
    pub release: u32,
    pub provider: String,
    pub route: String,
    pub priority: i32,
    pub provider_generation: u64,
    pub package_sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleResult {
    pub action: String,
    pub package: String,
    pub version: String,
    pub release: u32,
    pub provider: String,
    pub route: String,
    pub artifact_sha256: String,
    pub changed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceError {
    Configuration(String),
    Signature(String),
    Expired(String),
    Resource(String),
    Provider(String),
    PackageNotFound(String),
    Ambiguous(Vec<String>),
    State(String),
    Downgrade(String),
    Transaction(String),
    Hardware(String),
}

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(value) => {
                write!(formatter, "invalid service configuration: {value}")
            }
            Self::Signature(value) => write!(formatter, "signature verification failed: {value}"),
            Self::Expired(value) => write!(formatter, "repository metadata expired: {value}"),
            Self::Resource(value) => write!(formatter, "repository resource unavailable: {value}"),
            Self::Provider(value) => write!(formatter, "provider rejected: {value}"),
            Self::PackageNotFound(value) => write!(formatter, "package not found: {value}"),
            Self::Ambiguous(values) => write!(
                formatter,
                "ambiguous package providers: {}",
                values.join(", ")
            ),
            Self::State(value) => write!(formatter, "package state error: {value}"),
            Self::Downgrade(value) => write!(formatter, "downgrade rejected: {value}"),
            Self::Transaction(value) => write!(formatter, "transaction recovery failed: {value}"),
            Self::Hardware(value) => write!(formatter, "package operation failed: {value}"),
        }
    }
}

impl std::error::Error for ServiceError {}

impl From<HardwareError> for ServiceError {
    fn from(error: HardwareError) -> Self {
        Self::Hardware(error.to_string())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PackageSelector {
    namespace: Option<String>,
    name: String,
    version: Option<String>,
}

enum ResolvedPackage {
    Native(Box<NativeCandidate>),
    Source(Box<SourceCandidate>),
}

struct NativeCandidate {
    repository: NativeRepository,
    verified: VerifiedBinaryIndex,
    record_index: usize,
}

struct SourceCandidate {
    repository: SourceRepository,
    catalog_sha256: String,
    package: SourceCatalogPackage,
}

impl ResolvedPackage {
    fn package(&self) -> &str {
        match self {
            Self::Native(candidate) => &candidate.record().name,
            Self::Source(candidate) => &candidate.package.name,
        }
    }

    fn version(&self) -> &str {
        match self {
            Self::Native(candidate) => &candidate.record().version,
            Self::Source(candidate) => &candidate.package.version,
        }
    }

    fn release(&self) -> u32 {
        match self {
            Self::Native(candidate) => candidate.record().release,
            Self::Source(candidate) => candidate.package.release,
        }
    }

    fn provider(&self) -> &str {
        match self {
            Self::Native(candidate) => &candidate.repository.name,
            Self::Source(candidate) => &candidate.repository.name,
        }
    }

    fn channel(&self) -> &str {
        match self {
            Self::Native(candidate) => &candidate.repository.channel,
            Self::Source(candidate) => &candidate.repository.channel,
        }
    }

    fn priority(&self) -> i32 {
        match self {
            Self::Native(candidate) => candidate.repository.priority,
            Self::Source(candidate) => candidate.repository.priority,
        }
    }

    fn provider_generation(&self) -> u64 {
        match self {
            Self::Native(candidate) => candidate.repository.generation,
            Self::Source(candidate) => candidate.repository.generation,
        }
    }

    fn package_sequence(&self) -> u64 {
        match self {
            Self::Native(_) => 0,
            Self::Source(candidate) => candidate.package.sequence,
        }
    }

    fn authority_sha256(&self) -> &str {
        match self {
            Self::Native(candidate) => &candidate.verified.index_sha256,
            Self::Source(candidate) => &candidate.catalog_sha256,
        }
    }

    fn route(&self) -> &'static str {
        match self {
            Self::Native(_) => "native",
            Self::Source(_) => "source",
        }
    }

    fn namespace_matches(&self, namespace: &str) -> bool {
        if self.provider() == namespace || self.route() == namespace {
            return true;
        }
        matches!(self, Self::Source(candidate) if candidate.package.ecosystem.name() == namespace)
    }

    fn identity(&self) -> String {
        match self {
            Self::Native(candidate) => {
                let package = candidate.record();
                format!(
                    "native:{}:{}:{}:{}:{}",
                    package.version,
                    package.release,
                    package.artifact_sha256,
                    package.metadata_sha256,
                    package.source_lock_sha256
                )
            }
            Self::Source(candidate) => format!(
                "source:{}:{}:{}:{}:{}:{}",
                candidate.package.ecosystem.name(),
                candidate.package.version,
                candidate.package.release,
                candidate.package.sequence,
                candidate.package.ingress_lock_sha256,
                candidate.package.target_policy_sha256
            ),
        }
    }

    fn summary(&self) -> ResolutionSummary {
        ResolutionSummary {
            package: self.package().into(),
            version: self.version().into(),
            release: self.release(),
            provider: self.provider().into(),
            route: self.route().into(),
            priority: self.priority(),
            provider_generation: self.provider_generation(),
            package_sequence: self.package_sequence(),
        }
    }
}

impl NativeCandidate {
    fn record(&self) -> &crate::binary::BinaryPackage {
        &self.verified.index.packages[self.record_index]
    }
}

pub struct PackageService {
    config: ServiceConfig,
    config_sha256: String,
    keyring: Keyring,
    network: bool,
    now_unix: u64,
}

impl PackageService {
    pub fn open(
        config_path: &Path,
        signature_path: &Path,
        keyring_path: &Path,
        offline: bool,
    ) -> Result<Self, ServiceError> {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| ServiceError::Configuration(error.to_string()))?
            .as_secs();
        Self::open_at(config_path, signature_path, keyring_path, offline, now_unix)
    }

    fn open_at(
        config_path: &Path,
        signature_path: &Path,
        keyring_path: &Path,
        offline: bool,
        now_unix: u64,
    ) -> Result<Self, ServiceError> {
        let config_bytes = read_regular(config_path, MAX_SERVICE_DOCUMENT_BYTES)?;
        let signature_bytes = read_regular(signature_path, MAX_SIGNATURE_BYTES)?;
        let signature = String::from_utf8(signature_bytes)
            .map_err(|_| ServiceError::Signature("service signature is not UTF-8".into()))?;
        let keyring = Keyring::load(keyring_path)
            .map_err(|error| ServiceError::Signature(error.to_string()))?;
        let key_id = keyring
            .verify_payload(&config_bytes, &signature, "package-index")
            .map_err(|error| ServiceError::Signature(error.to_string()))?;
        let config: ServiceConfig = toml::from_slice(&config_bytes)
            .map_err(|error| ServiceError::Configuration(error.to_string()))?;
        if config.key_id != key_id {
            return Err(ServiceError::Configuration(
                "service key_id differs from its detached signature".into(),
            ));
        }
        validate_service_config(&config, now_unix)?;
        prepare_private_root(&config.state)?;
        prepare_private_root(&config.work)?;
        prepare_private_root(&config.artifacts)?;
        let network = config.allow_network && !offline;
        Ok(Self {
            config,
            config_sha256: hex_digest(&Sha256::digest(&config_bytes)),
            keyring,
            network,
            now_unix,
        })
    }

    pub fn search(&self, selector: &str) -> Result<ResolutionSummary, ServiceError> {
        let selector = parse_selector(selector)?;
        self.resolve(&selector, None)
            .map(|candidate| candidate.summary())
    }

    pub fn install(&self, selector: &str) -> Result<LifecycleResult, ServiceError> {
        self.lifecycle_install_or_update(selector, false)
    }

    pub fn update(&self, selector: &str) -> Result<LifecycleResult, ServiceError> {
        self.lifecycle_install_or_update(selector, true)
    }

    pub fn remove(&self, selector: &str) -> Result<LifecycleResult, ServiceError> {
        let selector = parse_selector(selector)?;
        let _lock = ServiceLock::acquire(&self.config.state)?;
        self.recover_pending()?;
        let old = self.read_service_receipt(&selector.name)?.ok_or_else(|| {
            ServiceError::State(format!("package is not installed: {}", selector.name))
        })?;
        selector_matches_receipt(&selector, &old, true)?;
        let binary_store =
            BinaryInstallStore::open(self.config.state.clone(), self.config.root.clone())?;
        let binary = binary_store
            .installed_receipt(&selector.name)?
            .ok_or_else(|| {
                ServiceError::State(
                    "service receipt exists without a binary ownership receipt".into(),
                )
            })?;
        ensure_binary_matches_service(&binary, &old)?;
        let journal = ServiceJournal {
            format: SERVICE_JOURNAL_FORMAT,
            action: JournalAction::Remove,
            package: selector.name.clone(),
            old: Some(old.clone()),
            new: None,
        };
        self.write_journal(&journal)?;
        self.remove_service_receipt(&selector.name)?;
        if let Err(error) = binary_store.remove(&selector.name) {
            match binary_store.installed_receipt(&selector.name) {
                Ok(None) => {
                    // The ownership receipt is removed only after every target
                    // file has left the target root. A later cleanup failure
                    // therefore means the removal itself committed.
                }
                Ok(Some(binary)) if binary_matches_service(&binary, &old) => {
                    self.write_service_receipt(&old)?;
                    self.clear_journal()?;
                    return Err(error.into());
                }
                Ok(Some(_)) => {
                    return Err(ServiceError::Transaction(format!(
                        "remove failed and binary ownership matches neither journal state: {error}"
                    )));
                }
                Err(inspect) => {
                    return Err(ServiceError::Transaction(format!(
                        "remove failed ({error}) and ownership could not be inspected: {inspect}"
                    )));
                }
            }
        }
        self.clear_journal()?;
        Ok(LifecycleResult {
            action: "remove".into(),
            package: old.package,
            version: old.version,
            release: old.release,
            provider: old.provider,
            route: old.origin.route_name().into(),
            artifact_sha256: old.artifact_sha256,
            changed: true,
        })
    }

    fn lifecycle_install_or_update(
        &self,
        selector: &str,
        update: bool,
    ) -> Result<LifecycleResult, ServiceError> {
        let selector = parse_selector(selector)?;
        let _lock = ServiceLock::acquire(&self.config.state)?;
        self.recover_pending()?;
        let old = self.read_service_receipt(&selector.name)?;
        if update && old.is_none() {
            return Err(ServiceError::State(format!(
                "package is not installed: {}",
                selector.name
            )));
        }
        if !update && old.is_some() {
            return Err(ServiceError::State(format!(
                "package is already installed: {}",
                selector.name
            )));
        }
        if let Some(receipt) = &old {
            selector_matches_receipt(&selector, receipt, false)?;
        }
        let binary_store =
            BinaryInstallStore::open(self.config.state.clone(), self.config.root.clone())?;
        let binary = binary_store.installed_receipt(&selector.name)?;
        match (&old, &binary) {
            (None, Some(_)) => {
                return Err(ServiceError::State(
                    "binary ownership exists without a service receipt".into(),
                ));
            }
            (Some(receipt), Some(binary)) => ensure_binary_matches_service(binary, receipt)?,
            (Some(_), None) => {
                return Err(ServiceError::State(
                    "service receipt exists without a binary ownership receipt".into(),
                ));
            }
            (None, None) => {}
        }

        let resolved = self.resolve(&selector, old.as_ref())?;
        if let Some(receipt) = &old {
            enforce_update_floor(
                receipt,
                &resolved,
                self.config.generation,
                &self.config_sha256,
            )?;
        }
        let prepared = self.prepare_candidate(resolved)?;
        let new = prepared.receipt;
        if let Some(old) = &old
            && old == &new
        {
            return Ok(result_from_receipt(
                if update { "update" } else { "install" },
                old,
                false,
            ));
        }
        if let Some(old) = &old
            && old.artifact_sha256 == new.artifact_sha256
            && old.package == new.package
            && old.version == new.version
            && old.release == new.release
        {
            self.write_service_receipt(&new)?;
            return Ok(result_from_receipt("update", &new, false));
        }

        let journal = ServiceJournal {
            format: SERVICE_JOURNAL_FORMAT,
            action: if update {
                JournalAction::Update
            } else {
                JournalAction::Install
            },
            package: selector.name,
            old: old.clone(),
            new: Some(new.clone()),
        };
        self.write_journal(&journal)?;
        self.write_service_receipt(&new)?;
        let operation = match prepared.payload {
            PreparedPayload::Native {
                provisioner,
                verified,
            } => {
                if update {
                    provisioner
                        .update_to_root(
                            self.config.state.clone(),
                            self.config.root.clone(),
                            &verified,
                            &new.package,
                            Some(&new.version),
                        )
                        .map(|_| ())
                } else {
                    provisioner
                        .install_to_root(
                            self.config.state.clone(),
                            self.config.root.clone(),
                            &verified,
                            &new.package,
                            Some(&new.version),
                        )
                        .map(|_| ())
                }
            }
            PreparedPayload::Source(payload) => binary_store
                .install_payload(&payload, &new.artifact_sha256, update)
                .map(|_| ()),
        };
        if let Err(error) = operation {
            match binary_store.installed_receipt(&new.package) {
                Ok(Some(binary)) if binary_matches_service(&binary, &new) => {
                    self.write_service_receipt(&new)?;
                    self.clear_journal()?;
                    return Ok(result_from_receipt(
                        if update { "update" } else { "install" },
                        &new,
                        true,
                    ));
                }
                Ok(Some(binary))
                    if old
                        .as_ref()
                        .is_some_and(|receipt| binary_matches_service(&binary, receipt)) =>
                {
                    self.write_service_receipt(old.as_ref().ok_or_else(|| {
                        ServiceError::Transaction(
                            "old ownership exists without an old journal receipt".into(),
                        )
                    })?)?;
                    self.clear_journal()?;
                    return Err(error.into());
                }
                Ok(None) if old.is_none() => {
                    self.remove_service_receipt(&new.package)?;
                    self.clear_journal()?;
                    return Err(error.into());
                }
                Ok(None) => {
                    return Err(ServiceError::Transaction(format!(
                        "update failed and lost both ownership states: {error}"
                    )));
                }
                Ok(Some(_)) => {
                    return Err(ServiceError::Transaction(format!(
                        "package operation failed and binary ownership matches neither journal state: {error}"
                    )));
                }
                Err(inspect) => {
                    return Err(ServiceError::Transaction(format!(
                        "package operation failed ({error}) and ownership could not be inspected: {inspect}"
                    )));
                }
            }
        }
        self.clear_journal()?;
        Ok(result_from_receipt(
            if update { "update" } else { "install" },
            &new,
            true,
        ))
    }

    fn resolve(
        &self,
        selector: &PackageSelector,
        installed: Option<&ServiceReceipt>,
    ) -> Result<ResolvedPackage, ServiceError> {
        let mut candidates = Vec::new();
        for repository in &self.config.native_repositories {
            let index_bytes = self.fetch_resource(
                &repository.index,
                &repository.index_sha256,
                MAX_SERVICE_DOCUMENT_BYTES,
            )?;
            let signature_bytes = self.fetch_resource(
                &repository.signature,
                &repository.signature_sha256,
                MAX_SIGNATURE_BYTES,
            )?;
            let signature = String::from_utf8(signature_bytes).map_err(|_| {
                ServiceError::Signature(format!("{} index signature is not UTF-8", repository.name))
            })?;
            let verified = verify_binary_index(&index_bytes, &signature, &self.keyring)?;
            if verified.index.repository != RepositoryAuthority::ArachNative {
                return Err(ServiceError::Provider(format!(
                    "{} is not a native Arach index",
                    repository.name
                )));
            }
            if let Some((record_index, _)) =
                verified
                    .index
                    .packages
                    .iter()
                    .enumerate()
                    .find(|(_, package)| {
                        package.name == selector.name
                            && package.scope == PackageScope::System
                            && selector
                                .version
                                .as_deref()
                                .is_none_or(|version| package.version == version)
                    })
            {
                candidates.push(ResolvedPackage::Native(Box::new(NativeCandidate {
                    repository: repository.clone(),
                    verified,
                    record_index,
                })));
            }
        }
        for repository in &self.config.source_repositories {
            let catalog_bytes = self.fetch_resource(
                &repository.catalog,
                &repository.catalog_sha256,
                MAX_SERVICE_DOCUMENT_BYTES,
            )?;
            let signature_bytes = self.fetch_resource(
                &repository.signature,
                &repository.signature_sha256,
                MAX_SIGNATURE_BYTES,
            )?;
            let signature = String::from_utf8(signature_bytes).map_err(|_| {
                ServiceError::Signature(format!(
                    "{} catalog signature is not UTF-8",
                    repository.name
                ))
            })?;
            let key_id = self
                .keyring
                .verify_payload(&catalog_bytes, &signature, "package-index")
                .map_err(|error| ServiceError::Signature(error.to_string()))?;
            let catalog: SourceCatalog = toml::from_slice(&catalog_bytes)
                .map_err(|error| ServiceError::Provider(error.to_string()))?;
            validate_source_catalog(&catalog, repository, &key_id, self.now_unix)?;
            let selected = catalog
                .packages
                .iter()
                .filter(|package| {
                    package.name == selector.name
                        && architecture_matches(
                            &package.architectures,
                            service_architecture(&self.config),
                        )
                        && selector
                            .version
                            .as_deref()
                            .is_none_or(|version| package.version == version)
                })
                .max_by_key(|package| package.sequence)
                .cloned();
            if let Some(package) = selected {
                candidates.push(ResolvedPackage::Source(Box::new(SourceCandidate {
                    repository: repository.clone(),
                    catalog_sha256: hex_digest(&Sha256::digest(&catalog_bytes)),
                    package,
                })));
            }
        }
        choose_candidate(candidates, selector, installed)
    }

    fn fetch_resource(
        &self,
        location: &str,
        expected_sha256: &str,
        maximum: u64,
    ) -> Result<Vec<u8>, ServiceError> {
        fetch_resource(
            location,
            expected_sha256,
            maximum,
            &self.config.work.join("repository-objects"),
            self.network,
        )
    }

    fn prepare_candidate(
        &self,
        candidate: ResolvedPackage,
    ) -> Result<PreparedCandidate, ServiceError> {
        match candidate {
            ResolvedPackage::Native(candidate) => self.prepare_native_candidate(*candidate),
            ResolvedPackage::Source(candidate) => self.prepare_source_candidate(*candidate),
        }
    }

    fn prepare_native_candidate(
        &self,
        candidate: NativeCandidate,
    ) -> Result<PreparedCandidate, ServiceError> {
        let package = candidate.record();
        let receipt = ServiceReceipt {
            format: SERVICE_RECEIPT_FORMAT,
            package: package.name.clone(),
            version: package.version.clone(),
            release: package.release,
            provider: candidate.repository.name.clone(),
            channel: candidate.repository.channel.clone(),
            service_generation: self.config.generation,
            service_config_sha256: self.config_sha256.clone(),
            provider_generation: candidate.repository.generation,
            package_sequence: 0,
            artifact_sha256: package.artifact_sha256.clone(),
            origin: ServiceOrigin::Native {
                index_sha256: candidate.verified.index_sha256.clone(),
                metadata_sha256: package.metadata_sha256.clone(),
                source_lock_sha256: package.source_lock_sha256.clone(),
            },
        };
        validate_service_receipt(&receipt)?;
        let mut provisioner = BinaryProvisioner::new(self.config.artifacts.join("binary"))?;
        provisioner.allow_network = self.network;
        Ok(PreparedCandidate {
            receipt,
            payload: PreparedPayload::Native {
                provisioner,
                verified: candidate.verified,
            },
        })
    }

    fn prepare_source_candidate(
        &self,
        candidate: SourceCandidate,
    ) -> Result<PreparedCandidate, ServiceError> {
        let package = &candidate.package;
        let lock_bytes = self.fetch_resource(
            &package.ingress_lock,
            &package.ingress_lock_sha256,
            MAX_SERVICE_DOCUMENT_BYTES,
        )?;
        let lock_signature_bytes = self.fetch_resource(
            &package.ingress_signature,
            &package.ingress_signature_sha256,
            MAX_SIGNATURE_BYTES,
        )?;
        let lock_signature = String::from_utf8(lock_signature_bytes)
            .map_err(|_| ServiceError::Signature("ingress signature is not UTF-8".into()))?;
        self.keyring
            .verify_payload(&lock_bytes, &lock_signature, "package-index")
            .map_err(|error| ServiceError::Signature(error.to_string()))?;
        let target_bytes = self.fetch_resource(
            &package.target_policy,
            &package.target_policy_sha256,
            MAX_SERVICE_DOCUMENT_BYTES,
        )?;
        let target_signature_bytes = self.fetch_resource(
            &package.target_signature,
            &package.target_signature_sha256,
            MAX_SIGNATURE_BYTES,
        )?;
        let target_signature = String::from_utf8(target_signature_bytes)
            .map_err(|_| ServiceError::Signature("target signature is not UTF-8".into()))?;
        self.keyring
            .verify_payload(&target_bytes, &target_signature, "package-index")
            .map_err(|error| ServiceError::Signature(error.to_string()))?;

        let lock = parse_universal_import_lock(&lock_bytes)
            .map_err(|error| ServiceError::Provider(error.to_string()))?;
        if lock.package != package.name || lock.ecosystem != package.ecosystem {
            return Err(ServiceError::Provider(
                "source catalog identity differs from its ingress lock".into(),
            ));
        }
        let target = parse_target_policy(&target_bytes)
            .map_err(|error| ServiceError::Provider(error.to_string()))?;
        validate_service_target(&target, package, service_architecture(&self.config))?;

        let mut provisioner = HardwareProvisioner::for_target(
            self.config.work.join("source-build"),
            self.config.artifacts.join("source"),
            service_architecture(&self.config),
        )?;
        provisioner.allow_network = self.network;
        provisioner.allow_host_toolchains = false;
        let repository;
        let repository_root = if let Some((url, revision, submodules)) = git_origin(&lock) {
            repository = provisioner.acquire_recipe_repository(url, revision, submodules)?;
            Some(repository.as_path())
        } else {
            let source = crates_io_acquisition_source(&lock).ok_or_else(|| {
                ServiceError::Provider("ingress lock has no acquisition source".into())
            })?;
            provisioner.acquire_locked_source(&source)?;
            None
        };
        let imported = import_universal_lock(&lock, repository_root, &target)
            .map_err(|error| ServiceError::Provider(error.to_string()))?;
        if imported.package != package.name
            || imported.version != package.version
            || metadata_sha256(&imported.recipe.bytes) != package.recipe_sha256
            || imported.recipe.metadata_sha256 != package.recipe_sha256
            || imported.recipe.source_lock_sha256 != package.source_lock_sha256
        {
            return Err(ServiceError::Provider(
                "translated recipe differs from the signed source catalog".into(),
            ));
        }
        let recipe = crate::hardware::parse_recipe(&imported.recipe.bytes)?;
        if recipe.package.release != package.release {
            return Err(ServiceError::Provider(
                "translated recipe release differs from the signed source catalog".into(),
            ));
        }
        if !recipe.build.depends.is_empty()
            || recipe
                .runtime
                .as_ref()
                .is_some_and(|runtime| !runtime.depends.is_empty())
        {
            return Err(ServiceError::Provider(
                "source package dependencies require a complete service transaction graph".into(),
            ));
        }
        let compiler = host_compiler_target(&self.config.compiler)?;
        let compiler_sha256 = compiler_digest(&compiler)?;
        let build = provisioner.build_admitted_system_recipe(&imported.recipe.bytes, &compiler)?;
        let payload =
            provisioner.payload_from_admitted_system_recipe(&imported.recipe.bytes, &build)?;
        let receipt = ServiceReceipt {
            format: SERVICE_RECEIPT_FORMAT,
            package: build.package,
            version: build.version,
            release: build.release,
            provider: candidate.repository.name,
            channel: candidate.repository.channel,
            service_generation: self.config.generation,
            service_config_sha256: self.config_sha256.clone(),
            provider_generation: candidate.repository.generation,
            package_sequence: package.sequence,
            artifact_sha256: build.artifact_sha256,
            origin: ServiceOrigin::Source {
                ecosystem: package.ecosystem,
                catalog_sha256: candidate.catalog_sha256,
                ingress_lock_sha256: package.ingress_lock_sha256.clone(),
                target_policy_sha256: package.target_policy_sha256.clone(),
                recipe_sha256: package.recipe_sha256.clone(),
                source_lock_sha256: package.source_lock_sha256.clone(),
                compiler_sha256,
            },
        };
        validate_service_receipt(&receipt)?;
        Ok(PreparedCandidate {
            receipt,
            payload: PreparedPayload::Source(payload),
        })
    }

    fn service_receipt_directory(&self) -> PathBuf {
        self.config.state.join("service-installed")
    }

    fn service_receipt_path(&self, package: &str) -> Result<PathBuf, ServiceError> {
        if !valid_package_name(package) {
            return Err(ServiceError::State("invalid package identity".into()));
        }
        Ok(self
            .service_receipt_directory()
            .join(format!("{package}.toml")))
    }

    fn read_service_receipt(&self, package: &str) -> Result<Option<ServiceReceipt>, ServiceError> {
        let path = self.service_receipt_path(package)?;
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => Err(
                ServiceError::State("service receipt is not a regular file".into()),
            ),
            Ok(_) => {
                let bytes = read_regular(&path, MAX_SERVICE_DOCUMENT_BYTES)?;
                let receipt: ServiceReceipt = toml::from_slice(&bytes)
                    .map_err(|error| ServiceError::State(error.to_string()))?;
                validate_service_receipt(&receipt)?;
                if receipt.package != package {
                    return Err(ServiceError::State(
                        "service receipt path and package differ".into(),
                    ));
                }
                Ok(Some(receipt))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(ServiceError::State(error.to_string())),
        }
    }

    fn write_service_receipt(&self, receipt: &ServiceReceipt) -> Result<(), ServiceError> {
        validate_service_receipt(receipt)?;
        ensure_private_directory(&self.service_receipt_directory())?;
        let bytes =
            toml::to_string(receipt).map_err(|error| ServiceError::State(error.to_string()))?;
        atomic_write(
            &self.service_receipt_path(&receipt.package)?,
            bytes.as_bytes(),
        )?;
        sync_directory(&self.service_receipt_directory())?;
        Ok(())
    }

    fn remove_service_receipt(&self, package: &str) -> Result<(), ServiceError> {
        let path = self.service_receipt_path(package)?;
        match fs::remove_file(path) {
            Ok(()) => sync_directory(&self.service_receipt_directory()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(ServiceError::State(error.to_string())),
        }
    }

    fn journal_path(&self) -> PathBuf {
        self.config.state.join("service-transaction.toml")
    }

    fn write_journal(&self, journal: &ServiceJournal) -> Result<(), ServiceError> {
        validate_journal(journal)?;
        let bytes = toml::to_string(journal)
            .map_err(|error| ServiceError::Transaction(error.to_string()))?;
        atomic_write(&self.journal_path(), bytes.as_bytes())?;
        sync_directory(&self.config.state)?;
        Ok(())
    }

    fn clear_journal(&self) -> Result<(), ServiceError> {
        match fs::remove_file(self.journal_path()) {
            Ok(()) => sync_directory(&self.config.state),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(ServiceError::Transaction(error.to_string())),
        }
    }

    fn recover_pending(&self) -> Result<(), ServiceError> {
        ensure_private_directory(&self.config.state)?;
        ensure_private_directory(&self.service_receipt_directory())?;
        let path = self.journal_path();
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(ServiceError::Transaction(error.to_string())),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ServiceError::Transaction(
                "transaction journal is not a regular file".into(),
            ));
        }
        let bytes = read_regular(&path, MAX_SERVICE_DOCUMENT_BYTES)?;
        let journal: ServiceJournal = toml::from_slice(&bytes)
            .map_err(|error| ServiceError::Transaction(error.to_string()))?;
        validate_journal(&journal)?;
        let binary_store =
            BinaryInstallStore::open(self.config.state.clone(), self.config.root.clone())?;
        let binary = binary_store.installed_receipt(&journal.package)?;
        if let Some(binary) = &binary {
            if let Some(new) = &journal.new
                && binary_matches_service(binary, new)
            {
                self.write_service_receipt(new)?;
                return self.clear_journal();
            }
            if let Some(old) = &journal.old
                && binary_matches_service(binary, old)
            {
                self.write_service_receipt(old)?;
                return self.clear_journal();
            }
            return Err(ServiceError::Transaction(
                "binary ownership state matches neither side of the journal".into(),
            ));
        }
        match journal.action {
            JournalAction::Install | JournalAction::Remove => {
                self.remove_service_receipt(&journal.package)?;
                self.clear_journal()
            }
            JournalAction::Update => Err(ServiceError::Transaction(
                "an interrupted update lost both old and new binary ownership".into(),
            )),
        }
    }
}

struct PreparedCandidate {
    receipt: ServiceReceipt,
    payload: PreparedPayload,
}

enum PreparedPayload {
    Native {
        provisioner: BinaryProvisioner,
        verified: VerifiedBinaryIndex,
    },
    Source(crate::binary::BinaryPayload),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum JournalAction {
    Install,
    Update,
    Remove,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceJournal {
    format: u32,
    action: JournalAction,
    package: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    old: Option<ServiceReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    new: Option<ServiceReceipt>,
}

struct ServiceLock {
    file: File,
}

impl ServiceLock {
    fn acquire(state: &Path) -> Result<Self, ServiceError> {
        prepare_private_root(state)?;
        let path = state.join("service.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|error| ServiceError::State(error.to_string()))?;
        let metadata = file
            .metadata()
            .map_err(|error| ServiceError::State(error.to_string()))?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(ServiceError::State(
                "service lock is not a private regular file".into(),
            ));
        }
        // SAFETY: `file` owns a live descriptor for the private regular lock
        // file, and `flock` does not retain it beyond this call.
        let result = unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&file), libc::LOCK_EX) };
        if result != 0 {
            return Err(ServiceError::State(
                std::io::Error::last_os_error().to_string(),
            ));
        }
        Ok(Self { file })
    }
}

impl Drop for ServiceLock {
    fn drop(&mut self) {
        // SAFETY: the descriptor remains live for the duration of `drop`; an
        // unlock failure cannot be recovered while destroying the guard.
        let _ = unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&self.file), libc::LOCK_UN) };
    }
}

fn validate_service_config(config: &ServiceConfig, now_unix: u64) -> Result<(), ServiceError> {
    if config.format != SERVICE_CONFIG_FORMAT
        || config.generation == 0
        || !valid_key_id(&config.key_id)
        || !valid_name(&config.channel)
    {
        return Err(ServiceError::Configuration(
            "invalid format, generation, key, or channel".into(),
        ));
    }
    if config.expires_unix <= now_unix {
        return Err(ServiceError::Expired("service configuration".into()));
    }
    validate_store_paths(config)?;
    validate_compiler_policy(&config.compiler)?;
    let provider_count = config.native_repositories.len() + config.source_repositories.len();
    if provider_count == 0 || provider_count > MAX_PROVIDER_COUNT {
        return Err(ServiceError::Configuration(
            "service must configure a bounded non-empty provider set".into(),
        ));
    }
    let architecture = service_architecture(config);
    let mut names = BTreeSet::new();
    for repository in &config.native_repositories {
        validate_repository(
            &repository.name,
            repository.generation,
            &repository.channel,
            &repository.architectures,
            &repository.index,
            &repository.index_sha256,
            &repository.signature,
            &repository.signature_sha256,
            &config.channel,
            architecture,
        )?;
        if !names.insert(repository.name.clone()) {
            return Err(ServiceError::Configuration(format!(
                "duplicate provider name: {}",
                repository.name
            )));
        }
    }
    for repository in &config.source_repositories {
        validate_repository(
            &repository.name,
            repository.generation,
            &repository.channel,
            &repository.architectures,
            &repository.catalog,
            &repository.catalog_sha256,
            &repository.signature,
            &repository.signature_sha256,
            &config.channel,
            architecture,
        )?;
        if !names.insert(repository.name.clone()) {
            return Err(ServiceError::Configuration(format!(
                "duplicate provider name: {}",
                repository.name
            )));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_repository(
    name: &str,
    generation: u64,
    channel: &str,
    architectures: &[String],
    document: &str,
    document_sha256: &str,
    signature: &str,
    signature_sha256: &str,
    expected_channel: &str,
    architecture: &str,
) -> Result<(), ServiceError> {
    if !valid_name(name)
        || matches!(name, "native" | "source")
        || generation == 0
        || channel != expected_channel
        || !valid_architecture_set(architectures)
        || !architecture_matches(architectures, architecture)
        || !valid_location(document)
        || !valid_digest(document_sha256)
        || !valid_location(signature)
        || !valid_digest(signature_sha256)
    {
        return Err(ServiceError::Configuration(format!(
            "invalid repository definition: {name}"
        )));
    }
    Ok(())
}

fn validate_store_paths(config: &ServiceConfig) -> Result<(), ServiceError> {
    for (label, path) in [
        ("state", &config.state),
        ("work", &config.work),
        ("artifacts", &config.artifacts),
    ] {
        if !safe_absolute_path(path) || path == Path::new("/") {
            return Err(ServiceError::Configuration(format!(
                "{label} must be a non-root normalized absolute path"
            )));
        }
    }
    if !safe_absolute_path(&config.root) {
        return Err(ServiceError::Configuration(
            "target root must be a normalized absolute path".into(),
        ));
    }
    let paths = [&config.state, &config.work, &config.artifacts];
    for (index, left) in paths.iter().enumerate() {
        for right in paths.iter().skip(index + 1) {
            if left == right || left.starts_with(right) || right.starts_with(left) {
                return Err(ServiceError::Configuration(
                    "state, work, and artifact roots must not overlap".into(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_compiler_policy(policy: &CompilerPolicy) -> Result<(), ServiceError> {
    let allowed = policy
        .allowed_features
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let required = policy
        .required_features
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if policy.architecture == CpuArchitecture::Unknown
        || allowed.is_empty()
        || allowed.len() != policy.allowed_features.len()
        || required.len() != policy.required_features.len()
        || policy
            .allowed_features
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || policy
            .required_features
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || allowed
            .iter()
            .any(|feature| !policy.architecture.supports(*feature))
        || !required.is_subset(&allowed)
    {
        return Err(ServiceError::Configuration(
            "invalid compiler capability policy".into(),
        ));
    }
    Ok(())
}

fn validate_source_catalog(
    catalog: &SourceCatalog,
    repository: &SourceRepository,
    key_id: &str,
    now_unix: u64,
) -> Result<(), ServiceError> {
    if catalog.format != SOURCE_CATALOG_FORMAT
        || catalog.key_id != key_id
        || catalog.name != repository.name
        || catalog.channel != repository.channel
        || catalog.generation != repository.generation
        || catalog.packages.len() > MAX_CATALOG_PACKAGES
    {
        return Err(ServiceError::Provider(format!(
            "{} catalog header differs from signed service metadata",
            repository.name
        )));
    }
    if catalog.expires_unix <= now_unix {
        return Err(ServiceError::Expired(format!(
            "{} source catalog",
            repository.name
        )));
    }
    let mut identities = BTreeSet::new();
    let mut sequences = BTreeSet::new();
    for package in &catalog.packages {
        let identity = (package.name.clone(), package.version.clone());
        if !valid_package_name(&package.name)
            || !valid_version(&package.version)
            || package.release == 0
            || package.sequence == 0
            || !valid_architecture_set(&package.architectures)
            || !identities.insert(identity)
            || !sequences.insert((package.name.clone(), package.sequence))
        {
            return Err(ServiceError::Provider(format!(
                "invalid or duplicate source package: {}",
                package.name
            )));
        }
        for (location, digest) in [
            (&package.ingress_lock, &package.ingress_lock_sha256),
            (
                &package.ingress_signature,
                &package.ingress_signature_sha256,
            ),
            (&package.target_policy, &package.target_policy_sha256),
            (&package.target_signature, &package.target_signature_sha256),
        ] {
            if !valid_location(location) || !valid_digest(digest) {
                return Err(ServiceError::Provider(format!(
                    "invalid source authority object for {}",
                    package.name
                )));
            }
        }
        if !valid_digest(&package.recipe_sha256) || !valid_digest(&package.source_lock_sha256) {
            return Err(ServiceError::Provider(format!(
                "invalid translated recipe digest for {}",
                package.name
            )));
        }
    }
    Ok(())
}

fn validate_service_target(
    target: &RecipeTargetPolicy,
    package: &SourceCatalogPackage,
    architecture: &str,
) -> Result<(), ServiceError> {
    if target.package != package.name
        || target.architecture != architecture
        || target.scope != "system"
        || target.publish_authority != "arach-native"
        || target.hardware.is_some()
        || target.outputs.as_slice() != ["@install-tree"]
        || target.network
        || !target.sandbox
        || !target.reproducible
    {
        return Err(ServiceError::Provider(
            "source target is not an installable native system policy".into(),
        ));
    }
    Ok(())
}

fn choose_candidate(
    mut candidates: Vec<ResolvedPackage>,
    selector: &PackageSelector,
    installed: Option<&ServiceReceipt>,
) -> Result<ResolvedPackage, ServiceError> {
    if let Some(receipt) = installed {
        candidates.retain(|candidate| {
            candidate.provider() == receipt.provider
                && candidate.channel() == receipt.channel
                && candidate.route() == receipt.origin.route_name()
        });
    } else if let Some(namespace) = selector.namespace.as_deref() {
        candidates.retain(|candidate| candidate.namespace_matches(namespace));
    } else if candidates
        .iter()
        .any(|candidate| matches!(candidate, ResolvedPackage::Native(_)))
    {
        candidates.retain(|candidate| matches!(candidate, ResolvedPackage::Native(_)));
    }
    if candidates.is_empty() {
        return Err(ServiceError::PackageNotFound(selector.name.clone()));
    }
    let highest = candidates
        .iter()
        .map(ResolvedPackage::priority)
        .max()
        .ok_or_else(|| ServiceError::PackageNotFound(selector.name.clone()))?;
    candidates.retain(|candidate| candidate.priority() == highest);
    let identities = candidates
        .iter()
        .map(ResolvedPackage::identity)
        .collect::<BTreeSet<_>>();
    if identities.len() != 1 {
        let mut providers = candidates
            .iter()
            .map(|candidate| {
                format!(
                    "{}:{}-{}",
                    candidate.provider(),
                    candidate.package(),
                    candidate.version()
                )
            })
            .collect::<Vec<_>>();
        providers.sort();
        providers.dedup();
        return Err(ServiceError::Ambiguous(providers));
    }
    candidates.sort_by(|left, right| left.provider().cmp(right.provider()));
    Ok(candidates.remove(0))
}

fn enforce_update_floor(
    old: &ServiceReceipt,
    candidate: &ResolvedPackage,
    service_generation: u64,
    service_config_sha256: &str,
) -> Result<(), ServiceError> {
    if candidate.provider() != old.provider
        || candidate.channel() != old.channel
        || candidate.route() != old.origin.route_name()
    {
        return Err(ServiceError::Downgrade(
            "updates must retain the installed provider and channel".into(),
        ));
    }
    if service_generation < old.service_generation
        || candidate.provider_generation() < old.provider_generation
        || candidate.package_sequence() < old.package_sequence
    {
        return Err(ServiceError::Downgrade(format!(
            "{} is older than its installed authority sequence",
            old.package
        )));
    }
    if service_generation == old.service_generation
        && service_config_sha256 != old.service_config_sha256
    {
        return Err(ServiceError::Downgrade(
            "service metadata changed without advancing its generation".into(),
        ));
    }
    let old_authority_sha256 = match &old.origin {
        ServiceOrigin::Native { index_sha256, .. } => index_sha256,
        ServiceOrigin::Source { catalog_sha256, .. } => catalog_sha256,
    };
    if candidate.provider_generation() == old.provider_generation
        && candidate.authority_sha256() != old_authority_sha256
    {
        return Err(ServiceError::Downgrade(
            "provider metadata changed without advancing its generation".into(),
        ));
    }
    Ok(())
}

fn parse_selector(value: &str) -> Result<PackageSelector, ServiceError> {
    if value.is_empty() || value.len() > MAX_VERSION_BYTES + MAX_NAME_BYTES + 2 {
        return Err(ServiceError::Configuration(
            "invalid package selector".into(),
        ));
    }
    let (namespace, package) = value
        .split_once(':')
        .map_or((None, value), |(namespace, package)| {
            (Some(namespace), package)
        });
    let (name, version) = package
        .rsplit_once('@')
        .map_or((package, None), |(name, version)| (name, Some(version)));
    if !valid_package_name(name)
        || namespace.is_some_and(|namespace| !valid_name(namespace))
        || version.is_some_and(|version| !valid_version(version))
    {
        return Err(ServiceError::Configuration(
            "invalid package selector".into(),
        ));
    }
    Ok(PackageSelector {
        namespace: namespace.map(str::to_string),
        name: name.into(),
        version: version.map(str::to_string),
    })
}

fn selector_matches_receipt(
    selector: &PackageSelector,
    receipt: &ServiceReceipt,
    require_version_match: bool,
) -> Result<(), ServiceError> {
    if selector.name != receipt.package
        || (require_version_match
            && selector
                .version
                .as_deref()
                .is_some_and(|version| version != receipt.version))
        || selector.namespace.as_deref().is_some_and(|namespace| {
            namespace != receipt.provider
                && namespace != receipt.origin.route_name()
                && !matches!(&receipt.origin, ServiceOrigin::Source { ecosystem, .. } if ecosystem.name() == namespace)
        })
    {
        return Err(ServiceError::State(
            "package selector differs from installed provider identity".into(),
        ));
    }
    Ok(())
}

fn validate_service_receipt(receipt: &ServiceReceipt) -> Result<(), ServiceError> {
    if receipt.format != SERVICE_RECEIPT_FORMAT
        || !valid_package_name(&receipt.package)
        || !valid_version(&receipt.version)
        || receipt.release == 0
        || !valid_name(&receipt.provider)
        || !valid_name(&receipt.channel)
        || receipt.service_generation == 0
        || receipt.provider_generation == 0
        || !valid_digest(&receipt.service_config_sha256)
        || !valid_digest(&receipt.artifact_sha256)
    {
        return Err(ServiceError::State("invalid service receipt".into()));
    }
    match &receipt.origin {
        ServiceOrigin::Native {
            index_sha256,
            metadata_sha256,
            source_lock_sha256,
        } => {
            if receipt.package_sequence != 0
                || ![index_sha256, metadata_sha256, source_lock_sha256]
                    .into_iter()
                    .all(|digest| valid_digest(digest))
            {
                return Err(ServiceError::State("invalid native service receipt".into()));
            }
        }
        ServiceOrigin::Source {
            catalog_sha256,
            ingress_lock_sha256,
            target_policy_sha256,
            recipe_sha256,
            source_lock_sha256,
            compiler_sha256,
            ..
        } => {
            if receipt.package_sequence == 0
                || ![
                    catalog_sha256,
                    ingress_lock_sha256,
                    target_policy_sha256,
                    recipe_sha256,
                    source_lock_sha256,
                    compiler_sha256,
                ]
                .into_iter()
                .all(|digest| valid_digest(digest))
            {
                return Err(ServiceError::State("invalid source service receipt".into()));
            }
        }
    }
    Ok(())
}

fn validate_journal(journal: &ServiceJournal) -> Result<(), ServiceError> {
    if journal.format != SERVICE_JOURNAL_FORMAT || !valid_package_name(&journal.package) {
        return Err(ServiceError::Transaction("invalid journal header".into()));
    }
    if let Some(old) = &journal.old {
        validate_service_receipt(old)?;
        if old.package != journal.package {
            return Err(ServiceError::Transaction(
                "journal old package differs".into(),
            ));
        }
    }
    if let Some(new) = &journal.new {
        validate_service_receipt(new)?;
        if new.package != journal.package {
            return Err(ServiceError::Transaction(
                "journal new package differs".into(),
            ));
        }
    }
    let valid_shape = match journal.action {
        JournalAction::Install => journal.old.is_none() && journal.new.is_some(),
        JournalAction::Update => journal.old.is_some() && journal.new.is_some(),
        JournalAction::Remove => journal.old.is_some() && journal.new.is_none(),
    };
    if !valid_shape {
        return Err(ServiceError::Transaction(
            "invalid journal transition".into(),
        ));
    }
    Ok(())
}

fn binary_matches_service(binary: &BinaryInstallReceipt, service: &ServiceReceipt) -> bool {
    binary.package == service.package
        && binary.version == service.version
        && binary.release == service.release
        && binary.artifact_sha256 == service.artifact_sha256
}

fn ensure_binary_matches_service(
    binary: &BinaryInstallReceipt,
    service: &ServiceReceipt,
) -> Result<(), ServiceError> {
    if binary_matches_service(binary, service) {
        Ok(())
    } else {
        Err(ServiceError::State(
            "binary ownership and service provenance receipts differ".into(),
        ))
    }
}

fn result_from_receipt(action: &str, receipt: &ServiceReceipt, changed: bool) -> LifecycleResult {
    LifecycleResult {
        action: action.into(),
        package: receipt.package.clone(),
        version: receipt.version.clone(),
        release: receipt.release,
        provider: receipt.provider.clone(),
        route: receipt.origin.route_name().into(),
        artifact_sha256: receipt.artifact_sha256.clone(),
        changed,
    }
}

fn host_compiler_target(policy: &CompilerPolicy) -> Result<CompilerTarget, ServiceError> {
    validate_compiler_policy(policy)?;
    let system = scan_system(Path::new("/sys"));
    if system.cpu.architecture != policy.architecture {
        return Err(ServiceError::Provider(format!(
            "host architecture {:?} differs from signed compiler policy {:?}",
            system.cpu.architecture, policy.architecture
        )));
    }
    let observed = system.cpu.features.iter().copied().collect::<BTreeSet<_>>();
    let required = policy
        .required_features
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let missing = required.difference(&observed).copied().collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(ServiceError::Provider(format!(
            "host is missing signed compiler requirements: {missing:?}"
        )));
    }
    let features = policy
        .allowed_features
        .iter()
        .copied()
        .filter(|feature| observed.contains(feature))
        .collect();
    Ok(CompilerTarget {
        architecture: system.cpu.architecture,
        vendor: system.cpu.vendor,
        family: system.cpu.family,
        model: system.cpu.model,
        stepping: system.cpu.stepping,
        features,
    })
}

fn compiler_digest(compiler: &CompilerTarget) -> Result<String, ServiceError> {
    let bytes =
        toml::to_string(compiler).map_err(|error| ServiceError::Provider(error.to_string()))?;
    Ok(hex_digest(&Sha256::digest(bytes.as_bytes())))
}

fn fetch_resource(
    location: &str,
    expected_sha256: &str,
    maximum: u64,
    cache_root: &Path,
    allow_network: bool,
) -> Result<Vec<u8>, ServiceError> {
    if !valid_location(location) || !valid_digest(expected_sha256) {
        return Err(ServiceError::Resource("invalid resource identity".into()));
    }
    if let Some(path) = local_location(location) {
        let bytes = read_regular(path, maximum)?;
        verify_resource_digest(location, &bytes, expected_sha256)?;
        return Ok(bytes);
    }
    prepare_private_root(cache_root)?;
    let destination = cache_root.join(expected_sha256);
    if destination.exists() {
        let bytes = read_regular(&destination, maximum)?;
        verify_resource_digest(location, &bytes, expected_sha256)?;
        return Ok(bytes);
    }
    if !allow_network {
        return Err(ServiceError::Resource(format!(
            "{location} is not cached and the service is offline"
        )));
    }
    let serial = RESOURCE_SERIAL.fetch_add(1, Ordering::Relaxed);
    let temporary = cache_root.join(format!(
        ".{expected_sha256}.{}.{serial}.download",
        std::process::id()
    ));
    let maximum_text = maximum.to_string();
    let status = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--max-filesize",
            &maximum_text,
            "--output",
        ])
        .arg(&temporary)
        .arg(location)
        .current_dir(cache_root)
        .stdin(Stdio::null())
        .status()
        .map_err(|error| ServiceError::Resource(error.to_string()))?;
    if !status.success() {
        let _ = fs::remove_file(&temporary);
        return Err(ServiceError::Resource(format!(
            "download failed: {location}"
        )));
    }
    let result = (|| {
        let bytes = read_regular(&temporary, maximum)?;
        verify_resource_digest(location, &bytes, expected_sha256)?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
            .map_err(|error| ServiceError::Resource(error.to_string()))?;
        match fs::rename(&temporary, &destination) {
            Ok(()) => {}
            Err(_) if destination.exists() => {
                let _ = fs::remove_file(&temporary);
                let existing = read_regular(&destination, maximum)?;
                verify_resource_digest(location, &existing, expected_sha256)?;
            }
            Err(error) => return Err(ServiceError::Resource(error.to_string())),
        }
        sync_directory(cache_root)?;
        Ok(bytes)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn verify_resource_digest(
    location: &str,
    bytes: &[u8],
    expected_sha256: &str,
) -> Result<(), ServiceError> {
    let actual = hex_digest(&Sha256::digest(bytes));
    if actual != expected_sha256 {
        return Err(ServiceError::Resource(format!(
            "SHA-256 mismatch for {location}: expected {expected_sha256}, got {actual}"
        )));
    }
    Ok(())
}

fn read_regular(path: &Path, maximum: u64) -> Result<Vec<u8>, ServiceError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| ServiceError::Resource(format!("{}: {error}", path.display())))?;
    let metadata = file
        .metadata()
        .map_err(|error| ServiceError::Resource(format!("{}: {error}", path.display())))?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(ServiceError::Resource(format!(
            "{} is not a bounded regular file",
            path.display()
        )));
    }
    let limit = maximum
        .checked_add(1)
        .ok_or_else(|| ServiceError::Resource("resource size limit overflow".into()))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|error| ServiceError::Resource(error.to_string()))?;
    if bytes.len() as u64 > maximum {
        return Err(ServiceError::Resource(format!(
            "{} grew beyond its size limit while being read",
            path.display()
        )));
    }
    Ok(bytes)
}

fn ensure_private_directory(path: &Path) -> Result<(), ServiceError> {
    prepare_private_root(path).map_err(Into::into)
}

fn sync_directory(path: &Path) -> Result<(), ServiceError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| ServiceError::State(error.to_string()))
}

fn local_location(value: &str) -> Option<&Path> {
    value.starts_with('/').then(|| Path::new(value))
}

fn valid_location(value: &str) -> bool {
    if value.starts_with('/') {
        return safe_absolute_path(Path::new(value));
    }
    value.starts_with("https://")
        && value.len() <= 4096
        && !value.contains('@')
        && !value.contains('#')
        && !value.contains('\\')
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        && value.strip_prefix("https://").is_some_and(|rest| {
            !rest.is_empty() && !rest.starts_with('/') && !rest.starts_with('-')
        })
}

fn safe_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

fn valid_architecture_set(values: &[String]) -> bool {
    !values.is_empty()
        && values.len() <= 4
        && values.windows(2).all(|pair| pair[0] < pair[1])
        && values
            .iter()
            .all(|value| matches!(value.as_str(), "any" | "x86-64" | "aarch64" | "riscv64"))
}

fn architecture_matches(values: &[String], architecture: &str) -> bool {
    values
        .iter()
        .any(|value| value == "any" || value == architecture)
}

fn service_architecture(config: &ServiceConfig) -> &'static str {
    match config.compiler.architecture {
        CpuArchitecture::X86_64 => "x86-64",
        CpuArchitecture::Aarch64 => "aarch64",
        CpuArchitecture::Riscv64 => "riscv64",
        CpuArchitecture::Unknown => "unknown",
    }
}

fn valid_package_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_NAME_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_VERSION_BYTES
        && value.bytes().all(|byte| {
            !byte.is_ascii_control()
                && !byte.is_ascii_whitespace()
                && !matches!(byte, b'/' | b'\\' | b':' | b'@')
        })
}

fn valid_name(value: &str) -> bool {
    valid_package_name(value)
}

fn valid_key_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        && value.bytes().any(|byte| byte != b'0')
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
    use crate::binary::{
        BINARY_INDEX_FORMAT, BinaryPackage, BinaryPayloadFile, BinaryRepositoryIndex,
        encode_binary_payload,
    };
    use crate::hardware::{RecipeSource, source_lock_sha256};
    use crate::universal_import::{
        UNIVERSAL_IMPORT_FORMAT, UniversalImportLock, UniversalOrigin,
        serialize_universal_import_lock,
    };
    use alloc::vec;
    use arach_hwd::facts::CpuFeature;
    use arach_hwd::profile::{PackageScope, RepositoryAuthority};
    use arach_hwd::signature::{encode, key_id};
    use ed25519_dalek::{Signer, SigningKey};
    use std::os::unix::fs::DirBuilderExt;

    struct TestRoots {
        root: PathBuf,
        state: PathBuf,
        work: PathBuf,
        artifacts: PathBuf,
        target: PathBuf,
        keyring: PathBuf,
    }

    struct SignedResource {
        path: PathBuf,
        sha256: String,
        signature_path: PathBuf,
        signature_sha256: String,
    }

    fn temporary_roots(label: &str, signing: &SigningKey) -> TestRoots {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "corinth-service-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let target = root.join("target");
        fs::DirBuilder::new().mode(0o755).create(&target).unwrap();
        let keyring = root.join("keys.toml");
        let public = signing.verifying_key().to_bytes();
        fs::write(
            &keyring,
            format!(
                "[[key]]\nid = \"{}\"\npublic_key = \"{}\"\nscope = \"package-index\"\nrevoked = false\n",
                key_id(&public),
                encode(&public)
            ),
        )
        .unwrap();
        TestRoots {
            state: root.join("state"),
            work: root.join("work"),
            artifacts: root.join("artifacts"),
            target,
            keyring,
            root,
        }
    }

    fn signature(signing: &SigningKey, bytes: &[u8]) -> String {
        format!(
            "key_id = \"{}\"\nsignature = \"{}\"\n",
            key_id(&signing.verifying_key().to_bytes()),
            encode(&signing.sign(bytes).to_bytes())
        )
    }

    fn write_signed(root: &Path, name: &str, bytes: &[u8], signing: &SigningKey) -> SignedResource {
        let path = root.join(name);
        let signature_path = root.join(format!("{name}.sig"));
        let signature = signature(signing, bytes);
        fs::write(&path, bytes).unwrap();
        fs::write(&signature_path, signature.as_bytes()).unwrap();
        SignedResource {
            path,
            sha256: hex_digest(&Sha256::digest(bytes)),
            signature_path,
            signature_sha256: hex_digest(&Sha256::digest(signature.as_bytes())),
        }
    }

    fn native_repository(
        roots: &TestRoots,
        signing: &SigningKey,
        generation: u64,
        version: &str,
        contents: &[u8],
    ) -> NativeRepository {
        let metadata_sha256 = "a".repeat(64);
        let source_lock_sha256 = "b".repeat(64);
        let mut package = BinaryPackage {
            name: "demo".into(),
            version: version.into(),
            release: 1,
            scope: PackageScope::System,
            repository: RepositoryAuthority::ArachNative,
            metadata_sha256,
            artifact_sha256: "c".repeat(64),
            source_lock_sha256,
            url: format!("https://packages.example/demo-{version}.pkg"),
            size: 1,
        };
        let payload = encode_binary_payload(
            &package,
            &[BinaryPayloadFile {
                path: "usr/bin/demo".into(),
                mode: 0o755,
                bytes: contents.to_vec(),
            }],
        )
        .unwrap();
        package.artifact_sha256 = hex_digest(&Sha256::digest(&payload));
        package.size = payload.len() as u64;
        let binary_cache = roots.artifacts.join("binary");
        if !binary_cache.exists() {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&binary_cache)
                .unwrap();
        }
        fs::write(binary_cache.join(format!("demo-{version}-1.pkg")), payload).unwrap();
        let index = BinaryRepositoryIndex {
            format: BINARY_INDEX_FORMAT,
            repository: RepositoryAuthority::ArachNative,
            key_id: key_id(&signing.verifying_key().to_bytes()),
            packages: vec![package],
        };
        let bytes = toml::to_string(&index).unwrap().into_bytes();
        let signed = write_signed(
            &roots.root,
            &format!("native-{generation}.toml"),
            &bytes,
            signing,
        );
        NativeRepository {
            name: "stable-native".into(),
            priority: 1000,
            generation,
            channel: "stable".into(),
            architectures: vec!["x86-64".into()],
            index: signed.path.to_string_lossy().into_owned(),
            index_sha256: signed.sha256,
            signature: signed.signature_path.to_string_lossy().into_owned(),
            signature_sha256: signed.signature_sha256,
        }
    }

    fn source_package(root: &Path, suffix: char) -> SourceCatalogPackage {
        let digest = suffix.to_string().repeat(64);
        SourceCatalogPackage {
            name: "demo".into(),
            version: "9.0.0".into(),
            release: 1,
            sequence: 9,
            ecosystem: UniversalEcosystem::Aur,
            architectures: vec!["x86-64".into()],
            ingress_lock: root
                .join(format!("demo-{suffix}.lock"))
                .to_string_lossy()
                .into_owned(),
            ingress_lock_sha256: digest.clone(),
            ingress_signature: root
                .join(format!("demo-{suffix}.lock.sig"))
                .to_string_lossy()
                .into_owned(),
            ingress_signature_sha256: digest.clone(),
            target_policy: root
                .join(format!("demo-{suffix}.target"))
                .to_string_lossy()
                .into_owned(),
            target_policy_sha256: digest.clone(),
            target_signature: root
                .join(format!("demo-{suffix}.target.sig"))
                .to_string_lossy()
                .into_owned(),
            target_signature_sha256: digest.clone(),
            recipe_sha256: digest.clone(),
            source_lock_sha256: digest,
        }
    }

    fn source_repository(
        roots: &TestRoots,
        signing: &SigningKey,
        name: &str,
        priority: i32,
        suffix: char,
    ) -> SourceRepository {
        let catalog = SourceCatalog {
            format: SOURCE_CATALOG_FORMAT,
            key_id: key_id(&signing.verifying_key().to_bytes()),
            name: name.into(),
            channel: "stable".into(),
            generation: 1,
            expires_unix: u64::MAX,
            packages: vec![source_package(&roots.root, suffix)],
        };
        let bytes = toml::to_string(&catalog).unwrap().into_bytes();
        let signed = write_signed(
            &roots.root,
            &format!("{name}.catalog.toml"),
            &bytes,
            signing,
        );
        SourceRepository {
            name: name.into(),
            priority,
            generation: 1,
            channel: "stable".into(),
            architectures: vec!["x86-64".into()],
            catalog: signed.path.to_string_lossy().into_owned(),
            catalog_sha256: signed.sha256,
            signature: signed.signature_path.to_string_lossy().into_owned(),
            signature_sha256: signed.signature_sha256,
        }
    }

    fn cache_git_source(roots: &TestRoots, url: &str, revision: &str, files: &[(&str, &[u8])]) {
        let source = RecipeSource {
            kind: "git".into(),
            url: Some(url.into()),
            revision: Some(revision.into()),
            checksum: None,
            package: None,
            version: None,
            destination: None,
            submodules: false,
        };
        let destination = roots
            .work
            .join("source-build/sources")
            .join(source_lock_sha256(&[source]));
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&destination)
            .unwrap();
        for (relative, bytes) in files {
            let path = destination.join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, bytes).unwrap();
        }
        fs::write(destination.join(".corinth-source-ready"), b"").unwrap();
    }

    fn buildable_source_repository(roots: &TestRoots, signing: &SigningKey) -> SourceRepository {
        let provider_repository = "https://aur.archlinux.org/demo.git";
        let provider_revision = "2".repeat(40);
        let source_repository = "https://example.org/demo.git";
        let source_revision = "1".repeat(40);
        let pkgbuild = format!(
            "pkgname=demo\npkgver=1.0.0\npkgrel=1\npkgdesc='demo service test'\narch=('x86_64')\nlicense=('MIT')\nsource=('git+{source_repository}#commit={source_revision}')\nsha256sums=('SKIP')\ndepends=()\nmakedepends=()\nprovides=()\nconflicts=()\n"
        );
        let upstream = roots.root.join("upstream-metadata");
        fs::create_dir(&upstream).unwrap();
        fs::write(upstream.join("PKGBUILD"), pkgbuild.as_bytes()).unwrap();
        let lock = UniversalImportLock {
            format: UNIVERSAL_IMPORT_FORMAT,
            ecosystem: UniversalEcosystem::Aur,
            package: "demo".into(),
            origin: UniversalOrigin::Git {
                repository: provider_repository.into(),
                revision: provider_revision.clone(),
                metadata_path: "PKGBUILD".into(),
                metadata_sha256: hex_digest(&Sha256::digest(pkgbuild.as_bytes())),
                source_lock_path: None,
                source_lock_sha256: None,
                submodules: false,
            },
        };
        let lock_bytes = serialize_universal_import_lock(&lock).unwrap();
        let signed_lock = write_signed(&roots.root, "demo.lock.toml", &lock_bytes, signing);
        let target_bytes = b"format = 1\npackage = \"demo\"\narchitecture = \"x86-64\"\nscope = \"system\"\npublish_authority = \"arach-native\"\nbuild_system = \"cargo\"\nbuild_commands = [\"cargo install --path . --root .corinth-install/usr --locked --offline\"]\noutputs = [\"@install-tree\"]\nnetwork = false\nsandbox = true\nreproducible = true\n";
        let signed_target = write_signed(&roots.root, "demo.target.toml", target_bytes, signing);
        let target = parse_target_policy(target_bytes).unwrap();
        let imported = import_universal_lock(&lock, Some(&upstream), &target).unwrap();
        let package = SourceCatalogPackage {
            name: "demo".into(),
            version: "1.0.0".into(),
            release: 1,
            sequence: 1,
            ecosystem: UniversalEcosystem::Aur,
            architectures: vec!["x86-64".into()],
            ingress_lock: signed_lock.path.to_string_lossy().into_owned(),
            ingress_lock_sha256: signed_lock.sha256,
            ingress_signature: signed_lock.signature_path.to_string_lossy().into_owned(),
            ingress_signature_sha256: signed_lock.signature_sha256,
            target_policy: signed_target.path.to_string_lossy().into_owned(),
            target_policy_sha256: signed_target.sha256,
            target_signature: signed_target.signature_path.to_string_lossy().into_owned(),
            target_signature_sha256: signed_target.signature_sha256,
            recipe_sha256: imported.recipe.metadata_sha256,
            source_lock_sha256: imported.recipe.source_lock_sha256,
        };
        let catalog = SourceCatalog {
            format: SOURCE_CATALOG_FORMAT,
            key_id: key_id(&signing.verifying_key().to_bytes()),
            name: "buildable-aur".into(),
            channel: "stable".into(),
            generation: 1,
            expires_unix: 4_000_000_000,
            packages: vec![package],
        };
        let catalog_bytes = toml::to_string(&catalog).unwrap().into_bytes();
        let signed_catalog = write_signed(
            &roots.root,
            "buildable-aur.catalog.toml",
            &catalog_bytes,
            signing,
        );
        cache_git_source(
            roots,
            provider_repository,
            &provider_revision,
            &[("PKGBUILD", pkgbuild.as_bytes())],
        );
        let cargo_manifest = b"[package]\nname = \"demo\"\nversion = \"1.0.0\"\nedition = \"2021\"\n\n[[bin]]\nname = \"demo\"\npath = \"src/main.rs\"\n";
        let cargo_lock = b"# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 3\n\n[[package]]\nname = \"demo\"\nversion = \"1.0.0\"\n";
        cache_git_source(
            roots,
            source_repository,
            &source_revision,
            &[
                ("Cargo.toml", cargo_manifest),
                ("Cargo.lock", cargo_lock),
                ("src/main.rs", b"fn main() { println!(\"demo\"); }\n"),
            ],
        );
        SourceRepository {
            name: "buildable-aur".into(),
            priority: 100,
            generation: 1,
            channel: "stable".into(),
            architectures: vec!["x86-64".into()],
            catalog: signed_catalog.path.to_string_lossy().into_owned(),
            catalog_sha256: signed_catalog.sha256,
            signature: signed_catalog.signature_path.to_string_lossy().into_owned(),
            signature_sha256: signed_catalog.signature_sha256,
        }
    }

    fn write_config(
        roots: &TestRoots,
        signing: &SigningKey,
        generation: u64,
        native_repositories: Vec<NativeRepository>,
        source_repositories: Vec<SourceRepository>,
    ) -> (PathBuf, PathBuf) {
        let config = ServiceConfig {
            format: SERVICE_CONFIG_FORMAT,
            key_id: key_id(&signing.verifying_key().to_bytes()),
            generation,
            channel: "stable".into(),
            expires_unix: u64::MAX,
            state: roots.state.clone(),
            work: roots.work.clone(),
            artifacts: roots.artifacts.clone(),
            root: roots.target.clone(),
            allow_network: false,
            compiler: CompilerPolicy {
                architecture: CpuArchitecture::X86_64,
                allowed_features: vec![CpuFeature::Sse2],
                required_features: vec![],
            },
            native_repositories,
            source_repositories,
        };
        let bytes = toml::to_string(&config).unwrap().into_bytes();
        let signed = write_signed(
            &roots.root,
            &format!("service-{generation}.toml"),
            &bytes,
            signing,
        );
        (signed.path, signed.signature_path)
    }

    fn open_service(roots: &TestRoots, config: &Path, signature: &Path) -> PackageService {
        PackageService::open_at(config, signature, &roots.keyring, true, 1).unwrap()
    }

    #[test]
    fn native_resolution_outranks_source_and_lifecycle_is_offline_transactional() {
        let signing = SigningKey::from_bytes(&[31_u8; 32]);
        let roots = temporary_roots("native-lifecycle", &signing);
        let native_v1 = native_repository(&roots, &signing, 1, "1.0.0", b"version-one\n");
        let source = source_repository(&roots, &signing, "curated-aur", 5000, 'd');
        let (config_v1, signature_v1) =
            write_config(&roots, &signing, 1, vec![native_v1], vec![source.clone()]);
        let service_v1 = open_service(&roots, &config_v1, &signature_v1);
        let resolution = service_v1.search("demo").unwrap();
        assert_eq!(
            (resolution.provider.as_str(), resolution.route.as_str()),
            ("stable-native", "native")
        );

        let installed = service_v1.install("demo").unwrap();
        assert!(installed.changed);
        assert_eq!(
            fs::read(roots.target.join("usr/bin/demo")).unwrap(),
            b"version-one\n"
        );

        let native_v2 = native_repository(&roots, &signing, 2, "2.0.0", b"version-two\n");
        let (config_v2, signature_v2) =
            write_config(&roots, &signing, 2, vec![native_v2], vec![source]);
        let service_v2 = open_service(&roots, &config_v2, &signature_v2);
        let updated = service_v2.update("demo@2.0.0").unwrap();
        assert!(updated.changed);
        assert_eq!(updated.version, "2.0.0");
        assert_eq!(
            fs::read(roots.target.join("usr/bin/demo")).unwrap(),
            b"version-two\n"
        );
        assert!(matches!(
            service_v1.update("demo"),
            Err(ServiceError::Downgrade(_))
        ));

        let removed = service_v2.remove("demo").unwrap();
        assert!(removed.changed);
        assert!(!roots.target.join("usr/bin/demo").exists());
        assert!(service_v2.read_service_receipt("demo").unwrap().is_none());
        fs::remove_dir_all(&roots.root).unwrap();
    }

    #[test]
    fn signed_source_catalog_builds_and_installs_through_the_standard_lifecycle() {
        let signing = SigningKey::from_bytes(&[36_u8; 32]);
        let roots = temporary_roots("source-lifecycle", &signing);
        let source = buildable_source_repository(&roots, &signing);
        let (config, signature) = write_config(&roots, &signing, 1, vec![], vec![source]);
        let service = open_service(&roots, &config, &signature);
        let resolution = service.search("demo").unwrap();
        assert_eq!(
            (resolution.provider.as_str(), resolution.route.as_str()),
            ("buildable-aur", "source")
        );
        let installed = service.install("demo").unwrap();
        assert!(installed.changed);
        let executable = roots.target.join("usr/bin/demo");
        assert!(executable.is_file());
        assert!(fs::metadata(&executable).unwrap().permissions().mode() & 0o111 != 0);
        service.remove("demo").unwrap();
        assert!(!executable.exists());
        fs::remove_dir_all(&roots.root).unwrap();
    }

    #[test]
    fn equal_priority_source_collisions_require_an_explicit_provider() {
        let signing = SigningKey::from_bytes(&[32_u8; 32]);
        let roots = temporary_roots("ambiguity", &signing);
        let first = source_repository(&roots, &signing, "first-source", 100, 'd');
        let second = source_repository(&roots, &signing, "second-source", 100, 'e');
        let (config, signature) = write_config(&roots, &signing, 1, vec![], vec![first, second]);
        let service = open_service(&roots, &config, &signature);
        let Err(ServiceError::Ambiguous(providers)) = service.search("demo") else {
            panic!("conflicting providers must not resolve implicitly")
        };
        assert_eq!(providers.len(), 2);
        assert_eq!(
            service.search("first-source:demo").unwrap().provider,
            "first-source"
        );
        fs::remove_dir_all(&roots.root).unwrap();
    }

    #[test]
    fn every_configured_catalog_is_authenticated_before_native_fallback() {
        let signing = SigningKey::from_bytes(&[33_u8; 32]);
        let roots = temporary_roots("catalog-tamper", &signing);
        let native = native_repository(&roots, &signing, 1, "1.0.0", b"native\n");
        let source = source_repository(&roots, &signing, "curated-aur", 1, 'd');
        let catalog_path = PathBuf::from(&source.catalog);
        let (config, signature) = write_config(&roots, &signing, 1, vec![native], vec![source]);
        fs::write(catalog_path, b"tampered\n").unwrap();
        let service = open_service(&roots, &config, &signature);
        assert!(matches!(
            service.search("demo"),
            Err(ServiceError::Resource(_))
        ));
        assert!(!roots.target.join("usr/bin/demo").exists());
        fs::remove_dir_all(&roots.root).unwrap();
    }

    #[test]
    fn failed_target_conflict_leaves_no_service_receipt_or_journal() {
        let signing = SigningKey::from_bytes(&[34_u8; 32]);
        let roots = temporary_roots("conflict", &signing);
        let native = native_repository(&roots, &signing, 1, "1.0.0", b"managed\n");
        let (config, signature) = write_config(&roots, &signing, 1, vec![native], vec![]);
        let service = open_service(&roots, &config, &signature);
        fs::create_dir_all(roots.target.join("usr/bin")).unwrap();
        fs::write(roots.target.join("usr/bin/demo"), b"unmanaged\n").unwrap();
        assert!(service.install("demo").is_err());
        assert_eq!(
            fs::read(roots.target.join("usr/bin/demo")).unwrap(),
            b"unmanaged\n"
        );
        assert!(service.read_service_receipt("demo").unwrap().is_none());
        assert!(!service.journal_path().exists());
        fs::remove_dir_all(&roots.root).unwrap();
    }

    #[test]
    fn interrupted_update_recovers_the_receipt_matching_binary_ownership() {
        let signing = SigningKey::from_bytes(&[35_u8; 32]);
        let roots = temporary_roots("recovery", &signing);
        let native = native_repository(&roots, &signing, 1, "1.0.0", b"installed\n");
        let (config, signature) = write_config(&roots, &signing, 1, vec![native], vec![]);
        let service = open_service(&roots, &config, &signature);
        service.install("demo").unwrap();
        let old = service.read_service_receipt("demo").unwrap().unwrap();
        let mut new = old.clone();
        new.service_generation += 1;
        new.service_config_sha256 = "d".repeat(64);
        new.artifact_sha256 = "e".repeat(64);
        service.write_service_receipt(&new).unwrap();
        service
            .write_journal(&ServiceJournal {
                format: SERVICE_JOURNAL_FORMAT,
                action: JournalAction::Update,
                package: "demo".into(),
                old: Some(old.clone()),
                new: Some(new),
            })
            .unwrap();
        service.recover_pending().unwrap();
        assert_eq!(service.read_service_receipt("demo").unwrap(), Some(old));
        assert!(!service.journal_path().exists());
        fs::remove_dir_all(&roots.root).unwrap();
    }
}
