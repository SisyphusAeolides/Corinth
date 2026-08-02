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
use std::collections::{BTreeMap, BTreeSet};
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
use crate::dependency::{
    DependencyError, PackageCapability, PackageConstraint, PackageRequirement, ResolutionCandidate,
    candidate_satisfies, package_satisfies_constraint, solve_dependency_graph,
    validate_dependency_metadata,
};
use crate::hardware::{
    HardwareError, HardwareProvisioner, atomic_write, metadata_sha256, prepare_private_root,
};
use crate::universal_import::{
    UniversalEcosystem, crates_io_acquisition_source, git_origin, import_universal_lock,
    parse_universal_import_lock,
};

pub const SERVICE_CONFIG_FORMAT: u32 = 1;
pub const LEGACY_SOURCE_CATALOG_FORMAT: u32 = 1;
pub const SOURCE_CATALOG_FORMAT: u32 = 2;
pub const LEGACY_SERVICE_RECEIPT_FORMAT: u32 = 1;
pub const SERVICE_RECEIPT_FORMAT: u32 = 2;
const SERVICE_JOURNAL_FORMAT: u32 = 1;
const SERVICE_GRAPH_JOURNAL_FORMAT: u32 = 1;
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
    #[serde(default)]
    pub requirements: Vec<PackageRequirement>,
    #[serde(default)]
    pub provides: Vec<PackageCapability>,
    #[serde(default)]
    pub conflicts: Vec<PackageConstraint>,
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
    #[serde(default)]
    pub requirements: Vec<PackageRequirement>,
    #[serde(default)]
    pub provides: Vec<PackageCapability>,
    #[serde(default)]
    pub conflicts: Vec<PackageConstraint>,
    pub artifact_sha256: String,
    pub origin: ServiceOrigin,
}

impl ServiceReceipt {
    fn dependency_metadata(&self) -> crate::dependency::DependencyMetadata {
        crate::dependency::DependencyMetadata {
            requirements: self.requirements.clone(),
            provides: self.provides.clone(),
            conflicts: self.conflicts.clone(),
        }
    }

    fn solver_candidate(&self) -> ResolutionCandidate {
        ResolutionCandidate {
            package: self.package.clone(),
            version: self.version.clone(),
            sequence: self.package_sequence,
            metadata: self.dependency_metadata(),
        }
    }
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
    Dependency(String),
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
            Self::Dependency(value) => write!(formatter, "dependency resolution failed: {value}"),
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

impl From<DependencyError> for ServiceError {
    fn from(error: DependencyError) -> Self {
        Self::Dependency(error.to_string())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PackageSelector {
    namespace: Option<String>,
    name: String,
    version: Option<String>,
}

#[derive(Clone)]
enum ResolvedPackage {
    Native(Box<NativeCandidate>),
    Source(Box<SourceCandidate>),
}

#[derive(Clone)]
struct NativeCandidate {
    repository: NativeRepository,
    verified: VerifiedBinaryIndex,
    record_index: usize,
}

#[derive(Clone)]
struct SourceCandidate {
    repository: SourceRepository,
    catalog_sha256: String,
    package: SourceCatalogPackage,
}

struct ResolvedDependencyPlan {
    order: Vec<ResolvedPackage>,
    installed: BTreeMap<String, ServiceReceipt>,
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
            Self::Native(candidate) => candidate.record().sequence,
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
                    "native:{}:{}:{}:{}:{}:{}:{:?}:{:?}:{:?}",
                    package.version,
                    package.release,
                    package.sequence,
                    package.artifact_sha256,
                    package.metadata_sha256,
                    package.source_lock_sha256,
                    package.requirements,
                    package.provides,
                    package.conflicts
                )
            }
            Self::Source(candidate) => format!(
                "source:{}:{}:{}:{}:{}:{}:{}:{:?}:{:?}:{:?}",
                candidate.package.ecosystem.name(),
                candidate.package.version,
                candidate.package.release,
                candidate.package.sequence,
                candidate.package.ingress_lock_sha256,
                candidate.package.target_policy_sha256,
                candidate.package.recipe_sha256,
                candidate.package.requirements,
                candidate.package.provides,
                candidate.package.conflicts
            ),
        }
    }

    fn dependency_metadata(&self) -> crate::dependency::DependencyMetadata {
        match self {
            Self::Native(candidate) => {
                let package = candidate.record();
                crate::dependency::DependencyMetadata {
                    requirements: package.requirements.clone(),
                    provides: package.provides.clone(),
                    conflicts: package.conflicts.clone(),
                }
            }
            Self::Source(candidate) => crate::dependency::DependencyMetadata {
                requirements: candidate.package.requirements.clone(),
                provides: candidate.package.provides.clone(),
                conflicts: candidate.package.conflicts.clone(),
            },
        }
    }

    fn solver_candidate(&self) -> ResolutionCandidate {
        ResolutionCandidate {
            package: self.package().into(),
            version: self.version().into(),
            sequence: self.package_sequence(),
            metadata: self.dependency_metadata(),
        }
    }

    fn graph_key(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            self.route(),
            self.provider(),
            self.package(),
            self.version(),
            self.package_sequence()
        )
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
        self.ensure_removal_safe(&old.package)?;
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
        self.lifecycle_dependency_graph(resolved, old, update, &binary_store)
    }

    fn lifecycle_dependency_graph(
        &self,
        root: ResolvedPackage,
        old: Option<ServiceReceipt>,
        update: bool,
        binary_store: &BinaryInstallStore,
    ) -> Result<LifecycleResult, ServiceError> {
        let root_package = root.package().to_string();
        let plan = self.resolve_dependency_plan(root, update)?;
        let mut entries = Vec::new();
        for candidate in plan.order {
            let package = candidate.package().to_string();
            let previous = if package == root_package {
                old.clone()
            } else {
                plan.installed.get(&package).cloned()
            };
            if package != root_package
                && let Some(receipt) = &previous
            {
                let binary = binary_store.installed_receipt(&package)?.ok_or_else(|| {
                    ServiceError::State(format!(
                        "dependency receipt exists without binary ownership: {package}"
                    ))
                })?;
                ensure_binary_matches_service(&binary, receipt)?;
                continue;
            }
            let prepared = self.prepare_candidate(candidate)?;
            let mutate_binary = previous.as_ref().is_none_or(|receipt| {
                receipt.package != prepared.receipt.package
                    || receipt.version != prepared.receipt.version
                    || receipt.release != prepared.receipt.release
                    || receipt.artifact_sha256 != prepared.receipt.artifact_sha256
            });
            entries.push(PreparedGraphEntry {
                old: previous,
                prepared,
                mutate_binary,
            });
        }
        let root_position = entries
            .iter()
            .position(|entry| entry.prepared.receipt.package == root_package)
            .ok_or_else(|| ServiceError::Dependency("root package was not selected".into()))?;
        let root_entry = entries.remove(root_position);
        entries.push(root_entry);
        let root_receipt = entries
            .last()
            .map(|entry| entry.prepared.receipt.clone())
            .ok_or_else(|| ServiceError::Dependency("dependency plan is empty".into()))?;
        let changed = entries.iter().any(|entry| {
            entry
                .old
                .as_ref()
                .is_none_or(|old| old != &entry.prepared.receipt)
        });
        if !changed {
            return Ok(result_from_receipt(
                if update { "update" } else { "install" },
                &root_receipt,
                false,
            ));
        }

        let journal = ServiceGraphJournal {
            format: SERVICE_GRAPH_JOURNAL_FORMAT,
            action: if update {
                JournalAction::Update
            } else {
                JournalAction::Install
            },
            root: root_package,
            entries: entries
                .iter()
                .map(|entry| ServiceGraphJournalEntry {
                    package: entry.prepared.receipt.package.clone(),
                    old: entry.old.clone(),
                    new: entry.prepared.receipt.clone(),
                })
                .collect(),
        };
        self.write_graph_journal(&journal)?;
        let mut applied = Vec::new();
        let operation = (|| {
            for (index, entry) in entries.iter().enumerate() {
                self.write_service_receipt(&entry.prepared.receipt)?;
                if !entry.mutate_binary {
                    continue;
                }
                match binary_store.install_payload(
                    &entry.prepared.payload,
                    &entry.prepared.receipt.artifact_sha256,
                    entry.old.is_some(),
                ) {
                    Ok(_) => applied.push(index),
                    Err(error) => {
                        let binary =
                            binary_store.installed_receipt(&entry.prepared.receipt.package)?;
                        if binary.as_ref().is_some_and(|binary| {
                            binary_matches_service(binary, &entry.prepared.receipt)
                        }) {
                            applied.push(index);
                            continue;
                        }
                        return Err(ServiceError::from(error));
                    }
                }
            }
            Ok::<(), ServiceError>(())
        })();
        if let Err(error) = operation {
            if let Err(rollback) = self.rollback_graph_entries(&entries, &applied, binary_store) {
                return Err(ServiceError::Transaction(format!(
                    "package graph failed ({error}) and rollback failed: {rollback}"
                )));
            }
            return Err(error);
        }
        self.clear_graph_journal()?;
        Ok(result_from_receipt(
            if update { "update" } else { "install" },
            &root_receipt,
            true,
        ))
    }

    fn rollback_graph_entries(
        &self,
        entries: &[PreparedGraphEntry],
        applied: &[usize],
        binary_store: &BinaryInstallStore,
    ) -> Result<(), ServiceError> {
        for index in applied.iter().rev() {
            let entry = &entries[*index];
            if entry.old.is_some() {
                return Err(ServiceError::Transaction(
                    "a committed graph update cannot be reversed after a later failure".into(),
                ));
            }
            binary_store.remove(&entry.prepared.receipt.package)?;
        }
        for entry in entries {
            if let Some(old) = &entry.old {
                self.write_service_receipt(old)?;
            } else {
                self.remove_service_receipt(&entry.prepared.receipt.package)?;
            }
        }
        self.clear_graph_journal()
    }

    fn resolve(
        &self,
        selector: &PackageSelector,
        installed: Option<&ServiceReceipt>,
    ) -> Result<ResolvedPackage, ServiceError> {
        let mut domain = self.resolve_domain(selector, installed)?;
        domain
            .pop()
            .ok_or_else(|| ServiceError::PackageNotFound(selector.name.clone()))
    }

    fn resolve_domain(
        &self,
        selector: &PackageSelector,
        installed: Option<&ServiceReceipt>,
    ) -> Result<Vec<ResolvedPackage>, ServiceError> {
        let mut candidates = self.collect_candidates(selector)?;
        self.choose_domain(&mut candidates, selector, installed)
    }

    fn resolve_constraint_domain(
        &self,
        constraint: &PackageConstraint,
    ) -> Result<Vec<ResolvedPackage>, ServiceError> {
        let selector = PackageSelector {
            namespace: None,
            name: constraint.name.clone(),
            version: None,
        };
        let mut candidates = self.collect_candidates_for_constraint(constraint)?;
        self.choose_domain(&mut candidates, &selector, None)
    }

    fn resolve_installed_candidate(
        &self,
        receipt: &ServiceReceipt,
    ) -> Result<ResolvedPackage, ServiceError> {
        let selector = PackageSelector {
            namespace: None,
            name: receipt.package.clone(),
            version: Some(receipt.version.clone()),
        };
        self.resolve_domain(&selector, Some(receipt))?
            .into_iter()
            .find(|candidate| {
                candidate.package_sequence() == receipt.package_sequence
                    && candidate.release() == receipt.release
                    && candidate.provider() == receipt.provider
                    && candidate.channel() == receipt.channel
                    && candidate.route() == receipt.origin.route_name()
                    && candidate.dependency_metadata() == receipt.dependency_metadata()
            })
            .ok_or_else(|| {
                ServiceError::State(format!(
                    "installed package is not retained by its signed provider: {}",
                    receipt.package
                ))
            })
    }

    fn ensure_removal_safe(&self, package: &str) -> Result<(), ServiceError> {
        let installed = self.read_all_service_receipts()?;
        let remaining = installed
            .values()
            .filter(|receipt| receipt.package != package)
            .map(ServiceReceipt::solver_candidate)
            .collect::<Vec<_>>();
        for candidate in &remaining {
            for requirement in &candidate.metadata.requirements {
                if !requirement.alternatives.iter().any(|constraint| {
                    remaining
                        .iter()
                        .any(|provider| candidate_satisfies(provider, constraint))
                }) {
                    return Err(ServiceError::Dependency(format!(
                        "cannot remove {package}: required by {}",
                        candidate.package
                    )));
                }
            }
        }
        Ok(())
    }

    fn choose_domain(
        &self,
        candidates: &mut Vec<ResolvedPackage>,
        selector: &PackageSelector,
        installed: Option<&ServiceReceipt>,
    ) -> Result<Vec<ResolvedPackage>, ServiceError> {
        if let Some(receipt) = installed {
            candidates.retain(|candidate| {
                candidate.package() == receipt.package
                    && candidate.provider() == receipt.provider
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

        let mut providers = std::collections::BTreeMap::<String, Vec<ResolvedPackage>>::new();
        for candidate in candidates.drain(..) {
            providers
                .entry(candidate.provider().into())
                .or_default()
                .push(candidate);
        }
        let identities = providers
            .values()
            .map(|domain| {
                let mut identities = domain
                    .iter()
                    .map(ResolvedPackage::identity)
                    .collect::<Vec<_>>();
                identities.sort();
                identities
            })
            .collect::<BTreeSet<_>>();
        if identities.len() != 1 {
            let mut conflicts = providers
                .iter()
                .flat_map(|(provider, domain)| {
                    domain.iter().map(move |candidate| {
                        format!(
                            "{}:{}-{}",
                            provider,
                            candidate.package(),
                            candidate.version()
                        )
                    })
                })
                .collect::<Vec<_>>();
            conflicts.sort();
            conflicts.dedup();
            return Err(ServiceError::Ambiguous(conflicts));
        }
        let provider = providers
            .keys()
            .next()
            .cloned()
            .ok_or_else(|| ServiceError::PackageNotFound(selector.name.clone()))?;
        let mut domain = providers
            .remove(&provider)
            .ok_or_else(|| ServiceError::PackageNotFound(selector.name.clone()))?;
        domain.sort_by(|left, right| {
            left.package_sequence()
                .cmp(&right.package_sequence())
                .then(left.version().cmp(right.version()))
        });
        Ok(domain)
    }

    fn collect_candidates(
        &self,
        selector: &PackageSelector,
    ) -> Result<Vec<ResolvedPackage>, ServiceError> {
        self.collect_candidate_query(selector, None)
    }

    fn collect_candidates_for_constraint(
        &self,
        constraint: &PackageConstraint,
    ) -> Result<Vec<ResolvedPackage>, ServiceError> {
        let selector = PackageSelector {
            namespace: None,
            name: constraint.name.clone(),
            version: None,
        };
        self.collect_candidate_query(&selector, Some(constraint))
    }

    fn collect_candidate_query(
        &self,
        selector: &PackageSelector,
        constraint: Option<&PackageConstraint>,
    ) -> Result<Vec<ResolvedPackage>, ServiceError> {
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
            let record_indexes = verified
                .index
                .packages
                .iter()
                .enumerate()
                .filter(|(_, package)| {
                    package.scope == PackageScope::System
                        && constraint.map_or_else(
                            || {
                                package.name == selector.name
                                    && selector
                                        .version
                                        .as_deref()
                                        .is_none_or(|version| package.version == version)
                            },
                            |constraint| {
                                package_satisfies_constraint(
                                    &package.name,
                                    &package.version,
                                    &package.provides,
                                    constraint,
                                )
                            },
                        )
                })
                .map(|(record_index, _)| record_index)
                .collect::<Vec<_>>();
            for record_index in record_indexes {
                candidates.push(ResolvedPackage::Native(Box::new(NativeCandidate {
                    repository: repository.clone(),
                    verified: verified.clone(),
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
                    architecture_matches(&package.architectures, service_architecture(&self.config))
                        && constraint.map_or_else(
                            || {
                                package.name == selector.name
                                    && selector
                                        .version
                                        .as_deref()
                                        .is_none_or(|version| package.version == version)
                            },
                            |constraint| {
                                package_satisfies_constraint(
                                    &package.name,
                                    &package.version,
                                    &package.provides,
                                    constraint,
                                )
                            },
                        )
                })
                .cloned()
                .collect::<Vec<_>>();
            let catalog_sha256 = hex_digest(&Sha256::digest(&catalog_bytes));
            for package in selected {
                candidates.push(ResolvedPackage::Source(Box::new(SourceCandidate {
                    repository: repository.clone(),
                    catalog_sha256: catalog_sha256.clone(),
                    package,
                })));
            }
        }
        Ok(candidates)
    }

    fn resolve_dependency_plan(
        &self,
        root: ResolvedPackage,
        updating: bool,
    ) -> Result<ResolvedDependencyPlan, ServiceError> {
        let installed = self.read_all_service_receipts()?;
        let root_package = root.package().to_string();
        let mut universe = Vec::new();
        let mut candidate_indexes = BTreeMap::new();
        let root_index = insert_graph_candidate(&mut universe, &mut candidate_indexes, root)?;
        let mut fixed = Vec::new();

        for receipt in installed.values() {
            if updating && receipt.package == root_package {
                continue;
            }
            let candidate = self.resolve_installed_candidate(receipt)?;
            fixed.push(insert_graph_candidate(
                &mut universe,
                &mut candidate_indexes,
                candidate,
            )?);
        }

        let mut cursor = 0usize;
        while cursor < universe.len() {
            let metadata = universe[cursor].dependency_metadata();
            for requirement in metadata.requirements {
                if fixed.iter().any(|candidate| {
                    requirement.alternatives.iter().any(|constraint| {
                        candidate_satisfies(&universe[*candidate].solver_candidate(), constraint)
                    })
                }) {
                    continue;
                }
                for alternative in requirement.alternatives {
                    let domain = match self.resolve_constraint_domain(&alternative) {
                        Ok(domain) => domain,
                        Err(ServiceError::PackageNotFound(_)) => continue,
                        Err(error) => return Err(error),
                    };
                    for candidate in domain {
                        if candidate_satisfies(&candidate.solver_candidate(), &alternative) {
                            insert_graph_candidate(
                                &mut universe,
                                &mut candidate_indexes,
                                candidate,
                            )?;
                        }
                    }
                }
            }
            cursor += 1;
        }

        let solver_candidates = universe
            .iter()
            .map(ResolvedPackage::solver_candidate)
            .collect::<Vec<_>>();
        let plan = solve_dependency_graph(&solver_candidates, root_index, &fixed)?;
        let order = plan
            .order
            .into_iter()
            .map(|candidate| universe[candidate].clone())
            .collect();
        Ok(ResolvedDependencyPlan { order, installed })
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
            package_sequence: package.sequence,
            requirements: package.requirements.clone(),
            provides: package.provides.clone(),
            conflicts: package.conflicts.clone(),
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
        let (binary_receipt, payload) = provisioner.prepare_system_payload(
            &candidate.verified,
            &receipt.package,
            Some(&receipt.version),
        )?;
        if binary_receipt.package != receipt.package
            || binary_receipt.version != receipt.version
            || binary_receipt.release != receipt.release
            || binary_receipt.artifact_sha256 != receipt.artifact_sha256
        {
            return Err(ServiceError::Provider(
                "prepared native payload differs from its service receipt".into(),
            ));
        }
        Ok(PreparedCandidate { receipt, payload })
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
        if !recipe.build.depends.is_empty() {
            return Err(ServiceError::Provider(
                "source build dependencies require an isolated build-root transaction".into(),
            ));
        }
        validate_source_dependency_binding(package, recipe.runtime.as_ref())?;
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
            requirements: package.requirements.clone(),
            provides: package.provides.clone(),
            conflicts: package.conflicts.clone(),
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
        Ok(PreparedCandidate { receipt, payload })
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

    fn read_all_service_receipts(&self) -> Result<BTreeMap<String, ServiceReceipt>, ServiceError> {
        let directory = self.service_receipt_directory();
        ensure_private_directory(&directory)?;
        let mut receipts = BTreeMap::new();
        for entry in
            fs::read_dir(&directory).map_err(|error| ServiceError::State(error.to_string()))?
        {
            let entry = entry.map_err(|error| ServiceError::State(error.to_string()))?;
            let metadata = entry
                .metadata()
                .map_err(|error| ServiceError::State(error.to_string()))?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(ServiceError::State(
                    "service receipt directory contains a non-regular entry".into(),
                ));
            }
            let filename = entry
                .file_name()
                .into_string()
                .map_err(|_| ServiceError::State("service receipt name is not UTF-8".into()))?;
            let package = filename.strip_suffix(".toml").ok_or_else(|| {
                ServiceError::State("service receipt has an invalid filename".into())
            })?;
            if !valid_package_name(package) {
                return Err(ServiceError::State(
                    "service receipt has an invalid package name".into(),
                ));
            }
            let receipt = self.read_service_receipt(package)?.ok_or_else(|| {
                ServiceError::State("service receipt disappeared during enumeration".into())
            })?;
            if receipts.insert(package.into(), receipt).is_some() {
                return Err(ServiceError::State("duplicate service receipt".into()));
            }
        }
        Ok(receipts)
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

    fn graph_journal_path(&self) -> PathBuf {
        self.config.state.join("service-graph-transaction.toml")
    }

    fn write_journal(&self, journal: &ServiceJournal) -> Result<(), ServiceError> {
        validate_journal(journal)?;
        if transaction_file_present(&self.journal_path(), "transaction journal")?
            || transaction_file_present(&self.graph_journal_path(), "graph transaction journal")?
        {
            return Err(ServiceError::Transaction(
                "a package transaction is already pending".into(),
            ));
        }
        let bytes = toml::to_string(journal)
            .map_err(|error| ServiceError::Transaction(error.to_string()))?;
        atomic_write(&self.journal_path(), bytes.as_bytes())?;
        sync_directory(&self.config.state)?;
        Ok(())
    }

    fn write_graph_journal(&self, journal: &ServiceGraphJournal) -> Result<(), ServiceError> {
        validate_graph_journal(journal)?;
        if transaction_file_present(&self.journal_path(), "transaction journal")?
            || transaction_file_present(&self.graph_journal_path(), "graph transaction journal")?
        {
            return Err(ServiceError::Transaction(
                "a package transaction is already pending".into(),
            ));
        }
        let bytes = toml::to_string(journal)
            .map_err(|error| ServiceError::Transaction(error.to_string()))?;
        atomic_write(&self.graph_journal_path(), bytes.as_bytes())?;
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

    fn clear_graph_journal(&self) -> Result<(), ServiceError> {
        match fs::remove_file(self.graph_journal_path()) {
            Ok(()) => sync_directory(&self.config.state),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(ServiceError::Transaction(error.to_string())),
        }
    }

    fn recover_pending(&self) -> Result<(), ServiceError> {
        ensure_private_directory(&self.config.state)?;
        ensure_private_directory(&self.service_receipt_directory())?;
        let single = transaction_file_present(&self.journal_path(), "transaction journal")?;
        let graph =
            transaction_file_present(&self.graph_journal_path(), "graph transaction journal")?;
        match (single, graph) {
            (true, true) => Err(ServiceError::Transaction(
                "multiple package transaction journals are pending".into(),
            )),
            (true, false) => self.recover_single_pending(),
            (false, true) => self.recover_graph_pending(),
            (false, false) => Ok(()),
        }
    }

    fn recover_single_pending(&self) -> Result<(), ServiceError> {
        let path = self.journal_path();
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

    fn recover_graph_pending(&self) -> Result<(), ServiceError> {
        let bytes = read_regular(&self.graph_journal_path(), MAX_SERVICE_DOCUMENT_BYTES)?;
        let journal: ServiceGraphJournal = toml::from_slice(&bytes)
            .map_err(|error| ServiceError::Transaction(error.to_string()))?;
        validate_graph_journal(&journal)?;
        let binary_store =
            BinaryInstallStore::open(self.config.state.clone(), self.config.root.clone())?;
        let ownership = journal
            .entries
            .iter()
            .map(|entry| binary_store.installed_receipt(&entry.package))
            .collect::<Result<Vec<_>, _>>()?;

        if journal
            .entries
            .iter()
            .zip(&ownership)
            .all(|(entry, binary)| {
                binary
                    .as_ref()
                    .is_some_and(|binary| binary_matches_service(binary, &entry.new))
            })
        {
            for entry in &journal.entries {
                self.write_service_receipt(&entry.new)?;
            }
            return self.clear_graph_journal();
        }

        for (index, (entry, binary)) in journal.entries.iter().zip(&ownership).enumerate() {
            let root = index + 1 == journal.entries.len();
            match journal.action {
                JournalAction::Install => {
                    if binary
                        .as_ref()
                        .is_some_and(|receipt| !binary_matches_service(receipt, &entry.new))
                    {
                        return Err(ServiceError::Transaction(format!(
                            "interrupted graph install has foreign ownership: {}",
                            entry.package
                        )));
                    }
                }
                JournalAction::Update if root => {
                    let old = entry.old.as_ref().ok_or_else(|| {
                        ServiceError::Transaction(
                            "graph update root is missing its old receipt".into(),
                        )
                    })?;
                    if !binary
                        .as_ref()
                        .is_some_and(|receipt| binary_matches_service(receipt, old))
                    {
                        return Err(ServiceError::Transaction(
                            "interrupted graph update committed its root without a complete dependency graph"
                                .into(),
                        ));
                    }
                }
                JournalAction::Update => {
                    if binary
                        .as_ref()
                        .is_some_and(|receipt| !binary_matches_service(receipt, &entry.new))
                    {
                        return Err(ServiceError::Transaction(format!(
                            "interrupted graph update has foreign dependency ownership: {}",
                            entry.package
                        )));
                    }
                }
                JournalAction::Remove => {
                    return Err(ServiceError::Transaction(
                        "graph removal journals are unsupported".into(),
                    ));
                }
            }
        }

        for (entry, binary) in journal.entries.iter().zip(&ownership).rev() {
            if entry.old.is_none()
                && binary
                    .as_ref()
                    .is_some_and(|receipt| binary_matches_service(receipt, &entry.new))
            {
                match binary_store.remove(&entry.package) {
                    Ok(()) => {}
                    Err(error) => {
                        if binary_store.installed_receipt(&entry.package)?.is_some() {
                            return Err(ServiceError::Transaction(format!(
                                "failed to roll back graph package {}: {error}",
                                entry.package
                            )));
                        }
                    }
                }
            }
        }
        for entry in &journal.entries {
            if let Some(old) = &entry.old {
                self.write_service_receipt(old)?;
            } else {
                self.remove_service_receipt(&entry.package)?;
            }
        }
        self.clear_graph_journal()
    }
}

struct PreparedCandidate {
    receipt: ServiceReceipt,
    payload: crate::binary::BinaryPayload,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceGraphJournal {
    format: u32,
    action: JournalAction,
    root: String,
    #[serde(rename = "entry")]
    entries: Vec<ServiceGraphJournalEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceGraphJournalEntry {
    package: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    old: Option<ServiceReceipt>,
    new: ServiceReceipt,
}

struct PreparedGraphEntry {
    old: Option<ServiceReceipt>,
    prepared: PreparedCandidate,
    mutate_binary: bool,
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
    if !matches!(
        catalog.format,
        LEGACY_SOURCE_CATALOG_FORMAT | SOURCE_CATALOG_FORMAT
    ) || catalog.key_id != key_id
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
        if (catalog.format == LEGACY_SOURCE_CATALOG_FORMAT
            && (!package.requirements.is_empty()
                || !package.provides.is_empty()
                || !package.conflicts.is_empty()))
            || (catalog.format == SOURCE_CATALOG_FORMAT
                && validate_dependency_metadata(
                    &package.requirements,
                    &package.provides,
                    &package.conflicts,
                )
                .is_err())
        {
            return Err(ServiceError::Provider(format!(
                "invalid source dependency metadata: {}",
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

fn validate_source_dependency_binding(
    package: &SourceCatalogPackage,
    runtime: Option<&crate::hardware::RecipeRuntime>,
) -> Result<(), ServiceError> {
    let empty = crate::hardware::RecipeRuntime::default();
    let runtime = runtime.unwrap_or(&empty);
    for dependency in &runtime.depends {
        if !package.requirements.iter().any(|requirement| {
            requirement
                .alternatives
                .iter()
                .any(|alternative| alternative.name == *dependency)
        }) {
            return Err(ServiceError::Provider(format!(
                "source catalog omits recipe dependency: {dependency}"
            )));
        }
    }
    if package.requirements.iter().any(|requirement| {
        !requirement.alternatives.iter().any(|alternative| {
            runtime
                .depends
                .iter()
                .any(|dependency| dependency == &alternative.name)
        })
    }) {
        return Err(ServiceError::Provider(
            "source catalog dependency has no recipe counterpart".into(),
        ));
    }
    let catalog_provides = package
        .provides
        .iter()
        .map(|capability| capability.name.as_str())
        .collect::<BTreeSet<_>>();
    let recipe_provides = runtime
        .provides
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let catalog_conflicts = package
        .conflicts
        .iter()
        .map(|constraint| constraint.name.as_str())
        .collect::<BTreeSet<_>>();
    let recipe_conflicts = runtime
        .conflicts
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if catalog_provides != recipe_provides || catalog_conflicts != recipe_conflicts {
        return Err(ServiceError::Provider(
            "source catalog capabilities or conflicts differ from the recipe".into(),
        ));
    }
    Ok(())
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
    if candidate.package_sequence() == old.package_sequence
        && !candidate_record_matches_receipt(candidate, old)
    {
        return Err(ServiceError::Downgrade(
            "package identity changed without advancing its sequence".into(),
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

fn candidate_record_matches_receipt(candidate: &ResolvedPackage, receipt: &ServiceReceipt) -> bool {
    if candidate.package() != receipt.package
        || candidate.version() != receipt.version
        || candidate.release() != receipt.release
        || candidate.package_sequence() != receipt.package_sequence
        || candidate.dependency_metadata() != receipt.dependency_metadata()
    {
        return false;
    }
    match (candidate, &receipt.origin) {
        (
            ResolvedPackage::Native(candidate),
            ServiceOrigin::Native {
                metadata_sha256,
                source_lock_sha256,
                ..
            },
        ) => {
            let package = candidate.record();
            package.artifact_sha256 == receipt.artifact_sha256
                && package.metadata_sha256 == metadata_sha256.as_str()
                && package.source_lock_sha256 == source_lock_sha256.as_str()
        }
        (
            ResolvedPackage::Source(candidate),
            ServiceOrigin::Source {
                ecosystem,
                ingress_lock_sha256,
                target_policy_sha256,
                recipe_sha256,
                source_lock_sha256,
                ..
            },
        ) => {
            candidate.package.ecosystem == *ecosystem
                && candidate.package.ingress_lock_sha256 == ingress_lock_sha256.as_str()
                && candidate.package.target_policy_sha256 == target_policy_sha256.as_str()
                && candidate.package.recipe_sha256 == recipe_sha256.as_str()
                && candidate.package.source_lock_sha256 == source_lock_sha256.as_str()
        }
        _ => false,
    }
}

fn insert_graph_candidate(
    universe: &mut Vec<ResolvedPackage>,
    indexes: &mut BTreeMap<String, usize>,
    candidate: ResolvedPackage,
) -> Result<usize, ServiceError> {
    let key = candidate.graph_key();
    if let Some(index) = indexes.get(&key) {
        return Ok(*index);
    }
    if universe.len() >= crate::alchemist::MAX_PACKAGES {
        return Err(ServiceError::Dependency(format!(
            "candidate closure exceeds {} records",
            crate::alchemist::MAX_PACKAGES
        )));
    }
    let index = universe.len();
    universe.push(candidate);
    indexes.insert(key, index);
    Ok(index)
}

fn parse_selector(value: &str) -> Result<PackageSelector, ServiceError> {
    if value.is_empty() || value.len() > MAX_VERSION_BYTES + MAX_NAME_BYTES + 2 {
        return Err(ServiceError::Configuration(
            "invalid package selector".into(),
        ));
    }
    let (qualified, version) = value
        .rsplit_once('@')
        .map_or((value, None), |(name, version)| (name, Some(version)));
    let (namespace, name) = qualified
        .split_once(':')
        .map_or((None, qualified), |(namespace, package)| {
            (Some(namespace), package)
        });
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
    if !matches!(
        receipt.format,
        LEGACY_SERVICE_RECEIPT_FORMAT | SERVICE_RECEIPT_FORMAT
    ) || !valid_package_name(&receipt.package)
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
    if (receipt.format == LEGACY_SERVICE_RECEIPT_FORMAT
        && (!receipt.requirements.is_empty()
            || !receipt.provides.is_empty()
            || !receipt.conflicts.is_empty()))
        || (receipt.format == SERVICE_RECEIPT_FORMAT
            && validate_dependency_metadata(
                &receipt.requirements,
                &receipt.provides,
                &receipt.conflicts,
            )
            .is_err())
    {
        return Err(ServiceError::State(
            "invalid service receipt dependency metadata".into(),
        ));
    }
    match &receipt.origin {
        ServiceOrigin::Native {
            index_sha256,
            metadata_sha256,
            source_lock_sha256,
        } => {
            if ![index_sha256, metadata_sha256, source_lock_sha256]
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

fn validate_graph_journal(journal: &ServiceGraphJournal) -> Result<(), ServiceError> {
    if journal.format != SERVICE_GRAPH_JOURNAL_FORMAT
        || !valid_package_name(&journal.root)
        || journal.entries.is_empty()
        || journal.entries.len() > crate::alchemist::MAX_PACKAGES
        || matches!(journal.action, JournalAction::Remove)
    {
        return Err(ServiceError::Transaction(
            "invalid graph journal header".into(),
        ));
    }
    let mut packages = BTreeSet::new();
    for (index, entry) in journal.entries.iter().enumerate() {
        if !valid_package_name(&entry.package) || !packages.insert(entry.package.clone()) {
            return Err(ServiceError::Transaction(
                "graph journal package identities are invalid or duplicated".into(),
            ));
        }
        validate_service_receipt(&entry.new)?;
        if entry.new.package != entry.package {
            return Err(ServiceError::Transaction(
                "graph journal new package differs".into(),
            ));
        }
        if let Some(old) = &entry.old {
            validate_service_receipt(old)?;
            if old.package != entry.package {
                return Err(ServiceError::Transaction(
                    "graph journal old package differs".into(),
                ));
            }
        }
        let root = index + 1 == journal.entries.len();
        let valid_shape = match journal.action {
            JournalAction::Install => entry.old.is_none(),
            JournalAction::Update => root == entry.old.is_some(),
            JournalAction::Remove => false,
        };
        if !valid_shape {
            return Err(ServiceError::Transaction(
                "invalid graph journal transition".into(),
            ));
        }
    }
    if journal
        .entries
        .last()
        .is_none_or(|entry| entry.package != journal.root)
    {
        return Err(ServiceError::Transaction(
            "graph journal root is not the final entry".into(),
        ));
    }
    Ok(())
}

fn transaction_file_present(path: &Path, label: &str) -> Result<bool, ServiceError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => Err(
            ServiceError::Transaction(format!("{label} is not a regular file")),
        ),
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(ServiceError::Transaction(error.to_string())),
    }
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
                && !matches!(byte, b'/' | b'\\' | b'@')
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
        native_repository_versions(
            roots,
            signing,
            generation,
            vec![(version, generation, contents)],
        )
    }

    struct NativePackageFixture {
        name: String,
        version: String,
        sequence: u64,
        contents: Vec<u8>,
        requirements: Vec<PackageRequirement>,
        provides: Vec<PackageCapability>,
        conflicts: Vec<PackageConstraint>,
    }

    fn native_package(
        name: &str,
        version: &str,
        sequence: u64,
        contents: &[u8],
    ) -> NativePackageFixture {
        NativePackageFixture {
            name: name.into(),
            version: version.into(),
            sequence,
            contents: contents.into(),
            requirements: Vec::new(),
            provides: Vec::new(),
            conflicts: Vec::new(),
        }
    }

    fn native_repository_versions(
        roots: &TestRoots,
        signing: &SigningKey,
        generation: u64,
        records: Vec<(&str, u64, &[u8])>,
    ) -> NativeRepository {
        native_repository_packages(
            roots,
            signing,
            generation,
            records
                .into_iter()
                .map(|(version, sequence, contents)| {
                    native_package("demo", version, sequence, contents)
                })
                .collect(),
        )
    }

    fn native_repository_packages(
        roots: &TestRoots,
        signing: &SigningKey,
        generation: u64,
        records: Vec<NativePackageFixture>,
    ) -> NativeRepository {
        let metadata_sha256 = "a".repeat(64);
        let source_lock_sha256 = "b".repeat(64);
        let binary_cache = roots.artifacts.join("binary");
        if !binary_cache.exists() {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&binary_cache)
                .unwrap();
        }
        let mut packages = Vec::with_capacity(records.len());
        for record in records {
            let NativePackageFixture {
                name,
                version,
                sequence,
                contents,
                requirements,
                provides,
                conflicts,
            } = record;
            let url = format!("https://packages.example/{name}-{version}.pkg");
            let mut package = BinaryPackage {
                name,
                version,
                release: 1,
                sequence,
                requirements,
                provides,
                conflicts,
                scope: PackageScope::System,
                repository: RepositoryAuthority::ArachNative,
                metadata_sha256: metadata_sha256.clone(),
                artifact_sha256: "c".repeat(64),
                source_lock_sha256: source_lock_sha256.clone(),
                url,
                size: 1,
            };
            let payload = encode_binary_payload(
                &package,
                &[BinaryPayloadFile {
                    path: format!("usr/bin/{}", package.name),
                    mode: 0o755,
                    bytes: contents,
                }],
            )
            .unwrap();
            package.artifact_sha256 = hex_digest(&Sha256::digest(&payload));
            package.size = payload.len() as u64;
            fs::write(
                binary_cache.join(format!("{}-{}-1.pkg", package.name, package.version)),
                payload,
            )
            .unwrap();
            packages.push(package);
        }
        let index = BinaryRepositoryIndex {
            format: BINARY_INDEX_FORMAT,
            repository: RepositoryAuthority::ArachNative,
            key_id: key_id(&signing.verifying_key().to_bytes()),
            packages,
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
            requirements: Vec::new(),
            provides: Vec::new(),
            conflicts: Vec::new(),
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
        buildable_source_repository_with_dependency(roots, signing, None)
    }

    fn buildable_source_repository_with_dependency(
        roots: &TestRoots,
        signing: &SigningKey,
        dependency: Option<&str>,
    ) -> SourceRepository {
        let provider_repository = "https://aur.archlinux.org/demo.git";
        let provider_revision = "2".repeat(40);
        let source_repository = "https://example.org/demo.git";
        let source_revision = "1".repeat(40);
        let depends = dependency.map_or_else(|| "()".into(), |name| format!("('{name}')"));
        let pkgbuild = format!(
            "pkgname=demo\npkgver=1.0.0\npkgrel=1\npkgdesc='demo service test'\narch=('x86_64')\nlicense=('MIT')\nsource=('git+{source_repository}#commit={source_revision}')\nsha256sums=('SKIP')\ndepends={depends}\nmakedepends=()\nprovides=()\nconflicts=()\n"
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
            requirements: dependency
                .map(crate::dependency::package_requirement)
                .into_iter()
                .collect(),
            provides: Vec::new(),
            conflicts: Vec::new(),
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

    fn buildable_fedora_source_repository(
        roots: &TestRoots,
        signing: &SigningKey,
    ) -> SourceRepository {
        let provider_repository = "https://src.fedoraproject.org/rpms/demo.git";
        let provider_revision = "3".repeat(40);
        let source_repository = "https://example.org/demo.git";
        let source_revision = "1".repeat(40);
        let spec = format!(
            "Name: demo\nVersion: 1.0.0\nRelease: 1\nSummary: demo service test\nLicense: MIT\nExclusiveArch: x86_64\nRequires: runtime-lib\nSource0: {source_repository}\n%description\ndemo\n"
        );
        let source_lock = format!(
            "format = 1\n\n[package]\nname = \"demo\"\nversion = \"1.0.0\"\nrelease = 1\nsummary = \"demo service test\"\nlicense = \"MIT\"\narchitectures = [\"x86-64\"]\ndepends = [\"runtime-lib\"]\nmakedepends = []\nprovides = []\nconflicts = []\n\n[[source]]\nkind = \"git\"\nurl = \"{source_repository}\"\nrevision = \"{source_revision}\"\n"
        );
        let upstream = roots.root.join("fedora-upstream-metadata");
        fs::create_dir(&upstream).unwrap();
        fs::write(upstream.join("demo.spec"), spec.as_bytes()).unwrap();
        fs::write(upstream.join("sources.toml"), source_lock.as_bytes()).unwrap();
        let lock = UniversalImportLock {
            format: UNIVERSAL_IMPORT_FORMAT,
            ecosystem: UniversalEcosystem::Fedora,
            package: "demo".into(),
            origin: UniversalOrigin::Git {
                repository: provider_repository.into(),
                revision: provider_revision.clone(),
                metadata_path: "demo.spec".into(),
                metadata_sha256: hex_digest(&Sha256::digest(spec.as_bytes())),
                source_lock_path: Some("sources.toml".into()),
                source_lock_sha256: Some(hex_digest(&Sha256::digest(source_lock.as_bytes()))),
                submodules: false,
            },
        };
        let lock_bytes = serialize_universal_import_lock(&lock).unwrap();
        let signed_lock = write_signed(&roots.root, "demo-fedora.lock.toml", &lock_bytes, signing);
        let target_bytes = b"format = 1\npackage = \"demo\"\narchitecture = \"x86-64\"\nscope = \"system\"\npublish_authority = \"arach-native\"\nbuild_system = \"cargo\"\nbuild_commands = [\"cargo install --path . --root .corinth-install/usr --locked --offline\"]\noutputs = [\"@install-tree\"]\nnetwork = false\nsandbox = true\nreproducible = true\n";
        let signed_target = write_signed(
            &roots.root,
            "demo-fedora.target.toml",
            target_bytes,
            signing,
        );
        let target = parse_target_policy(target_bytes).unwrap();
        let imported = import_universal_lock(&lock, Some(&upstream), &target).unwrap();
        let package = SourceCatalogPackage {
            name: "demo".into(),
            version: "1.0.0".into(),
            release: 1,
            sequence: 1,
            requirements: vec![crate::dependency::package_requirement("runtime-lib")],
            provides: Vec::new(),
            conflicts: Vec::new(),
            ecosystem: UniversalEcosystem::Fedora,
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
            name: "buildable-fedora".into(),
            channel: "stable".into(),
            generation: 1,
            expires_unix: 4_000_000_000,
            packages: vec![package],
        };
        let catalog_bytes = toml::to_string(&catalog).unwrap().into_bytes();
        let signed_catalog = write_signed(
            &roots.root,
            "buildable-fedora.catalog.toml",
            &catalog_bytes,
            signing,
        );
        cache_git_source(
            roots,
            provider_repository,
            &provider_revision,
            &[
                ("demo.spec", spec.as_bytes()),
                ("sources.toml", source_lock.as_bytes()),
            ],
        );
        let cargo_manifest = b"[package]\nname = \"demo\"\nversion = \"1.0.0\"\nedition = \"2021\"\n\n[[bin]]\nname = \"demo\"\npath = \"src/main.rs\"\n";
        let cargo_lock = b"version = 3\n\n[[package]]\nname = \"demo\"\nversion = \"1.0.0\"\n";
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
            name: "buildable-fedora".into(),
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
    fn selectors_preserve_provider_names_and_foreign_version_epochs() {
        let selector = parse_selector("stable-native:demo@2:1.4.0~rc1-3.fc44").unwrap();
        assert_eq!(selector.namespace.as_deref(), Some("stable-native"));
        assert_eq!(selector.name, "demo");
        assert_eq!(selector.version.as_deref(), Some("2:1.4.0~rc1-3.fc44"));
        assert!(parse_selector("demo@bad version").is_err());
        assert!(parse_selector("demo@bad/path").is_err());
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
    fn native_exact_install_and_default_update_use_monotonic_sequence() {
        let signing = SigningKey::from_bytes(&[37_u8; 32]);
        let roots = temporary_roots("native-multiversion", &signing);
        let native = native_repository_versions(
            &roots,
            &signing,
            1,
            vec![
                ("1.0.0", 10, b"pinned-old\n"),
                ("2.0.0", 20, b"default-new\n"),
            ],
        );
        let (config, signature) = write_config(&roots, &signing, 1, vec![native], vec![]);
        let service = open_service(&roots, &config, &signature);

        let resolution = service.search("demo").unwrap();
        assert_eq!(
            (resolution.version.as_str(), resolution.package_sequence),
            ("2.0.0", 20)
        );
        let installed = service.install("demo@1.0.0").unwrap();
        assert_eq!(installed.version, "1.0.0");
        assert_eq!(
            service
                .read_service_receipt("demo")
                .unwrap()
                .unwrap()
                .package_sequence,
            10
        );
        assert_eq!(
            fs::read(roots.target.join("usr/bin/demo")).unwrap(),
            b"pinned-old\n"
        );

        let updated = service.update("demo").unwrap();
        assert_eq!(updated.version, "2.0.0");
        assert_eq!(
            service
                .read_service_receipt("demo")
                .unwrap()
                .unwrap()
                .package_sequence,
            20
        );
        assert_eq!(
            fs::read(roots.target.join("usr/bin/demo")).unwrap(),
            b"default-new\n"
        );
        assert!(matches!(
            service.update("demo@1.0.0"),
            Err(ServiceError::Downgrade(_))
        ));
        service.remove("demo").unwrap();
        fs::remove_dir_all(&roots.root).unwrap();
    }

    #[test]
    fn standard_install_resolves_and_commits_a_native_dependency_graph() {
        let signing = SigningKey::from_bytes(&[40_u8; 32]);
        let roots = temporary_roots("native-graph", &signing);
        let mut app = native_package("app", "1.0.0", 1, b"application\n");
        app.requirements = vec![crate::dependency::package_requirement("runtime-lib")];
        let runtime = native_package("runtime-lib", "2.0.0", 2, b"runtime\n");
        let repository = native_repository_packages(&roots, &signing, 1, vec![app, runtime]);
        let (config, signature) = write_config(&roots, &signing, 1, vec![repository], vec![]);
        let service = open_service(&roots, &config, &signature);

        let installed = service.install("app").unwrap();
        assert_eq!(installed.package, "app");
        assert_eq!(
            fs::read(roots.target.join("usr/bin/app")).unwrap(),
            b"application\n"
        );
        assert_eq!(
            fs::read(roots.target.join("usr/bin/runtime-lib")).unwrap(),
            b"runtime\n"
        );
        assert!(service.read_service_receipt("app").unwrap().is_some());
        assert!(
            service
                .read_service_receipt("runtime-lib")
                .unwrap()
                .is_some()
        );
        assert!(!service.graph_journal_path().exists());

        assert!(matches!(
            service.remove("runtime-lib"),
            Err(ServiceError::Dependency(_))
        ));
        assert!(roots.target.join("usr/bin/runtime-lib").exists());
        service.remove("app").unwrap();
        assert!(!roots.target.join("usr/bin/app").exists());
        assert!(roots.target.join("usr/bin/runtime-lib").exists());
        service.remove("runtime-lib").unwrap();
        fs::remove_dir_all(&roots.root).unwrap();
    }

    #[test]
    fn standard_update_adds_missing_dependencies_before_replacing_the_root() {
        let signing = SigningKey::from_bytes(&[48_u8; 32]);
        let roots = temporary_roots("native-graph-update", &signing);
        let repository_v1 = native_repository_packages(
            &roots,
            &signing,
            1,
            vec![native_package("app", "1.0.0", 1, b"version-one\n")],
        );
        let (config_v1, signature_v1) =
            write_config(&roots, &signing, 1, vec![repository_v1], vec![]);
        let service_v1 = open_service(&roots, &config_v1, &signature_v1);
        service_v1.install("app").unwrap();

        let mut app_v2 = native_package("app", "2.0.0", 2, b"version-two\n");
        app_v2.requirements = vec![crate::dependency::package_requirement("runtime-lib")];
        let runtime = native_package("runtime-lib", "1.0.0", 1, b"runtime\n");
        let repository_v2 = native_repository_packages(&roots, &signing, 2, vec![app_v2, runtime]);
        let (config_v2, signature_v2) =
            write_config(&roots, &signing, 2, vec![repository_v2], vec![]);
        let service_v2 = open_service(&roots, &config_v2, &signature_v2);

        let updated = service_v2.update("app").unwrap();
        assert_eq!(updated.version, "2.0.0");
        assert_eq!(
            fs::read(roots.target.join("usr/bin/runtime-lib")).unwrap(),
            b"runtime\n"
        );
        assert_eq!(
            fs::read(roots.target.join("usr/bin/app")).unwrap(),
            b"version-two\n"
        );
        assert!(!service_v2.graph_journal_path().exists());
        service_v2.remove("app").unwrap();
        service_v2.remove("runtime-lib").unwrap();
        fs::remove_dir_all(&roots.root).unwrap();
    }

    #[test]
    fn update_rejects_dependency_metadata_rewrite_without_a_new_package_sequence() {
        let signing = SigningKey::from_bytes(&[53_u8; 32]);
        let roots = temporary_roots("native-dependency-rewrite", &signing);
        let mut app_v1 = native_package("app", "1.0.0", 1, b"application\n");
        app_v1.requirements = vec![crate::dependency::package_requirement("runtime-lib")];
        let runtime_v1 = native_package("runtime-lib", "1.0.0", 1, b"runtime\n");
        let repository_v1 =
            native_repository_packages(&roots, &signing, 1, vec![app_v1, runtime_v1]);
        let (config_v1, signature_v1) =
            write_config(&roots, &signing, 1, vec![repository_v1], vec![]);
        let service_v1 = open_service(&roots, &config_v1, &signature_v1);
        service_v1.install("app").unwrap();

        let mut rewritten = native_package("app", "1.0.0", 1, b"application\n");
        rewritten.requirements = vec![crate::dependency::package_requirement("other-runtime")];
        let runtime_v2 = native_package("runtime-lib", "1.0.0", 1, b"runtime\n");
        let other = native_package("other-runtime", "1.0.0", 1, b"other\n");
        let repository_v2 =
            native_repository_packages(&roots, &signing, 2, vec![rewritten, runtime_v2, other]);
        let (config_v2, signature_v2) =
            write_config(&roots, &signing, 2, vec![repository_v2], vec![]);
        let service_v2 = open_service(&roots, &config_v2, &signature_v2);

        assert!(matches!(
            service_v2.update("app"),
            Err(ServiceError::Downgrade(_))
        ));
        assert_eq!(
            fs::read(roots.target.join("usr/bin/app")).unwrap(),
            b"application\n"
        );
        assert!(roots.target.join("usr/bin/runtime-lib").exists());
        assert!(!roots.target.join("usr/bin/other-runtime").exists());
        assert!(!service_v2.graph_journal_path().exists());
        fs::remove_dir_all(&roots.root).unwrap();
    }

    #[test]
    fn dependency_graph_discovers_an_exact_virtual_capability_provider() {
        let signing = SigningKey::from_bytes(&[41_u8; 32]);
        let roots = temporary_roots("native-capability", &signing);
        let mut app = native_package("app", "1.0.0", 1, b"application\n");
        app.requirements = vec![PackageRequirement {
            alternatives: vec![PackageConstraint {
                name: "ssl-api".into(),
                versions: vec!["3".into()],
            }],
        }];
        let mut openssl = native_package("openssl", "3.4.0", 3, b"openssl\n");
        openssl.provides = vec![PackageCapability {
            name: "ssl-api".into(),
            version: Some("3".into()),
        }];
        let mut incompatible = native_package("other-tls", "4.0.0", 4, b"other\n");
        incompatible.provides = vec![PackageCapability {
            name: "ssl-api".into(),
            version: Some("4".into()),
        }];
        let repository =
            native_repository_packages(&roots, &signing, 1, vec![app, openssl, incompatible]);
        let (config, signature) = write_config(&roots, &signing, 1, vec![repository], vec![]);
        let service = open_service(&roots, &config, &signature);

        service.install("app").unwrap();
        assert!(roots.target.join("usr/bin/openssl").exists());
        assert!(!roots.target.join("usr/bin/other-tls").exists());
        assert!(service.read_service_receipt("openssl").unwrap().is_some());
        fs::remove_dir_all(&roots.root).unwrap();
    }

    #[test]
    fn dependency_graph_honors_exact_foreign_versions_instead_of_latest_sequence() {
        let signing = SigningKey::from_bytes(&[52_u8; 32]);
        let roots = temporary_roots("native-exact-dependency", &signing);
        let required_version = "1:1.0~rc1-1";
        let mut app = native_package("app", "1.0.0", 1, b"application\n");
        app.requirements = vec![PackageRequirement {
            alternatives: vec![PackageConstraint {
                name: "runtime-lib".into(),
                versions: vec![required_version.into()],
            }],
        }];
        let required = native_package("runtime-lib", required_version, 1, b"required\n");
        let latest = native_package("runtime-lib", "2.0.0", 2, b"latest\n");
        let repository =
            native_repository_packages(&roots, &signing, 1, vec![app, required, latest]);
        let (config, signature) = write_config(&roots, &signing, 1, vec![repository], vec![]);
        let service = open_service(&roots, &config, &signature);

        service.install("app").unwrap();
        assert_eq!(
            service
                .read_service_receipt("runtime-lib")
                .unwrap()
                .unwrap()
                .version,
            required_version
        );
        assert_eq!(
            fs::read(roots.target.join("usr/bin/runtime-lib")).unwrap(),
            b"required\n"
        );
        fs::remove_dir_all(&roots.root).unwrap();
    }

    #[test]
    fn installed_package_conflicts_block_a_later_standard_install() {
        let signing = SigningKey::from_bytes(&[42_u8; 32]);
        let roots = temporary_roots("native-conflict", &signing);
        let mut legacy = native_package("legacy", "1.0.0", 1, b"legacy\n");
        legacy.conflicts = vec![PackageConstraint {
            name: "app".into(),
            versions: Vec::new(),
        }];
        let app = native_package("app", "1.0.0", 1, b"application\n");
        let repository = native_repository_packages(&roots, &signing, 1, vec![legacy, app]);
        let (config, signature) = write_config(&roots, &signing, 1, vec![repository], vec![]);
        let service = open_service(&roots, &config, &signature);

        service.install("legacy").unwrap();
        assert!(matches!(
            service.install("app"),
            Err(ServiceError::Dependency(_))
        ));
        assert!(!roots.target.join("usr/bin/app").exists());
        assert!(service.read_service_receipt("app").unwrap().is_none());
        assert!(!service.graph_journal_path().exists());
        fs::remove_dir_all(&roots.root).unwrap();
    }

    #[test]
    fn dependency_cycles_fail_before_any_target_mutation() {
        let signing = SigningKey::from_bytes(&[43_u8; 32]);
        let roots = temporary_roots("native-cycle", &signing);
        let mut alpha = native_package("alpha", "1.0.0", 1, b"alpha\n");
        alpha.requirements = vec![crate::dependency::package_requirement("beta")];
        let mut beta = native_package("beta", "1.0.0", 1, b"beta\n");
        beta.requirements = vec![crate::dependency::package_requirement("alpha")];
        let repository = native_repository_packages(&roots, &signing, 1, vec![alpha, beta]);
        let (config, signature) = write_config(&roots, &signing, 1, vec![repository], vec![]);
        let service = open_service(&roots, &config, &signature);

        assert!(matches!(
            service.install("alpha"),
            Err(ServiceError::Dependency(_))
        ));
        assert!(!roots.target.join("usr/bin/alpha").exists());
        assert!(!roots.target.join("usr/bin/beta").exists());
        assert!(service.read_all_service_receipts().unwrap().is_empty());
        assert!(!service.graph_journal_path().exists());
        fs::remove_dir_all(&roots.root).unwrap();
    }

    #[test]
    fn failed_graph_root_install_rolls_back_new_dependencies() {
        let signing = SigningKey::from_bytes(&[44_u8; 32]);
        let roots = temporary_roots("native-graph-rollback", &signing);
        let mut app = native_package("app", "1.0.0", 1, b"managed-app\n");
        app.requirements = vec![crate::dependency::package_requirement("runtime-lib")];
        let runtime = native_package("runtime-lib", "1.0.0", 1, b"runtime\n");
        let repository = native_repository_packages(&roots, &signing, 1, vec![app, runtime]);
        let (config, signature) = write_config(&roots, &signing, 1, vec![repository], vec![]);
        let service = open_service(&roots, &config, &signature);
        fs::create_dir_all(roots.target.join("usr/bin")).unwrap();
        fs::write(roots.target.join("usr/bin/app"), b"unmanaged\n").unwrap();

        assert!(service.install("app").is_err());
        assert_eq!(
            fs::read(roots.target.join("usr/bin/app")).unwrap(),
            b"unmanaged\n"
        );
        assert!(!roots.target.join("usr/bin/runtime-lib").exists());
        assert!(service.read_all_service_receipts().unwrap().is_empty());
        assert!(!service.graph_journal_path().exists());
        fs::remove_dir_all(&roots.root).unwrap();
    }

    #[test]
    fn interrupted_partial_graph_install_rolls_back_owned_dependencies() {
        let signing = SigningKey::from_bytes(&[45_u8; 32]);
        let roots = temporary_roots("native-graph-recovery-rollback", &signing);
        let mut app = native_package("app", "1.0.0", 1, b"application\n");
        app.requirements = vec![crate::dependency::package_requirement("runtime-lib")];
        let runtime = native_package("runtime-lib", "1.0.0", 1, b"runtime\n");
        let repository = native_repository_packages(&roots, &signing, 1, vec![app, runtime]);
        let (config, signature) = write_config(&roots, &signing, 1, vec![repository], vec![]);
        let service = open_service(&roots, &config, &signature);
        let selector = parse_selector("app").unwrap();
        let root = service.resolve(&selector, None).unwrap();
        let plan = service.resolve_dependency_plan(root, false).unwrap();
        let prepared = plan
            .order
            .into_iter()
            .map(|candidate| service.prepare_candidate(candidate).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            prepared
                .iter()
                .map(|entry| entry.receipt.package.as_str())
                .collect::<Vec<_>>(),
            vec!["runtime-lib", "app"]
        );
        service
            .write_graph_journal(&ServiceGraphJournal {
                format: SERVICE_GRAPH_JOURNAL_FORMAT,
                action: JournalAction::Install,
                root: "app".into(),
                entries: prepared
                    .iter()
                    .map(|entry| ServiceGraphJournalEntry {
                        package: entry.receipt.package.clone(),
                        old: None,
                        new: entry.receipt.clone(),
                    })
                    .collect(),
            })
            .unwrap();
        let binary_store =
            BinaryInstallStore::open(roots.state.clone(), roots.target.clone()).unwrap();
        service.write_service_receipt(&prepared[0].receipt).unwrap();
        binary_store
            .install_payload(
                &prepared[0].payload,
                &prepared[0].receipt.artifact_sha256,
                false,
            )
            .unwrap();
        service.write_service_receipt(&prepared[1].receipt).unwrap();

        service.recover_pending().unwrap();
        assert!(!roots.target.join("usr/bin/runtime-lib").exists());
        assert!(!roots.target.join("usr/bin/app").exists());
        assert!(service.read_all_service_receipts().unwrap().is_empty());
        assert!(!service.graph_journal_path().exists());
        fs::remove_dir_all(&roots.root).unwrap();
    }

    #[test]
    fn interrupted_fully_owned_graph_install_rolls_receipts_forward() {
        let signing = SigningKey::from_bytes(&[46_u8; 32]);
        let roots = temporary_roots("native-graph-recovery-forward", &signing);
        let mut app = native_package("app", "1.0.0", 1, b"application\n");
        app.requirements = vec![crate::dependency::package_requirement("runtime-lib")];
        let runtime = native_package("runtime-lib", "1.0.0", 1, b"runtime\n");
        let repository = native_repository_packages(&roots, &signing, 1, vec![app, runtime]);
        let (config, signature) = write_config(&roots, &signing, 1, vec![repository], vec![]);
        let service = open_service(&roots, &config, &signature);
        let selector = parse_selector("app").unwrap();
        let root = service.resolve(&selector, None).unwrap();
        let plan = service.resolve_dependency_plan(root, false).unwrap();
        let prepared = plan
            .order
            .into_iter()
            .map(|candidate| service.prepare_candidate(candidate).unwrap())
            .collect::<Vec<_>>();
        service
            .write_graph_journal(&ServiceGraphJournal {
                format: SERVICE_GRAPH_JOURNAL_FORMAT,
                action: JournalAction::Install,
                root: "app".into(),
                entries: prepared
                    .iter()
                    .map(|entry| ServiceGraphJournalEntry {
                        package: entry.receipt.package.clone(),
                        old: None,
                        new: entry.receipt.clone(),
                    })
                    .collect(),
            })
            .unwrap();
        let binary_store =
            BinaryInstallStore::open(roots.state.clone(), roots.target.clone()).unwrap();
        for entry in &prepared {
            binary_store
                .install_payload(&entry.payload, &entry.receipt.artifact_sha256, false)
                .unwrap();
        }

        service.recover_pending().unwrap();
        assert!(roots.target.join("usr/bin/runtime-lib").exists());
        assert!(roots.target.join("usr/bin/app").exists());
        assert!(
            service
                .read_service_receipt("runtime-lib")
                .unwrap()
                .is_some()
        );
        assert!(service.read_service_receipt("app").unwrap().is_some());
        assert!(!service.graph_journal_path().exists());
        fs::remove_dir_all(&roots.root).unwrap();
    }

    #[test]
    fn interrupted_graph_update_with_an_old_root_rolls_dependencies_back() {
        let signing = SigningKey::from_bytes(&[49_u8; 32]);
        let roots = temporary_roots("native-graph-update-recovery", &signing);
        let repository_v1 = native_repository_packages(
            &roots,
            &signing,
            1,
            vec![native_package("app", "1.0.0", 1, b"version-one\n")],
        );
        let (config_v1, signature_v1) =
            write_config(&roots, &signing, 1, vec![repository_v1], vec![]);
        let service_v1 = open_service(&roots, &config_v1, &signature_v1);
        service_v1.install("app").unwrap();
        let old = service_v1.read_service_receipt("app").unwrap().unwrap();

        let mut app_v2 = native_package("app", "2.0.0", 2, b"version-two\n");
        app_v2.requirements = vec![crate::dependency::package_requirement("runtime-lib")];
        let runtime = native_package("runtime-lib", "1.0.0", 1, b"runtime\n");
        let repository_v2 = native_repository_packages(&roots, &signing, 2, vec![app_v2, runtime]);
        let (config_v2, signature_v2) =
            write_config(&roots, &signing, 2, vec![repository_v2], vec![]);
        let service_v2 = open_service(&roots, &config_v2, &signature_v2);
        let selector = parse_selector("app").unwrap();
        let root = service_v2.resolve(&selector, Some(&old)).unwrap();
        let plan = service_v2.resolve_dependency_plan(root, true).unwrap();
        let prepared = plan
            .order
            .into_iter()
            .map(|candidate| service_v2.prepare_candidate(candidate).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(prepared.last().unwrap().receipt.package, "app");
        service_v2
            .write_graph_journal(&ServiceGraphJournal {
                format: SERVICE_GRAPH_JOURNAL_FORMAT,
                action: JournalAction::Update,
                root: "app".into(),
                entries: prepared
                    .iter()
                    .map(|entry| ServiceGraphJournalEntry {
                        package: entry.receipt.package.clone(),
                        old: (entry.receipt.package == "app").then(|| old.clone()),
                        new: entry.receipt.clone(),
                    })
                    .collect(),
            })
            .unwrap();
        let binary_store =
            BinaryInstallStore::open(roots.state.clone(), roots.target.clone()).unwrap();
        let dependency = prepared
            .iter()
            .find(|entry| entry.receipt.package == "runtime-lib")
            .unwrap();
        service_v2
            .write_service_receipt(&dependency.receipt)
            .unwrap();
        binary_store
            .install_payload(
                &dependency.payload,
                &dependency.receipt.artifact_sha256,
                false,
            )
            .unwrap();
        service_v2
            .write_service_receipt(&prepared.last().unwrap().receipt)
            .unwrap();

        service_v2.recover_pending().unwrap();
        assert_eq!(
            fs::read(roots.target.join("usr/bin/app")).unwrap(),
            b"version-one\n"
        );
        assert!(!roots.target.join("usr/bin/runtime-lib").exists());
        assert_eq!(service_v2.read_service_receipt("app").unwrap(), Some(old));
        assert!(
            service_v2
                .read_service_receipt("runtime-lib")
                .unwrap()
                .is_none()
        );
        assert!(!service_v2.graph_journal_path().exists());
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
    fn signed_fedora_catalog_installs_through_the_standard_lifecycle() {
        let signing = SigningKey::from_bytes(&[52_u8; 32]);
        let roots = temporary_roots("fedora-source-lifecycle", &signing);
        let source = buildable_fedora_source_repository(&roots, &signing);
        let native = native_repository_packages(
            &roots,
            &signing,
            1,
            vec![native_package("runtime-lib", "1.0.0", 1, b"runtime\n")],
        );
        let (config, signature) = write_config(&roots, &signing, 1, vec![native], vec![source]);
        let service = open_service(&roots, &config, &signature);
        let resolution = service.search("demo").unwrap();
        assert_eq!(
            (resolution.provider.as_str(), resolution.route.as_str()),
            ("buildable-fedora", "source")
        );
        let installed = service.install("demo").unwrap();
        assert!(installed.changed);
        let executable = roots.target.join("usr/bin/demo");
        assert!(executable.is_file());
        assert!(fs::metadata(&executable).unwrap().permissions().mode() & 0o111 != 0);
        assert_eq!(
            fs::read(roots.target.join("usr/bin/runtime-lib")).unwrap(),
            b"runtime\n"
        );
        assert!(matches!(
            service.remove("runtime-lib"),
            Err(ServiceError::Dependency(_))
        ));
        service.remove("demo").unwrap();
        service.remove("runtime-lib").unwrap();
        assert!(!executable.exists());
        fs::remove_dir_all(&roots.root).unwrap();
    }

    #[test]
    fn standard_source_install_regenerates_a_pkgbuild_recipe_and_adds_native_runtime() {
        let signing = SigningKey::from_bytes(&[51_u8; 32]);
        let roots = temporary_roots("source-native-graph", &signing);
        let source =
            buildable_source_repository_with_dependency(&roots, &signing, Some("runtime-lib"));
        let native = native_repository_packages(
            &roots,
            &signing,
            1,
            vec![native_package("runtime-lib", "1.0.0", 1, b"runtime\n")],
        );
        let (config, signature) = write_config(&roots, &signing, 1, vec![native], vec![source]);
        let service = open_service(&roots, &config, &signature);

        let installed = service.install("demo").unwrap();
        assert_eq!(installed.route, "source");
        assert!(roots.target.join("usr/bin/demo").exists());
        assert_eq!(
            fs::read(roots.target.join("usr/bin/runtime-lib")).unwrap(),
            b"runtime\n"
        );
        assert!(matches!(
            service.remove("runtime-lib"),
            Err(ServiceError::Dependency(_))
        ));
        service.remove("demo").unwrap();
        service.remove("runtime-lib").unwrap();
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
    fn legacy_source_catalogs_remain_readable_without_dependency_metadata() {
        let signing = SigningKey::from_bytes(&[47_u8; 32]);
        let roots = temporary_roots("source-catalog-migration", &signing);
        let repository = source_repository(&roots, &signing, "legacy-source", 100, 'd');
        let bytes = fs::read(&repository.catalog).unwrap();
        let mut catalog: SourceCatalog = toml::from_slice(&bytes).unwrap();
        catalog.format = LEGACY_SOURCE_CATALOG_FORMAT;
        let signing_key_id = key_id(&signing.verifying_key().to_bytes());
        assert!(validate_source_catalog(&catalog, &repository, &signing_key_id, 1).is_ok());

        catalog.packages[0].requirements = vec![crate::dependency::package_requirement("runtime")];
        assert!(validate_source_catalog(&catalog, &repository, &signing_key_id, 1).is_err());
        fs::remove_dir_all(&roots.root).unwrap();
    }

    #[test]
    fn legacy_service_receipts_default_to_an_empty_dependency_closure() {
        let signing = SigningKey::from_bytes(&[50_u8; 32]);
        let roots = temporary_roots("service-receipt-migration", &signing);
        let repository = native_repository(&roots, &signing, 1, "1.0.0", b"installed\n");
        let (config, signature) = write_config(&roots, &signing, 1, vec![repository], vec![]);
        let service = open_service(&roots, &config, &signature);
        service.install("demo").unwrap();
        let current = service.read_service_receipt("demo").unwrap().unwrap();
        let mut value: toml::Value = toml::from_str(&toml::to_string(&current).unwrap()).unwrap();
        let table = value.as_table_mut().unwrap();
        table.insert("format".into(), toml::Value::Integer(1));
        table.remove("requirements");
        table.remove("provides");
        table.remove("conflicts");
        let legacy: ServiceReceipt = toml::from_str(&toml::to_string(&value).unwrap()).unwrap();
        assert!(legacy.requirements.is_empty());
        assert!(legacy.provides.is_empty());
        assert!(legacy.conflicts.is_empty());
        assert!(validate_service_receipt(&legacy).is_ok());

        let mut invalid = legacy;
        invalid.requirements = vec![crate::dependency::package_requirement("runtime")];
        assert!(validate_service_receipt(&invalid).is_err());
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
