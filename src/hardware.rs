//! Host-side HWD bridge for Corinth.
//!
//! Arach-HWD is deliberately not a package fetcher.  It emits a signed,
//! digest-bound `ProvisionPlan`; this module is the small authority bridge
//! that turns that plan into a reproducible build.  The bridge is host-only
//! (`host-store`) and never runs a shell: source acquisition and build
//! commands are parsed, allow-listed, and executed as direct processes.

use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::str::FromStr;

use arach_hwd::facts::{CpuArchitecture, CpuFeature};
use arach_hwd::plan::{
    CompilerTarget, CorinthIntent, CorinthVerb, PLAN_SCHEMA, PlanSet, ProvisionPlan,
};
use arach_hwd::profile::{AbiVersion, CompilerPolicy, PackageScope, RepositoryAuthority};
use arach_hwd::signature::Keyring;
use serde::{Deserialize, Serialize};

pub const RECIPE_FORMAT: u32 = 1;
pub const MAX_RECIPE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_OUTPUT_BYTES: u64 = 512 * 1024 * 1024;
pub const TARGET_ARCH: &str = "x86-64";
const SANDBOX_PROGRAM: &str = "/usr/bin/bwrap";
const BUILD_DEPENDENCY_MOUNT: &str = "/corinth-build";

/// Digest helpers are public so the Arach-Packages forge and HWD profile
/// generator can compute the exact values that cross the plan boundary.
pub fn metadata_sha256(recipe_bytes: &[u8]) -> String {
    hex_digest(&Sha256::digest(recipe_bytes))
}

pub fn source_lock_sha256(sources: &[RecipeSource]) -> String {
    hex_digest(&source_lock_digest(sources))
}

pub fn parse_recipe(recipe_bytes: &[u8]) -> Result<RecipeDocument, HardwareError> {
    if recipe_bytes.is_empty() || recipe_bytes.len() > MAX_RECIPE_BYTES {
        return Err(HardwareError::RecipeTooLarge);
    }
    let text = core::str::from_utf8(recipe_bytes)
        .map_err(|_| HardwareError::RecipeParse("recipe is not UTF-8".into()))?;
    toml::from_str(text).map_err(|error| HardwareError::RecipeParse(error.to_string()))
}

/// A strict Arach-Packages recipe.  Unknown fields are rejected so that a
/// typo cannot silently change what Corinth builds.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeDocument {
    pub format: u32,
    pub package: RecipePackage,
    pub source: Vec<RecipeSource>,
    pub build: RecipeBuild,
    #[serde(default)]
    pub runtime: Option<RecipeRuntime>,
    pub policy: RecipePolicy,
    #[serde(default)]
    pub hardware: Option<RecipeHardware>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cargo_closure: Option<RecipeCargoClosure>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeCargoClosure {
    pub lock: String,
    pub packages: Vec<RecipeCargoPackage>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeCargoPackage {
    pub name: String,
    pub version: String,
    pub checksum: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecipePackage {
    pub name: String,
    pub version: String,
    pub release: u32,
    pub summary: String,
    pub license: String,
    pub scope: String,
    pub publish_authority: String,
    pub architectures: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeSource {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    #[serde(default)]
    pub submodules: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeBuild {
    pub system: String,
    #[serde(default)]
    pub depends: Vec<String>,
    pub commands: Vec<String>,
    pub outputs: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeRuntime {
    #[serde(default)]
    pub depends: Vec<String>,
    #[serde(default)]
    pub provides: Vec<String>,
    #[serde(default)]
    pub conflicts: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecipePolicy {
    pub network: bool,
    pub sandbox: bool,
    pub reproducible: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RecipeHardware {
    pub matches: Vec<String>,
    pub driver_abi_min: String,
    pub driver_abi_max: String,
    pub health_checks: Vec<String>,
    pub rollback: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedHardwarePlan {
    pub(crate) plan: ProvisionPlan,
}

impl VerifiedHardwarePlan {
    pub fn plan(&self) -> &ProvisionPlan {
        &self.plan
    }

    /// Split an already-verified package set without permitting callers to
    /// manufacture or mutate any authority-bearing plan field.
    pub fn partition_packages<F>(&self, mut left: F) -> (Option<Self>, Option<Self>)
    where
        F: FnMut(&CorinthIntent) -> bool,
    {
        let mut left_package = Vec::new();
        let mut right_package = Vec::new();
        for intent in &self.plan.package {
            if left(intent) {
                left_package.push(intent.clone());
            } else {
                right_package.push(intent.clone());
            }
        }
        let mut left_plan = self.plan.clone();
        let mut right_plan = self.plan.clone();
        left_plan.package = left_package;
        right_plan.package = right_package;
        let left = (!left_plan.package.is_empty()).then_some(Self { plan: left_plan });
        let right = (!right_plan.package.is_empty()).then_some(Self { plan: right_plan });
        (left, right)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HardwareBuildReceipt {
    pub package: String,
    pub version: String,
    pub release: u32,
    pub source_revision: String,
    pub metadata_sha256: String,
    pub source_lock_sha256: String,
    pub artifact_sha256: String,
    pub outputs: Vec<PathBuf>,
}

/// Private receipt store for staged host artifacts.  It records exactly which
/// files a transaction published, so remove never needs to infer paths from a
/// package name and cannot delete an unrelated file.
#[derive(Clone, Debug)]
pub struct HostPackageStore {
    root: PathBuf,
    artifacts: PathBuf,
}

impl HostPackageStore {
    pub fn open(root: PathBuf, artifacts: PathBuf) -> Result<Self, HardwareError> {
        prepare_private_root(&root)?;
        prepare_private_root(&artifacts)?;
        fs::create_dir_all(root.join("installed"))?;
        fs::create_dir_all(&artifacts)?;
        Ok(Self { root, artifacts })
    }

    pub fn install(&self, receipts: &[HardwareBuildReceipt]) -> Result<(), HardwareError> {
        for receipt in receipts {
            self.validate_receipt(receipt)?;
            let path = self.record_path(&receipt.package)?;
            let bytes = toml::to_string(receipt)
                .map_err(|error| HardwareError::State(error.to_string()))?;
            atomic_write(&path, bytes.as_bytes())?;
        }
        Ok(())
    }

    pub fn update(&self, receipts: &[HardwareBuildReceipt]) -> Result<(), HardwareError> {
        // New outputs have already been measured and copied before this call.
        // Remove the old receipt only after every new receipt is valid.
        for receipt in receipts {
            self.validate_receipt(receipt)?;
        }
        for receipt in receipts {
            let path = self.record_path(&receipt.package)?;
            if !path.is_file() {
                continue;
            }
            let bytes = read_bounded(&path, MAX_RECIPE_BYTES as u64)
                .map_err(|error| HardwareError::State(error.to_string()))?;
            let previous: HardwareBuildReceipt = toml::from_slice(&bytes)
                .map_err(|error| HardwareError::State(error.to_string()))?;
            self.validate_receipt(&previous)?;
            self.remove_recorded_except(&previous, &receipt.outputs)?;
            fs::remove_file(path)?;
        }
        self.install(receipts)
    }

    pub fn remove(&self, package: &str) -> Result<(), HardwareError> {
        let path = self.record_path(package)?;
        let bytes = read_bounded(&path, MAX_RECIPE_BYTES as u64)
            .map_err(|error| HardwareError::State(error.to_string()))?;
        let receipt: HardwareBuildReceipt =
            toml::from_slice(&bytes).map_err(|error| HardwareError::State(error.to_string()))?;
        self.validate_receipt(&receipt)?;
        self.remove_recorded(package)
    }

    fn remove_recorded(&self, package: &str) -> Result<(), HardwareError> {
        let path = self.record_path(package)?;
        if !path.is_file() {
            return Err(HardwareError::State(format!(
                "package is not installed: {package}"
            )));
        }
        let bytes = read_bounded(&path, MAX_RECIPE_BYTES as u64)
            .map_err(|error| HardwareError::State(error.to_string()))?;
        let receipt: HardwareBuildReceipt =
            toml::from_slice(&bytes).map_err(|error| HardwareError::State(error.to_string()))?;
        self.validate_receipt(&receipt)?;
        self.remove_recorded_except(&receipt, &[])?;
        fs::remove_file(path)?;
        Ok(())
    }

    fn remove_recorded_except(
        &self,
        receipt: &HardwareBuildReceipt,
        keep: &[PathBuf],
    ) -> Result<(), HardwareError> {
        for output in &receipt.outputs {
            if keep.iter().any(|path| path == output) {
                continue;
            }
            if output.starts_with(&self.artifacts)
                && fs::symlink_metadata(output)
                    .map(|metadata| metadata.file_type().is_file())
                    .unwrap_or(false)
            {
                fs::remove_file(output)?;
            }
        }
        Ok(())
    }

    fn record_path(&self, package: &str) -> Result<PathBuf, HardwareError> {
        if package.is_empty()
            || !package.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
            })
        {
            return Err(HardwareError::State("invalid package identity".into()));
        }
        Ok(self.root.join("installed").join(format!("{package}.toml")))
    }

    fn validate_receipt(&self, receipt: &HardwareBuildReceipt) -> Result<(), HardwareError> {
        if !valid_digest(&receipt.artifact_sha256)
            || !valid_digest(&receipt.metadata_sha256)
            || !valid_digest(&receipt.source_lock_sha256)
            || receipt.outputs.is_empty()
            || receipt
                .outputs
                .iter()
                .any(|path| !path.starts_with(&self.artifacts))
        {
            return Err(HardwareError::State(format!(
                "invalid receipt for {}",
                receipt.package
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HardwareError {
    Io(String),
    InvalidPlan(String),
    InvalidPlanSet,
    Signature(String),
    RecipeTooLarge,
    RecipeParse(String),
    InvalidRecipe(String),
    PackageNotFound(String),
    UnsupportedSource(String),
    UnsupportedBuildSystem(String),
    InvalidSource(String),
    SourceUnavailable(String),
    State(String),
    NetworkNotAllowed,
    BuildNetworkNotAllowed,
    CommandRejected(String),
    CommandFailed(String),
    OutputRejected(String),
    ArtifactDigestMismatch {
        package: String,
        expected: String,
        actual: String,
    },
    MetadataDigestMismatch {
        package: String,
        expected: String,
        actual: String,
    },
    SourceLockDigestMismatch {
        package: String,
        expected: String,
        actual: String,
    },
}

impl fmt::Display for HardwareError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for HardwareError {}

impl From<io::Error> for HardwareError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

/// Verifies the exact profile bytes that authorized a plan and checks that
/// every intent is still exactly the intent from that signed profile.
pub fn verify_plan(
    plan: ProvisionPlan,
    profile_bytes: &[u8],
    signature_text: &str,
    keyring: &Keyring,
) -> Result<VerifiedHardwarePlan, HardwareError> {
    if plan.schema != PLAN_SCHEMA {
        return Err(HardwareError::InvalidPlan("unsupported schema".into()));
    }
    if plan.profile_id.is_empty() || plan.signing_key_id.is_empty() || plan.device_key.is_empty() {
        return Err(HardwareError::InvalidPlan("missing plan identity".into()));
    }
    let verified = keyring
        .verify(profile_bytes, signature_text)
        .map_err(|error| HardwareError::Signature(error.to_string()))?;
    if verified.profile().profile.id != plan.profile_id
        || verified.key_id() != plan.signing_key_id
        || verified.profile_sha256() != plan.profile_sha256
    {
        return Err(HardwareError::InvalidPlan(
            "profile identity or digest does not match the signed plan".into(),
        ));
    }
    if plan.package.len() != verified.profile().package.len()
        || !plan
            .package
            .iter()
            .zip(&verified.profile().package)
            .all(|(left, right)| intent_matches(left, right))
    {
        return Err(HardwareError::InvalidPlan(
            "package intents do not match the signed profile".into(),
        ));
    }
    let running_abi = AbiVersion::from_str(&plan.driver_abi)
        .map_err(|_| HardwareError::InvalidPlan("invalid running Driver ABI".into()))?;
    let requires_driver_abi = verified
        .profile()
        .package
        .iter()
        .any(|package| matches!(package.scope, PackageScope::Driver | PackageScope::Firmware));
    match verified.profile().driver_abi.as_ref() {
        Some(range) => {
            let minimum = AbiVersion::from_str(&range.minimum)
                .map_err(|_| HardwareError::InvalidPlan("invalid profile Driver ABI".into()))?;
            let maximum = AbiVersion::from_str(&range.maximum)
                .map_err(|_| HardwareError::InvalidPlan("invalid profile Driver ABI".into()))?;
            if running_abi < minimum || running_abi > maximum {
                return Err(HardwareError::InvalidPlan(
                    "running Driver ABI is outside the signed profile range".into(),
                ));
            }
        }
        None if requires_driver_abi => {
            return Err(HardwareError::InvalidPlan(
                "hardware profile does not authorize a Driver ABI".into(),
            ));
        }
        None => {}
    }
    if plan.health != verified.profile().health
        || plan.rollback != verified.profile().rollback
        || plan.recovery != verified.profile().recovery
    {
        return Err(HardwareError::InvalidPlan(
            "health, rollback, or recovery policy differs from the signed profile".into(),
        ));
    }
    verify_compiler_target(&plan.compiler, verified.profile().compiler.as_ref())?;
    for intent in &plan.package {
        validate_intent(intent)?;
    }
    Ok(VerifiedHardwarePlan { plan })
}

fn verify_compiler_target(
    target: &CompilerTarget,
    policy: Option<&CompilerPolicy>,
) -> Result<(), HardwareError> {
    let observed = arach_hwd::scan::scan_system(Path::new("/sys")).cpu;
    if target.architecture != observed.architecture
        || target.vendor != observed.vendor
        || target.family != observed.family
        || target.model != observed.model
        || target.stepping != observed.stepping
    {
        return Err(HardwareError::InvalidPlan(
            "compiler target does not describe the local CPU".into(),
        ));
    }
    let observed_features = observed.features.into_iter().collect::<BTreeSet<_>>();
    let expected = if let Some(policy) = policy {
        if policy.architecture != target.architecture {
            return Err(HardwareError::InvalidPlan(
                "compiler target architecture differs from signed policy".into(),
            ));
        }
        if policy
            .required_features
            .iter()
            .any(|feature| !observed_features.contains(feature))
        {
            return Err(HardwareError::InvalidPlan(
                "local CPU lacks a feature required by signed policy".into(),
            ));
        }
        policy
            .allowed_features
            .iter()
            .copied()
            .filter(|feature| observed_features.contains(feature))
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    if target.features != expected
        || target
            .features
            .iter()
            .any(|feature| !target.architecture.supports(*feature))
    {
        return Err(HardwareError::InvalidPlan(
            "compiler features are not the exact observed signed-policy intersection".into(),
        ));
    }
    Ok(())
}

/// Verifies every plan in an HWD plan-set.  Duplicate devices or profiles
/// are rejected before any source is fetched or any build is started.
pub fn verify_plan_set(
    set: PlanSet,
    profiles: &[(Vec<u8>, String, Keyring)],
) -> Result<Vec<VerifiedHardwarePlan>, HardwareError> {
    if set.schema != PLAN_SCHEMA || set.plan.is_empty() {
        return Err(HardwareError::InvalidPlanSet);
    }
    let mut devices = BTreeSet::new();
    let mut output = Vec::with_capacity(set.plan.len());
    for plan in set.plan {
        if !devices.insert(plan.device_key.clone()) {
            return Err(HardwareError::InvalidPlanSet);
        }
        let Some((bytes, signature, keyring)) =
            profiles.iter().find(|(bytes, signature, keyring)| {
                keyring
                    .verify(bytes, signature)
                    .ok()
                    .is_some_and(|profile| profile.profile().profile.id == plan.profile_id)
            })
        else {
            return Err(HardwareError::InvalidPlan(
                "no trusted profile supplied for plan".into(),
            ));
        };
        output.push(verify_plan(plan, bytes, signature, keyring)?);
    }
    Ok(output)
}

fn intent_matches(intent: &CorinthIntent, profile: &arach_hwd::profile::PackageIntent) -> bool {
    matches!(intent.verb, CorinthVerb::Install)
        && intent.name == profile.name
        && intent.version == profile.version
        && intent.scope == profile.scope
        && intent.repository == profile.repository
        && intent.metadata_sha256 == profile.metadata_sha256
        && intent.artifact_sha256 == profile.artifact_sha256
        && intent.source_lock_sha256 == profile.source_lock_sha256
}

fn validate_intent(intent: &CorinthIntent) -> Result<(), HardwareError> {
    if intent.name.is_empty()
        || !intent.name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        })
        || intent.version.trim().is_empty()
        || !valid_digest(&intent.metadata_sha256)
        || !valid_digest(&intent.artifact_sha256)
        || !valid_digest(&intent.source_lock_sha256)
    {
        return Err(HardwareError::InvalidPlan(format!(
            "invalid intent {}",
            intent.name
        )));
    }
    let valid_authority = match intent.scope {
        PackageScope::System => intent.repository == RepositoryAuthority::ArachNative,
        PackageScope::Driver | PackageScope::Firmware => {
            intent.repository == RepositoryAuthority::ArachHardware
        }
    };
    if !valid_authority {
        return Err(HardwareError::InvalidPlan(format!(
            "authority does not match scope for {}",
            intent.name
        )));
    }
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        && value.bytes().any(|byte| byte != b'0')
}

/// Host build policy and output publisher.  The roots must be absolute and
/// are intentionally separate: source work trees are disposable while the
/// artifact root is the measured hand-off to the durable store.
#[derive(Clone, Debug)]
pub struct HardwareProvisioner {
    pub work_root: PathBuf,
    pub artifact_root: PathBuf,
    pub allow_network: bool,
    /// Legacy image builders may bind an explicitly selected user toolchain.
    /// The package service disables this and uses only OS-managed `/usr`
    /// toolchains inside the sandbox.
    pub allow_host_toolchains: bool,
    pub target_arch: String,
}

impl HardwareProvisioner {
    pub fn new(work_root: PathBuf, artifact_root: PathBuf) -> Result<Self, HardwareError> {
        Self::for_target(work_root, artifact_root, TARGET_ARCH)
    }

    pub fn for_target(
        work_root: PathBuf,
        artifact_root: PathBuf,
        target_arch: impl Into<String>,
    ) -> Result<Self, HardwareError> {
        prepare_private_root(&work_root)?;
        prepare_private_root(&artifact_root)?;
        Ok(Self {
            work_root,
            artifact_root,
            allow_network: false,
            allow_host_toolchains: true,
            target_arch: target_arch.into(),
        })
    }

    /// Build only a plan that passed signature, intent, and digest checks.
    pub fn build_verified(
        &self,
        plan: &VerifiedHardwarePlan,
        recipes_root: &Path,
    ) -> Result<Vec<HardwareBuildReceipt>, HardwareError> {
        self.build_verified_set(std::slice::from_ref(plan), recipes_root)
    }

    /// Build the union of several device plans.  A catalog commonly resolves
    /// the same firmware or driver for multiple devices; build it once and
    /// retain deterministic package order rather than rebuilding or
    /// overwriting the measured artifact.
    pub fn build_verified_set(
        &self,
        plans: &[VerifiedHardwarePlan],
        recipes_root: &Path,
    ) -> Result<Vec<HardwareBuildReceipt>, HardwareError> {
        fs::create_dir_all(&self.work_root)?;
        fs::create_dir_all(&self.artifact_root)?;
        let mut intents = std::collections::BTreeMap::new();
        for plan in plans {
            for intent in &plan.plan.package {
                let key = (intent.name.clone(), intent.version.clone());
                if let Some((previous, previous_target)) =
                    intents.insert(key.clone(), (intent, &plan.plan.compiler))
                {
                    if previous.metadata_sha256 != intent.metadata_sha256
                        || previous.artifact_sha256 != intent.artifact_sha256
                        || previous.source_lock_sha256 != intent.source_lock_sha256
                        || previous_target != &plan.plan.compiler
                    {
                        return Err(HardwareError::InvalidPlan(format!(
                            "conflicting package intents or compiler targets across hardware plans: {}",
                            intent.name
                        )));
                    }
                }
            }
        }
        intents
            .into_values()
            .map(|(intent, compiler)| self.build_intent(intent, compiler, recipes_root))
            .collect()
    }

    /// Build one package-index-admitted system recipe and measure the artifact
    /// produced on this host. The caller must have authenticated the ingress
    /// lock and target policy before invoking this crate-private path. Unlike a
    /// hardware plan build, the resulting artifact digest is evidence produced
    /// by the local build rather than an input asserted in advance.
    pub(crate) fn build_admitted_system_recipe(
        &self,
        recipe_bytes: &[u8],
        compiler: &CompilerTarget,
        build_dependency_root: Option<&Path>,
    ) -> Result<HardwareBuildReceipt, HardwareError> {
        fs::create_dir_all(&self.work_root)?;
        fs::create_dir_all(&self.artifact_root)?;
        let metadata = metadata_sha256(recipe_bytes);
        let recipe = parse_recipe(recipe_bytes)?;
        let source_lock = source_lock_sha256(&recipe.source);
        let intent = CorinthIntent {
            verb: CorinthVerb::Install,
            name: recipe.package.name.clone(),
            version: recipe.package.version.clone(),
            scope: PackageScope::System,
            repository: RepositoryAuthority::ArachNative,
            metadata_sha256: metadata.clone(),
            artifact_sha256: "a".repeat(64),
            source_lock_sha256: source_lock.clone(),
        };
        validate_recipe(&recipe, &intent, &self.target_arch)?;
        if recipe.build.outputs.as_slice() != ["@install-tree"] {
            return Err(HardwareError::InvalidRecipe(
                "service source recipes must publish @install-tree".into(),
            ));
        }
        if compiler_architecture_name(compiler.architecture) != Some(self.target_arch.as_str()) {
            return Err(HardwareError::InvalidPlan(
                "compiler target architecture differs from the package target".into(),
            ));
        }
        if !recipe.policy.sandbox || !recipe.policy.reproducible {
            return Err(HardwareError::InvalidRecipe(
                "service source builds require sandbox=true and reproducible=true".into(),
            ));
        }
        if recipe.policy.network && !self.allow_network {
            return Err(HardwareError::BuildNetworkNotAllowed);
        }

        let materialized_sources = kernel_materialization_sources(&recipe)?;
        let source_dir = self.materialize_sources(&materialized_sources, &source_lock)?;
        prepare_cargo_closure(&recipe, &source_dir)?;
        if recipe.build.system == "cosmic" {
            run_cosmic_workspace(
                &source_dir,
                recipe.policy.network,
                compiler,
                self.allow_host_toolchains,
                build_dependency_root,
            )?;
        } else {
            for command in &recipe.build.commands {
                run_build_command(
                    command,
                    &recipe.build.system,
                    &source_dir,
                    recipe.policy.network,
                    compiler,
                    self.allow_host_toolchains,
                    build_dependency_root,
                )?;
            }
        }
        let (artifact_sha256, outputs) = self.measure_outputs(&recipe, &source_dir, None)?;
        Ok(HardwareBuildReceipt {
            package: recipe.package.name,
            version: recipe.package.version,
            release: recipe.package.release,
            source_revision: source_revision(&recipe.source, &source_lock),
            metadata_sha256: metadata,
            source_lock_sha256: source_lock,
            artifact_sha256,
            outputs,
        })
    }

    /// Convert the measured install tree from an admitted system recipe into
    /// the same ownership-aware payload used by native binary packages.
    pub(crate) fn payload_from_admitted_system_recipe(
        &self,
        recipe_bytes: &[u8],
        receipt: &HardwareBuildReceipt,
    ) -> Result<crate::binary::BinaryPayload, HardwareError> {
        let recipe = parse_recipe(recipe_bytes)?;
        if recipe.package.name != receipt.package
            || recipe.package.version != receipt.version
            || recipe.package.release != receipt.release
            || recipe.package.scope != "system"
            || recipe.package.publish_authority != "arach-native"
            || recipe.build.outputs.as_slice() != ["@install-tree"]
            || metadata_sha256(recipe_bytes) != receipt.metadata_sha256
            || source_lock_sha256(&recipe.source) != receipt.source_lock_sha256
        {
            return Err(HardwareError::State(
                "source build receipt does not match the admitted recipe".into(),
            ));
        }
        let intent = CorinthIntent {
            verb: CorinthVerb::Install,
            name: receipt.package.clone(),
            version: receipt.version.clone(),
            scope: PackageScope::System,
            repository: RepositoryAuthority::ArachNative,
            metadata_sha256: receipt.metadata_sha256.clone(),
            artifact_sha256: receipt.artifact_sha256.clone(),
            source_lock_sha256: receipt.source_lock_sha256.clone(),
        };
        let payload = self.payload_from_receipt(&intent, receipt)?;
        let mut digest = Sha256::new();
        for file in &payload.files {
            digest.update(file.path.as_bytes());
            digest.update([0]);
            digest.update(file.mode.to_le_bytes());
            digest.update(&file.bytes);
        }
        let actual = hex_digest(&digest.finalize());
        if actual != receipt.artifact_sha256 {
            return Err(HardwareError::ArtifactDigestMismatch {
                package: receipt.package.clone(),
                expected: receipt.artifact_sha256.clone(),
                actual,
            });
        }
        Ok(payload)
    }

    /// Install the measured output of a verified hardware plan into a target
    /// root.  Hardware recipes are required to publish `@install-tree`; this
    /// keeps the target paths explicit (for example `usr/lib/firmware/...` or
    /// `usr/lib/modules/...`) instead of guessing from a compiler output path.
    /// The binary install store owns every file and will refuse conflicts,
    /// symlinks, or modified files on rollback/removal.
    pub fn install_plan_to_root(
        &self,
        state: PathBuf,
        target: PathBuf,
        plan: &VerifiedHardwarePlan,
        receipts: &[HardwareBuildReceipt],
    ) -> Result<Vec<crate::binary::BinaryInstallReceipt>, HardwareError> {
        self.install_plan_set_to_root(state, target, std::slice::from_ref(plan), receipts)
    }

    /// Install the union of several already-verified device plans.  Duplicate
    /// package intents are intentionally coalesced, while conflicting digests
    /// fail before any target mutation.
    pub fn install_plan_set_to_root(
        &self,
        state: PathBuf,
        target: PathBuf,
        plans: &[VerifiedHardwarePlan],
        receipts: &[HardwareBuildReceipt],
    ) -> Result<Vec<crate::binary::BinaryInstallReceipt>, HardwareError> {
        let mut intents = std::collections::BTreeMap::new();
        for plan in plans {
            for intent in &plan.plan.package {
                let key = (intent.name.clone(), intent.version.clone());
                if let Some(previous) = intents.insert(key, intent) {
                    if previous.metadata_sha256 != intent.metadata_sha256
                        || previous.artifact_sha256 != intent.artifact_sha256
                        || previous.source_lock_sha256 != intent.source_lock_sha256
                    {
                        return Err(HardwareError::InvalidPlan(format!(
                            "conflicting package intents across hardware plans: {}",
                            intent.name
                        )));
                    }
                }
            }
        }
        if receipts.len() != intents.len() {
            return Err(HardwareError::State(
                "hardware receipt count differs from the verified plan set".into(),
            ));
        }
        let receipts = receipts
            .iter()
            .map(|receipt| ((receipt.package.clone(), receipt.version.clone()), receipt))
            .collect::<std::collections::BTreeMap<_, _>>();
        if receipts.len() != intents.len() {
            return Err(HardwareError::State(
                "hardware receipts contain duplicate package identities".into(),
            ));
        }
        let store = crate::binary::BinaryInstallStore::open(state, target)?;
        let mut installed = Vec::with_capacity(intents.len());
        for (key, intent) in intents {
            let receipt = receipts.get(&key).ok_or_else(|| {
                HardwareError::State(format!("missing hardware receipt: {}", intent.name))
            })?;
            let payload = self.payload_from_receipt(intent, receipt)?;
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

    fn payload_from_receipt(
        &self,
        intent: &CorinthIntent,
        receipt: &HardwareBuildReceipt,
    ) -> Result<crate::binary::BinaryPayload, HardwareError> {
        if receipt.package != intent.name
            || receipt.version != intent.version
            || receipt.metadata_sha256 != intent.metadata_sha256
            || receipt.source_lock_sha256 != intent.source_lock_sha256
            || receipt.artifact_sha256 != intent.artifact_sha256
        {
            return Err(HardwareError::InvalidPlan(format!(
                "hardware receipt does not match intent: {}",
                intent.name
            )));
        }
        let package_root = self.artifact_root.join(format!(
            "{}-{}-{}",
            receipt.package, receipt.version, receipt.release
        ));
        let mut files = Vec::with_capacity(receipt.outputs.len());
        let mut seen = BTreeSet::new();
        for output in &receipt.outputs {
            let relative = output
                .strip_prefix(&package_root)
                .map_err(|_| HardwareError::OutputRejected(output.display().to_string()))?;
            let relative = safe_relative_path(
                relative
                    .to_str()
                    .ok_or_else(|| HardwareError::OutputRejected(output.display().to_string()))?,
            )?;
            if !seen.insert(relative.to_string_lossy().into_owned()) {
                return Err(HardwareError::OutputRejected(
                    relative.display().to_string(),
                ));
            }
            let metadata = fs::symlink_metadata(output)
                .map_err(|_| HardwareError::OutputRejected(output.display().to_string()))?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(HardwareError::OutputRejected(output.display().to_string()));
            }
            let bytes = read_bounded(output, MAX_OUTPUT_BYTES)
                .map_err(|error| HardwareError::OutputRejected(error.to_string()))?;
            files.push(crate::binary::BinaryPayloadFile {
                path: relative.to_string_lossy().into_owned(),
                mode: metadata.permissions().mode() & 0o7777,
                bytes,
            });
        }
        if files.is_empty() {
            return Err(HardwareError::OutputRejected(intent.name.clone()));
        }
        files.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(crate::binary::BinaryPayload {
            package: receipt.package.clone(),
            version: receipt.version.clone(),
            release: receipt.release,
            metadata_sha256: receipt.metadata_sha256.clone(),
            source_lock_sha256: receipt.source_lock_sha256.clone(),
            files,
        })
    }

    /// Pin and cache the Arach-Packages recipe repository itself.  GitHub is
    /// only transport here; the caller still supplies a signed plan whose
    /// metadata and source locks authorize the resulting build.
    pub fn acquire_recipe_repository(
        &self,
        url: &str,
        revision: &str,
        submodules: bool,
    ) -> Result<PathBuf, HardwareError> {
        self.acquire_source(&RecipeSource {
            kind: "git".into(),
            url: Some(url.into()),
            revision: Some(revision.into()),
            checksum: None,
            package: None,
            version: None,
            destination: None,
            submodules,
        })
    }

    /// Fetches one fully locked build input into the private source cache.
    ///
    /// This is an availability operation only. The returned path carries no
    /// package or installation authority; callers must still admit the
    /// canonical recipe and its signed repository intent.
    pub fn acquire_locked_source(&self, source: &RecipeSource) -> Result<PathBuf, HardwareError> {
        validate_source(source)?;
        self.acquire_source(source)
    }

    fn build_intent(
        &self,
        intent: &CorinthIntent,
        compiler: &CompilerTarget,
        recipes_root: &Path,
    ) -> Result<HardwareBuildReceipt, HardwareError> {
        let recipe_path = find_recipe(recipes_root, &intent.name)?;
        let recipe_bytes = read_bounded(&recipe_path, MAX_RECIPE_BYTES as u64)
            .map_err(|error| HardwareError::RecipeParse(error.to_string()))?;
        let metadata = metadata_sha256(&recipe_bytes);
        if metadata != intent.metadata_sha256 {
            return Err(HardwareError::MetadataDigestMismatch {
                package: intent.name.clone(),
                expected: intent.metadata_sha256.clone(),
                actual: metadata,
            });
        }
        let recipe = parse_recipe(&recipe_bytes)?;
        validate_recipe(&recipe, intent, &self.target_arch)?;
        if compiler_architecture_name(compiler.architecture) != Some(self.target_arch.as_str()) {
            return Err(HardwareError::InvalidPlan(
                "compiler target architecture differs from the package target".into(),
            ));
        }
        let source_lock = source_lock_sha256(&recipe.source);
        if source_lock != intent.source_lock_sha256 {
            return Err(HardwareError::SourceLockDigestMismatch {
                package: intent.name.clone(),
                expected: intent.source_lock_sha256.clone(),
                actual: source_lock,
            });
        }
        if !recipe.policy.sandbox || !recipe.policy.reproducible {
            return Err(HardwareError::InvalidRecipe(
                "hardware builds require sandbox=true and reproducible=true".into(),
            ));
        }
        if recipe.policy.network && !self.allow_network {
            return Err(HardwareError::BuildNetworkNotAllowed);
        }

        let materialized_sources = kernel_materialization_sources(&recipe)?;
        let source_dir = self.materialize_sources(&materialized_sources, &source_lock)?;
        prepare_cargo_closure(&recipe, &source_dir)?;
        if recipe.build.system == "cosmic" {
            run_cosmic_workspace(
                &source_dir,
                recipe.policy.network,
                compiler,
                self.allow_host_toolchains,
                None,
            )?;
        } else if is_fixed_kernel_recipe(&recipe) {
            run_arach_kernel_workspace(
                &source_dir,
                recipe.policy.network,
                compiler,
                self.allow_host_toolchains,
            )?;
        } else {
            for command in &recipe.build.commands {
                run_build_command(
                    command,
                    &recipe.build.system,
                    &source_dir,
                    recipe.policy.network,
                    compiler,
                    self.allow_host_toolchains,
                    None,
                )?;
            }
        }
        let (artifact_digest, outputs) = self.measure_outputs(
            &recipe,
            &source_dir,
            Some((&intent.name, &intent.artifact_sha256)),
        )?;
        Ok(HardwareBuildReceipt {
            package: recipe.package.name,
            version: recipe.package.version,
            release: recipe.package.release,
            source_revision: source_revision(&recipe.source, &source_lock),
            metadata_sha256: metadata,
            source_lock_sha256: source_lock,
            artifact_sha256: artifact_digest,
            outputs,
        })
    }

    /// Materialize every locked source into one disposable build tree.  A
    /// recipe may use a primary archive plus patches or generated inputs; the
    /// old single-source shortcut made those recipes appear valid while
    /// silently omitting later sources.  Collisions are rejected instead of
    /// allowing one source to overwrite another.
    fn materialize_sources(
        &self,
        sources: &[RecipeSource],
        source_lock: &str,
    ) -> Result<PathBuf, HardwareError> {
        let build_root = self.work_root.join("build");
        fs::create_dir_all(&build_root)?;
        let destination = build_root.join(source_lock);
        if destination.exists() {
            fs::remove_dir_all(&destination)?;
        }
        fs::create_dir_all(&destination)?;
        for source in sources {
            let cached = self.acquire_source(source)?;
            if let Some(relative) = source.destination.as_deref() {
                let relative = safe_source_destination(relative)?;
                let target = destination.join(relative);
                if target.exists() {
                    return Err(HardwareError::InvalidSource(format!(
                        "source destination collision: {}",
                        target.display()
                    )));
                }
                fs::create_dir_all(&target)?;
                merge_tree_without_symlinks(&cached, &target)?;
            } else {
                merge_tree_without_symlinks(&cached, &destination)?;
            }
        }
        Ok(destination)
    }

    fn acquire_source(&self, source: &RecipeSource) -> Result<PathBuf, HardwareError> {
        let key = Sha256::digest(source_lock_bytes(core::slice::from_ref(source)));
        let source_root = self.work_root.join("sources");
        fs::create_dir_all(&source_root)?;
        let destination = source_root.join(hex_digest(&key));
        if destination.join(".corinth-source-ready").is_file() {
            return Ok(destination);
        }
        if destination.exists() {
            return Err(HardwareError::SourceUnavailable(format!(
                "incomplete source cache {}",
                destination.display()
            )));
        }
        match source.kind.as_str() {
            "git" => self.acquire_git(source, &destination)?,
            "local" => self.acquire_local(source, &destination)?,
            "crates-io" | "crates.io" | "crate" => self.acquire_crate(source, &destination)?,
            "archive" => self.acquire_archive(source, &destination)?,
            other => return Err(HardwareError::UnsupportedSource(other.into())),
        }
        let marker = destination.join(".corinth-source-ready");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(marker)?
            .sync_all()?;
        Ok(destination)
    }

    fn acquire_git(&self, source: &RecipeSource, destination: &Path) -> Result<(), HardwareError> {
        let url = source
            .url
            .as_deref()
            .ok_or_else(|| HardwareError::InvalidSource("git URL is missing".into()))?;
        let revision = source
            .revision
            .as_deref()
            .ok_or_else(|| HardwareError::InvalidSource("git revision is missing".into()))?;
        if !is_https_url(url) || !valid_git_revision(revision) {
            return Err(HardwareError::InvalidSource(
                "git sources require an HTTPS URL and a 40-hex revision".into(),
            ));
        }
        if !self.allow_network {
            return Err(HardwareError::NetworkNotAllowed);
        }
        let parent = destination
            .parent()
            .ok_or_else(|| HardwareError::SourceUnavailable("source root has no parent".into()))?;
        run_direct(
            "git",
            &[
                "clone",
                "--no-checkout",
                "--filter=blob:none",
                "--no-tags",
                "--depth=1",
                url,
                destination
                    .to_str()
                    .ok_or_else(|| HardwareError::InvalidSource("non-UTF-8 source path".into()))?,
            ],
            parent,
            false,
        )?;
        run_direct(
            "git",
            &[
                "-C",
                path_str(destination)?,
                "fetch",
                "--depth=1",
                "origin",
                revision,
            ],
            parent,
            false,
        )?;
        run_direct(
            "git",
            &[
                "-C",
                path_str(destination)?,
                "checkout",
                "--detach",
                "--force",
                revision,
            ],
            parent,
            false,
        )?;
        let head = command_output(
            "git",
            &["-C", path_str(destination)?, "rev-parse", "HEAD"],
            parent,
        )?;
        if head.trim() != revision {
            return Err(HardwareError::InvalidSource(
                "git checkout did not produce the locked revision".into(),
            ));
        }
        if source.submodules {
            run_direct(
                "git",
                &[
                    "-C",
                    path_str(destination)?,
                    "submodule",
                    "update",
                    "--init",
                    "--recursive",
                ],
                parent,
                false,
            )?;
        }
        Ok(())
    }

    fn acquire_local(
        &self,
        source: &RecipeSource,
        destination: &Path,
    ) -> Result<(), HardwareError> {
        let path =
            PathBuf::from(source.url.as_deref().ok_or_else(|| {
                HardwareError::InvalidSource("local source path is missing".into())
            })?);
        if !path.is_absolute() || !path.is_dir() {
            return Err(HardwareError::InvalidSource(
                "local sources require an absolute directory".into(),
            ));
        }
        copy_tree_without_symlinks(&path, destination)?;
        let marker = destination.join(".corinth-local-revision");
        fs::write(
            marker,
            source.revision.as_deref().unwrap_or_default().as_bytes(),
        )?;
        Ok(())
    }

    fn acquire_crate(
        &self,
        source: &RecipeSource,
        destination: &Path,
    ) -> Result<(), HardwareError> {
        let package = source
            .package
            .as_deref()
            .ok_or_else(|| HardwareError::InvalidSource("crate package is missing".into()))?;
        let version = source
            .version
            .as_deref()
            .ok_or_else(|| HardwareError::InvalidSource("crate version is missing".into()))?;
        let generated_url;
        let url = if let Some(url) = source.url.as_deref() {
            url
        } else {
            generated_url = format!("https://crates.io/api/v1/crates/{package}/{version}/download");
            &generated_url
        };
        if !self.allow_network || !is_exact_crates_io_url(url, package, version) {
            return Err(HardwareError::InvalidSource(
                "crates-io sources require the crates.io HTTPS download URL and network permission"
                    .into(),
            ));
        }
        fs::create_dir_all(destination)?;
        let archive = destination.with_extension("crate");
        run_direct(
            "curl",
            &[
                "--fail",
                "--silent",
                "--show-error",
                "--location",
                "--proto",
                "=https",
                "--tlsv1.2",
                url,
                "--output",
                path_str(&archive)?,
            ],
            destination
                .parent()
                .ok_or_else(|| HardwareError::SourceUnavailable("crate parent missing".into()))?,
            true,
        )?;
        verify_download_checksum(&archive, source.checksum.as_deref())?;
        run_direct(
            "tar",
            &[
                "--extract",
                "--gzip",
                "--file",
                path_str(&archive)?,
                "--strip-components=1",
                "--directory",
                path_str(destination)?,
            ],
            destination
                .parent()
                .ok_or_else(|| HardwareError::SourceUnavailable("crate parent missing".into()))?,
            false,
        )?;
        reject_symlinks(destination)?;
        fs::remove_file(archive)?;
        Ok(())
    }

    fn acquire_archive(
        &self,
        source: &RecipeSource,
        destination: &Path,
    ) -> Result<(), HardwareError> {
        let url = source
            .url
            .as_deref()
            .ok_or_else(|| HardwareError::InvalidSource("archive URL is missing".into()))?;
        let checksum = source
            .checksum
            .as_deref()
            .ok_or_else(|| HardwareError::InvalidSource("archive checksum is missing".into()))?;
        if !self.allow_network || !is_https_url(url) || !valid_digest(checksum) {
            return Err(HardwareError::InvalidSource(
                "archives require an HTTPS URL, checksum, and network permission".into(),
            ));
        }
        fs::create_dir_all(destination)?;
        let archive = destination.with_extension("archive");
        run_direct(
            "curl",
            &[
                "--fail",
                "--silent",
                "--show-error",
                "--location",
                "--proto",
                "=https",
                "--tlsv1.2",
                url,
                "--output",
                path_str(&archive)?,
            ],
            destination
                .parent()
                .ok_or_else(|| HardwareError::SourceUnavailable("archive parent missing".into()))?,
            true,
        )?;
        verify_download_checksum(&archive, Some(checksum))?;
        run_direct(
            "tar",
            &[
                "--extract",
                "--gzip",
                "--file",
                path_str(&archive)?,
                "--strip-components=1",
                "--directory",
                path_str(destination)?,
            ],
            destination
                .parent()
                .ok_or_else(|| HardwareError::SourceUnavailable("archive parent missing".into()))?,
            false,
        )?;
        reject_symlinks(destination)?;
        fs::remove_file(archive)?;
        Ok(())
    }

    fn measure_outputs(
        &self,
        recipe: &RecipeDocument,
        source_dir: &Path,
        expected: Option<(&str, &str)>,
    ) -> Result<(String, Vec<PathBuf>), HardwareError> {
        if recipe.build.outputs.as_slice() == ["@install-tree"] {
            return self.measure_install_tree(recipe, source_dir, expected);
        }
        if recipe.build.outputs.is_empty() {
            return Err(HardwareError::InvalidRecipe(
                "build.outputs is empty".into(),
            ));
        }
        let mut entries = Vec::new();
        for output in &recipe.build.outputs {
            let relative = safe_relative_path(output)?;
            let path = source_dir.join(relative);
            let metadata = fs::symlink_metadata(&path)
                .map_err(|_| HardwareError::OutputRejected(output.clone()))?;
            if !metadata.file_type().is_file() || metadata.len() > MAX_OUTPUT_BYTES {
                return Err(HardwareError::OutputRejected(output.clone()));
            }
            let bytes = read_bounded(&path, MAX_OUTPUT_BYTES)
                .map_err(|_| HardwareError::OutputRejected(output.clone()))?;
            entries.push((output.as_str(), bytes));
        }
        entries.sort_by(|left, right| left.0.cmp(right.0));
        let mut digest = Sha256::new();
        for (path, bytes) in &entries {
            digest.update(path.as_bytes());
            digest.update([0]);
            digest.update(bytes);
        }
        let actual = hex_digest(&digest.finalize());
        if let Some((package, expected)) = expected
            && actual != expected
        {
            return Err(HardwareError::ArtifactDigestMismatch {
                package: package.into(),
                expected: expected.into(),
                actual,
            });
        }
        let destination = self.artifact_root.join(format!(
            "{}-{}-{}",
            recipe.package.name, recipe.package.version, recipe.package.release
        ));
        fs::create_dir_all(&destination)?;
        let mut published = Vec::with_capacity(entries.len());
        for (relative, bytes) in entries {
            let target = destination.join(safe_relative_path(relative)?);
            atomic_write(&target, &bytes)?;
            published.push(target);
        }
        Ok((actual, published))
    }

    fn measure_install_tree(
        &self,
        recipe: &RecipeDocument,
        source_dir: &Path,
        expected: Option<(&str, &str)>,
    ) -> Result<(String, Vec<PathBuf>), HardwareError> {
        let install_root = source_dir.join(".corinth-install");
        let metadata = fs::symlink_metadata(&install_root)
            .map_err(|_| HardwareError::OutputRejected("@install-tree".into()))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(HardwareError::OutputRejected("@install-tree".into()));
        }
        let mut entries = Vec::new();
        collect_install_files_with_modes(&install_root, &install_root, &mut entries)?;
        if entries.is_empty() {
            return Err(HardwareError::OutputRejected("@install-tree".into()));
        }
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        let mut digest = Sha256::new();
        let mut total = 0_u64;
        for (relative, bytes, mode) in &entries {
            total = total
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| HardwareError::OutputRejected(relative.clone()))?;
            if total > MAX_OUTPUT_BYTES {
                return Err(HardwareError::OutputRejected(
                    "COSMIC install tree exceeds the output limit".into(),
                ));
            }
            digest.update(relative.as_bytes());
            digest.update([0]);
            if expected.is_none() {
                digest.update(mode.to_le_bytes());
            }
            digest.update(bytes);
        }
        let actual = hex_digest(&digest.finalize());
        if let Some((package, expected)) = expected
            && actual != expected
        {
            return Err(HardwareError::ArtifactDigestMismatch {
                package: package.into(),
                expected: expected.into(),
                actual,
            });
        }

        let destination = self.artifact_root.join(format!(
            "{}-{}-{}",
            recipe.package.name, recipe.package.version, recipe.package.release
        ));
        if let Ok(existing) = fs::symlink_metadata(&destination) {
            if existing.file_type().is_symlink() || !existing.is_dir() {
                return Err(HardwareError::OutputRejected(
                    destination.display().to_string(),
                ));
            }
            reject_symlinks(&destination)?;
            fs::remove_dir_all(&destination)?;
        }
        fs::create_dir_all(&destination)?;
        let mut published = Vec::with_capacity(entries.len());
        for (relative, bytes, mode) in entries {
            let target = destination.join(safe_relative_path(&relative)?);
            atomic_write_mode(&target, &bytes, mode)?;
            published.push(target);
        }
        Ok((actual, published))
    }
}

const ARACH_KERNEL_REPOSITORY: &str = "https://github.com/SisyphusAeolides/Arach-Kernel.git";
const ARACH_PUSH_REPOSITORY: &str = "https://github.com/SisyphusAeolides/Push.git";

fn is_fixed_kernel_recipe(recipe: &RecipeDocument) -> bool {
    if recipe.package.name != "arach-kernel" || recipe.source.len() != 2 {
        return false;
    }
    let kernel = &recipe.source[0];
    let push = &recipe.source[1];
    let ordered_sources = kernel.kind == "git"
        && kernel.url.as_deref() == Some(ARACH_KERNEL_REPOSITORY)
        && push.kind == "git"
        && push.url.as_deref() == Some(ARACH_PUSH_REPOSITORY);
    if !ordered_sources {
        return false;
    }
    match recipe.build.system.as_str() {
        "arach-kernel" => {
            kernel.destination.is_none() && push.destination.as_deref() == Some("sources/push")
        }
        "custom" => kernel.destination.is_none() && push.destination.is_none(),
        _ => false,
    }
}

fn kernel_materialization_sources(
    recipe: &RecipeDocument,
) -> Result<Vec<RecipeSource>, HardwareError> {
    if !is_fixed_kernel_recipe(recipe) {
        return Ok(recipe.source.clone());
    }
    let mut sources = recipe.source.clone();
    if recipe.build.system == "custom" {
        sources[1].destination = Some("sources/push".into());
    }
    Ok(sources)
}

fn validate_recipe(
    recipe: &RecipeDocument,
    intent: &CorinthIntent,
    target_arch: &str,
) -> Result<(), HardwareError> {
    if recipe.format != RECIPE_FORMAT
        || recipe.package.name != intent.name
        || recipe.package.version != intent.version
        || recipe.package.summary.trim().is_empty()
        || recipe.package.license.trim().is_empty()
        || recipe.package.architectures.is_empty()
        || !recipe
            .package
            .architectures
            .iter()
            .any(|arch| arch == target_arch)
    {
        return Err(HardwareError::InvalidRecipe(format!(
            "identity or target mismatch for {}",
            intent.name
        )));
    }
    let expected_scope = match intent.scope {
        PackageScope::System => "system",
        PackageScope::Driver => "driver",
        PackageScope::Firmware => "firmware",
    };
    let expected_authority = match intent.repository {
        RepositoryAuthority::ArachNative => "arach-native",
        RepositoryAuthority::ArachHardware => "arach-hardware",
    };
    if recipe.package.scope != expected_scope
        || recipe.package.publish_authority != expected_authority
    {
        return Err(HardwareError::InvalidRecipe(format!(
            "scope or authority mismatch for {}",
            intent.name
        )));
    }
    if recipe.source.is_empty() {
        return Err(HardwareError::InvalidRecipe(
            "at least one locked source is required".into(),
        ));
    }
    let mut source_destinations = BTreeSet::new();
    for source in &recipe.source {
        validate_source(source)?;
        if let Some(destination) = source.destination.as_deref() {
            safe_source_destination(destination)?;
            if !source_destinations.insert(destination) {
                return Err(HardwareError::InvalidRecipe(format!(
                    "duplicate source destination: {destination}"
                )));
            }
        }
    }
    if !valid_build_system(&recipe.build.system) {
        return Err(HardwareError::UnsupportedBuildSystem(
            recipe.build.system.clone(),
        ));
    }
    validate_cargo_closure(recipe)?;
    for dependency in &recipe.build.depends {
        if !valid_package_atom(dependency) {
            return Err(HardwareError::InvalidRecipe(format!(
                "invalid build dependency: {dependency}"
            )));
        }
    }
    if recipe.build.depends.iter().collect::<BTreeSet<_>>().len() != recipe.build.depends.len() {
        return Err(HardwareError::InvalidRecipe(
            "build dependencies contain duplicates".into(),
        ));
    }
    if let Some(runtime) = &recipe.runtime {
        for (label, values) in [
            ("runtime dependency", &runtime.depends),
            ("runtime capability", &runtime.provides),
            ("runtime conflict", &runtime.conflicts),
        ] {
            if values.iter().any(|value| !valid_package_atom(value))
                || values.iter().collect::<BTreeSet<_>>().len() != values.len()
            {
                return Err(HardwareError::InvalidRecipe(format!(
                    "invalid or duplicate {label}"
                )));
            }
        }
    }
    if recipe.build.commands.is_empty() || recipe.build.outputs.is_empty() {
        return Err(HardwareError::InvalidRecipe(
            "build commands and outputs are required".into(),
        ));
    }
    if recipe.build.system == "cosmic" {
        if recipe.build.commands != ["just build", "just install"]
            || recipe.build.outputs.as_slice() != ["@install-tree"]
        {
            return Err(HardwareError::InvalidRecipe(
                "COSMIC recipes must use the fixed workspace adapter".into(),
            ));
        }
    } else if is_fixed_kernel_recipe(recipe) {
        if recipe.policy.network
            || recipe.build.commands != ["cargo build-kernel-package"]
            || recipe.build.outputs.as_slice()
                != ["target/package-kernel/x86_64-arach/release/arach"]
        {
            return Err(HardwareError::InvalidRecipe(
                "Arach kernel recipes must use the fixed offline kernel adapter".into(),
            ));
        }
    } else if recipe.package.name == "arach-kernel" || recipe.build.system == "arach-kernel" {
        return Err(HardwareError::InvalidRecipe(
            "Arach kernel recipe does not match the fixed adapter contract".into(),
        ));
    } else {
        if matches!(intent.scope, PackageScope::Driver | PackageScope::Firmware)
            && recipe.build.outputs.as_slice() != ["@install-tree"]
        {
            return Err(HardwareError::InvalidRecipe(
                "driver and firmware recipes must publish @install-tree".into(),
            ));
        }
        for output in &recipe.build.outputs {
            safe_relative_path(output)?;
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CargoLockDocument {
    version: u32,
    #[serde(default)]
    package: Vec<CargoLockPackage>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CargoLockPackage {
    name: String,
    version: String,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    checksum: Option<String>,
    #[serde(default)]
    dependencies: Vec<String>,
}

fn validate_cargo_closure(recipe: &RecipeDocument) -> Result<(), HardwareError> {
    let Some(closure) = &recipe.cargo_closure else {
        if recipe
            .source
            .iter()
            .any(|source| matches!(source.kind.as_str(), "crates-io" | "crates.io" | "crate"))
        {
            return Err(HardwareError::InvalidRecipe(
                "crates.io recipes require a complete Cargo closure".into(),
            ));
        }
        return Ok(());
    };
    if recipe.build.system != "cargo"
        || recipe.policy.network
        || recipe.build.commands.iter().any(|command| {
            !command
                .split_ascii_whitespace()
                .any(|word| word == "--locked")
        })
    {
        return Err(HardwareError::InvalidRecipe(
            "Cargo closures require offline cargo commands with --locked".into(),
        ));
    }
    validate_cargo_lock_closure(
        &closure.lock,
        &closure.packages,
        &recipe.package.name,
        &recipe.package.version,
    )?;
    let crate_sources = recipe
        .source
        .iter()
        .filter(|source| matches!(source.kind.as_str(), "crates-io" | "crates.io" | "crate"))
        .collect::<Vec<_>>();
    let root_sources = crate_sources
        .iter()
        .filter(|source| {
            source.package.as_deref() == Some(recipe.package.name.as_str())
                && source.version.as_deref() == Some(recipe.package.version.as_str())
                && source.destination.is_none()
        })
        .count();
    if root_sources != 1
        || crate_sources.len() != closure.packages.len() + 1
        || closure.packages.iter().any(|package| {
            !crate_sources.iter().any(|source| {
                source.package.as_deref() == Some(package.name.as_str())
                    && source.version.as_deref() == Some(package.version.as_str())
                    && source.checksum.as_deref() == Some(package.checksum.as_str())
                    && source.destination.as_deref()
                        == Some(
                            format!(".corinth-vendor/{}-{}", package.name, package.version)
                                .as_str(),
                        )
            })
        })
    {
        return Err(HardwareError::InvalidRecipe(
            "Cargo sources do not match the locked package closure".into(),
        ));
    }
    Ok(())
}

pub fn validate_cargo_lock_closure(
    lock_text: &str,
    packages: &[RecipeCargoPackage],
    root_name: &str,
    root_version: &str,
) -> Result<(), HardwareError> {
    let lock: CargoLockDocument = toml::from_str(lock_text)
        .map_err(|error| HardwareError::InvalidRecipe(error.to_string()))?;
    if !(3..=4).contains(&lock.version) || lock.package.is_empty() {
        return Err(HardwareError::InvalidRecipe(
            "unsupported or empty Cargo lock".into(),
        ));
    }
    let mut locked = Vec::new();
    let mut root_count = 0usize;
    for package in lock.package {
        let Some(source) = package.source else {
            if package.name == root_name
                && package.version == root_version
                && package.checksum.is_none()
            {
                root_count += 1;
                continue;
            }
            return Err(HardwareError::InvalidRecipe(
                "Cargo lock contains an unexpected local package".into(),
            ));
        };
        if package.name == root_name && package.version == root_version {
            return Err(HardwareError::InvalidRecipe(
                "Cargo root appears as a registry dependency".into(),
            ));
        }
        if source != "registry+https://github.com/rust-lang/crates.io-index"
            || package
                .dependencies
                .iter()
                .any(|value| value.trim().is_empty())
        {
            return Err(HardwareError::InvalidRecipe(
                "Cargo closure contains a non-crates.io dependency".into(),
            ));
        }
        let checksum = package.checksum.ok_or_else(|| {
            HardwareError::InvalidRecipe("Cargo registry checksum is missing".into())
        })?;
        if !valid_package_atom_extended(&package.name)
            || !valid_version(&package.version)
            || !valid_digest(&checksum)
        {
            return Err(HardwareError::InvalidRecipe(
                "Cargo lock identity is invalid".into(),
            ));
        }
        locked.push(RecipeCargoPackage {
            name: package.name,
            version: package.version,
            checksum,
        });
    }
    locked.sort_by(|left, right| (&left.name, &left.version).cmp(&(&right.name, &right.version)));
    if root_count != 1 || locked.windows(2).any(|pair| pair[0] == pair[1]) || locked != packages {
        return Err(HardwareError::InvalidRecipe(
            "Cargo package closure does not match Cargo.lock".into(),
        ));
    }
    Ok(())
}

fn prepare_cargo_closure(recipe: &RecipeDocument, source_root: &Path) -> Result<(), HardwareError> {
    let Some(closure) = &recipe.cargo_closure else {
        return Ok(());
    };
    validate_cargo_closure(recipe)?;
    let configuration_root = source_root.join(".cargo");
    if configuration_root.exists() {
        return Err(HardwareError::InvalidSource(
            "Cargo source contains a conflicting .cargo directory".into(),
        ));
    }
    fs::create_dir(&configuration_root)?;
    fs::write(
        configuration_root.join("config.toml"),
        b"[source.crates-io]\nreplace-with = \"corinth-vendor\"\n\n[source.corinth-vendor]\ndirectory = \".corinth-vendor\"\n\n[net]\noffline = true\n",
    )?;
    let lock_path = source_root.join("Cargo.lock");
    if let Ok(metadata) = fs::symlink_metadata(&lock_path)
        && (metadata.file_type().is_symlink() || !metadata.is_file())
    {
        return Err(HardwareError::InvalidSource(
            "Cargo.lock is not a regular file".into(),
        ));
    }
    fs::write(lock_path, closure.lock.as_bytes())?;
    for package in &closure.packages {
        if package.name == recipe.package.name && package.version == recipe.package.version {
            continue;
        }
        let directory = source_root
            .join(".corinth-vendor")
            .join(format!("{}-{}", package.name, package.version));
        let metadata = fs::symlink_metadata(&directory)
            .map_err(|_| HardwareError::InvalidSource(directory.display().to_string()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(HardwareError::InvalidSource(
                directory.display().to_string(),
            ));
        }
        let mut files = BTreeMap::new();
        collect_cargo_vendor_digests(&directory, &directory, &mut files)?;
        let checksum = serde_json::json!({
            "files": files,
            "package": package.checksum,
        });
        let bytes = serde_json::to_vec(&checksum)
            .map_err(|error| HardwareError::InvalidSource(error.to_string()))?;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(directory.join(".cargo-checksum.json"))?
            .write_all(&bytes)?;
    }
    Ok(())
}

fn collect_cargo_vendor_digests(
    root: &Path,
    directory: &Path,
    files: &mut BTreeMap<String, String>,
) -> Result<(), HardwareError> {
    let mut entries = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(HardwareError::InvalidSource(path.display().to_string()));
        }
        if metadata.is_dir() {
            collect_cargo_vendor_digests(root, &path, files)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| HardwareError::InvalidSource(path.display().to_string()))?;
            let relative = relative
                .to_str()
                .ok_or_else(|| HardwareError::InvalidSource(path.display().to_string()))?
                .replace('\\', "/");
            let bytes = read_bounded(&path, MAX_OUTPUT_BYTES)
                .map_err(|error| HardwareError::InvalidSource(error.to_string()))?;
            if files
                .insert(relative, hex_digest(&Sha256::digest(bytes)))
                .is_some()
            {
                return Err(HardwareError::InvalidSource(
                    "duplicate Cargo vendor path".into(),
                ));
            }
        } else {
            return Err(HardwareError::InvalidSource(path.display().to_string()));
        }
    }
    Ok(())
}

fn validate_source(source: &RecipeSource) -> Result<(), HardwareError> {
    match source.kind.as_str() {
        "git" => {
            let url = source
                .url
                .as_deref()
                .ok_or_else(|| HardwareError::InvalidSource("git URL is missing".into()))?;
            let revision = source
                .revision
                .as_deref()
                .ok_or_else(|| HardwareError::InvalidSource("git revision is missing".into()))?;
            if !is_https_url(url) || !valid_git_revision(revision) {
                return Err(HardwareError::InvalidSource(
                    "Git sources require HTTPS and a full revision".into(),
                ));
            }
            if source.checksum.is_some() || source.package.is_some() || source.version.is_some() {
                return Err(HardwareError::InvalidSource(
                    "Git sources cannot contain archive or crates.io fields".into(),
                ));
            }
        }
        "archive" => {
            let url = source
                .url
                .as_deref()
                .ok_or_else(|| HardwareError::InvalidSource("archive URL is missing".into()))?;
            let checksum = source.checksum.as_deref().ok_or_else(|| {
                HardwareError::InvalidSource("archive checksum is missing".into())
            })?;
            if !is_https_url(url) || !valid_digest(checksum) {
                return Err(HardwareError::InvalidSource(
                    "archives require HTTPS and a SHA-256 checksum".into(),
                ));
            }
            if source.revision.is_some() || source.package.is_some() || source.version.is_some() {
                return Err(HardwareError::InvalidSource(
                    "archives cannot contain Git or crates.io fields".into(),
                ));
            }
        }
        "crates-io" | "crates.io" | "crate" => {
            let package = source.package.as_deref().ok_or_else(|| {
                HardwareError::InvalidSource("crates.io package is missing".into())
            })?;
            let version = source.version.as_deref().ok_or_else(|| {
                HardwareError::InvalidSource("crates.io version is missing".into())
            })?;
            let checksum = source.checksum.as_deref().ok_or_else(|| {
                HardwareError::InvalidSource("crates.io checksum is missing".into())
            })?;
            if !valid_package_atom(package)
                || version.trim().is_empty()
                || !valid_digest(checksum)
                || source.revision.is_some()
                || source
                    .url
                    .as_deref()
                    .is_some_and(|url| !is_exact_crates_io_url(url, package, version))
            {
                return Err(HardwareError::InvalidSource(
                    "crates.io source fields are not an immutable package lock".into(),
                ));
            }
        }
        "local" => {
            let path = source
                .url
                .as_deref()
                .ok_or_else(|| HardwareError::InvalidSource("local path is missing".into()))?;
            if path.is_empty() || !Path::new(path).is_absolute() || source.submodules {
                return Err(HardwareError::InvalidSource(
                    "local source requires an absolute path and no submodules".into(),
                ));
            }
            if source.revision.is_some()
                || source.checksum.is_some()
                || source.package.is_some()
                || source.version.is_some()
            {
                return Err(HardwareError::InvalidSource(
                    "local source has unsupported lock fields".into(),
                ));
            }
        }
        other => return Err(HardwareError::UnsupportedSource(other.into())),
    }
    Ok(())
}

fn valid_package_atom(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn valid_package_atom_extended(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            !byte.is_ascii_control()
                && !byte.is_ascii_whitespace()
                && !matches!(byte, b'/' | b'\\' | b'@')
        })
}

fn valid_build_system(value: &str) -> bool {
    matches!(
        value,
        "cargo"
            | "c"
            | "fortran"
            | "idris2"
            | "agda"
            | "make"
            | "cmake"
            | "meson"
            | "custom"
            | "cosmic"
            | "arach-kernel"
    )
}

fn find_recipe(root: &Path, package: &str) -> Result<PathBuf, HardwareError> {
    if !root.is_dir() {
        return Err(HardwareError::PackageNotFound(package.into()));
    }
    let preferred = root.join("base").join(package).join("package.toml");
    if preferred.is_file() {
        return Ok(preferred);
    }
    let mut stack = vec![(root.to_path_buf(), 0_u8)];
    let mut seen = 0_usize;
    while let Some((directory, depth)) = stack.pop() {
        if depth > 4 || seen > 4096 {
            break;
        }
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() {
                continue;
            }
            let path = entry.path();
            if metadata.is_dir() {
                stack.push((path, depth + 1));
            } else if metadata.is_file()
                && path.file_name().is_some_and(|name| name == "package.toml")
                && path
                    .parent()
                    .and_then(Path::file_name)
                    .is_some_and(|name| name == package)
            {
                return Ok(path);
            }
            seen += 1;
        }
    }
    Err(HardwareError::PackageNotFound(package.into()))
}

fn source_lock_digest(sources: &[RecipeSource]) -> [u8; 32] {
    Sha256::digest(source_lock_bytes(sources)).into()
}

fn source_lock_bytes(sources: &[RecipeSource]) -> Vec<u8> {
    let mut output = Vec::new();
    for source in sources {
        for value in [
            Some(source.kind.as_str()),
            source.url.as_deref(),
            source.revision.as_deref(),
            source.checksum.as_deref(),
            source.package.as_deref(),
            source.version.as_deref(),
        ] {
            output.extend_from_slice(value.unwrap_or_default().as_bytes());
            output.push(b'\n');
        }
        output.extend_from_slice(if source.submodules {
            b"submodules=1\n"
        } else {
            b"submodules=0\n"
        });
        if let Some(destination) = source.destination.as_deref() {
            output.extend_from_slice(b"destination=");
            output.extend_from_slice(destination.as_bytes());
            output.push(b'\n');
        }
    }
    output
}

fn source_revision(sources: &[RecipeSource], source_lock: &str) -> String {
    let revisions: Vec<&str> = sources
        .iter()
        .filter_map(|source| source.revision.as_deref().or(source.version.as_deref()))
        .collect();
    if revisions.len() == 1 {
        revisions[0].to_string()
    } else {
        // A multi-source recipe has no single upstream revision.  Keeping the
        // canonical lock digest in the receipt makes that fact explicit.
        format!("source-lock:{source_lock}")
    }
}

fn verify_download_checksum(path: &Path, expected: Option<&str>) -> Result<(), HardwareError> {
    let expected = expected
        .ok_or_else(|| HardwareError::InvalidSource("download checksum is missing".into()))?;
    if !valid_digest(expected) {
        return Err(HardwareError::InvalidSource(
            "download checksum is not a SHA-256 digest".into(),
        ));
    }
    let bytes = read_bounded(path, MAX_OUTPUT_BYTES)
        .map_err(|error| HardwareError::SourceUnavailable(error.to_string()))?;
    let actual = hex_digest(&Sha256::digest(bytes));
    if actual != expected {
        return Err(HardwareError::InvalidSource(format!(
            "download checksum mismatch: expected {expected}, got {actual}"
        )));
    }
    Ok(())
}

fn run_arach_kernel_workspace(
    directory: &Path,
    network: bool,
    compiler: &CompilerTarget,
    allow_host_toolchains: bool,
) -> Result<(), HardwareError> {
    if network {
        return Err(HardwareError::BuildNetworkNotAllowed);
    }
    let target = directory.join("x86_64-arach.json");
    let push_manifest = directory.join("sources/push/Cargo.toml");
    let probe_manifest = directory.join("probes/c0/Cargo.toml");
    for required in [
        directory.join("Cargo.toml"),
        target.clone(),
        push_manifest.clone(),
        probe_manifest.clone(),
    ] {
        let metadata = fs::symlink_metadata(&required)
            .map_err(|_| HardwareError::InvalidSource(required.display().to_string()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(HardwareError::InvalidSource(format!(
                "kernel adapter input is not a regular file: {}",
                required.display()
            )));
        }
    }

    let push_target = directory.join("target/package-push");
    let probe_target = directory.join("target/package-probe");
    let kernel_target = directory.join("target/package-kernel");
    run_kernel_cargo(
        directory,
        &[
            "build",
            "--locked",
            "--release",
            "--manifest-path",
            path_str(&push_manifest)?,
            "--target",
            path_str(&target)?,
            "-Z",
            "json-target-spec",
            "-Z",
            "build-std=core,alloc,compiler_builtins",
            "-Z",
            "build-std-features=compiler-builtins-mem",
            "--features",
            "os-bin",
        ],
        &[("CARGO_TARGET_DIR", path_str(&push_target)?)],
        compiler,
        allow_host_toolchains,
    )?;
    run_kernel_cargo(
        directory,
        &[
            "build",
            "--locked",
            "--release",
            "--manifest-path",
            path_str(&probe_manifest)?,
            "--target",
            path_str(&target)?,
            "-Z",
            "json-target-spec",
            "-Z",
            "build-std=core,alloc,compiler_builtins",
            "-Z",
            "build-std-features=compiler-builtins-mem",
        ],
        &[("CARGO_TARGET_DIR", path_str(&probe_target)?)],
        compiler,
        allow_host_toolchains,
    )?;

    let push_image = push_target.join("x86_64-arach/release/push");
    let probe_image = probe_target.join("x86_64-arach/release/arach-c0-probe");
    require_nonempty_regular(&push_image, "measured Push image")?;
    require_nonempty_regular(&probe_image, "measured bootstrap image")?;
    run_kernel_cargo(
        directory,
        &[
            "build",
            "--locked",
            "--release",
            "-p",
            "arach",
            "--bin",
            "arach",
            "--no-default-features",
            "--features",
            "kernel-bin,reference-driver,fortran-control",
            "--target",
            path_str(&target)?,
            "-Z",
            "json-target-spec",
            "-Z",
            "build-std=core,alloc,compiler_builtins",
            "-Z",
            "build-std-features=compiler-builtins-mem",
        ],
        &[
            ("CARGO_TARGET_DIR", path_str(&kernel_target)?),
            ("ARACH_PUSH_IMAGE", path_str(&push_image)?),
            ("ARACH_BOOTSTRAP_IMAGE", path_str(&probe_image)?),
            ("ARACH_BOOTSTRAP_ABI", "linux"),
        ],
        compiler,
        allow_host_toolchains,
    )?;
    require_nonempty_regular(
        &kernel_target.join("x86_64-arach/release/arach"),
        "Arach kernel image",
    )
}

fn run_kernel_cargo(
    directory: &Path,
    arguments: &[&str],
    environment: &[(&str, &str)],
    compiler: &CompilerTarget,
    allow_host_toolchains: bool,
) -> Result<(), HardwareError> {
    let status = run_sandboxed(
        "cargo",
        arguments,
        directory,
        false,
        environment,
        SandboxBuildContext {
            compiler: Some(compiler),
            allow_host_toolchains,
            build_dependency_root: None,
        },
    )?;
    if status.success() {
        Ok(())
    } else {
        Err(HardwareError::CommandFailed(
            "fixed Arach kernel build phase failed".into(),
        ))
    }
}

fn require_nonempty_regular(path: &Path, label: &str) -> Result<(), HardwareError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| HardwareError::OutputRejected(path.display().to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
        return Err(HardwareError::OutputRejected(format!(
            "{label} is not a non-empty regular file: {}",
            path.display()
        )));
    }
    Ok(())
}

fn run_build_command(
    command: &str,
    system: &str,
    directory: &Path,
    network: bool,
    compiler: &CompilerTarget,
    allow_host_toolchains: bool,
    build_dependency_root: Option<&Path>,
) -> Result<(), HardwareError> {
    let argv = parse_command(command)?;
    if argv.is_empty() || !allowed_program(system, argv[0]) {
        return Err(HardwareError::CommandRejected(command.into()));
    }
    let status = run_sandboxed(
        argv[0],
        &argv[1..],
        directory,
        network,
        &[],
        SandboxBuildContext {
            compiler: Some(compiler),
            allow_host_toolchains,
            build_dependency_root,
        },
    )?;
    if !status.success() {
        return Err(HardwareError::CommandFailed(command.into()));
    }
    Ok(())
}

/// The pinned upstream COSMIC workspace is a compatibility build boundary:
/// its checked-in `justfile` coordinates the component-specific Cargo and
/// Make builds and installs into a caller-owned root. Corinth does not accept
/// arbitrary `just` commands; only the fixed `build` and `install` phases are
/// reached from the `cosmic` recipe system.
fn run_cosmic_workspace(
    directory: &Path,
    network: bool,
    compiler: &CompilerTarget,
    allow_host_toolchains: bool,
    build_dependency_root: Option<&Path>,
) -> Result<(), HardwareError> {
    let justfile = directory.join("justfile");
    let metadata = fs::symlink_metadata(&justfile)
        .map_err(|_| HardwareError::InvalidSource("COSMIC justfile is missing".into()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(HardwareError::InvalidSource(
            "COSMIC justfile is not a regular file".into(),
        ));
    }
    run_cosmic_phase(
        directory,
        &["build"],
        network,
        compiler,
        allow_host_toolchains,
        build_dependency_root,
    )?;
    let install_root = directory.join(".corinth-install");
    if let Ok(existing) = fs::symlink_metadata(&install_root) {
        if existing.file_type().is_symlink() || !existing.is_dir() {
            return Err(HardwareError::InvalidSource(
                "COSMIC install root is unsafe".into(),
            ));
        }
        fs::remove_dir_all(&install_root)?;
    }
    fs::create_dir(&install_root)?;
    let rootdir = format!("rootdir={}", install_root.display());
    run_cosmic_phase(
        directory,
        &[&rootdir, "prefix=/usr", "install"],
        network,
        compiler,
        allow_host_toolchains,
        build_dependency_root,
    )?;
    install_cosmic_greeter_config(directory, &install_root)?;
    reject_symlinks(&install_root)
}

/// The upstream COSMIC greeter build installs its executable and launcher
/// through `just install`, while the distribution package owns the greetd
/// configuration file.  Keep that runtime contract in the pinned COSMIC
/// adapter so a Corinth install tree cannot advertise a greeter which has no
/// greetd session definition.
fn install_cosmic_greeter_config(
    source_root: &Path,
    install_root: &Path,
) -> Result<(), HardwareError> {
    let source = source_root.join("cosmic-greeter/cosmic-greeter.toml");
    let metadata = fs::symlink_metadata(&source)
        .map_err(|_| HardwareError::InvalidSource("COSMIC greetd config is missing".into()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(HardwareError::InvalidSource(
            "COSMIC greetd config is not a regular file".into(),
        ));
    }

    let destination = install_root.join("etc/greetd/cosmic-greeter.toml");
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(&source, &destination)?;
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o644))?;
    Ok(())
}

fn run_cosmic_phase(
    directory: &Path,
    arguments: &[&str],
    network: bool,
    compiler: &CompilerTarget,
    allow_host_toolchains: bool,
    build_dependency_root: Option<&Path>,
) -> Result<(), HardwareError> {
    let status = run_sandboxed(
        "just",
        arguments,
        directory,
        network,
        &[],
        SandboxBuildContext {
            compiler: Some(compiler),
            allow_host_toolchains,
            build_dependency_root,
        },
    )?;
    if !status.success() {
        return Err(HardwareError::CommandFailed(format!(
            "just {} failed",
            arguments.join(" ")
        )));
    }
    Ok(())
}

/// Executes an admitted build phase inside a fresh bubblewrap boundary.
///
/// The source tree is the only persistent writable mount. Toolchains and
/// package caches are read-only, HOME and temporary state are private, all
/// capabilities are dropped, and offline recipes receive a distinct network
/// namespace. A missing or mutable sandbox executable is a hard failure.
#[derive(Clone, Copy)]
struct SandboxBuildContext<'a> {
    compiler: Option<&'a CompilerTarget>,
    allow_host_toolchains: bool,
    build_dependency_root: Option<&'a Path>,
}

fn run_sandboxed(
    program: &str,
    arguments: &[&str],
    directory: &Path,
    network: bool,
    environment: &[(&str, &str)],
    context: SandboxBuildContext<'_>,
) -> Result<std::process::ExitStatus, HardwareError> {
    validate_sandbox_backend()?;
    let source = fs::canonicalize(directory)
        .map_err(|error| HardwareError::CommandRejected(error.to_string()))?;
    let metadata = fs::symlink_metadata(&source)
        .map_err(|error| HardwareError::CommandRejected(error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() || !source.is_absolute() {
        return Err(HardwareError::CommandRejected(
            "sandbox source must be an absolute real directory".into(),
        ));
    }

    let mut command = Command::new(SANDBOX_PROGRAM);
    append_sandbox_boundary(
        &mut command,
        &source,
        network,
        context.allow_host_toolchains,
        context.build_dependency_root,
    )?;
    for (name, value) in environment {
        if !valid_environment_name(name) || value.contains('\0') {
            return Err(HardwareError::CommandRejected(format!(
                "invalid sandbox environment key: {name}"
            )));
        }
        command.args(["--setenv", name, value]);
    }
    if let Some(compiler) = context.compiler {
        append_compiler_environment(&mut command, compiler)?;
    }
    command
        .arg("--")
        .arg(program)
        .args(arguments)
        .stdin(Stdio::null());
    command
        .status()
        .map_err(|error| HardwareError::CommandFailed(error.to_string()))
}

fn append_compiler_environment(
    command: &mut Command,
    target: &CompilerTarget,
) -> Result<(), HardwareError> {
    if target.features.windows(2).any(|pair| pair[0] >= pair[1])
        || target
            .features
            .iter()
            .any(|feature| !target.architecture.supports(*feature))
    {
        return Err(HardwareError::InvalidPlan(
            "compiler target is not a canonical architecture capability set".into(),
        ));
    }

    let (mut native_flags, rust_cpu) = match target.architecture {
        CpuArchitecture::X86_64 => (String::from("-O2 -pipe -march=x86-64"), "x86-64"),
        CpuArchitecture::Aarch64 => (String::from("-O2 -pipe -march=armv8-a"), "generic"),
        CpuArchitecture::Riscv64 => (
            String::from("-O2 -pipe -march=rv64gc -mabi=lp64d"),
            "generic-rv64",
        ),
        CpuArchitecture::Unknown => {
            return Err(HardwareError::InvalidPlan(
                "unknown CPU architecture cannot authorize a native build".into(),
            ));
        }
    };
    let mut rust_features = Vec::with_capacity(target.features.len());
    if target.architecture == CpuArchitecture::Aarch64 && !target.features.is_empty() {
        native_flags.push('+');
    }
    for (index, feature) in target.features.iter().copied().enumerate() {
        let (native, rust) = compiler_feature(target.architecture, feature)?;
        if target.architecture == CpuArchitecture::Aarch64 {
            if index > 0 {
                native_flags.push('+');
            }
            native_flags.push_str(native);
        } else {
            native_flags.push(' ');
            native_flags.push_str(native);
        }
        rust_features.push(rust);
    }
    let mut rust_flags = format!("-Ctarget-cpu={rust_cpu}");
    if !rust_features.is_empty() {
        rust_flags.push_str(" -Ctarget-feature=+");
        rust_flags.push_str(&rust_features.join(",+"));
    }
    for name in ["CFLAGS", "CXXFLAGS", "FFLAGS"] {
        command.args(["--setenv", name, native_flags.as_str()]);
    }
    command.args(["--setenv", "RUSTFLAGS", rust_flags.as_str()]);
    Ok(())
}

fn compiler_feature(
    architecture: CpuArchitecture,
    feature: CpuFeature,
) -> Result<(&'static str, &'static str), HardwareError> {
    let flags = match (architecture, feature) {
        (CpuArchitecture::X86_64, CpuFeature::Aes) => ("-maes", "aes"),
        (CpuArchitecture::X86_64, CpuFeature::Avx) => ("-mavx", "avx"),
        (CpuArchitecture::X86_64, CpuFeature::Avx2) => ("-mavx2", "avx2"),
        (CpuArchitecture::X86_64, CpuFeature::Avx512bw) => ("-mavx512bw", "avx512bw"),
        (CpuArchitecture::X86_64, CpuFeature::Avx512cd) => ("-mavx512cd", "avx512cd"),
        (CpuArchitecture::X86_64, CpuFeature::Avx512dq) => ("-mavx512dq", "avx512dq"),
        (CpuArchitecture::X86_64, CpuFeature::Avx512f) => ("-mavx512f", "avx512f"),
        (CpuArchitecture::X86_64, CpuFeature::Avx512vl) => ("-mavx512vl", "avx512vl"),
        (CpuArchitecture::X86_64, CpuFeature::Bmi1) => ("-mbmi", "bmi1"),
        (CpuArchitecture::X86_64, CpuFeature::Bmi2) => ("-mbmi2", "bmi2"),
        (CpuArchitecture::X86_64, CpuFeature::Fma) => ("-mfma", "fma"),
        (CpuArchitecture::X86_64, CpuFeature::Fxsr) => ("-mfxsr", "fxsr"),
        (CpuArchitecture::X86_64, CpuFeature::Lzcnt) => ("-mlzcnt", "lzcnt"),
        (CpuArchitecture::X86_64, CpuFeature::Mmx) => ("-mmmx", "mmx"),
        (CpuArchitecture::X86_64, CpuFeature::Pclmulqdq) => ("-mpclmul", "pclmulqdq"),
        (CpuArchitecture::X86_64, CpuFeature::Popcnt) => ("-mpopcnt", "popcnt"),
        (CpuArchitecture::X86_64, CpuFeature::Sse) => ("-msse", "sse"),
        (CpuArchitecture::X86_64, CpuFeature::Sse2) => ("-msse2", "sse2"),
        (CpuArchitecture::X86_64, CpuFeature::Sse3) => ("-msse3", "sse3"),
        (CpuArchitecture::X86_64, CpuFeature::Sse41) => ("-msse4.1", "sse4.1"),
        (CpuArchitecture::X86_64, CpuFeature::Sse42) => ("-msse4.2", "sse4.2"),
        (CpuArchitecture::X86_64, CpuFeature::Ssse3) => ("-mssse3", "ssse3"),
        (CpuArchitecture::Aarch64, CpuFeature::Aes) => ("aes", "aes"),
        (CpuArchitecture::Aarch64, CpuFeature::Crc32) => ("crc", "crc"),
        (CpuArchitecture::Aarch64, CpuFeature::Neon) => ("simd", "neon"),
        (CpuArchitecture::Aarch64, CpuFeature::Sha2) => ("sha2", "sha2"),
        (CpuArchitecture::Aarch64, CpuFeature::Sve) => ("sve", "sve"),
        (CpuArchitecture::Aarch64, CpuFeature::Sve2) => ("sve2", "sve2"),
        _ => {
            return Err(HardwareError::InvalidPlan(
                "compiler feature is not valid for the target architecture".into(),
            ));
        }
    };
    Ok(flags)
}

fn compiler_architecture_name(architecture: CpuArchitecture) -> Option<&'static str> {
    match architecture {
        CpuArchitecture::X86_64 => Some("x86-64"),
        CpuArchitecture::Aarch64 => Some("aarch64"),
        CpuArchitecture::Riscv64 => Some("riscv64"),
        CpuArchitecture::Unknown => None,
    }
}

fn validate_sandbox_backend() -> Result<(), HardwareError> {
    let metadata = fs::symlink_metadata(SANDBOX_PROGRAM)
        .map_err(|_| HardwareError::CommandRejected("bubblewrap sandbox is unavailable".into()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
    {
        return Err(HardwareError::CommandRejected(
            "bubblewrap sandbox is not a trusted executable".into(),
        ));
    }
    Ok(())
}

fn append_sandbox_boundary(
    command: &mut Command,
    source: &Path,
    network: bool,
    allow_host_toolchains: bool,
    build_dependency_root: Option<&Path>,
) -> Result<(), HardwareError> {
    command.args([
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
        "--unshare-user",
        "--disable-userns",
        "--cap-drop",
        "ALL",
        "--clearenv",
        "--ro-bind",
        "/usr",
        "/usr",
        "--symlink",
        "usr/bin",
        "/bin",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib64",
        "/lib64",
        "--symlink",
        "usr/sbin",
        "/sbin",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--dir",
        "/run",
        "--dir",
        "/var",
        "--dir",
        "/home",
        "--dir",
        "/etc",
        "--dir",
        "/tmp/corinth-home",
        "--dir",
        "/tmp/corinth-cargo",
        "--hostname",
        "corinth-build",
    ]);
    if network {
        command.arg("--share-net");
    }

    let build_dependency_root = build_dependency_root
        .map(|root| {
            if !root.is_absolute() {
                return Err(HardwareError::CommandRejected(
                    "build dependency root must be absolute".into(),
                ));
            }
            let metadata = fs::symlink_metadata(root)
                .map_err(|error| HardwareError::CommandRejected(error.to_string()))?;
            let canonical = fs::canonicalize(root)
                .map_err(|error| HardwareError::CommandRejected(error.to_string()))?;
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || metadata.permissions().mode() & 0o077 != 0
                || canonical != root
            {
                return Err(HardwareError::CommandRejected(
                    "build dependency root must be a private real directory".into(),
                ));
            }
            Ok(canonical)
        })
        .transpose()?;
    if let Some(root) = &build_dependency_root {
        command.args(["--ro-bind", path_str(root)?, BUILD_DEPENDENCY_MOUNT]);
    }

    for path in [
        "/etc/alternatives",
        "/etc/hosts",
        "/etc/nsswitch.conf",
        "/etc/resolv.conf",
        "/etc/ssl",
        "/etc/pki",
    ] {
        if fs::symlink_metadata(path).is_ok() {
            command.args(["--ro-bind", path, path]);
        }
    }

    let mut tool_roots = BTreeSet::new();
    let mut sandbox_path = vec![PathBuf::from("/usr/bin")];
    if build_dependency_root.is_some() {
        sandbox_path.insert(0, PathBuf::from("/corinth-build/usr/sbin"));
        sandbox_path.insert(0, PathBuf::from("/corinth-build/usr/bin"));
    }
    if allow_host_toolchains {
        sandbox_path.insert(0, PathBuf::from("/usr/local/bin"));
        for name in ["RUSTUP_HOME", "IDRIS2_PREFIX", "AGDA_DIR"] {
            if let Some(root) = absolute_environment_directory(name) {
                tool_roots.insert(root);
            }
        }
        if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
            for relative in [".rustup", ".idris2", ".agda"] {
                let root = home.join(relative);
                if fs::symlink_metadata(&root)
                    .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
                {
                    tool_roots.insert(root);
                }
            }
        }
        if let Some(cargo_home) = cargo_home() {
            let bin = cargo_home.join("bin");
            if fs::symlink_metadata(&bin)
                .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
            {
                sandbox_path.insert(0, bin.clone());
                tool_roots.insert(bin);
            }
        }
    }
    let sandbox_path = std::env::join_paths(&sandbox_path)
        .map_err(|error| HardwareError::CommandRejected(error.to_string()))?;
    let sandbox_path = sandbox_path
        .to_str()
        .ok_or_else(|| HardwareError::CommandRejected("sandbox PATH is not UTF-8".into()))?;
    for root in tool_roots {
        let root = path_str(&root)?;
        command.args(["--ro-bind", root, root]);
    }

    if allow_host_toolchains && let Some(cargo_home) = cargo_home() {
        for child in ["registry", "git"] {
            let cache = cargo_home.join(child);
            if fs::symlink_metadata(&cache)
                .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
            {
                let destination = format!("/tmp/corinth-cargo/{child}");
                command.args(["--ro-bind", path_str(&cache)?, &destination]);
            }
        }
    }

    command
        .args(["--bind", path_str(source)?, path_str(source)?])
        .args(["--chdir", path_str(source)?])
        .args(["--setenv", "HOME", "/tmp/corinth-home"])
        .args(["--setenv", "CARGO_HOME", "/tmp/corinth-cargo"])
        .args(["--setenv", "PATH", sandbox_path])
        .args(["--setenv", "LANG", "C.UTF-8"])
        .args(["--setenv", "LC_ALL", "C.UTF-8"])
        .args(["--setenv", "TZ", "UTC"])
        .args(["--setenv", "SOURCE_DATE_EPOCH", "1"])
        .args(["--setenv", "GIT_CONFIG_NOSYSTEM", "1"])
        .args(["--setenv", "RUSTUP_NO_UPDATE_CHECK", "1"]);
    if build_dependency_root.is_some() {
        command
            .args(["--setenv", "CORINTH_BUILD_ROOT", BUILD_DEPENDENCY_MOUNT])
            .args([
                "--setenv",
                "PKG_CONFIG_SYSROOT_DIR",
                BUILD_DEPENDENCY_MOUNT,
            ])
            .args([
                "--setenv",
                "PKG_CONFIG_LIBDIR",
                "/corinth-build/usr/lib/pkgconfig:/corinth-build/usr/lib64/pkgconfig:/corinth-build/usr/share/pkgconfig",
            ])
            .args([
                "--setenv",
                "CMAKE_PREFIX_PATH",
                "/corinth-build/usr",
            ])
            .args([
                "--setenv",
                "CPATH",
                "/corinth-build/usr/include",
            ])
            .args([
                "--setenv",
                "LIBRARY_PATH",
                "/corinth-build/usr/lib:/corinth-build/usr/lib64",
            ])
            .args([
                "--setenv",
                "LD_LIBRARY_PATH",
                "/corinth-build/usr/lib:/corinth-build/usr/lib64",
            ])
            .args([
                "--setenv",
                "ACLOCAL_PATH",
                "/corinth-build/usr/share/aclocal",
            ]);
    }
    if !network {
        command.args(["--setenv", "CARGO_NET_OFFLINE", "true"]);
    }
    if allow_host_toolchains {
        if let Ok(toolchain) = std::env::var("RUSTUP_TOOLCHAIN") {
            command.args(["--setenv", "RUSTUP_TOOLCHAIN", &toolchain]);
        }
        if let Some(rustup_home) = absolute_environment_directory("RUSTUP_HOME").or_else(|| {
            let path = PathBuf::from(std::env::var_os("HOME")?).join(".rustup");
            fs::symlink_metadata(&path)
                .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
                .then_some(path)
        }) {
            command.args(["--setenv", "RUSTUP_HOME", path_str(&rustup_home)?]);
        }
    }
    Ok(())
}

fn absolute_environment_directory(name: &str) -> Option<PathBuf> {
    let path = PathBuf::from(std::env::var_os(name)?);
    (path.is_absolute()
        && fs::symlink_metadata(&path)
            .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink()))
    .then_some(path)
}

fn cargo_home() -> Option<PathBuf> {
    absolute_environment_directory("CARGO_HOME").or_else(|| {
        let path = PathBuf::from(std::env::var_os("HOME")?).join(".cargo");
        fs::symlink_metadata(&path)
            .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
            .then_some(path)
    })
}

fn valid_environment_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

#[cfg(test)]
fn collect_install_files(
    root: &Path,
    directory: &Path,
    entries: &mut Vec<(String, Vec<u8>)>,
) -> Result<(), HardwareError> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(HardwareError::OutputRejected(path.display().to_string()));
        }
        if metadata.is_dir() {
            collect_install_files(root, &path, entries)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| HardwareError::OutputRejected(path.display().to_string()))?
                .to_str()
                .ok_or_else(|| HardwareError::OutputRejected(path.display().to_string()))?;
            safe_relative_path(relative)?;
            entries.push((
                relative.to_string(),
                read_bounded(&path, MAX_OUTPUT_BYTES)
                    .map_err(|error| HardwareError::OutputRejected(error.to_string()))?,
            ));
        } else {
            return Err(HardwareError::OutputRejected(path.display().to_string()));
        }
    }
    Ok(())
}

fn collect_install_files_with_modes(
    root: &Path,
    directory: &Path,
    entries: &mut Vec<(String, Vec<u8>, u32)>,
) -> Result<(), HardwareError> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(HardwareError::OutputRejected(path.display().to_string()));
        }
        if metadata.is_dir() {
            collect_install_files_with_modes(root, &path, entries)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| HardwareError::OutputRejected(path.display().to_string()))?
                .to_str()
                .ok_or_else(|| HardwareError::OutputRejected(path.display().to_string()))?;
            safe_relative_path(relative)?;
            entries.push((
                relative.to_string(),
                read_bounded(&path, MAX_OUTPUT_BYTES)
                    .map_err(|error| HardwareError::OutputRejected(error.to_string()))?,
                metadata.permissions().mode() & 0o7777,
            ));
        } else {
            return Err(HardwareError::OutputRejected(path.display().to_string()));
        }
    }
    Ok(())
}

fn parse_command(command: &str) -> Result<Vec<&str>, HardwareError> {
    if command.trim().is_empty()
        || command.bytes().any(|byte| {
            matches!(
                byte,
                b';' | b'|'
                    | b'&'
                    | b'>'
                    | b'<'
                    | b'$'
                    | b'`'
                    | b'('
                    | b')'
                    | b'{'
                    | b'}'
                    | b'*'
                    | b'?'
                    | b'\\'
            )
        })
    {
        return Err(HardwareError::CommandRejected(command.into()));
    }
    let words: Vec<_> = command.split_ascii_whitespace().collect();
    if words
        .iter()
        .any(|word| word.contains('"') || word.contains('\''))
    {
        return Err(HardwareError::CommandRejected(command.into()));
    }
    Ok(words)
}

fn allowed_program(system: &str, program: &str) -> bool {
    let common = [
        "cargo", "rustc", "make", "cmake", "meson", "ninja", "cc", "gcc", "clang", "gfortran",
        "flang", "idris2", "agda",
    ];
    common.contains(&program)
        && (system == "custom"
            || (system == "cargo" && matches!(program, "cargo" | "rustc"))
            || (system == "make" && program == "make")
            || (system == "cmake" && matches!(program, "cmake" | "make"))
            || (system == "meson" && matches!(program, "meson" | "ninja"))
            || (system == "c" && matches!(program, "cc" | "gcc" | "clang" | "make"))
            || (system == "fortran" && matches!(program, "gfortran" | "flang" | "make"))
            || (system == "idris2" && program == "idris2")
            || (system == "agda" && program == "agda"))
}

fn run_direct(
    program: &str,
    args: &[&str],
    directory: &Path,
    _network: bool,
) -> Result<(), HardwareError> {
    if !matches!(program, "git" | "curl" | "tar") {
        return Err(HardwareError::CommandRejected(program.into()));
    }
    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir(directory)
        .stdin(Stdio::null());
    if program == "git" {
        command
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_ASKPASS", "/bin/false")
            .env("GIT_ALLOW_PROTOCOL", "https");
    }
    let status = command
        .status()
        .map_err(|error| HardwareError::CommandFailed(error.to_string()))?;
    if !status.success() {
        return Err(HardwareError::CommandFailed(format!("{program} failed")));
    }
    Ok(())
}

fn command_output(program: &str, args: &[&str], directory: &Path) -> Result<String, HardwareError> {
    let output = Command::new(program)
        .args(args)
        .current_dir(directory)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| HardwareError::CommandFailed(error.to_string()))?;
    if !output.status.success() {
        return Err(HardwareError::CommandFailed(format!("{program} failed")));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| HardwareError::CommandFailed("command output is not UTF-8".into()))
}

fn copy_tree_without_symlinks(source: &Path, destination: &Path) -> Result<(), HardwareError> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() {
            return Err(HardwareError::InvalidSource(format!(
                "symlink in local source: {}",
                entry.path().display()
            )));
        }
        let target = destination.join(entry.file_name());
        if metadata.is_dir() {
            copy_tree_without_symlinks(&entry.path(), &target)?;
        } else if metadata.is_file() {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

fn merge_tree_without_symlinks(source: &Path, destination: &Path) -> Result<(), HardwareError> {
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let name = entry.file_name();
        if name == ".corinth-source-ready" || name == ".corinth-local-revision" {
            continue;
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(HardwareError::InvalidSource(format!(
                "symlink in source cache: {}",
                path.display()
            )));
        }
        let target = destination.join(&name);
        if metadata.is_dir() {
            if target.exists() {
                if !target.is_dir() {
                    return Err(HardwareError::InvalidSource(format!(
                        "source path collision: {}",
                        target.display()
                    )));
                }
            } else {
                fs::create_dir(&target)?;
            }
            merge_tree_without_symlinks(&path, &target)?;
        } else if metadata.is_file() {
            if target.exists() {
                return Err(HardwareError::InvalidSource(format!(
                    "source path collision: {}",
                    target.display()
                )));
            }
            fs::copy(path, target)?;
        } else {
            return Err(HardwareError::InvalidSource(format!(
                "unsupported source entry: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn reject_symlinks(root: &Path) -> Result<(), HardwareError> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() {
            return Err(HardwareError::InvalidSource(format!(
                "archive contains a symlink: {}",
                entry.path().display()
            )));
        }
        if metadata.is_dir() {
            reject_symlinks(&entry.path())?;
        }
    }
    Ok(())
}

pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), HardwareError> {
    atomic_write_mode(path, bytes, 0o644)
}

fn atomic_write_mode(path: &Path, bytes: &[u8], mode: u32) -> Result<(), HardwareError> {
    let parent = path
        .parent()
        .ok_or_else(|| HardwareError::OutputRejected(path.display().to_string()))?;
    fs::create_dir_all(parent)?;
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    fs::rename(temporary, path)?;
    Ok(())
}

pub(crate) fn read_bounded(path: &Path, maximum: u64) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let size = file.metadata()?.len();
    if size > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file is too large",
        ));
    }
    let mut bytes = Vec::with_capacity(size as usize);
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

pub(crate) fn validate_root(path: &Path) -> Result<(), HardwareError> {
    if !path.is_absolute() || path.parent().is_none() || path == Path::new("/") {
        return Err(HardwareError::InvalidSource(format!(
            "root must be a non-root absolute path: {}",
            path.display()
        )));
    }
    Ok(())
}

pub(crate) fn prepare_private_root(path: &Path) -> Result<(), HardwareError> {
    validate_root(path)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(HardwareError::State(format!(
                    "store root is not a directory: {}",
                    path.display()
                )));
            }
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(HardwareError::State(format!(
                    "store root is group/world accessible: {}",
                    path.display()
                )));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .ok_or_else(|| HardwareError::InvalidSource("store root has no parent".into()))?;
            let metadata = fs::symlink_metadata(parent)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(HardwareError::State(format!(
                    "store parent is unsafe: {}",
                    parent.display()
                )));
            }
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700).create(path)?;
        }
        Err(error) => return Err(HardwareError::Io(error.to_string())),
    }
    Ok(())
}

fn safe_source_destination(value: &str) -> Result<&Path, HardwareError> {
    let path = safe_relative_path(value)?;
    if path.components().any(|component| !matches!(component, Component::Normal(_)))
        || path
            .components()
            .next()
            .is_some_and(|component| matches!(component, Component::Normal(name) if name == "target" || name == ".git" || name == ".corinth-install"))
    {
        return Err(HardwareError::InvalidSource(format!(
            "unsafe source destination: {value}"
        )));
    }
    Ok(path)
}

fn safe_relative_path(value: &str) -> Result<&Path, HardwareError> {
    let path = Path::new(value);
    if value.is_empty() || path.is_absolute() {
        return Err(HardwareError::OutputRejected(value.into()));
    }
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(HardwareError::OutputRejected(value.into()));
    }
    Ok(path)
}

fn path_str(path: &Path) -> Result<&str, HardwareError> {
    path.to_str()
        .ok_or_else(|| HardwareError::InvalidSource("non-UTF-8 path".into()))
}

fn valid_git_revision(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_https_url(value: &str) -> bool {
    value.starts_with("https://") && !value.contains([' ', '\n', '\r', '\t'])
}

fn is_exact_crates_io_url(value: &str, package: &str, version: &str) -> bool {
    value == format!("https://crates.io/api/v1/crates/{package}/{version}/download")
        || value == format!("https://static.crates.io/crates/{package}/{package}-{version}.crate")
}

pub(crate) fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> RecipeSource {
        RecipeSource {
            kind: "git".into(),
            url: Some("https://github.com/SisyphusAeolides/Corinth.git".into()),
            revision: Some("0123456789abcdef0123456789abcdef01234567".into()),
            checksum: None,
            package: None,
            version: None,
            destination: None,
            submodules: false,
        }
    }

    #[test]
    fn source_lock_is_stable_and_binds_every_source_field() {
        let first = source_lock_digest(std::slice::from_ref(&source()));
        let mut changed = source();
        changed.submodules = true;
        assert_ne!(first, source_lock_digest(&[changed]));
        let mut placed = source();
        placed.destination = Some("sources/push".into());
        assert_ne!(first, source_lock_digest(&[placed]));
        assert!(safe_source_destination("sources/push").is_ok());
        assert!(safe_source_destination("../push").is_err());
        assert!(safe_source_destination("target/push").is_err());
    }

    #[test]
    fn crates_io_url_must_name_the_locked_package_and_version() {
        let mut source = RecipeSource {
            kind: "crates-io".into(),
            url: Some("https://crates.io/api/v1/crates/demo/1.2.3/download".into()),
            revision: None,
            checksum: Some(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            ),
            package: Some("demo".into()),
            version: Some("1.2.3".into()),
            destination: None,
            submodules: false,
        };
        assert!(validate_source(&source).is_ok());
        source.url = Some("https://crates.io/api/v1/crates/other/1.2.3/download".into());
        assert!(matches!(
            validate_source(&source),
            Err(HardwareError::InvalidSource(_))
        ));
    }

    #[test]
    fn cargo_closure_binds_every_registry_package() {
        let checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let lock = format!(
            "version = 4\n\n[[package]]\nname = \"demo\"\nversion = \"1.0.0\"\ndependencies = [\"helper\"]\n\n[[package]]\nname = \"helper\"\nversion = \"2.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{checksum}\"\n"
        );
        let packages = vec![RecipeCargoPackage {
            name: "helper".into(),
            version: "2.0.0".into(),
            checksum: checksum.into(),
        }];
        validate_cargo_lock_closure(&lock, &packages, "demo", "1.0.0").unwrap();
        let mut drifted = packages;
        drifted[0].version = "2.0.1".into();
        assert!(validate_cargo_lock_closure(&lock, &drifted, "demo", "1.0.0").is_err());
    }

    #[test]
    fn cargo_closure_materializes_an_offline_vendor_boundary() {
        let checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let lock = format!(
            "version = 4\n\n[[package]]\nname = \"demo\"\nversion = \"1.0.0\"\ndependencies = [\"helper\"]\n\n[[package]]\nname = \"helper\"\nversion = \"2.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{checksum}\"\n"
        );
        let package = RecipeCargoPackage {
            name: "helper".into(),
            version: "2.0.0".into(),
            checksum: checksum.into(),
        };
        let recipe = RecipeDocument {
            format: RECIPE_FORMAT,
            package: RecipePackage {
                name: "demo".into(),
                version: "1.0.0".into(),
                release: 1,
                summary: "demo".into(),
                license: "MIT".into(),
                scope: "system".into(),
                publish_authority: "arach-native".into(),
                architectures: vec!["x86-64".into()],
            },
            source: vec![
                RecipeSource {
                    kind: "crates-io".into(),
                    url: Some("https://crates.io/api/v1/crates/demo/1.0.0/download".into()),
                    revision: None,
                    checksum: Some(checksum.into()),
                    package: Some("demo".into()),
                    version: Some("1.0.0".into()),
                    destination: None,
                    submodules: false,
                },
                RecipeSource {
                    kind: "crates-io".into(),
                    url: Some("https://crates.io/api/v1/crates/helper/2.0.0/download".into()),
                    revision: None,
                    checksum: Some(checksum.into()),
                    package: Some("helper".into()),
                    version: Some("2.0.0".into()),
                    destination: Some(".corinth-vendor/helper-2.0.0".into()),
                    submodules: false,
                },
            ],
            build: RecipeBuild {
                system: "cargo".into(),
                depends: vec![],
                commands: vec!["cargo build --release --locked".into()],
                outputs: vec!["target/release/demo".into()],
            },
            runtime: None,
            policy: RecipePolicy {
                network: false,
                sandbox: true,
                reproducible: true,
            },
            hardware: None,
            cargo_closure: Some(RecipeCargoClosure {
                lock: lock.clone(),
                packages: vec![package],
            }),
        };
        let root =
            std::env::temp_dir().join(format!("corinth-cargo-closure-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let vendor = root.join(".corinth-vendor/helper-2.0.0/src");
        fs::create_dir_all(&vendor).unwrap();
        fs::write(vendor.join("lib.rs"), b"pub fn helper() {}\n").unwrap();
        prepare_cargo_closure(&recipe, &root).unwrap();
        assert_eq!(fs::read_to_string(root.join("Cargo.lock")).unwrap(), lock);
        assert!(root.join(".cargo/config.toml").is_file());
        let checksum_document: serde_json::Value = serde_json::from_slice(
            &fs::read(root.join(".corinth-vendor/helper-2.0.0/.cargo-checksum.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(checksum_document["package"], checksum);
        assert!(checksum_document["files"]["src/lib.rs"].is_string());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn shell_syntax_is_never_accepted() {
        assert!(parse_command("cargo build --release").is_ok());
        assert!(parse_command("cargo build; rm -rf /").is_err());
        assert!(parse_command("sh -c cargo").is_ok());
        assert!(!allowed_program("cargo", "sh"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn portable_compiler_target_is_bound_to_the_local_cpu() {
        let cpu = arach_hwd::scan::scan_system(Path::new("/sys")).cpu;
        let mut target = CompilerTarget {
            architecture: cpu.architecture,
            vendor: cpu.vendor,
            family: cpu.family,
            model: cpu.model,
            stepping: cpu.stepping,
            features: Vec::new(),
        };
        assert_eq!(verify_compiler_target(&target, None), Ok(()));
        target.vendor.push_str("-forged");
        assert!(matches!(
            verify_compiler_target(&target, None),
            Err(HardwareError::InvalidPlan(_))
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn compiler_environment_uses_only_typed_capabilities() {
        let target = CompilerTarget {
            architecture: CpuArchitecture::X86_64,
            vendor: "ignored-as-command-input".into(),
            family: Some(6),
            model: Some(158),
            stepping: Some(10),
            features: vec![CpuFeature::Avx2, CpuFeature::Sse2],
        };
        let mut command = Command::new(SANDBOX_PROGRAM);
        append_compiler_environment(&mut command, &target).unwrap();
        let arguments = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(arguments.windows(3).any(|window| {
            window
                == [
                    "--setenv",
                    "CFLAGS",
                    "-O2 -pipe -march=x86-64 -mavx2 -msse2",
                ]
        }));
        assert!(arguments.windows(3).any(|window| {
            window
                == [
                    "--setenv",
                    "RUSTFLAGS",
                    "-Ctarget-cpu=x86-64 -Ctarget-feature=+avx2,+sse2",
                ]
        }));
        assert!(!arguments.iter().any(|value| value.contains(&target.vendor)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn compiler_environment_rejects_noncanonical_features() {
        let target = CompilerTarget {
            architecture: CpuArchitecture::X86_64,
            vendor: String::new(),
            family: None,
            model: None,
            stepping: None,
            features: vec![CpuFeature::Sse2, CpuFeature::Avx2],
        };
        assert!(matches!(
            append_compiler_environment(&mut Command::new(SANDBOX_PROGRAM), &target),
            Err(HardwareError::InvalidPlan(_))
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn build_process_is_isolated_or_fails_without_an_output() {
        let root =
            std::env::temp_dir().join(format!("corinth-build-sandbox-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();

        let status = run_sandboxed(
            "sh",
            &[
                "-c",
                "printf sealed > sandbox-write && test ! -e /etc/shadow && test \"$HOME\" = /tmp/corinth-home && test -z \"${CARGO_NET_OFFLINE:-}\"",
            ],
            &root,
            true,
            &[],
            SandboxBuildContext {
                compiler: None,
                allow_host_toolchains: true,
                build_dependency_root: None,
            },
        )
        .unwrap();
        if !status.success() {
            assert!(!root.join("sandbox-write").exists());
            fs::remove_dir_all(root).unwrap();
            return;
        }
        assert_eq!(fs::read(root.join("sandbox-write")).unwrap(), b"sealed");
        assert!(
            run_sandboxed(
                "cargo",
                &["--version"],
                &root,
                true,
                &[],
                SandboxBuildContext {
                    compiler: None,
                    allow_host_toolchains: true,
                    build_dependency_root: None,
                },
            )
            .unwrap()
            .success()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn offline_boundary_never_retains_the_callers_network_namespace() {
        let root = std::env::temp_dir();
        let mut offline = Command::new(SANDBOX_PROGRAM);
        append_sandbox_boundary(&mut offline, &root, false, true, None).unwrap();
        let offline = offline
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(offline.iter().any(|argument| argument == "--unshare-all"));
        assert!(!offline.iter().any(|argument| argument == "--share-net"));

        let mut online = Command::new(SANDBOX_PROGRAM);
        append_sandbox_boundary(&mut online, &root, true, true, None).unwrap();
        assert!(online.get_args().any(|argument| argument == "--share-net"));
    }

    #[test]
    fn package_service_boundary_excludes_mutable_host_toolchains() {
        let root = std::env::temp_dir();
        let mut command = Command::new(SANDBOX_PROGRAM);
        append_sandbox_boundary(&mut command, &root, false, false, None).unwrap();
        let arguments = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(
            arguments
                .windows(2)
                .any(|pair| pair == ["PATH", "/usr/bin"])
        );
        for value in [".cargo", ".rustup", ".idris2", ".agda", "RUSTUP_HOME"] {
            assert!(!arguments.iter().any(|argument| argument.contains(value)));
        }
    }

    #[test]
    fn package_service_mounts_build_dependencies_read_only_with_bounded_paths() {
        let root =
            std::env::temp_dir().join(format!("corinth-build-dependencies-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let mut command = Command::new(SANDBOX_PROGRAM);
        append_sandbox_boundary(&mut command, &root, false, false, Some(&root)).unwrap();
        let arguments = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let root_text = root.to_string_lossy();
        assert!(
            arguments.windows(3).any(|window| {
                window == ["--ro-bind", root_text.as_ref(), BUILD_DEPENDENCY_MOUNT]
            })
        );
        assert!(arguments.windows(3).any(|window| {
            window
                == [
                    "--setenv",
                    "PATH",
                    "/corinth-build/usr/bin:/corinth-build/usr/sbin:/usr/bin",
                ]
        }));
        for (name, value) in [
            ("CORINTH_BUILD_ROOT", "/corinth-build"),
            ("PKG_CONFIG_SYSROOT_DIR", "/corinth-build"),
            ("CMAKE_PREFIX_PATH", "/corinth-build/usr"),
        ] {
            assert!(
                arguments
                    .windows(3)
                    .any(|window| window == ["--setenv", name, value])
            );
        }
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        let mut rejected = Command::new(SANDBOX_PROGRAM);
        assert!(matches!(
            append_sandbox_boundary(&mut rejected, &root, false, false, Some(&root)),
            Err(HardwareError::CommandRejected(_))
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn source_system_allowlist_covers_the_experimental_toolchains() {
        for (system, program) in [
            ("cargo", "cargo"),
            ("c", "cc"),
            ("fortran", "gfortran"),
            ("idris2", "idris2"),
            ("agda", "agda"),
        ] {
            assert!(allowed_program(system, program));
        }
        assert!(valid_build_system("cosmic"));
    }

    #[test]
    fn cosmic_install_tree_is_the_only_workspace_output() {
        assert!(safe_relative_path("@install-tree").is_ok());
        assert!(!valid_build_system("cosmic-shell"));
    }

    #[cfg(unix)]
    #[test]
    fn cosmic_install_tree_rejects_symlinks() {
        let root = std::env::temp_dir().join(format!("corinth-cosmic-tree-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("usr/bin")).unwrap();
        fs::write(root.join("usr/bin/cosmic-session"), b"session").unwrap();
        std::os::unix::fs::symlink("cosmic-session", root.join("usr/bin/link")).unwrap();
        let mut entries = Vec::new();
        assert!(collect_install_files(&root, &root, &mut entries).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn cosmic_adapter_carries_the_greetd_session_config() {
        let root = std::env::temp_dir().join(format!(
            "corinth-cosmic-greetd-config-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("cosmic-greeter")).unwrap();
        fs::write(
            root.join("cosmic-greeter/cosmic-greeter.toml"),
            b"[default_session]\ncommand = \"cosmic-greeter-start\"\n",
        )
        .unwrap();
        let install = root.join(".corinth-install");
        fs::create_dir_all(&install).unwrap();

        install_cosmic_greeter_config(&root, &install).unwrap();
        let installed = install.join("etc/greetd/cosmic-greeter.toml");
        assert_eq!(
            fs::read_to_string(installed).unwrap(),
            "[default_session]\ncommand = \"cosmic-greeter-start\"\n"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn relative_outputs_cannot_escape_the_source_tree() {
        assert!(safe_relative_path("target/release/corinth").is_ok());
        assert!(safe_relative_path("../outside").is_err());
        assert!(safe_relative_path("/outside").is_err());
    }

    #[test]
    fn receipt_store_removes_only_recorded_outputs() {
        let root =
            std::env::temp_dir().join(format!("corinth-hardware-store-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let artifacts = root.join("artifacts");
        let state = root.join("state");
        let store = HostPackageStore::open(state, artifacts.clone()).unwrap();
        let output = artifacts.join("demo-1.0.0-1/demo");
        fs::create_dir_all(output.parent().unwrap()).unwrap();
        fs::write(&output, b"measured").unwrap();
        let receipt = HardwareBuildReceipt {
            package: "demo".into(),
            version: "1.0.0".into(),
            release: 1,
            source_revision: "0123456789abcdef0123456789abcdef01234567".into(),
            metadata_sha256: "1".repeat(64),
            source_lock_sha256: "2".repeat(64),
            artifact_sha256: "3".repeat(64),
            outputs: vec![output.clone()],
        };
        store.install(&[receipt]).unwrap();
        store.remove("demo").unwrap();
        assert!(!output.exists());
        let _ = fs::remove_dir_all(root);
    }
}
