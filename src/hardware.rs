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
use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use arach_hwd::plan::{CorinthIntent, CorinthVerb, PLAN_SCHEMA, PlanSet, ProvisionPlan};
use arach_hwd::profile::{PackageScope, RepositoryAuthority};
use arach_hwd::signature::Keyring;
use serde::{Deserialize, Serialize};

pub const RECIPE_FORMAT: u32 = 1;
pub const MAX_RECIPE_BYTES: usize = 128 * 1024;
pub const MAX_OUTPUT_BYTES: u64 = 512 * 1024 * 1024;
pub const TARGET_ARCH: &str = "x86-64";

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
    pub plan: ProvisionPlan,
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
    for intent in &plan.package {
        validate_intent(intent)?;
    }
    Ok(VerifiedHardwarePlan { plan })
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
            target_arch: target_arch.into(),
        })
    }

    /// Build only a plan that passed signature, intent, and digest checks.
    pub fn build_verified(
        &self,
        plan: &VerifiedHardwarePlan,
        recipes_root: &Path,
    ) -> Result<Vec<HardwareBuildReceipt>, HardwareError> {
        fs::create_dir_all(&self.work_root)?;
        fs::create_dir_all(&self.artifact_root)?;
        let mut receipts = Vec::with_capacity(plan.plan.package.len());
        for intent in &plan.plan.package {
            receipts.push(self.build_intent(intent, recipes_root)?);
        }
        Ok(receipts)
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
            submodules,
        })
    }

    fn build_intent(
        &self,
        intent: &CorinthIntent,
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

        let source_dir = self.materialize_sources(&recipe.source, &source_lock)?;
        if recipe.build.system == "cosmic" {
            run_cosmic_workspace(&source_dir, recipe.policy.network)?;
        } else {
            for command in &recipe.build.commands {
                run_build_command(
                    command,
                    &recipe.build.system,
                    &source_dir,
                    recipe.policy.network,
                )?;
            }
        }
        let (artifact_digest, outputs) = self.measure_outputs(&recipe, &source_dir, intent)?;
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
            merge_tree_without_symlinks(&cached, &destination)?;
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
        if !self.allow_network || !is_crates_io_url(url) {
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
        intent: &CorinthIntent,
    ) -> Result<(String, Vec<PathBuf>), HardwareError> {
        if recipe.build.outputs.as_slice() == ["@install-tree"] {
            return self.measure_install_tree(recipe, source_dir, intent);
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
        if actual != intent.artifact_sha256 {
            return Err(HardwareError::ArtifactDigestMismatch {
                package: intent.name.clone(),
                expected: intent.artifact_sha256.clone(),
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
        Ok((intent.artifact_sha256.clone(), published))
    }

    fn measure_install_tree(
        &self,
        recipe: &RecipeDocument,
        source_dir: &Path,
        intent: &CorinthIntent,
    ) -> Result<(String, Vec<PathBuf>), HardwareError> {
        let install_root = source_dir.join(".corinth-install");
        let metadata = fs::symlink_metadata(&install_root)
            .map_err(|_| HardwareError::OutputRejected("@install-tree".into()))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(HardwareError::OutputRejected("@install-tree".into()));
        }
        let mut entries = Vec::new();
        collect_install_files(&install_root, &install_root, &mut entries)?;
        if entries.is_empty() {
            return Err(HardwareError::OutputRejected("@install-tree".into()));
        }
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        let mut digest = Sha256::new();
        let mut total = 0_u64;
        for (relative, bytes) in &entries {
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
            digest.update(bytes);
        }
        let actual = hex_digest(&digest.finalize());
        if actual != intent.artifact_sha256 {
            return Err(HardwareError::ArtifactDigestMismatch {
                package: intent.name.clone(),
                expected: intent.artifact_sha256.clone(),
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
        for (relative, bytes) in entries {
            let target = destination.join(safe_relative_path(&relative)?);
            atomic_write(&target, &bytes)?;
            published.push(target);
        }
        Ok((intent.artifact_sha256.clone(), published))
    }
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
    for source in &recipe.source {
        validate_source(source)?;
    }
    if !valid_build_system(&recipe.build.system) {
        return Err(HardwareError::UnsupportedBuildSystem(
            recipe.build.system.clone(),
        ));
    }
    for dependency in &recipe.build.depends {
        if !valid_package_atom(dependency) {
            return Err(HardwareError::InvalidRecipe(format!(
                "invalid build dependency: {dependency}"
            )));
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
    } else {
        for output in &recipe.build.outputs {
            safe_relative_path(output)?;
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
                    .is_some_and(|url| !is_crates_io_url(url))
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
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
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

fn run_build_command(
    command: &str,
    system: &str,
    directory: &Path,
    network: bool,
) -> Result<(), HardwareError> {
    let argv = parse_command(command)?;
    if argv.is_empty() || !allowed_program(system, argv[0]) {
        return Err(HardwareError::CommandRejected(command.into()));
    }
    let mut child = Command::new(argv[0]);
    child
        .args(&argv[1..])
        .current_dir(directory)
        .stdin(Stdio::null());
    child.env("SOURCE_DATE_EPOCH", "1");
    if !network {
        child.env("CARGO_NET_OFFLINE", "true");
        child.env("GIT_CONFIG_NOSYSTEM", "1");
    }
    let status = child
        .status()
        .map_err(|error| HardwareError::CommandFailed(error.to_string()))?;
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
fn run_cosmic_workspace(directory: &Path, network: bool) -> Result<(), HardwareError> {
    let justfile = directory.join("justfile");
    let metadata = fs::symlink_metadata(&justfile)
        .map_err(|_| HardwareError::InvalidSource("COSMIC justfile is missing".into()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(HardwareError::InvalidSource(
            "COSMIC justfile is not a regular file".into(),
        ));
    }
    run_cosmic_phase(directory, &["build"], network)?;
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
    run_cosmic_phase(directory, &[&rootdir, "prefix=/usr", "install"], network)?;
    reject_symlinks(&install_root)
}

fn run_cosmic_phase(
    directory: &Path,
    arguments: &[&str],
    network: bool,
) -> Result<(), HardwareError> {
    let mut command = Command::new("just");
    command
        .args(arguments)
        .current_dir(directory)
        .stdin(Stdio::null())
        .env("SOURCE_DATE_EPOCH", "1")
        .env("GIT_CONFIG_NOSYSTEM", "1");
    if !network {
        command.env("CARGO_NET_OFFLINE", "true");
    }
    let status = command
        .status()
        .map_err(|error| HardwareError::CommandFailed(error.to_string()))?;
    if !status.success() {
        return Err(HardwareError::CommandFailed(format!(
            "just {} failed",
            arguments.join(" ")
        )));
    }
    Ok(())
}

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
    network: bool,
) -> Result<(), HardwareError> {
    if !matches!(program, "git" | "curl" | "tar") {
        return Err(HardwareError::CommandRejected(program.into()));
    }
    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir(directory)
        .stdin(Stdio::null());
    if !network {
        command.env("GIT_CONFIG_NOSYSTEM", "1");
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
    let parent = path
        .parent()
        .ok_or_else(|| HardwareError::OutputRejected(path.display().to_string()))?;
    fs::create_dir_all(parent)?;
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
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

fn is_crates_io_url(value: &str) -> bool {
    is_https_url(value)
        && (value.starts_with("https://crates.io/")
            || value.starts_with("https://static.crates.io/"))
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
            submodules: false,
        }
    }

    #[test]
    fn source_lock_is_stable_and_binds_every_source_field() {
        let first = source_lock_digest(std::slice::from_ref(&source()));
        let mut changed = source();
        changed.submodules = true;
        assert_ne!(first, source_lock_digest(&[changed]));
    }

    #[test]
    fn shell_syntax_is_never_accepted() {
        assert!(parse_command("cargo build --release").is_ok());
        assert!(parse_command("cargo build; rm -rf /").is_err());
        assert!(parse_command("sh -c cargo").is_ok());
        assert!(!allowed_program("cargo", "sh"));
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
