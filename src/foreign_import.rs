//! Safe CRUX and Nix metadata adapters.
//!
//! Neither adapter evaluates a package language. CRUX Pkgfiles are limited to
//! static assignments and are paired with an immutable source lock. Nix input
//! is a fixed-output export manifest, not a Nix expression. The resulting
//! metadata still requires a detached-signature Arach target policy before it
//! can become a native Corinth recipe.

use alloc::collections::BTreeSet;
use alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;
use serde::Deserialize;

use crate::arch_import::{
    ArchPackageMetadata, ArchSource, ArchSourceKind, ImportedRecipe, RecipeTargetPolicy,
    build_recipe, target_profile_for_package,
};

pub const MAX_FOREIGN_MANIFEST_BYTES: usize = 512 * 1024;
pub const FOREIGN_MANIFEST_FORMAT: u32 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ForeignPackage {
    pub name: String,
    pub version: Option<String>,
    pub release: Option<u32>,
    pub summary: String,
    pub license: String,
    pub architectures: Vec<String>,
    #[serde(default)]
    pub depends: Vec<String>,
    #[serde(default)]
    pub makedepends: Vec<String>,
    #[serde(default)]
    pub provides: Vec<String>,
    #[serde(default)]
    pub conflicts: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ForeignSource {
    pub kind: String,
    pub url: String,
    #[serde(default)]
    pub revision: Option<String>,
    #[serde(default)]
    pub sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ForeignManifest {
    pub format: u32,
    pub package: ForeignPackage,
    #[serde(rename = "source")]
    pub sources: Vec<ForeignSource>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ForeignImportError {
    TooLarge,
    InvalidUtf8,
    Parse(String),
    UnsupportedSyntax(String),
    MissingField(&'static str),
    InvalidField(String),
    SourceMismatch(String),
    Target(String),
}

impl fmt::Display for ForeignImportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ForeignImportError {}

/// Parse a fixed-output Nix export manifest. The caller must produce this
/// document from an already locked flake or derivation; arbitrary Nix
/// evaluation is intentionally outside Corinth's installer trust boundary.
pub fn parse_nix_export(bytes: &[u8]) -> Result<ArchPackageMetadata, ForeignImportError> {
    let manifest = parse_manifest(bytes)?;
    let version = manifest
        .package
        .version
        .clone()
        .ok_or(ForeignImportError::MissingField("package.version"))?;
    let release = manifest
        .package
        .release
        .ok_or(ForeignImportError::MissingField("package.release"))?;
    build_metadata(
        &manifest,
        version,
        release,
        manifest.package.depends.clone(),
    )
}

/// Parse the static metadata subset of a CRUX Pkgfile and bind every source to
/// an immutable companion manifest. Shell functions, substitutions, variable
/// expansion, and local unmeasured files are rejected.
pub fn parse_crux_pkgfile(
    pkgfile: &[u8],
    source_lock: &[u8],
) -> Result<ArchPackageMetadata, ForeignImportError> {
    let manifest = parse_manifest(source_lock)?;
    if pkgfile.is_empty() || pkgfile.len() > MAX_FOREIGN_MANIFEST_BYTES {
        return Err(ForeignImportError::TooLarge);
    }
    let text = core::str::from_utf8(pkgfile).map_err(|_| ForeignImportError::InvalidUtf8)?;
    let assignments = collect_static_assignments(text)?;
    let name = scalar_required(&assignments, "name")?;
    if name != manifest.package.name {
        return Err(ForeignImportError::InvalidField(
            "Pkgfile name differs from source lock".into(),
        ));
    }
    let version = scalar_required(&assignments, "version")?;
    let release = scalar_required(&assignments, "release")?
        .parse::<u32>()
        .map_err(|_| ForeignImportError::InvalidField("release".into()))?;
    if release == 0 {
        return Err(ForeignImportError::InvalidField("release".into()));
    }
    let declared_sources = array_required(&assignments, "source")?;
    if declared_sources.len() != manifest.sources.len() {
        return Err(ForeignImportError::SourceMismatch(
            "Pkgfile source count differs from source lock".into(),
        ));
    }
    for (declared, locked) in declared_sources.iter().zip(&manifest.sources) {
        if declared != &locked.url {
            return Err(ForeignImportError::SourceMismatch(format!(
                "unlocked CRUX source: {declared}"
            )));
        }
    }
    let depends = array_optional(&assignments, "depends").unwrap_or_default();
    build_metadata(&manifest, version, release, depends)
}

/// Parse the bounded, static preamble of a Fedora RPM spec and bind its source
/// declarations to the same immutable source-lock format used by the CRUX and
/// Nix adapters. RPM macros, script sections, generated dependencies, and
/// unlisted sources are rejected; an isolated compatibility worker is needed
/// for specs that require those features.
pub fn parse_fedora_spec(
    spec: &[u8],
    source_lock: &[u8],
) -> Result<ArchPackageMetadata, ForeignImportError> {
    let manifest = parse_manifest(source_lock)?;
    let text = bounded_utf8(spec)?;
    let fields = collect_tagged_fields(text)?;
    let name = tagged_required(&fields, "Name")?;
    let version = tagged_required(&fields, "Version")?;
    let release = tagged_required(&fields, "Release")?
        .parse::<u32>()
        .map_err(|_| ForeignImportError::InvalidField("Release".into()))?;
    if release == 0 {
        return Err(ForeignImportError::InvalidField("Release".into()));
    }
    let summary = tagged_required(&fields, "Summary")?;
    let license = tagged_required(&fields, "License")?;
    let architectures = fields
        .iter()
        .find(|(key, _)| key == "ExclusiveArch")
        .map(|(_, value)| parse_dependency_list(value))
        .transpose()?;
    let architectures = architectures
        .map(|values| normalize_external_architectures(&values))
        .transpose()?;
    let depends = tagged_optional(&fields, "Requires")
        .as_deref()
        .map(parse_dependency_list)
        .transpose()?;
    let makedepends = tagged_optional(&fields, "BuildRequires")
        .as_deref()
        .map(parse_dependency_list)
        .transpose()?;
    let provides = tagged_optional(&fields, "Provides")
        .as_deref()
        .map(parse_dependency_list)
        .transpose()?;
    let conflicts = tagged_optional(&fields, "Conflicts")
        .as_deref()
        .map(parse_dependency_list)
        .transpose()?;
    let mut source_fields = fields
        .iter()
        .filter_map(|(key, value)| {
            key.strip_prefix("Source").and_then(|suffix| {
                if suffix.is_empty() || suffix.bytes().all(|b| b.is_ascii_digit()) {
                    Some((suffix.parse::<usize>().unwrap_or(0), value.as_str()))
                } else {
                    None
                }
            })
        })
        .collect::<Vec<_>>();
    source_fields.sort_by_key(|(index, _)| *index);
    if source_fields
        .windows(2)
        .any(|fields| fields[0].0 == fields[1].0)
    {
        return Err(ForeignImportError::UnsupportedSyntax(
            "duplicate Fedora Source index".into(),
        ));
    }
    let source_values = source_fields
        .into_iter()
        .map(|(_, value)| static_source_url(value))
        .collect::<Result<Vec<_>, _>>()?;
    validate_declared_sources(&manifest, &source_values, "Fedora Source")?;
    validate_declared_package(
        &manifest,
        DeclaredPackage {
            name: &name,
            version: &version,
            release,
            summary: Some(&summary),
            license: Some(&license),
            architectures: architectures.as_deref(),
            depends: depends.as_deref(),
            makedepends: makedepends.as_deref(),
            provides: provides.as_deref(),
            conflicts: conflicts.as_deref(),
        },
    )?;
    build_metadata(&manifest, version, release, depends.unwrap_or_default())
}

/// Parse a Debian `debian/control` binary stanza. The control file is data,
/// not a build program, but versioned or alternative dependencies are rejected
/// until Corinth's dependency model can represent them without loss.
pub fn parse_debian_control(
    control: &[u8],
    source_lock: &[u8],
) -> Result<ArchPackageMetadata, ForeignImportError> {
    let manifest = parse_manifest(source_lock)?;
    let text = bounded_utf8(control)?;
    let paragraphs = parse_debian_paragraphs(text)?;
    let package_name = manifest.package.name.as_str();
    let fields = paragraphs
        .iter()
        .find(|fields| {
            fields
                .get("Package")
                .is_some_and(|name| name == package_name)
        })
        .ok_or(ForeignImportError::MissingField("Package"))?;
    let version = debian_required(fields, "Version")?;
    let release = manifest.package.release.unwrap_or(1);
    let architectures = debian_required(fields, "Architecture")?
        .split_whitespace()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let architectures = normalize_external_architectures(&architectures)?;
    let summary = debian_required(fields, "Description")?
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();
    let depends = debian_dependency_field(fields, "Depends")?;
    let makedepends = ["Build-Depends", "Build-Depends-Indep"]
        .iter()
        .filter_map(|key| fields.get(*key))
        .map(|value| parse_dependency_list(value))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    let provides = debian_dependency_field(fields, "Provides")?;
    let conflicts = debian_dependency_field(fields, "Conflicts")?;
    let license = manifest.package.license.clone();
    validate_declared_package(
        &manifest,
        DeclaredPackage {
            name: package_name,
            version: &version,
            release,
            summary: Some(&summary),
            license: Some(&license),
            architectures: Some(&architectures),
            depends: Some(&depends),
            makedepends: Some(&makedepends),
            provides: Some(&provides),
            conflicts: Some(&conflicts),
        },
    )?;
    build_metadata(&manifest, version, release, depends)
}

/// Parse the static metadata subset of an Alpine APKBUILD. Alpine build
/// functions are deliberately ignored after the preamble; variable expansion
/// and shell-generated source URLs are rejected.
pub fn parse_alpine_apkbuild(
    apkbuild: &[u8],
    source_lock: &[u8],
) -> Result<ArchPackageMetadata, ForeignImportError> {
    let manifest = parse_manifest(source_lock)?;
    let text = bounded_utf8(apkbuild)?;
    let assignments = collect_static_assignments_with_allowed(
        text,
        &[
            "pkgname",
            "pkgver",
            "pkgrel",
            "pkgdesc",
            "arch",
            "license",
            "source",
            "sha256sums",
            "depends",
            "makedepends",
            "provides",
            "replaces",
        ],
    )?;
    let name = scalar_required(&assignments, "pkgname")?;
    let version = scalar_required(&assignments, "pkgver")?;
    let release = scalar_required(&assignments, "pkgrel")?
        .parse::<u32>()
        .map_err(|_| ForeignImportError::InvalidField("pkgrel".into()))?;
    if release == 0 {
        return Err(ForeignImportError::InvalidField("pkgrel".into()));
    }
    let summary = static_text_required(&assignments, "pkgdesc")?;
    let license = scalar_required(&assignments, "license")?;
    let architectures = normalize_external_architectures(&list_required(&assignments, "arch")?)?;
    let source_values = list_required(&assignments, "source")?
        .iter()
        .map(|value| static_source_url(value))
        .collect::<Result<Vec<_>, _>>()?;
    validate_declared_sources(&manifest, &source_values, "Alpine source")?;
    validate_locked_checksums(&manifest, &list_required(&assignments, "sha256sums")?)?;
    let depends = list_optional(&assignments, "depends")?.unwrap_or_default();
    let makedepends = list_optional(&assignments, "makedepends")?.unwrap_or_default();
    let provides = list_optional(&assignments, "provides")?.unwrap_or_default();
    let conflicts = list_optional(&assignments, "replaces")?.unwrap_or_default();
    validate_dependency_names(&depends)?;
    validate_dependency_names(&makedepends)?;
    validate_dependency_names(&provides)?;
    validate_dependency_names(&conflicts)?;
    validate_declared_package(
        &manifest,
        DeclaredPackage {
            name: &name,
            version: &version,
            release,
            summary: Some(&summary),
            license: Some(&license),
            architectures: Some(&architectures),
            depends: Some(&depends),
            makedepends: Some(&makedepends),
            provides: Some(&provides),
            conflicts: Some(&conflicts),
        },
    )?;
    build_metadata(&manifest, version, release, depends)
}

/// Parse the static variable preamble of a Gentoo ebuild. The package name and
/// version come from the pinned ebuild filename; all phase functions and
/// dynamic Bash expressions remain outside this parser's trust boundary.
pub fn parse_gentoo_ebuild(
    ebuild_name: &str,
    ebuild: &[u8],
    source_lock: &[u8],
) -> Result<ArchPackageMetadata, ForeignImportError> {
    let manifest = parse_manifest(source_lock)?;
    let text = bounded_utf8(ebuild)?;
    let (name, version, release) = parse_gentoo_filename(ebuild_name)?;
    let fields = collect_gentoo_assignments(text)?;
    let summary = shell_scalar(&fields, "DESCRIPTION")?;
    let license = shell_scalar(&fields, "LICENSE")?;
    let architectures = gentoo_architectures(&shell_list(&fields, "KEYWORDS")?)?;
    let mut source_values = Vec::new();
    let mut redirect_target = false;
    for value in shell_list(&fields, "SRC_URI")? {
        if redirect_target {
            redirect_target = false;
        } else if value == "->" {
            redirect_target = true;
        } else {
            source_values.push(static_source_url(&value)?);
        }
    }
    if redirect_target {
        return Err(ForeignImportError::UnsupportedSyntax(
            "Gentoo SRC_URI redirect has no target".into(),
        ));
    }
    validate_declared_sources(&manifest, &source_values, "Gentoo SRC_URI")?;
    let depends = shell_list_optional(&fields, "RDEPEND")?
        .unwrap_or_default()
        .into_iter()
        .chain(shell_list_optional(&fields, "PDEPEND")?.unwrap_or_default())
        .collect::<Vec<_>>();
    let makedepends = shell_list_optional(&fields, "DEPEND")?
        .unwrap_or_default()
        .into_iter()
        .chain(shell_list_optional(&fields, "BDEPEND")?.unwrap_or_default())
        .collect::<Vec<_>>();
    validate_dependency_names(&depends)?;
    validate_dependency_names(&makedepends)?;
    validate_declared_package(
        &manifest,
        DeclaredPackage {
            name: &name,
            version: &version,
            release,
            summary: Some(&summary),
            license: Some(&license),
            architectures: Some(&architectures),
            depends: Some(&depends),
            makedepends: Some(&makedepends),
            provides: None,
            conflicts: None,
        },
    )?;
    build_metadata(&manifest, version, release, depends)
}

fn bounded_utf8(bytes: &[u8]) -> Result<&str, ForeignImportError> {
    if bytes.is_empty() || bytes.len() > MAX_FOREIGN_MANIFEST_BYTES {
        return Err(ForeignImportError::TooLarge);
    }
    core::str::from_utf8(bytes).map_err(|_| ForeignImportError::InvalidUtf8)
}

fn collect_tagged_fields(text: &str) -> Result<Vec<(String, String)>, ForeignImportError> {
    let mut fields = Vec::new();
    let mut current: Option<(String, String)> = None;
    for raw in text.lines() {
        let line = raw.trim_end_matches('\r');
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with('%') {
            break;
        }
        if line.chars().next().is_some_and(char::is_whitespace) {
            let Some((_, value)) = current.as_mut() else {
                return Err(ForeignImportError::UnsupportedSyntax(
                    "Fedora continuation without a field".into(),
                ));
            };
            value.push(' ');
            value.push_str(trimmed);
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            return Err(ForeignImportError::UnsupportedSyntax(
                "Fedora preamble contains a non-field line".into(),
            ));
        };
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(ForeignImportError::UnsupportedSyntax(
                "invalid Fedora field name".into(),
            ));
        }
        if let Some(field) = current.take() {
            fields.push(field);
        }
        let value = value.trim().to_string();
        if value.contains(['$', '`', '\\']) || value.contains("%{") || value.contains("%(") {
            return Err(ForeignImportError::UnsupportedSyntax(format!(
                "dynamic Fedora field: {key}"
            )));
        }
        current = Some((key.into(), value));
    }
    if let Some(field) = current {
        fields.push(field);
    }
    Ok(fields)
}

fn tagged_required(
    fields: &[(String, String)],
    key: &'static str,
) -> Result<String, ForeignImportError> {
    let values = fields
        .iter()
        .filter(|(name, _)| name == key)
        .map(|(_, value)| value.clone())
        .collect::<Vec<_>>();
    match values.as_slice() {
        [] => Err(ForeignImportError::MissingField(key)),
        [value] if !value.trim().is_empty() => Ok(value.clone()),
        _ => Err(ForeignImportError::InvalidField(key.into())),
    }
}

fn tagged_optional(fields: &[(String, String)], key: &'static str) -> Option<String> {
    fields
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.clone())
}

fn static_source_url(value: &str) -> Result<String, ForeignImportError> {
    let value = value.trim();
    if value.contains(char::is_whitespace) {
        return Err(ForeignImportError::UnsupportedSyntax(
            "source declaration contains shell or filename syntax".into(),
        ));
    }
    let value = value.split_once("::").map(|(_, url)| url).unwrap_or(value);
    if !is_https_url(value) {
        return Err(ForeignImportError::InvalidField(format!(
            "source URL is not HTTPS: {value}"
        )));
    }
    Ok(value.into())
}

fn validate_declared_sources(
    manifest: &ForeignManifest,
    declared: &[String],
    format: &str,
) -> Result<(), ForeignImportError> {
    if declared.len() != manifest.sources.len() {
        return Err(ForeignImportError::SourceMismatch(format!(
            "{format} count differs from source lock"
        )));
    }
    for (declared, locked) in declared.iter().zip(&manifest.sources) {
        if declared != &locked.url {
            return Err(ForeignImportError::SourceMismatch(format!(
                "{format} is not locked: {declared}"
            )));
        }
    }
    Ok(())
}

fn validate_locked_checksums(
    manifest: &ForeignManifest,
    checksums: &[String],
) -> Result<(), ForeignImportError> {
    if checksums.len() != manifest.sources.len() {
        return Err(ForeignImportError::SourceMismatch(
            "Alpine checksum count differs from source lock".into(),
        ));
    }
    for (checksum, source) in checksums.iter().zip(&manifest.sources) {
        if source.kind != "archive"
            || source.sha256.as_deref() != Some(checksum.as_str())
            || !valid_digest(checksum)
        {
            return Err(ForeignImportError::SourceMismatch(
                "Alpine checksum differs from source lock".into(),
            ));
        }
    }
    Ok(())
}

struct DeclaredPackage<'a> {
    name: &'a str,
    version: &'a str,
    release: u32,
    summary: Option<&'a str>,
    license: Option<&'a str>,
    architectures: Option<&'a [String]>,
    depends: Option<&'a [String]>,
    makedepends: Option<&'a [String]>,
    provides: Option<&'a [String]>,
    conflicts: Option<&'a [String]>,
}

fn validate_declared_package(
    manifest: &ForeignManifest,
    declared: DeclaredPackage<'_>,
) -> Result<(), ForeignImportError> {
    if declared.name != manifest.package.name
        || manifest
            .package
            .version
            .as_deref()
            .is_some_and(|locked| locked != declared.version)
        || manifest
            .package
            .release
            .is_some_and(|locked| locked != declared.release)
    {
        return Err(ForeignImportError::InvalidField(
            "foreign package identity differs from source lock".into(),
        ));
    }
    if declared
        .summary
        .is_some_and(|value| value != manifest.package.summary)
        || declared
            .license
            .is_some_and(|value| value != manifest.package.license)
    {
        return Err(ForeignImportError::InvalidField(
            "foreign package description differs from source lock".into(),
        ));
    }
    if let Some(values) = declared.architectures {
        if BTreeSet::from_iter(values.iter().cloned())
            != BTreeSet::from_iter(manifest.package.architectures.iter().cloned())
        {
            return Err(ForeignImportError::InvalidField(
                "foreign architecture set differs from source lock".into(),
            ));
        }
    }
    validate_declared_dependency_set(declared.depends, &manifest.package.depends, "depends")?;
    validate_declared_dependency_set(
        declared.makedepends,
        &manifest.package.makedepends,
        "makedepends",
    )?;
    validate_declared_dependency_set(declared.provides, &manifest.package.provides, "provides")?;
    validate_declared_dependency_set(declared.conflicts, &manifest.package.conflicts, "conflicts")?;
    Ok(())
}

fn validate_declared_dependency_set(
    declared: Option<&[String]>,
    locked: &[String],
    field: &str,
) -> Result<(), ForeignImportError> {
    if let Some(values) = declared {
        let declared = BTreeSet::from_iter(values.iter().cloned());
        let locked = BTreeSet::from_iter(locked.iter().cloned());
        if declared != locked {
            return Err(ForeignImportError::InvalidField(format!(
                "foreign {field} differs from source lock"
            )));
        }
    }
    Ok(())
}

fn parse_dependency_list(value: &str) -> Result<Vec<String>, ForeignImportError> {
    if value.contains(['|', '(', ')', '<', '>', '=', ':', '?', '*']) {
        return Err(ForeignImportError::UnsupportedSyntax(
            "versioned, alternative, or generated dependency is not representable".into(),
        ));
    }
    let mut dependencies = Vec::new();
    for token in value
        .split([',', ' ', '\t', '\r', '\n'])
        .filter(|token| !token.is_empty())
    {
        if !valid_package_name(token) {
            return Err(ForeignImportError::InvalidField(format!(
                "invalid dependency: {token}"
            )));
        }
        dependencies.push(token.into());
    }
    Ok(dependencies)
}

fn validate_dependency_names(values: &[String]) -> Result<(), ForeignImportError> {
    if values.iter().any(|value| !valid_package_name(value)) {
        return Err(ForeignImportError::InvalidField(
            "dependency name is not representable".into(),
        ));
    }
    Ok(())
}

fn normalize_external_architectures(values: &[String]) -> Result<Vec<String>, ForeignImportError> {
    if values.is_empty() {
        return Err(ForeignImportError::MissingField("architecture"));
    }
    let mut normalized = BTreeSet::new();
    for value in values {
        let value = value.trim_start_matches('~');
        let value = match value {
            "all" | "noarch" | "any" | "*" => "any",
            "amd64" | "x86_64" | "x86-64" => "x86-64",
            "arm64" | "aarch64" => "aarch64",
            "riscv64" => "riscv64",
            other => {
                return Err(ForeignImportError::InvalidField(format!(
                    "unsupported architecture: {other}"
                )));
            }
        };
        normalized.insert(value.into());
    }
    Ok(normalized.into_iter().collect())
}

fn parse_debian_paragraphs(
    text: &str,
) -> Result<Vec<BTreeMap<String, String>>, ForeignImportError> {
    let mut paragraphs = Vec::new();
    let mut fields: BTreeMap<String, String> = BTreeMap::new();
    let mut current: Option<String> = None;
    for raw in text.lines() {
        let line = raw.trim_end_matches('\r');
        if line.trim().is_empty() {
            if !fields.is_empty() {
                paragraphs.push(core::mem::take(&mut fields));
                current = None;
            }
            continue;
        }
        if line.chars().next().is_some_and(char::is_whitespace) {
            let Some(key) = current.as_ref() else {
                return Err(ForeignImportError::UnsupportedSyntax(
                    "Debian continuation without a field".into(),
                ));
            };
            let value = fields.get_mut(key).expect("current Debian field exists");
            value.push('\n');
            value.push_str(line.trim());
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            return Err(ForeignImportError::UnsupportedSyntax(
                "Debian control contains a non-field line".into(),
            ));
        };
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(ForeignImportError::UnsupportedSyntax(
                "invalid Debian field name".into(),
            ));
        }
        if fields.insert(key.into(), value.trim().into()).is_some() {
            return Err(ForeignImportError::UnsupportedSyntax(format!(
                "duplicate Debian field: {key}"
            )));
        }
        current = Some(key.into());
    }
    if !fields.is_empty() {
        paragraphs.push(fields);
    }
    Ok(paragraphs)
}

fn debian_required(
    fields: &BTreeMap<String, String>,
    key: &'static str,
) -> Result<String, ForeignImportError> {
    fields
        .get(key)
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .ok_or(ForeignImportError::MissingField(key))
}

fn debian_dependency_field(
    fields: &BTreeMap<String, String>,
    key: &str,
) -> Result<Vec<String>, ForeignImportError> {
    fields
        .get(key)
        .map(|value| parse_dependency_list(value))
        .transpose()
        .map(|value| value.unwrap_or_default())
}

fn list_required(
    assignments: &BTreeMap<String, String>,
    key: &'static str,
) -> Result<Vec<String>, ForeignImportError> {
    assignments
        .get(key)
        .ok_or(ForeignImportError::MissingField(key))
        .and_then(|value| parse_shell_list(value))
}

fn list_optional(
    assignments: &BTreeMap<String, String>,
    key: &str,
) -> Result<Option<Vec<String>>, ForeignImportError> {
    assignments
        .get(key)
        .map(String::as_str)
        .map(parse_shell_list)
        .transpose()
}

fn parse_shell_list(value: &str) -> Result<Vec<String>, ForeignImportError> {
    let value = value.trim();
    if value.starts_with('(') {
        return parse_array(value);
    }
    let value = unquote(value)?;
    if value.is_empty() || value.contains(['$', '`', ';', '|', '&', '<', '>']) {
        return Err(ForeignImportError::UnsupportedSyntax(
            "shell expansion in static assignment".into(),
        ));
    }
    Ok(value.split_whitespace().map(String::from).collect())
}

fn parse_gentoo_filename(ebuild_name: &str) -> Result<(String, String, u32), ForeignImportError> {
    let stem = ebuild_name
        .strip_suffix(".ebuild")
        .ok_or_else(|| ForeignImportError::InvalidField("ebuild filename".into()))?;
    let split = stem
        .rfind('-')
        .ok_or_else(|| ForeignImportError::InvalidField("ebuild filename".into()))?;
    let name = &stem[..split];
    let version_with_release = &stem[split + 1..];
    if !valid_package_name(name) || version_with_release.is_empty() {
        return Err(ForeignImportError::InvalidField("ebuild filename".into()));
    }
    let (version, release) =
        if let Some((version, release)) = version_with_release.rsplit_once("-r") {
            let release = release
                .parse::<u32>()
                .map_err(|_| ForeignImportError::InvalidField("ebuild release".into()))?;
            (version, release)
        } else {
            (version_with_release, 1)
        };
    if version.is_empty() || release == 0 || version.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(ForeignImportError::InvalidField("ebuild version".into()));
    }
    Ok((name.into(), version.into(), release))
}

fn collect_gentoo_assignments(text: &str) -> Result<BTreeMap<String, String>, ForeignImportError> {
    let allowed = [
        "EAPI",
        "DESCRIPTION",
        "HOMEPAGE",
        "LICENSE",
        "KEYWORDS",
        "SRC_URI",
        "SLOT",
        "DEPEND",
        "RDEPEND",
        "BDEPEND",
        "PDEPEND",
        "IUSE",
        "RESTRICT",
    ];
    let mut assignments = BTreeMap::new();
    let mut pending: Option<(String, String)> = None;
    for raw in text.lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with("src_")
            || trimmed.starts_with("pkg_")
            || trimmed.contains("() {")
            || trimmed.contains("()\n")
        {
            break;
        }
        if let Some((key, value)) = pending.as_mut() {
            value.push(' ');
            value.push_str(trimmed);
            if shell_assignment_complete(value) {
                assignments.insert(core::mem::take(key), core::mem::take(value));
                pending = None;
            }
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            return Err(ForeignImportError::UnsupportedSyntax(
                "Gentoo preamble contains a non-assignment".into(),
            ));
        };
        if !allowed.contains(&key.trim()) {
            return Err(ForeignImportError::UnsupportedSyntax(format!(
                "unsupported Gentoo assignment: {}",
                key.trim()
            )));
        }
        let key = key.trim().to_string();
        let value = value.trim().to_string();
        if value.contains(['$', '`', '\\']) {
            return Err(ForeignImportError::UnsupportedSyntax(format!(
                "dynamic Gentoo assignment: {key}"
            )));
        }
        if shell_assignment_complete(&value) {
            if assignments.insert(key.clone(), value).is_some() {
                return Err(ForeignImportError::UnsupportedSyntax(format!(
                    "duplicate Gentoo assignment: {key}"
                )));
            }
        } else {
            pending = Some((key, value));
        }
    }
    if pending.is_some() {
        return Err(ForeignImportError::UnsupportedSyntax(
            "unterminated Gentoo assignment".into(),
        ));
    }
    Ok(assignments)
}

fn shell_assignment_complete(value: &str) -> bool {
    let mut quote = None;
    for byte in value.bytes() {
        match (quote, byte) {
            (Some(active), value) if active == value => quote = None,
            (None, b'\'' | b'"') => quote = Some(byte),
            _ => {}
        }
    }
    quote.is_none()
}

fn shell_scalar(
    fields: &BTreeMap<String, String>,
    key: &'static str,
) -> Result<String, ForeignImportError> {
    let value = fields
        .get(key)
        .ok_or(ForeignImportError::MissingField(key))?;
    unquote(value)
}

fn shell_list(
    fields: &BTreeMap<String, String>,
    key: &'static str,
) -> Result<Vec<String>, ForeignImportError> {
    fields
        .get(key)
        .ok_or(ForeignImportError::MissingField(key))
        .and_then(|value| parse_shell_list(value))
}

fn shell_list_optional(
    fields: &BTreeMap<String, String>,
    key: &str,
) -> Result<Option<Vec<String>>, ForeignImportError> {
    fields
        .get(key)
        .map(String::as_str)
        .map(parse_shell_list)
        .transpose()
}

fn gentoo_architectures(values: &[String]) -> Result<Vec<String>, ForeignImportError> {
    let values = values
        .iter()
        .filter(|value| !value.starts_with('-'))
        .cloned()
        .collect::<Vec<_>>();
    normalize_external_architectures(&values)
}

pub fn build_foreign_recipe(
    metadata: &ArchPackageMetadata,
    policy: &RecipeTargetPolicy,
) -> Result<ImportedRecipe, ForeignImportError> {
    let target = target_profile_for_package(policy, &metadata.name)
        .map_err(|error| ForeignImportError::Target(error.to_string()))?;
    build_recipe(metadata, &target).map_err(|error| ForeignImportError::Target(error.to_string()))
}

fn parse_manifest(bytes: &[u8]) -> Result<ForeignManifest, ForeignImportError> {
    if bytes.is_empty() || bytes.len() > MAX_FOREIGN_MANIFEST_BYTES {
        return Err(ForeignImportError::TooLarge);
    }
    let manifest: ForeignManifest =
        toml::from_slice(bytes).map_err(|error| ForeignImportError::Parse(error.to_string()))?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

fn validate_manifest(manifest: &ForeignManifest) -> Result<(), ForeignImportError> {
    if manifest.format != FOREIGN_MANIFEST_FORMAT
        || !valid_package_name(&manifest.package.name)
        || manifest.package.summary.trim().is_empty()
        || manifest.package.license.trim().is_empty()
        || manifest.package.architectures.is_empty()
        || manifest.sources.is_empty()
    {
        return Err(ForeignImportError::InvalidField(
            "foreign manifest header".into(),
        ));
    }
    if manifest
        .package
        .architectures
        .iter()
        .any(|value| !valid_architecture(value))
        || manifest
            .package
            .depends
            .iter()
            .chain(&manifest.package.makedepends)
            .chain(&manifest.package.provides)
            .chain(&manifest.package.conflicts)
            .any(|value| !valid_package_name(value))
    {
        return Err(ForeignImportError::InvalidField(
            "foreign package metadata".into(),
        ));
    }
    let mut urls = alloc::collections::BTreeSet::new();
    for source in &manifest.sources {
        if !urls.insert(source.url.as_str()) || !is_https_url(&source.url) {
            return Err(ForeignImportError::InvalidField(format!(
                "invalid or duplicate source URL: {}",
                source.url
            )));
        }
        match source.kind.as_str() {
            "git" => {
                if !source.revision.as_deref().is_some_and(valid_revision)
                    || source.sha256.is_some()
                {
                    return Err(ForeignImportError::InvalidField(format!(
                        "Git source is not pinned: {}",
                        source.url
                    )));
                }
            }
            "archive" => {
                if !source.sha256.as_deref().is_some_and(valid_digest) || source.revision.is_some()
                {
                    return Err(ForeignImportError::InvalidField(format!(
                        "archive source lacks SHA-256: {}",
                        source.url
                    )));
                }
            }
            _ => {
                return Err(ForeignImportError::InvalidField(format!(
                    "unsupported source kind: {}",
                    source.kind
                )));
            }
        }
    }
    Ok(())
}

fn build_metadata(
    manifest: &ForeignManifest,
    version: String,
    release: u32,
    depends: Vec<String>,
) -> Result<ArchPackageMetadata, ForeignImportError> {
    if version.trim().is_empty() || release == 0 {
        return Err(ForeignImportError::InvalidField(
            "package version or release".into(),
        ));
    }
    if manifest
        .package
        .version
        .as_deref()
        .is_some_and(|locked| locked != version)
        || manifest
            .package
            .release
            .is_some_and(|locked| locked != release)
    {
        return Err(ForeignImportError::InvalidField(
            "package version or release differs from source lock".into(),
        ));
    }
    if depends.iter().any(|value| !valid_package_name(value)) {
        return Err(ForeignImportError::InvalidField("depends".into()));
    }
    let sources = manifest
        .sources
        .iter()
        .map(|source| ArchSource {
            kind: if source.kind == "git" {
                ArchSourceKind::Git
            } else {
                ArchSourceKind::Archive
            },
            url: source.url.clone(),
            revision: source.revision.clone(),
            checksum: source.sha256.clone(),
        })
        .collect();
    Ok(ArchPackageMetadata {
        name: manifest.package.name.clone(),
        version,
        release,
        summary: manifest.package.summary.clone(),
        license: manifest.package.license.clone(),
        architectures: manifest.package.architectures.clone(),
        sources,
        depends,
        makedepends: manifest.package.makedepends.clone(),
        provides: manifest.package.provides.clone(),
        conflicts: manifest.package.conflicts.clone(),
    })
}

fn collect_static_assignments(text: &str) -> Result<BTreeMap<String, String>, ForeignImportError> {
    collect_static_assignments_with_allowed(
        text,
        &["name", "version", "release", "source", "depends"],
    )
}

fn collect_static_assignments_with_allowed(
    text: &str,
    allowed: &[&str],
) -> Result<BTreeMap<String, String>, ForeignImportError> {
    if text.contains("$('")
        || text.contains("$(")
        || text.contains("${")
        || text.contains('`')
        || text.contains("eval ")
        || text.contains("source ")
        || text.contains(". ")
    {
        return Err(ForeignImportError::UnsupportedSyntax(
            "CRUX metadata contains evaluation or substitution".into(),
        ));
    }
    let mut statements = Vec::new();
    let mut current = String::new();
    let mut depth = 0i32;
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("build()") || line.starts_with("build ()") {
            break;
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(line);
        depth += line.bytes().filter(|byte| *byte == b'(').count() as i32;
        depth -= line.bytes().filter(|byte| *byte == b')').count() as i32;
        if depth < 0 {
            return Err(ForeignImportError::UnsupportedSyntax(
                "unbalanced CRUX array".into(),
            ));
        }
        if depth == 0 {
            statements.push(core::mem::take(&mut current));
        }
    }
    if depth != 0 || !current.is_empty() {
        return Err(ForeignImportError::UnsupportedSyntax(
            "unterminated CRUX assignment".into(),
        ));
    }
    let mut assignments = BTreeMap::new();
    for statement in statements {
        let Some((key, value)) = statement.split_once('=') else {
            return Err(ForeignImportError::UnsupportedSyntax(statement));
        };
        let key = key.trim();
        if !allowed.contains(&key)
            || assignments
                .insert(key.into(), value.trim().into())
                .is_some()
        {
            return Err(ForeignImportError::UnsupportedSyntax(format!(
                "unsupported or duplicate CRUX field: {key}"
            )));
        }
    }
    Ok(assignments)
}

fn scalar_required(
    assignments: &BTreeMap<String, String>,
    key: &'static str,
) -> Result<String, ForeignImportError> {
    let value = assignments
        .get(key)
        .ok_or(ForeignImportError::MissingField(key))?;
    let value = unquote(value)?;
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        || value.contains('$')
    {
        return Err(ForeignImportError::InvalidField(key.into()));
    }
    Ok(value)
}

fn static_text_required(
    assignments: &BTreeMap<String, String>,
    key: &'static str,
) -> Result<String, ForeignImportError> {
    let value = assignments
        .get(key)
        .ok_or(ForeignImportError::MissingField(key))?;
    let value = unquote(value)?;
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b'$' || byte == b'`')
    {
        return Err(ForeignImportError::InvalidField(key.into()));
    }
    Ok(value)
}

fn array_required(
    assignments: &BTreeMap<String, String>,
    key: &'static str,
) -> Result<Vec<String>, ForeignImportError> {
    array_optional(assignments, key).ok_or(ForeignImportError::MissingField(key))
}

fn array_optional(assignments: &BTreeMap<String, String>, key: &str) -> Option<Vec<String>> {
    assignments
        .get(key)
        .and_then(|value| parse_array(value).ok())
}

fn parse_array(value: &str) -> Result<Vec<String>, ForeignImportError> {
    let value = value.trim();
    let Some(inner) = value
        .strip_prefix('(')
        .and_then(|value| value.strip_suffix(')'))
    else {
        return Err(ForeignImportError::UnsupportedSyntax(
            "CRUX array must use parentheses".into(),
        ));
    };
    let mut values = Vec::new();
    let mut token = String::new();
    let mut quote = None;
    for character in inner.chars() {
        match (quote, character) {
            (Some(active), value) if value == active => quote = None,
            (Some(_), value) => token.push(value),
            (None, '\'' | '"') => quote = Some(character),
            (None, value) if value.is_whitespace() => {
                if !token.is_empty() {
                    values.push(core::mem::take(&mut token));
                }
            }
            (None, '\\' | ';' | '|' | '&' | '<' | '>') => {
                return Err(ForeignImportError::UnsupportedSyntax(
                    "CRUX array contains shell syntax".into(),
                ));
            }
            (None, value) => token.push(value),
        }
    }
    if quote.is_some() {
        return Err(ForeignImportError::UnsupportedSyntax(
            "unterminated CRUX quote".into(),
        ));
    }
    if !token.is_empty() {
        values.push(token);
    }
    if values
        .iter()
        .any(|value| value.is_empty() || value.contains('$'))
    {
        return Err(ForeignImportError::UnsupportedSyntax(
            "CRUX array contains expansion".into(),
        ));
    }
    Ok(values)
}

fn unquote(value: &str) -> Result<String, ForeignImportError> {
    let value = value.trim();
    if (value.starts_with('"') && value.ends_with('"'))
        || (value.starts_with('\'') && value.ends_with('\''))
    {
        Ok(value[1..value.len() - 1].to_string())
    } else if value.contains('"') || value.contains('\'') {
        Err(ForeignImportError::UnsupportedSyntax(
            "mismatched CRUX quote".into(),
        ))
    } else {
        Ok(value.to_string())
    }
}

fn valid_package_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_' | b'+' | b'.')
        })
}

fn valid_architecture(value: &str) -> bool {
    matches!(value, "any" | "x86-64" | "aarch64" | "riscv64")
}

fn valid_revision(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn is_https_url(value: &str) -> bool {
    value.starts_with("https://")
        && !value.contains(char::is_whitespace)
        && !value.contains('@')
        && !value.contains('#')
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn manifest(version: Option<&str>) -> Vec<u8> {
        format!(
            "format = 1\n\n[package]\nname = \"example-driver\"\n{}release = 1\nsummary = \"Example driver\"\nlicense = \"MIT\"\narchitectures = [\"x86-64\"]\ndepends = []\nmakedepends = []\nprovides = []\nconflicts = []\n\n[[source]]\nkind = \"archive\"\nurl = \"https://example.invalid/driver.tar.gz\"\nsha256 = \"{}\"\n",
            version
                .map(|value| format!("version = \"{value}\"\n"))
                .unwrap_or_default(),
            "a".repeat(64)
        )
        .into_bytes()
    }

    #[test]
    fn imports_fixed_nix_export() {
        let metadata = parse_nix_export(&manifest(Some("1.0.0"))).unwrap();
        assert_eq!(metadata.name, "example-driver");
        assert_eq!(metadata.version, "1.0.0");
    }

    #[test]
    fn imports_static_crux_pkgfile() {
        let pkgfile = b"name=example-driver\nversion=1.0.0\nrelease=1\nsource=(https://example.invalid/driver.tar.gz)\ndepends=()\nbuild() { false; }\n";
        let metadata = parse_crux_pkgfile(pkgfile, &manifest(None)).unwrap();
        assert_eq!(metadata.version, "1.0.0");
    }

    #[test]
    fn rejects_crux_substitution() {
        let pkgfile = b"name=example-driver\nversion=$(date)\nrelease=1\nsource=(https://example.invalid/driver.tar.gz)\n";
        assert!(parse_crux_pkgfile(pkgfile, &manifest(None)).is_err());
    }

    #[test]
    fn imports_static_fedora_spec() {
        let spec = b"Name: example-driver\nVersion: 1.0.0\nRelease: 1\nSummary: Example driver\nLicense: MIT\nExclusiveArch: x86_64\nSource0: https://example.invalid/driver.tar.gz\n%description\nExample\n";
        let metadata = parse_fedora_spec(spec, &manifest(Some("1.0.0"))).unwrap();
        assert_eq!(metadata.name, "example-driver");
        assert_eq!(metadata.architectures, vec!["x86-64"]);
    }

    #[test]
    fn imports_debian_control_stanza() {
        let control = b"Source: example-driver\nSection: misc\n\nPackage: example-driver\nArchitecture: amd64\nVersion: 1.0.0\nDescription: Example driver\n A bounded example.\n";
        let metadata = parse_debian_control(control, &manifest(Some("1.0.0"))).unwrap();
        assert_eq!(metadata.version, "1.0.0");
        assert_eq!(metadata.architectures, vec!["x86-64"]);
    }

    #[test]
    fn imports_static_alpine_apkbuild() {
        let apkbuild = format!(
            "pkgname=example-driver\npkgver=1.0.0\npkgrel=1\npkgdesc=\"Example driver\"\narch=\"x86_64\"\nlicense=MIT\nsource=\"https://example.invalid/driver.tar.gz\"\nsha256sums=\"{}\"\nbuild() {{ false; }}\n",
            "a".repeat(64)
        );
        let metadata =
            parse_alpine_apkbuild(apkbuild.as_bytes(), &manifest(Some("1.0.0"))).unwrap();
        assert_eq!(metadata.license, "MIT");
        assert_eq!(metadata.release, 1);
    }

    #[test]
    fn imports_static_gentoo_ebuild() {
        let ebuild = b"EAPI=8\nDESCRIPTION=\"Example driver\"\nHOMEPAGE=\"https://example.invalid\"\nLICENSE=MIT\nKEYWORDS=\"~amd64\"\nSLOT=\"0\"\nSRC_URI=\"https://example.invalid/driver.tar.gz\"\nsrc_compile() { false; }\n";
        let metadata = parse_gentoo_ebuild(
            "example-driver-1.0.0.ebuild",
            ebuild,
            &manifest(Some("1.0.0")),
        )
        .unwrap();
        assert_eq!(metadata.name, "example-driver");
        assert_eq!(metadata.architectures, vec!["x86-64"]);
    }

    #[test]
    fn rejects_fedora_macros_instead_of_evaluating_them() {
        let spec = b"Name: example-driver\nVersion: %{version}\nRelease: 1\nSummary: Example driver\nLicense: MIT\nSource0: https://example.invalid/driver.tar.gz\n";
        assert!(parse_fedora_spec(spec, &manifest(None)).is_err());
    }
}
