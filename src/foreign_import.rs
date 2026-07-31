//! Safe CRUX and Nix metadata adapters.
//!
//! Neither adapter evaluates a package language. CRUX Pkgfiles are limited to
//! static assignments and are paired with an immutable source lock. Nix input
//! is a fixed-output export manifest, not a Nix expression. The resulting
//! metadata still requires a detached-signature Arach target policy before it
//! can become a native Corinth recipe.

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
    build_metadata(&manifest, version, release, manifest.package.depends.clone())
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
                if !source.sha256.as_deref().is_some_and(valid_digest)
                    || source.revision.is_some()
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

fn collect_static_assignments(
    text: &str,
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
    let allowed = ["name", "version", "release", "source", "depends"];
    let mut assignments = BTreeMap::new();
    for statement in statements {
        let Some((key, value)) = statement.split_once('=') else {
            return Err(ForeignImportError::UnsupportedSyntax(statement));
        };
        let key = key.trim();
        if !allowed.contains(&key) || assignments.insert(key.into(), value.trim().into()).is_some() {
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
        || value.bytes().any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        || value.contains('$')
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
    assignments.get(key).and_then(|value| parse_array(value).ok())
}

fn parse_array(value: &str) -> Result<Vec<String>, ForeignImportError> {
    let value = value.trim();
    let Some(inner) = value.strip_prefix('(').and_then(|value| value.strip_suffix(')')) else {
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
    if values.iter().any(|value| value.is_empty() || value.contains('$')) {
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
}
