//! Safe metadata importer for Arch PKGBUILD repositories.
//!
//! A PKGBUILD is executable shell code, not a portable package manifest.  The
//! importer therefore reads only a small, static assignment subset and never
//! sources or evaluates the file.  The target profile supplies the build
//! commands selected by a trusted Arach policy; legacy functions can be run by
//! an explicitly separated compatibility worker, but never by this module.

use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use std::fmt;

use crate::hardware::{
    RECIPE_FORMAT, RecipeBuild, RecipeDocument, RecipeHardware, RecipePackage, RecipePolicy,
    RecipeRuntime, RecipeSource, metadata_sha256, source_lock_sha256,
};

pub const MAX_PKGBUILD_BYTES: usize = 512 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchPackageMetadata {
    pub name: String,
    pub version: String,
    pub release: u32,
    pub summary: String,
    pub license: String,
    pub architectures: Vec<String>,
    pub sources: Vec<ArchSource>,
    pub depends: Vec<String>,
    pub makedepends: Vec<String>,
    pub provides: Vec<String>,
    pub conflicts: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchSource {
    pub kind: ArchSourceKind,
    pub url: String,
    pub revision: Option<String>,
    pub checksum: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchSourceKind {
    Git,
    Archive,
}

/// HWD-selected build policy.  HWD supplies the target facts and signed
/// profile; this structure is the already-authorized, deterministic build
/// choice for one imported package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchTargetProfile {
    pub architecture: String,
    pub scope: String,
    pub publish_authority: String,
    pub build_system: String,
    pub build_commands: Vec<String>,
    pub outputs: Vec<String>,
    pub network: bool,
    pub sandbox: bool,
    pub reproducible: bool,
    pub hardware: Option<RecipeHardware>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportedRecipe {
    pub bytes: Vec<u8>,
    pub metadata_sha256: String,
    pub source_lock_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArchImportError {
    TooLarge,
    InvalidUtf8,
    UnsupportedSyntax(String),
    MissingField(&'static str),
    InvalidField(String),
    UnsupportedSource(String),
    UnpinnedGit(String),
    ChecksumRequired(String),
    ArchitectureMismatch(String),
    TargetInvalid(String),
    RecipeSerialization(String),
}

impl fmt::Display for ArchImportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ArchImportError {}

/// Parse static PKGBUILD assignments without executing shell code.
pub fn parse_pkgbuild(bytes: &[u8]) -> Result<ArchPackageMetadata, ArchImportError> {
    if bytes.is_empty() || bytes.len() > MAX_PKGBUILD_BYTES {
        return Err(ArchImportError::TooLarge);
    }
    let text = core::str::from_utf8(bytes).map_err(|_| ArchImportError::InvalidUtf8)?;
    let assignments = collect_assignments(text)?;
    let name = scalar_required(&assignments, "pkgname")?;
    if name.contains('(') || name.contains(')') {
        return Err(ArchImportError::UnsupportedSyntax(
            "split PKGBUILD packages require the compatibility worker".into(),
        ));
    }
    let version = scalar_required(&assignments, "pkgver")?;
    let release_text = scalar_required(&assignments, "pkgrel")?;
    let release = release_text
        .parse::<u32>()
        .map_err(|_| ArchImportError::InvalidField("pkgrel".into()))?;
    if release == 0 {
        return Err(ArchImportError::InvalidField("pkgrel".into()));
    }
    let summary = scalar_required(&assignments, "pkgdesc")?;
    let architectures = normalize_architectures(&array_required(&assignments, "arch")?)?;
    let license_values = array_required(&assignments, "license")?;
    let license = license_values
        .first()
        .cloned()
        .ok_or(ArchImportError::MissingField("license"))?;
    let source_values = array_required(&assignments, "source")?;
    let checksums = array_optional(&assignments, "sha256sums").unwrap_or_default();
    if checksums.len() != source_values.len() {
        return Err(ArchImportError::ChecksumRequired(
            "sha256sums must contain one entry per source".into(),
        ));
    }
    let mut sources = Vec::with_capacity(source_values.len());
    for (index, value) in source_values.iter().enumerate() {
        sources.push(parse_source(
            value,
            checksums.get(index).map(String::as_str),
        )?);
    }
    if sources.is_empty() {
        return Err(ArchImportError::MissingField("source"));
    }
    Ok(ArchPackageMetadata {
        name,
        version,
        release,
        summary,
        license,
        architectures,
        sources,
        depends: array_optional(&assignments, "depends").unwrap_or_default(),
        makedepends: array_optional(&assignments, "makedepends").unwrap_or_default(),
        provides: array_optional(&assignments, "provides").unwrap_or_default(),
        conflicts: array_optional(&assignments, "conflicts").unwrap_or_default(),
    })
}

/// Convert parsed Arch metadata plus an HWD-selected target policy into the
/// canonical Arach recipe.  The returned digests are the values that must be
/// placed in the signed Arach/HWD intent.
pub fn build_recipe(
    metadata: &ArchPackageMetadata,
    target: &ArchTargetProfile,
) -> Result<ImportedRecipe, ArchImportError> {
    if !metadata
        .architectures
        .iter()
        .any(|arch| arch == "any" || arch == &normalize_architecture(&target.architecture))
    {
        return Err(ArchImportError::ArchitectureMismatch(
            target.architecture.clone(),
        ));
    }
    if metadata.name.is_empty()
        || !metadata
            .name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(ArchImportError::InvalidField("pkgname".into()));
    }
    if target.build_commands.is_empty() || target.outputs.is_empty() {
        return Err(ArchImportError::TargetInvalid(
            "target policy must supply build commands and outputs".into(),
        ));
    }
    if !valid_build_system(&target.build_system) {
        return Err(ArchImportError::TargetInvalid(
            "target policy selected an unsupported build system".into(),
        ));
    }
    if target.scope == "driver" || target.scope == "firmware" {
        if target.hardware.is_none() {
            return Err(ArchImportError::TargetInvalid(
                "hardware policy is required for driver and firmware recipes".into(),
            ));
        }
    } else if target.hardware.is_some() {
        return Err(ArchImportError::TargetInvalid(
            "hardware policy is only valid for driver and firmware recipes".into(),
        ));
    }
    let sources = metadata
        .sources
        .iter()
        .map(|source| match source.kind {
            ArchSourceKind::Git => RecipeSource {
                kind: "git".into(),
                url: Some(source.url.clone()),
                revision: source.revision.clone(),
                checksum: None,
                package: None,
                version: None,
                submodules: false,
            },
            ArchSourceKind::Archive => RecipeSource {
                kind: "archive".into(),
                url: Some(source.url.clone()),
                revision: None,
                checksum: source.checksum.clone(),
                package: None,
                version: None,
                submodules: false,
            },
        })
        .collect::<Vec<_>>();
    let document = RecipeDocument {
        format: RECIPE_FORMAT,
        package: RecipePackage {
            name: metadata.name.clone(),
            version: metadata.version.clone(),
            release: metadata.release,
            summary: metadata.summary.clone(),
            license: metadata.license.clone(),
            scope: target.scope.clone(),
            publish_authority: target.publish_authority.clone(),
            architectures: vec![normalize_architecture(&target.architecture)],
        },
        source: sources,
        build: RecipeBuild {
            system: target.build_system.clone(),
            depends: metadata.makedepends.clone(),
            commands: target.build_commands.clone(),
            outputs: target.outputs.clone(),
        },
        runtime: Some(RecipeRuntime {
            depends: metadata.depends.clone(),
            provides: metadata.provides.clone(),
        }),
        policy: RecipePolicy {
            network: target.network,
            sandbox: target.sandbox,
            reproducible: target.reproducible,
        },
        hardware: target.hardware.clone(),
    };
    let bytes = toml::to_string(&document)
        .map_err(|error| ArchImportError::RecipeSerialization(error.to_string()))?
        .into_bytes();
    Ok(ImportedRecipe {
        metadata_sha256: metadata_sha256(&bytes),
        source_lock_sha256: source_lock_sha256(&document.source),
        bytes,
    })
}

fn collect_assignments(text: &str) -> Result<Vec<(String, String)>, ArchImportError> {
    let mut output = Vec::new();
    let mut lines = text.lines().enumerate().peekable();
    let mut function_depth = 0_i32;
    while let Some((line_number, line)) = lines.next() {
        let code = strip_comment(line);
        let trimmed = code.trim();
        if function_depth == 0 {
            if let Some((key, rest)) = split_assignment(trimmed) {
                let mut value = rest.to_string();
                while !value_complete(&value) {
                    let Some((_, continuation)) = lines.next() else {
                        return Err(ArchImportError::UnsupportedSyntax(format!(
                            "unterminated assignment on line {}",
                            line_number + 1
                        )));
                    };
                    value.push(' ');
                    value.push_str(strip_comment(continuation).trim());
                }
                output.push((key.to_string(), value));
            }
        }
        function_depth += brace_delta(&code);
        if function_depth < 0 {
            return Err(ArchImportError::UnsupportedSyntax(format!(
                "unbalanced function body on line {}",
                line_number + 1
            )));
        }
    }
    if function_depth != 0 {
        return Err(ArchImportError::UnsupportedSyntax(
            "unterminated function body".into(),
        ));
    }
    Ok(output)
}

fn split_assignment(line: &str) -> Option<(&str, &str)> {
    let keys = [
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
        "conflicts",
    ];
    keys.iter().find_map(|key| {
        line.strip_prefix(key).and_then(|rest| {
            let rest = rest.trim_start();
            rest.strip_prefix('=').map(|value| (*key, value))
        })
    })
}

fn scalar_required(
    assignments: &[(String, String)],
    key: &'static str,
) -> Result<String, ArchImportError> {
    let value = assignments
        .iter()
        .rev()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.as_str())
        .ok_or(ArchImportError::MissingField(key))?;
    parse_scalar(value).ok_or_else(|| ArchImportError::InvalidField(key.into()))
}

fn array_required(
    assignments: &[(String, String)],
    key: &'static str,
) -> Result<Vec<String>, ArchImportError> {
    let value = assignments
        .iter()
        .rev()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.as_str())
        .ok_or(ArchImportError::MissingField(key))?;
    parse_array(value).ok_or_else(|| ArchImportError::InvalidField(key.into()))
}

fn array_optional(assignments: &[(String, String)], key: &str) -> Option<Vec<String>> {
    assignments
        .iter()
        .rev()
        .find(|(name, _)| name == key)
        .and_then(|(_, value)| parse_array(value))
}

fn parse_scalar(value: &str) -> Option<String> {
    let value = value.trim();
    if value.starts_with('(') {
        return None;
    }
    let parsed = parse_token(value)?;
    if parsed.is_empty() || value_has_shell(value) {
        None
    } else {
        Some(parsed)
    }
}

fn parse_array(value: &str) -> Option<Vec<String>> {
    let value = value.trim();
    if !value.starts_with('(') || !value.ends_with(')') || value_has_shell(value) {
        return None;
    }
    let body = &value[1..value.len() - 1];
    let mut output = Vec::new();
    let mut cursor = 0;
    while cursor < body.len() {
        while body
            .as_bytes()
            .get(cursor)
            .is_some_and(u8::is_ascii_whitespace)
        {
            cursor += 1;
        }
        if cursor == body.len() {
            break;
        }
        let (token, next) = parse_token_at(body, cursor)?;
        output.push(token);
        cursor = next;
    }
    Some(output)
}

fn parse_token(value: &str) -> Option<String> {
    let (token, next) = parse_token_at(value, 0)?;
    if value[next..].trim().is_empty() {
        Some(token)
    } else {
        None
    }
}

fn parse_token_at(value: &str, start: usize) -> Option<(String, usize)> {
    let bytes = value.as_bytes();
    if start >= bytes.len() {
        return None;
    }
    if bytes[start] == b'\'' || bytes[start] == b'"' {
        let quote = bytes[start];
        let mut index = start + 1;
        let mut output = String::new();
        while index < bytes.len() {
            match bytes[index] {
                byte if byte == quote => return Some((output, index + 1)),
                b'\\' if quote == b'"' => return None,
                byte => output.push(byte as char),
            }
            index += 1;
        }
        return None;
    }
    let mut index = start;
    while index < bytes.len() && !bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    let token = &value[start..index];
    if token.is_empty() || value_has_shell(token) {
        None
    } else {
        Some((token.into(), index))
    }
}

fn parse_source(value: &str, checksum: Option<&str>) -> Result<ArchSource, ArchImportError> {
    let raw = value.split_once("::").map(|(_, url)| url).unwrap_or(value);
    if let Some(git_url) = raw.strip_prefix("git+") {
        let (url, fragment) = git_url
            .split_once('#')
            .ok_or_else(|| ArchImportError::UnpinnedGit(raw.into()))?;
        let revision = fragment
            .strip_prefix("commit=")
            .filter(|value| value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or_else(|| ArchImportError::UnpinnedGit(raw.into()))?;
        if !https_url(url) {
            return Err(ArchImportError::UnsupportedSource(raw.into()));
        }
        Ok(ArchSource {
            kind: ArchSourceKind::Git,
            url: url.into(),
            revision: Some(revision.into()),
            checksum: None,
        })
    } else {
        if !https_url(raw) {
            return Err(ArchImportError::UnsupportedSource(raw.into()));
        }
        let checksum = checksum
            .filter(|value| *value != "SKIP")
            .ok_or_else(|| ArchImportError::ChecksumRequired(raw.into()))?;
        if checksum.len() != 64 || !checksum.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ArchImportError::ChecksumRequired(raw.into()));
        }
        Ok(ArchSource {
            kind: ArchSourceKind::Archive,
            url: raw.into(),
            revision: None,
            checksum: Some(checksum.into()),
        })
    }
}

fn normalize_architectures(values: &[String]) -> Result<Vec<String>, ArchImportError> {
    if values.is_empty() {
        return Err(ArchImportError::MissingField("arch"));
    }
    Ok(values
        .iter()
        .map(|value| normalize_architecture(value))
        .collect())
}

fn normalize_architecture(value: &str) -> String {
    match value {
        "x86_64" => "x86-64".into(),
        "armv7h" => "armv7".into(),
        other => other.into(),
    }
}

fn valid_build_system(value: &str) -> bool {
    matches!(
        value,
        "cargo" | "c" | "fortran" | "idris2" | "agda" | "make" | "cmake" | "meson" | "custom"
    )
}

fn value_complete(value: &str) -> bool {
    let mut quote = None;
    let mut parentheses = 0_i32;
    for byte in value.bytes() {
        if let Some(current) = quote {
            if byte == current {
                quote = None;
            }
            continue;
        }
        match byte {
            b'\'' | b'"' => quote = Some(byte),
            b'(' => parentheses += 1,
            b')' => parentheses -= 1,
            _ => {}
        }
    }
    quote.is_none() && parentheses == 0
}

fn brace_delta(value: &str) -> i32 {
    let mut quote = None;
    let mut delta = 0;
    for byte in value.bytes() {
        if let Some(current) = quote {
            if byte == current {
                quote = None;
            }
            continue;
        }
        match byte {
            b'\'' | b'"' => quote = Some(byte),
            b'{' => delta += 1,
            b'}' => delta -= 1,
            _ => {}
        }
    }
    delta
}

fn strip_comment(value: &str) -> String {
    let mut quote = None;
    for (index, byte) in value.bytes().enumerate() {
        if let Some(current) = quote {
            if byte == current {
                quote = None;
            }
        } else if byte == b'\'' || byte == b'"' {
            quote = Some(byte);
        } else if byte == b'#' {
            return value[..index].into();
        }
    }
    value.into()
}

fn value_has_shell(value: &str) -> bool {
    value.bytes().any(|byte| {
        matches!(
            byte,
            b'$' | b'`' | b';' | b'|' | b'&' | b'<' | b'>' | b'{' | b'}' | b'\\'
        )
    })
}

fn https_url(value: &str) -> bool {
    value.starts_with("https://") && !value.contains(char::is_whitespace)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PKGBUILD: &str = r#"
pkgname=demo
pkgver=1.2.3
pkgrel=4
pkgdesc='demo package # literal'
arch=('x86_64' 'aarch64')
license=('MIT')
source=('https://example.com/demo-1.2.3.tar.gz')
sha256sums=('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
depends=('glibc')
makedepends=('cmake')
provides=('demo-api')

build() {
  # This must never be executed by the importer.
  rm -rf /
}

package() {
  install -Dm755 demo "$pkgdir/usr/bin/demo"
}
"#;

    fn target() -> ArchTargetProfile {
        ArchTargetProfile {
            architecture: "x86-64".into(),
            scope: "system".into(),
            publish_authority: "arach-native".into(),
            build_system: "cmake".into(),
            build_commands: vec!["cmake -S . -B build".into(), "cmake --build build".into()],
            outputs: vec!["build/demo".into()],
            network: false,
            sandbox: true,
            reproducible: true,
            hardware: None,
        }
    }

    #[test]
    fn parser_reads_metadata_and_ignores_functions() {
        let parsed = parse_pkgbuild(PKGBUILD.as_bytes()).unwrap();
        assert_eq!(parsed.name, "demo");
        assert_eq!(parsed.release, 4);
        assert_eq!(parsed.sources.len(), 1);
        assert_eq!(parsed.makedepends, vec!["cmake"]);
    }

    #[test]
    fn shell_and_unpinned_sources_fail_closed() {
        let shell = b"pkgname=$(touch /tmp/pwned)\npkgver=1\npkgrel=1";
        assert!(parse_pkgbuild(shell).is_err());
        let unpinned = PKGBUILD.replace(
            "https://example.com/demo-1.2.3.tar.gz",
            "git+https://github.com/example/demo.git#branch=main",
        );
        assert!(matches!(
            parse_pkgbuild(unpinned.as_bytes()),
            Err(ArchImportError::UnpinnedGit(_))
        ));
    }

    #[test]
    fn recipe_builder_binds_target_and_digests() {
        let metadata = parse_pkgbuild(PKGBUILD.as_bytes()).unwrap();
        let imported = build_recipe(&metadata, &target()).unwrap();
        assert_eq!(imported.metadata_sha256.len(), 64);
        assert_eq!(imported.source_lock_sha256.len(), 64);
        let text = core::str::from_utf8(&imported.bytes).unwrap();
        assert!(text.contains("scope = \"system\""));
        assert!(text.contains("system = \"cmake\""));
        assert!(text.contains("depends = [\"cmake\"]"));
    }
}
