use arach_hwd::signature::Keyring;
use corinth::arch_import::parse_target_policy;
use corinth::corpus::{
    MAXIMUM_CORPUS_BYTES, RecipeCorpusEntry, RecipeGenerationStrategy, parse_recipe_corpus,
};
use corinth::indexer::Upstream;
use corinth::universal_import::{UniversalEcosystem, parse_universal_import_lock};
use corinth::worker::WorkerRequest;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

const SIGNATURE_LIMIT: u64 = 512 * 1024;
const ENTRY_INPUT_LIMIT: u64 = 4 * 1024 * 1024;

#[derive(Clone, Debug, Serialize)]
struct CorpusVerificationReport {
    format: u32,
    corpus_sha256: String,
    target_count: u32,
    shard_count: u16,
    selected_shard: Option<u16>,
    selected_entries: u32,
    static_entries: u32,
    worker_entries: u32,
    verified_files: u32,
}

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("corinth-corpus: {error}");
        std::process::exit(1);
    }
}

fn run(arguments: Vec<String>) -> Result<(), String> {
    let (flags, production, selected_shard) = parse_flags(arguments)?;
    require_exact(
        &flags,
        &[
            "manifest",
            "manifest-signature",
            "keyring",
            "root",
            "report",
        ],
    )?;

    let manifest_path = required(&flags, "manifest")?;
    let signature_path = required(&flags, "manifest-signature")?;
    let keyring_path = required(&flags, "keyring")?;
    let root_path = required(&flags, "root")?;
    let report_path = required(&flags, "report")?;

    let manifest_bytes = read_regular(manifest_path, MAXIMUM_CORPUS_BYTES as u64)?;
    let signature = String::from_utf8(read_regular(signature_path, SIGNATURE_LIMIT)?)
        .map_err(|_| "corpus signature is not UTF-8".to_string())?;
    let keyring = Keyring::load(keyring_path).map_err(|error| error.to_string())?;
    keyring
        .verify_payload(&manifest_bytes, &signature, "package-index")
        .map_err(|error| error.to_string())?;

    let manifest = parse_recipe_corpus(&manifest_bytes).map_err(|error| error.to_string())?;
    if production {
        manifest
            .validate_production()
            .map_err(|error| error.to_string())?;
    }
    if selected_shard.is_some_and(|shard| shard >= manifest.shard_count) {
        return Err("selected shard is outside the corpus".into());
    }

    let root = canonical_directory(root_path)?;
    let mut selected_entries = 0_u32;
    let mut static_entries = 0_u32;
    let mut worker_entries = 0_u32;
    let mut verified_files = 0_u32;
    for entry in &manifest.entries {
        if selected_shard.is_some_and(|shard| entry.shard != shard) {
            continue;
        }
        verify_entry(&root, entry, &keyring)?;
        selected_entries = selected_entries
            .checked_add(1)
            .ok_or_else(|| "selected entry count overflow".to_string())?;
        verified_files = verified_files
            .checked_add(match entry.strategy {
                RecipeGenerationStrategy::StaticImporter => 4,
                RecipeGenerationStrategy::DeterministicWorker => 5,
            })
            .ok_or_else(|| "verified file count overflow".to_string())?;
        match entry.strategy {
            RecipeGenerationStrategy::StaticImporter => static_entries += 1,
            RecipeGenerationStrategy::DeterministicWorker => worker_entries += 1,
        }
    }

    let report = CorpusVerificationReport {
        format: 1,
        corpus_sha256: hex_digest(&Sha256::digest(&manifest_bytes)),
        target_count: manifest.target_count,
        shard_count: manifest.shard_count,
        selected_shard,
        selected_entries,
        static_entries,
        worker_entries,
        verified_files,
    };
    let report_bytes = serde_json::to_vec_pretty(&report).map_err(|error| error.to_string())?;
    write_atomic(report_path, &report_bytes)?;
    println!(
        "verified {} corpus entries (static={}, worker={}) across {} signed input files",
        selected_entries, static_entries, worker_entries, verified_files
    );
    Ok(())
}

fn verify_entry(root: &Path, entry: &RecipeCorpusEntry, keyring: &Keyring) -> Result<(), String> {
    let lock = verify_relative(
        root,
        &entry.ingress_lock,
        &entry.ingress_lock_sha256,
        ENTRY_INPUT_LIMIT,
    )?;
    let lock_signature_bytes = verify_relative(
        root,
        &entry.ingress_signature,
        &entry.ingress_signature_sha256,
        SIGNATURE_LIMIT,
    )?;
    let lock_signature = String::from_utf8(lock_signature_bytes)
        .map_err(|_| format!("{} is not UTF-8", entry.ingress_signature))?;
    keyring
        .verify_payload(&lock, &lock_signature, "package-index")
        .map_err(|error| format!("{}: {error}", entry.ingress_lock))?;

    let target = verify_relative(
        root,
        &entry.target_policy,
        &entry.target_policy_sha256,
        ENTRY_INPUT_LIMIT,
    )?;
    let target_signature_bytes = verify_relative(
        root,
        &entry.target_signature,
        &entry.target_signature_sha256,
        SIGNATURE_LIMIT,
    )?;
    let target_signature = String::from_utf8(target_signature_bytes)
        .map_err(|_| format!("{} is not UTF-8", entry.target_signature))?;
    keyring
        .verify_payload(&target, &target_signature, "package-index")
        .map_err(|error| format!("{}: {error}", entry.target_policy))?;
    let policy = parse_target_policy(&target).map_err(|error| error.to_string())?;
    if policy.package != entry.package || policy.architecture != entry.architecture {
        return Err(format!(
            "{} target policy differs from corpus identity",
            entry.package
        ));
    }

    match entry.strategy {
        RecipeGenerationStrategy::StaticImporter => {
            let ingress = parse_universal_import_lock(&lock).map_err(|error| error.to_string())?;
            if ingress.package != entry.package
                || !ecosystem_matches(entry.upstream, ingress.ecosystem)
            {
                return Err(format!(
                    "{} ingress lock differs from corpus identity",
                    entry.package
                ));
            }
        }
        RecipeGenerationStrategy::DeterministicWorker => {
            let path = entry
                .worker_request
                .as_deref()
                .ok_or_else(|| "worker request is missing".to_string())?;
            let digest = entry
                .worker_request_sha256
                .as_deref()
                .ok_or_else(|| "worker request digest is missing".to_string())?;
            let bytes = verify_relative(root, path, digest, ENTRY_INPUT_LIMIT)?;
            let request: WorkerRequest =
                serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            request.validate().map_err(|error| error.to_string())?;
            if request.ecosystem != upstream_name(entry.upstream) {
                return Err(format!(
                    "{} worker ecosystem differs from corpus identity",
                    entry.package
                ));
            }
        }
    }
    Ok(())
}

fn ecosystem_matches(upstream: Upstream, ecosystem: UniversalEcosystem) -> bool {
    matches!(
        (upstream, ecosystem),
        (Upstream::Arch, UniversalEcosystem::Arch)
            | (Upstream::Aur, UniversalEcosystem::Aur)
            | (Upstream::Fedora, UniversalEcosystem::Fedora)
            | (Upstream::Debian, UniversalEcosystem::Debian)
            | (Upstream::Alpine, UniversalEcosystem::Alpine)
            | (Upstream::Gentoo, UniversalEcosystem::Gentoo)
            | (Upstream::Crux, UniversalEcosystem::Crux)
            | (Upstream::Nix, UniversalEcosystem::Nix)
            | (Upstream::Cargo, UniversalEcosystem::Cargo)
    )
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

fn verify_relative(
    root: &Path,
    relative: &str,
    expected: &str,
    limit: u64,
) -> Result<Vec<u8>, String> {
    let path = root.join(relative);
    let metadata =
        fs::symlink_metadata(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > limit {
        return Err(format!("{} is not a bounded regular file", path.display()));
    }
    let canonical = fs::canonicalize(&path).map_err(|error| error.to_string())?;
    if canonical != path || !canonical.starts_with(root) {
        return Err(format!(
            "{} traverses a symlink or escapes the corpus root",
            relative
        ));
    }
    let bytes = fs::read(&canonical).map_err(|error| error.to_string())?;
    let actual = hex_digest(&Sha256::digest(&bytes));
    if actual != expected {
        return Err(format!(
            "{} digest differs from the signed corpus",
            relative
        ));
    }
    Ok(bytes)
}

fn canonical_directory(path: &Path) -> Result<PathBuf, String> {
    if path.is_symlink() || !path.is_dir() {
        return Err("corpus root is not a regular directory".into());
    }
    fs::canonicalize(path).map_err(|error| error.to_string())
}

fn read_regular(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > limit {
        return Err(format!("{} is not a bounded regular file", path.display()));
    }
    fs::read(path).map_err(|error| format!("{}: {error}", path.display()))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if path.is_symlink() || path.exists() {
        return Err("report path must be a new non-symlink path".into());
    }
    let parent = path
        .parent()
        .ok_or_else(|| "report has no parent".to_string())?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("corpus"),
        std::process::id()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&temporary)
            .map_err(|error| error.to_string())?;
        file.write_all(bytes)
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.sync_all())
            .map_err(|error| error.to_string())?;
        fs::rename(&temporary, path).map_err(|error| error.to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

type ParsedFlags = (BTreeMap<String, PathBuf>, bool, Option<u16>);

fn parse_flags(arguments: Vec<String>) -> Result<ParsedFlags, String> {
    let mut flags = BTreeMap::new();
    let mut production = false;
    let mut selected_shard = None;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--production" => {
                if production {
                    return Err(usage());
                }
                production = true;
                index += 1;
            }
            "--shard" => {
                if selected_shard.is_some() {
                    return Err(usage());
                }
                let value = arguments.get(index + 1).ok_or_else(usage)?;
                selected_shard = Some(value.parse::<u16>().map_err(|_| usage())?);
                index += 2;
            }
            value => {
                let name = value.strip_prefix("--").ok_or_else(usage)?;
                let value = arguments.get(index + 1).ok_or_else(usage)?;
                if !matches!(
                    name,
                    "manifest" | "manifest-signature" | "keyring" | "root" | "report"
                ) || flags
                    .insert(name.to_string(), PathBuf::from(value))
                    .is_some()
                {
                    return Err(usage());
                }
                index += 2;
            }
        }
    }
    Ok((flags, production, selected_shard))
}

fn require_exact(flags: &BTreeMap<String, PathBuf>, expected: &[&str]) -> Result<(), String> {
    if flags.len() == expected.len() && expected.iter().all(|name| flags.contains_key(*name)) {
        Ok(())
    } else {
        Err(usage())
    }
}

fn required<'a>(flags: &'a BTreeMap<String, PathBuf>, name: &str) -> Result<&'a Path, String> {
    flags.get(name).map(PathBuf::as_path).ok_or_else(usage)
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn usage() -> String {
    "usage: corinth-corpus --manifest FILE --manifest-signature FILE --keyring FILE --root DIRECTORY --report NEW_FILE [--production] [--shard NUMBER]".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_accept_production_and_one_shard() {
        let arguments = [
            "--manifest",
            "corpus.json",
            "--manifest-signature",
            "corpus.sig",
            "--keyring",
            "keys.toml",
            "--root",
            "/corpus",
            "--report",
            "/tmp/report.json",
            "--production",
            "--shard",
            "17",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        let (flags, production, shard) = parse_flags(arguments).unwrap();
        assert_eq!(flags.len(), 5);
        assert!(production);
        assert_eq!(shard, Some(17));
    }

    #[test]
    fn github_requires_the_worker_path() {
        assert!(!ecosystem_matches(
            Upstream::Github,
            UniversalEcosystem::Arch
        ));
        assert_eq!(upstream_name(Upstream::Github), "github");
    }
}
