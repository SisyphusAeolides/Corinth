use arach_hwd::signature::Keyring;
use corinth::arch_import::parse_target_policy;
use corinth::foreign_import::{build_foreign_recipe, parse_nix_export};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

const LIMIT: u64 = 512 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("corinth-import-nix: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let flags = parse_flags(std::env::args().skip(1).collect())?;
    require_exact(
        &flags,
        &[
            "manifest",
            "target",
            "target-signature",
            "keyring",
            "output",
        ],
    )?;
    let manifest = read_regular(required(&flags, "manifest")?)?;
    let target = read_regular(required(&flags, "target")?)?;
    let signature = String::from_utf8(read_regular(required(&flags, "target-signature")?)?)
        .map_err(|_| "target signature is not UTF-8".to_string())?;
    let keyring = Keyring::load(required(&flags, "keyring")?).map_err(|error| error.to_string())?;
    keyring
        .verify_payload(&target, &signature, "package-index")
        .map_err(|error| error.to_string())?;
    let policy = parse_target_policy(&target).map_err(|error| error.to_string())?;
    let metadata = parse_nix_export(&manifest).map_err(|error| error.to_string())?;
    let recipe = build_foreign_recipe(&metadata, &policy).map_err(|error| error.to_string())?;
    write_atomic(required(&flags, "output")?, &recipe.bytes)?;
    println!(
        "imported {}-{} metadata_sha256={} source_lock_sha256={}",
        metadata.name, metadata.version, recipe.metadata_sha256, recipe.source_lock_sha256
    );
    Ok(())
}

fn parse_flags(arguments: Vec<String>) -> Result<BTreeMap<String, PathBuf>, String> {
    if arguments.len() % 2 != 0 {
        return Err(usage());
    }
    let mut flags = BTreeMap::new();
    for pair in arguments.chunks_exact(2) {
        let name = pair[0].strip_prefix("--").ok_or_else(usage)?;
        if !matches!(
            name,
            "manifest" | "target" | "target-signature" | "keyring" | "output"
        ) || flags
            .insert(name.to_string(), PathBuf::from(&pair[1]))
            .is_some()
        {
            return Err(usage());
        }
    }
    Ok(flags)
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

fn read_regular(path: &Path) -> Result<Vec<u8>, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > LIMIT {
        return Err(format!("{} is not a bounded regular file", path.display()));
    }
    fs::read(path).map_err(|error| format!("{}: {error}", path.display()))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("output path must be absolute".into());
    }
    let parent = path
        .parent()
        .ok_or_else(|| "output has no parent".to_string())?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("recipe"),
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
            .and_then(|()| file.sync_all())
            .map_err(|error| error.to_string())?;
        fs::rename(&temporary, path).map_err(|error| error.to_string())?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn usage() -> String {
    "usage: corinth-import-nix --manifest FILE --target FILE --target-signature FILE --keyring FILE --output ABSOLUTE_PATH".into()
}
