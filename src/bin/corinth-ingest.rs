use arach_hwd::signature::Keyring;
use corinth::arch_import::parse_target_policy;
use corinth::hardware::HardwareProvisioner;
use corinth::universal_import::{
    build_universal_import_receipt, crates_io_acquisition_source, git_origin,
    import_universal_lock, parse_universal_import_lock, serialize_universal_import_receipt,
};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

const INPUT_LIMIT: u64 = 512 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("corinth-ingest: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let (flags, allow_network) = parse_flags(std::env::args().skip(1).collect())?;
    require_exact(
        &flags,
        &[
            "lock",
            "lock-signature",
            "target",
            "target-signature",
            "keyring",
            "work",
            "output",
            "receipt",
        ],
    )?;
    let lock_bytes = read_regular(required(&flags, "lock")?)?;
    let lock_signature = String::from_utf8(read_regular(required(&flags, "lock-signature")?)?)
        .map_err(|_| "ingress-lock signature is not UTF-8".to_string())?;
    let target_bytes = read_regular(required(&flags, "target")?)?;
    let target_signature = String::from_utf8(read_regular(required(&flags, "target-signature")?)?)
        .map_err(|_| "target-policy signature is not UTF-8".to_string())?;
    let keyring = Keyring::load(required(&flags, "keyring")?).map_err(|error| error.to_string())?;
    keyring
        .verify_payload(&lock_bytes, &lock_signature, "package-index")
        .map_err(|error| error.to_string())?;
    keyring
        .verify_payload(&target_bytes, &target_signature, "package-index")
        .map_err(|error| error.to_string())?;

    let lock = parse_universal_import_lock(&lock_bytes).map_err(|error| error.to_string())?;
    let policy = parse_target_policy(&target_bytes).map_err(|error| error.to_string())?;
    let output_path = required(&flags, "output")?;
    let receipt_path = required(&flags, "receipt")?;
    if output_path == receipt_path || output_path.exists() || receipt_path.exists() {
        return Err("output and receipt must be distinct new paths".into());
    }
    let work = required(&flags, "work")?.to_path_buf();
    let mut provisioner = HardwareProvisioner::new(work.clone(), work.join("ingress-artifacts"))
        .map_err(|error| error.to_string())?;
    provisioner.allow_network = allow_network;

    let repository;
    let repository_root = if let Some((url, revision, submodules)) = git_origin(&lock) {
        repository = provisioner
            .acquire_recipe_repository(url, revision, submodules)
            .map_err(|error| error.to_string())?;
        Some(repository.as_path())
    } else {
        let source = crates_io_acquisition_source(&lock)
            .ok_or_else(|| "ingress lock has no acquisition source".to_string())?;
        provisioner
            .acquire_locked_source(&source)
            .map_err(|error| error.to_string())?;
        None
    };

    let imported = import_universal_lock(&lock, repository_root, &policy)
        .map_err(|error| error.to_string())?;
    let receipt = build_universal_import_receipt(&lock_bytes, &lock, &imported);
    let receipt_bytes =
        serialize_universal_import_receipt(&receipt).map_err(|error| error.to_string())?;
    write_atomic(output_path, &imported.recipe.bytes)?;
    if let Err(error) = write_atomic(receipt_path, &receipt_bytes) {
        let _ = fs::remove_file(output_path);
        return Err(error);
    }
    println!(
        "ingested {}-{} ecosystem={} ingress_lock_sha256={} recipe_sha256={} source_lock_sha256={}",
        imported.package,
        imported.version,
        lock.ecosystem.name(),
        receipt.ingress_lock_sha256,
        receipt.recipe_metadata_sha256,
        receipt.recipe_source_lock_sha256
    );
    Ok(())
}

fn parse_flags(arguments: Vec<String>) -> Result<(BTreeMap<String, PathBuf>, bool), String> {
    let mut flags = BTreeMap::new();
    let mut allow_network = false;
    let mut index = 0;
    while index < arguments.len() {
        if arguments[index] == "--allow-network" {
            if allow_network {
                return Err(usage());
            }
            allow_network = true;
            index += 1;
            continue;
        }
        let name = arguments[index].strip_prefix("--").ok_or_else(usage)?;
        let value = arguments.get(index + 1).ok_or_else(usage)?;
        if !matches!(
            name,
            "lock"
                | "lock-signature"
                | "target"
                | "target-signature"
                | "keyring"
                | "work"
                | "output"
                | "receipt"
        ) || flags
            .insert(name.to_string(), PathBuf::from(value))
            .is_some()
        {
            return Err(usage());
        }
        index += 2;
    }
    Ok((flags, allow_network))
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
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > INPUT_LIMIT {
        return Err(format!("{} is not a bounded regular file", path.display()));
    }
    fs::read(path).map_err(|error| format!("{}: {error}", path.display()))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("output and receipt paths must be absolute".into());
    }
    let parent = path
        .parent()
        .ok_or_else(|| "output has no parent".to_string())?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("ingress"),
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
    "usage: corinth-ingest --lock FILE --lock-signature FILE --target FILE --target-signature FILE --keyring FILE --work DIRECTORY --output ABSOLUTE_RECIPE --receipt ABSOLUTE_RECEIPT [--allow-network]".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_require_the_complete_signed_ingress_boundary() {
        let arguments = [
            "--lock",
            "lock.toml",
            "--lock-signature",
            "lock.sig",
            "--target",
            "target.toml",
            "--target-signature",
            "target.sig",
            "--keyring",
            "keys.toml",
            "--work",
            "/tmp/work",
            "--output",
            "/tmp/recipe.toml",
            "--receipt",
            "/tmp/receipt.toml",
            "--allow-network",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        let (flags, network) = parse_flags(arguments).unwrap();
        assert_eq!(flags.len(), 8);
        assert!(network);
    }
}
