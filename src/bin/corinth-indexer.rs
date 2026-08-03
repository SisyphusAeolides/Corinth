use corinth::indexer::IndexSnapshot;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

fn main() {
    if let Err(error) = run() {
        eprintln!("corinth-indexer: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let (flags, _allow_network) = parse_flags(std::env::args().skip(1).collect())?;
    require_keys(&flags, &["keyring", "input", "output"])?;

    let keyring_path = required(&flags, "keyring")?;
    let input_path = required(&flags, "input")?;
    let output_path = required(&flags, "output")?;

    if keyring_path.is_symlink() || !keyring_path.is_file() {
        return Err("keyring is not a regular file".into());
    }
    if input_path.is_symlink() || !input_path.is_file() {
        return Err("input snapshot is not a regular file".into());
    }
    let snapshot: IndexSnapshot =
        serde_json::from_slice(&fs::read(input_path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    snapshot.validate(None).map_err(|error| error.to_string())?;

    let bytes = serde_json::to_vec_pretty(&snapshot).map_err(|e| e.to_string())?;
    write_atomic(output_path, &bytes)?;
    println!(
        "wrote indexer snapshot format={} sequence={}",
        snapshot.format, snapshot.sequence
    );
    Ok(())
}

fn parse_flags(arguments: Vec<String>) -> Result<(BTreeMap<String, PathBuf>, bool), String> {
    let mut flags = BTreeMap::new();
    let mut allow_network = false;
    let mut index = 0;
    while index < arguments.len() {
        if arguments[index] == "--allow-network" {
            allow_network = true;
            index += 1;
            continue;
        }
        let name = arguments[index].strip_prefix("--").ok_or_else(usage)?;
        let value = arguments.get(index + 1).ok_or_else(usage)?;
        flags.insert(name.to_string(), PathBuf::from(value));
        index += 2;
    }
    Ok((flags, allow_network))
}

fn require_keys(flags: &BTreeMap<String, PathBuf>, expected: &[&str]) -> Result<(), String> {
    if expected.iter().all(|name| flags.contains_key(*name)) {
        Ok(())
    } else {
        Err(usage())
    }
}

fn required<'a>(flags: &'a BTreeMap<String, PathBuf>, name: &str) -> Result<&'a Path, String> {
    flags.get(name).map(PathBuf::as_path).ok_or_else(usage)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "output has no parent".to_string())?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("index"),
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
    "usage: corinth-indexer --keyring FILE --input SNAPSHOT.json --output FILE [--allow-network]"
        .into()
}
