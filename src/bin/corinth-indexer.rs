use corinth::indexer::{ALL_UPSTREAMS, INDEX_SNAPSHOT_FORMAT, IndexSnapshot, UpstreamRoot};
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
    let (flags, allow_network) = parse_flags(std::env::args().skip(1).collect())?;
    require_keys(&flags, &["keyring", "output"])?;

    let keyring_path = required(&flags, "keyring")?;
    let output_path = required(&flags, "output")?;

    // We construct a blank snapshot for demonstration.
    // In a real service this would process arguments, loop, and update.
    let created_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();

    let mut roots = Vec::new();
    for upstream in ALL_UPSTREAMS {
        roots.push(UpstreamRoot {
            upstream,
            revision: "0000000000000000000000000000000000000000000000000000000000000000".into(),
            index_sha256: "0000000000000000000000000000000000000000000000000000000000000000".into(),
        });
    }

    let mut snapshot = IndexSnapshot {
        format: INDEX_SNAPSHOT_FORMAT,
        sequence: 1,
        created_unix,
        key_id: "corinth-auto-indexer-1".into(),
        signature_sha256: "0000000000000000000000000000000000000000000000000000000000000000".into(),
        upstream_roots: roots,
        entries: Vec::new(),
    };

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
        let name = arguments[index].strip_prefix("--").ok_or_else(|| usage())?;
        let value = arguments.get(index + 1).ok_or_else(|| usage())?;
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
    flags.get(name).map(PathBuf::as_path).ok_or_else(|| usage())
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
    "usage: corinth-indexer --keyring FILE --output FILE [--allow-network]".into()
}
