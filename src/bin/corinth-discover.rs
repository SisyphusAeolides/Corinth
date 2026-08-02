use corinth::hardware::HardwareProvisioner;
use corinth::universal_discovery::{
    CargoDiscoveryRequest, GitDiscoveryRequest, arch_discovery_request, aur_discovery_request,
    discover_cargo_candidate, discover_git_candidate,
};
use corinth::universal_import::{
    UniversalEcosystem, UniversalOrigin, serialize_universal_import_lock,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

fn main() {
    if let Err(error) = run() {
        eprintln!("corinth-discover: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let flags = parse_flags(std::env::args().skip(1).collect())?;
    let ecosystem = parse_ecosystem(required(&flags, "ecosystem")?)?;
    let package = required(&flags, "package")?;
    let request = match ecosystem {
        UniversalEcosystem::Aur => {
            require_keys(
                &flags,
                &["ecosystem", "package", "reference", "work", "output"],
            )?;
            DiscoveryRequest::Git(aur_discovery_request(
                package,
                required(&flags, "reference")?,
            ))
        }
        UniversalEcosystem::Arch => {
            require_keys(
                &flags,
                &["ecosystem", "package", "reference", "work", "output"],
            )?;
            DiscoveryRequest::Git(arch_discovery_request(
                package,
                required(&flags, "reference")?,
            ))
        }
        UniversalEcosystem::Nix => {
            require_keys(
                &flags,
                &[
                    "ecosystem",
                    "package",
                    "repository",
                    "reference",
                    "metadata-path",
                    "work",
                    "output",
                ],
            )?;
            DiscoveryRequest::Git(git_request(ecosystem, package, &flags, None)?)
        }
        UniversalEcosystem::Crux
        | UniversalEcosystem::Fedora
        | UniversalEcosystem::Debian
        | UniversalEcosystem::Alpine
        | UniversalEcosystem::Gentoo => {
            require_keys(
                &flags,
                &[
                    "ecosystem",
                    "package",
                    "repository",
                    "reference",
                    "metadata-path",
                    "source-lock-path",
                    "work",
                    "output",
                ],
            )?;
            DiscoveryRequest::Git(git_request(
                ecosystem,
                package,
                &flags,
                Some(required(&flags, "source-lock-path")?.into()),
            )?)
        }
        UniversalEcosystem::Cargo => {
            require_keys(
                &flags,
                &[
                    "ecosystem",
                    "package",
                    "version",
                    "architecture",
                    "work",
                    "output",
                ],
            )?;
            DiscoveryRequest::Cargo(CargoDiscoveryRequest {
                package: package.into(),
                version: required(&flags, "version")?.into(),
                architecture: required(&flags, "architecture")?.into(),
            })
        }
    };
    let work = absolute_path(required(&flags, "work")?, "work")?;
    let output = absolute_path(required(&flags, "output")?, "output")?;
    if output.exists() {
        return Err("output must be a new path".into());
    }
    let mut provisioner = HardwareProvisioner::new(work.clone(), work.join("discovery-artifacts"))
        .map_err(|error| error.to_string())?;
    provisioner.allow_network = true;
    let candidate = match request {
        DiscoveryRequest::Git(request) => discover_git_candidate(&request, &provisioner),
        DiscoveryRequest::Cargo(request) => discover_cargo_candidate(&request, &provisioner),
    }
    .map_err(|error| error.to_string())?;
    let bytes = serialize_universal_import_lock(&candidate).map_err(|error| error.to_string())?;
    write_atomic(&output, &bytes)?;
    match &candidate.origin {
        UniversalOrigin::Git {
            revision,
            metadata_sha256,
            source_lock_sha256,
            ..
        } => println!(
            "discovered {} ecosystem={} revision={} metadata_sha256={} source_lock_sha256={} candidate_sha256={} status=unsigned",
            candidate.package,
            candidate.ecosystem.name(),
            revision,
            metadata_sha256,
            source_lock_sha256.as_deref().unwrap_or("none"),
            hex_digest(&Sha256::digest(&bytes)),
        ),
        UniversalOrigin::CratesIo {
            version,
            checksum,
            packages,
            cargo_lock_sha256,
            ..
        } => println!(
            "discovered {} ecosystem=cargo version={} archive_sha256={} dependency_archives={} cargo_lock_sha256={} candidate_sha256={} status=unsigned",
            candidate.package,
            version,
            checksum,
            packages.len(),
            cargo_lock_sha256,
            hex_digest(&Sha256::digest(&bytes)),
        ),
    }
    Ok(())
}

enum DiscoveryRequest {
    Git(GitDiscoveryRequest),
    Cargo(CargoDiscoveryRequest),
}

fn git_request(
    ecosystem: UniversalEcosystem,
    package: &str,
    flags: &BTreeMap<String, String>,
    source_lock_path: Option<String>,
) -> Result<GitDiscoveryRequest, String> {
    Ok(GitDiscoveryRequest {
        ecosystem,
        package: package.into(),
        repository: required(flags, "repository")?.into(),
        reference: required(flags, "reference")?.into(),
        metadata_path: required(flags, "metadata-path")?.into(),
        source_lock_path,
    })
}

fn parse_flags(arguments: Vec<String>) -> Result<BTreeMap<String, String>, String> {
    let mut flags = BTreeMap::new();
    let mut network = false;
    let mut index = 0;
    while index < arguments.len() {
        if arguments[index] == "--allow-network" {
            if network {
                return Err(usage());
            }
            network = true;
            index += 1;
            continue;
        }
        let name = arguments[index].strip_prefix("--").ok_or_else(usage)?;
        if !matches!(
            name,
            "ecosystem"
                | "package"
                | "repository"
                | "reference"
                | "metadata-path"
                | "source-lock-path"
                | "version"
                | "architecture"
                | "work"
                | "output"
        ) {
            return Err(usage());
        }
        let value = arguments.get(index + 1).ok_or_else(usage)?;
        if value.starts_with("--") || flags.insert(name.into(), value.clone()).is_some() {
            return Err(usage());
        }
        index += 2;
    }
    if !network {
        return Err("provider discovery requires explicit --allow-network".into());
    }
    Ok(flags)
}

fn parse_ecosystem(value: &str) -> Result<UniversalEcosystem, String> {
    match value {
        "arch" => Ok(UniversalEcosystem::Arch),
        "aur" => Ok(UniversalEcosystem::Aur),
        "fedora" => Ok(UniversalEcosystem::Fedora),
        "debian" => Ok(UniversalEcosystem::Debian),
        "alpine" => Ok(UniversalEcosystem::Alpine),
        "gentoo" => Ok(UniversalEcosystem::Gentoo),
        "crux" => Ok(UniversalEcosystem::Crux),
        "nix" => Ok(UniversalEcosystem::Nix),
        "cargo" => Ok(UniversalEcosystem::Cargo),
        _ => Err("unsupported discovery ecosystem".into()),
    }
}

fn require_keys(flags: &BTreeMap<String, String>, expected: &[&str]) -> Result<(), String> {
    if flags.len() == expected.len() && expected.iter().all(|name| flags.contains_key(*name)) {
        Ok(())
    } else {
        Err(usage())
    }
}

fn required<'a>(flags: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str, String> {
    flags.get(name).map(String::as_str).ok_or_else(usage)
}

fn absolute_path(value: &str, label: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(format!("{label} path must be absolute"));
    }
    Ok(path)
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
            .unwrap_or("candidate"),
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
        fs::hard_link(&temporary, path).map_err(|error| error.to_string())?;
        let _ = fs::remove_file(&temporary);
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn usage() -> String {
    "usage: corinth-discover --ecosystem <arch|aur|fedora|debian|alpine|gentoo|crux|nix|cargo> --package NAME [--version EXACT --architecture ARCH] [--repository HTTPS_GIT] [--reference <HEAD|FULL_REF|COMMIT>] [--metadata-path PATH] [--source-lock-path PATH] --work ABSOLUTE_DIRECTORY --output ABSOLUTE_CANDIDATE --allow-network".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_authority_is_always_explicit() {
        let arguments = [
            "--ecosystem",
            "aur",
            "--package",
            "demo",
            "--reference",
            "HEAD",
            "--work",
            "/tmp/work",
            "--output",
            "/tmp/demo.toml",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        assert!(parse_flags(arguments).is_err());
    }

    #[test]
    fn aur_surface_excludes_repository_override() {
        let arguments = [
            "--ecosystem",
            "aur",
            "--package",
            "demo",
            "--repository",
            "https://example.org/demo.git",
            "--reference",
            "HEAD",
            "--work",
            "/tmp/work",
            "--output",
            "/tmp/demo.toml",
            "--allow-network",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        let flags = parse_flags(arguments).unwrap();
        assert!(
            require_keys(
                &flags,
                &["ecosystem", "package", "reference", "work", "output"]
            )
            .is_err()
        );
    }

    #[test]
    fn every_supported_ecosystem_has_an_explicit_cli_identity() {
        for (name, ecosystem) in [
            ("arch", UniversalEcosystem::Arch),
            ("aur", UniversalEcosystem::Aur),
            ("fedora", UniversalEcosystem::Fedora),
            ("debian", UniversalEcosystem::Debian),
            ("alpine", UniversalEcosystem::Alpine),
            ("gentoo", UniversalEcosystem::Gentoo),
            ("crux", UniversalEcosystem::Crux),
            ("nix", UniversalEcosystem::Nix),
            ("cargo", UniversalEcosystem::Cargo),
        ] {
            assert_eq!(parse_ecosystem(name).unwrap(), ecosystem);
        }
        assert!(parse_ecosystem("unknown").is_err());
    }
}
