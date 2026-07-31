#!/usr/bin/env python3
from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one match, found {count}")
    target.write_text(text.replace(old, new), encoding="utf-8")


replace_once(
    "src/hardware.rs",
    """    #[serde(default)]
    pub submodules: bool,
""",
    """    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    #[serde(default)]
    pub submodules: bool,
""",
)

replace_once(
    "src/hardware.rs",
    """        for source in sources {
            let cached = self.acquire_source(source)?;
            merge_tree_without_symlinks(&cached, &destination)?;
        }
""",
    """        for source in sources {
            let cached = self.acquire_source(source)?;
            if let Some(relative) = source.destination.as_deref() {
                let relative = safe_source_destination(relative)?;
                let target = destination.join(relative);
                if target.exists() {
                    return Err(HardwareError::InvalidSource(format!(
                        "source destination collision: {}",
                        target.display()
                    )));
                }
                fs::create_dir_all(&target)?;
                merge_tree_without_symlinks(&cached, &target)?;
            } else {
                merge_tree_without_symlinks(&cached, &destination)?;
            }
        }
""",
)

replace_once(
    "src/hardware.rs",
    """        if recipe.build.system == "cosmic" {
            run_cosmic_workspace(&source_dir, recipe.policy.network)?;
        } else {
""",
    """        if recipe.build.system == "cosmic" {
            run_cosmic_workspace(&source_dir, recipe.policy.network)?;
        } else if recipe.build.system == "arach-kernel" {
            run_arach_kernel_workspace(&source_dir, recipe.policy.network)?;
        } else {
""",
)

replace_once(
    "src/hardware.rs",
    """    for source in &recipe.source {
        validate_source(source)?;
    }
""",
    """    let mut source_destinations = BTreeSet::new();
    for source in &recipe.source {
        validate_source(source)?;
        if let Some(destination) = source.destination.as_deref() {
            safe_source_destination(destination)?;
            if !source_destinations.insert(destination) {
                return Err(HardwareError::InvalidRecipe(format!(
                    "duplicate source destination: {destination}"
                )));
            }
        }
    }
""",
)

replace_once(
    "src/hardware.rs",
    """    if recipe.build.system == "cosmic" {
        if recipe.build.commands != ["just build", "just install"]
            || recipe.build.outputs.as_slice() != ["@install-tree"]
        {
            return Err(HardwareError::InvalidRecipe(
                "COSMIC recipes must use the fixed workspace adapter".into(),
            ));
        }
    } else {
""",
    """    if recipe.build.system == "cosmic" {
        if recipe.build.commands != ["just build", "just install"]
            || recipe.build.outputs.as_slice() != ["@install-tree"]
        {
            return Err(HardwareError::InvalidRecipe(
                "COSMIC recipes must use the fixed workspace adapter".into(),
            ));
        }
    } else if recipe.build.system == "arach-kernel" {
        let primary = recipe
            .source
            .iter()
            .filter(|source| source.destination.is_none())
            .count();
        let push = recipe
            .source
            .iter()
            .filter(|source| source.destination.as_deref() == Some("sources/push"))
            .count();
        if recipe.policy.network
            || recipe.source.len() != 2
            || primary != 1
            || push != 1
            || recipe.build.commands != ["cargo build-kernel-package"]
            || recipe.build.outputs.as_slice()
                != ["target/package-kernel/x86_64-arach/release/arach"]
        {
            return Err(HardwareError::InvalidRecipe(
                "Arach kernel recipes must use the fixed offline kernel adapter".into(),
            ));
        }
    } else {
""",
)

replace_once(
    "src/hardware.rs",
    """            | "custom"
            | "cosmic"
""",
    """            | "custom"
            | "cosmic"
            | "arach-kernel"
""",
)

replace_once(
    "src/hardware.rs",
    """        output.extend_from_slice(if source.submodules {
            b"submodules=1\n"
        } else {
            b"submodules=0\n"
        });
""",
    """        output.extend_from_slice(if source.submodules {
            b"submodules=1\n"
        } else {
            b"submodules=0\n"
        });
        if let Some(destination) = source.destination.as_deref() {
            output.extend_from_slice(b"destination=");
            output.extend_from_slice(destination.as_bytes());
            output.push(b'\n');
        }
""",
)

replace_once(
    "src/hardware.rs",
    """fn run_build_command(
""",
    """fn run_arach_kernel_workspace(directory: &Path, network: bool) -> Result<(), HardwareError> {
    if network {
        return Err(HardwareError::BuildNetworkNotAllowed);
    }
    let target = directory.join("x86_64-arach.json");
    let push_manifest = directory.join("sources/push/Cargo.toml");
    let probe_manifest = directory.join("probes/c0/Cargo.toml");
    for required in [
        directory.join("Cargo.toml"),
        target.clone(),
        push_manifest.clone(),
        probe_manifest.clone(),
    ] {
        let metadata = fs::symlink_metadata(&required)
            .map_err(|_| HardwareError::InvalidSource(required.display().to_string()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(HardwareError::InvalidSource(format!(
                "kernel adapter input is not a regular file: {}",
                required.display()
            )));
        }
    }

    let push_target = directory.join("target/package-push");
    let probe_target = directory.join("target/package-probe");
    let kernel_target = directory.join("target/package-kernel");
    run_kernel_cargo(
        directory,
        &[
            "build",
            "--locked",
            "--release",
            "--manifest-path",
            path_str(&push_manifest)?,
            "--target",
            path_str(&target)?,
            "-Z",
            "json-target-spec",
            "-Z",
            "build-std=core,alloc,compiler_builtins",
            "-Z",
            "build-std-features=compiler-builtins-mem",
            "--features",
            "os-bin",
        ],
        &[("CARGO_TARGET_DIR", path_str(&push_target)?)],
    )?;
    run_kernel_cargo(
        directory,
        &[
            "build",
            "--locked",
            "--release",
            "--manifest-path",
            path_str(&probe_manifest)?,
            "--target",
            path_str(&target)?,
            "-Z",
            "json-target-spec",
            "-Z",
            "build-std=core,alloc,compiler_builtins",
            "-Z",
            "build-std-features=compiler-builtins-mem",
        ],
        &[("CARGO_TARGET_DIR", path_str(&probe_target)?)],
    )?;

    let push_image = push_target.join("x86_64-arach/release/push");
    let probe_image = probe_target.join("x86_64-arach/release/arach-c0-probe");
    require_nonempty_regular(&push_image, "measured Push image")?;
    require_nonempty_regular(&probe_image, "measured bootstrap image")?;
    run_kernel_cargo(
        directory,
        &[
            "build",
            "--locked",
            "--release",
            "-p",
            "arach",
            "--bin",
            "arach",
            "--no-default-features",
            "--features",
            "kernel-bin,reference-driver,fortran-control",
            "--target",
            path_str(&target)?,
            "-Z",
            "json-target-spec",
            "-Z",
            "build-std=core,alloc,compiler_builtins",
            "-Z",
            "build-std-features=compiler-builtins-mem",
        ],
        &[
            ("CARGO_TARGET_DIR", path_str(&kernel_target)?),
            ("ARACH_PUSH_IMAGE", path_str(&push_image)?),
            ("ARACH_BOOTSTRAP_IMAGE", path_str(&probe_image)?),
            ("ARACH_BOOTSTRAP_ABI", "linux"),
        ],
    )?;
    require_nonempty_regular(
        &kernel_target.join("x86_64-arach/release/arach"),
        "Arach kernel image",
    )
}

fn run_kernel_cargo(
    directory: &Path,
    arguments: &[&str],
    environment: &[(&str, &str)],
) -> Result<(), HardwareError> {
    let mut command = Command::new("cargo");
    command
        .args(arguments)
        .current_dir(directory)
        .stdin(Stdio::null())
        .env("SOURCE_DATE_EPOCH", "1")
        .env("CARGO_NET_OFFLINE", "true")
        .env("GIT_CONFIG_NOSYSTEM", "1");
    for (name, value) in environment {
        command.env(name, value);
    }
    let status = command
        .status()
        .map_err(|error| HardwareError::CommandFailed(error.to_string()))?;
    if status.success() {
        Ok(())
    } else {
        Err(HardwareError::CommandFailed(
            "fixed Arach kernel build phase failed".into(),
        ))
    }
}

fn require_nonempty_regular(path: &Path, label: &str) -> Result<(), HardwareError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| HardwareError::OutputRejected(path.display().to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
        return Err(HardwareError::OutputRejected(format!(
            "{label} is not a non-empty regular file: {}",
            path.display()
        )));
    }
    Ok(())
}

fn run_build_command(
""",
)

replace_once(
    "src/hardware.rs",
    """fn safe_relative_path(value: &str) -> Result<&Path, HardwareError> {
""",
    """fn safe_source_destination(value: &str) -> Result<&Path, HardwareError> {
    let path = safe_relative_path(value)?;
    if path.components().any(|component| !matches!(component, Component::Normal(_)))
        || path
            .components()
            .next()
            .is_some_and(|component| matches!(component, Component::Normal(name) if name == "target" || name == ".git" || name == ".corinth-install"))
    {
        return Err(HardwareError::InvalidSource(format!(
            "unsafe source destination: {value}"
        )));
    }
    Ok(path)
}

fn safe_relative_path(value: &str) -> Result<&Path, HardwareError> {
""",
)

replace_once(
    "src/hardware.rs",
    """            submodules: false,
        }
""",
    """            destination: None,
            submodules: false,
        }
""",
)

replace_once(
    "src/hardware.rs",
    """        changed.submodules = true;
        assert_ne!(first, source_lock_digest(&[changed]));
""",
    """        changed.submodules = true;
        assert_ne!(first, source_lock_digest(&[changed]));
        let mut placed = source();
        placed.destination = Some("sources/push".into());
        assert_ne!(first, source_lock_digest(&[placed]));
        assert!(safe_source_destination("sources/push").is_ok());
        assert!(safe_source_destination("../push").is_err());
        assert!(safe_source_destination("target/push").is_err());
""",
)

arch = Path("src/arch_import.rs")
text = arch.read_text(encoding="utf-8")
needle = "            submodules: false,\n"
count = text.count(needle)
if count != 2:
    raise SystemExit(f"src/arch_import.rs: expected two source constructors, found {count}")
arch.write_text(text.replace(needle, "            destination: None,\n" + needle), encoding="utf-8")
