#![cfg_attr(feature = "os-bin", no_std)]
#![cfg_attr(feature = "os-bin", no_main)]

#[cfg(feature = "os-bin")]
mod os_service {
    use core::panic::PanicInfo;

    use corinth::command::{CommandError, CommandResult, execute, parse_argv};
    use corinth::pkg::PackageLedger;

    #[global_allocator]
    static HEAP: slope::memory::GlobalSlabHeap = slope::memory::GlobalSlabHeap::new();

    core::arch::global_asm!(
        ".section .text._start,\"ax\"",
        ".global _start",
        ".type _start,@function",
        "_start:",
        "mov %rsp, %rdi",
        "jmp corinth_start_with_stack",
        ".size _start, .-_start",
        options(att_syntax)
    );

    #[unsafe(no_mangle)]
    pub extern "C" fn corinth_start_with_stack(stack_ptr: *const u8) -> ! {
        HEAP.init();
        // SAFETY: Arach supplies the documented `[argc][argv][envp]` entry ABI.
        let argv = unsafe { slope::env::QuantumArgv::from_stack(stack_ptr) };
        let result = parse_argv(&argv).and_then(|command| {
            let mut ledger = PackageLedger::new();
            execute(command, &mut ledger)
        });
        match result {
            Ok(CommandResult::Search { known: true }) => {
                finish(b"corinth: package found in measured build catalog\n", 0)
            }
            Ok(CommandResult::Search { known: false }) => {
                finish(b"corinth: package not found\n", 1)
            }
            Ok(CommandResult::Staged(_)) => finish(
                b"corinth: transaction staged; durable artifact store is unavailable\n",
                69,
            ),
            Err(CommandError::PackageUnavailable) => finish(
                b"corinth: package is not rooted in the measured build catalog\n",
                69,
            ),
            Err(CommandError::Package(_)) => finish(b"corinth: package transaction rejected\n", 65),
            Err(_) => finish(
                b"usage: corinth <install|remove|update|search> <package>\n",
                64,
            ),
        }
    }

    fn finish(message: &[u8], status: i32) -> ! {
        let _ = slope::io::write(1, message);
        let _ = slope::process::request_exit(status);
        loop {
            let _ = slope::process::yield_now();
        }
    }

    #[panic_handler]
    fn panic(_info: &PanicInfo<'_>) -> ! {
        finish(b"corinth: unrecoverable package-service panic\n", 70)
    }
}

#[cfg(all(not(feature = "os-bin"), feature = "host-store"))]
mod host_cli {
    use std::env;
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::path::PathBuf;

    use arach_hwd::catalog::verify_catalog;
    use arach_hwd::plan::{PlanSet, ProvisionPlan};
    use arach_hwd::signature::Keyring;
    use corinth::arch_import::{
        build_recipe, parse_pkgbuild, parse_target_policy, read_pkgbuild_file,
        read_repository_pkgbuild, target_profile_for_package,
    };
    use corinth::binary::{BinaryInstallStore, BinaryProvisioner, verify_binary_index};
    use corinth::hardware::{
        HardwareError, HardwareProvisioner, HostPackageStore, verify_plan, verify_plan_set,
    };

    pub fn run() -> Result<(), String> {
        let mut args = env::args().skip(1);
        let verb = args.next().ok_or_else(usage)?;
        let mut plan = None;
        let mut profile = None;
        let mut profiles = None;
        let mut catalog_lock = None;
        let mut signature = None;
        let mut keyring = None;
        let mut recipes = None;
        let mut recipes_git = None;
        let mut index = None;
        let mut work = None;
        let mut artifacts = None;
        let mut state = None;
        let mut root = None;
        let mut pkgbuild = None;
        let mut pkgbuild_git = None;
        let mut target = None;
        let mut target_signature = None;
        let mut output = None;
        let mut package: Option<String> = None;
        let mut allow_network = false;

        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--plan" => plan = Some(PathBuf::from(args.next().ok_or_else(usage)?)),
                "--profile" => profile = Some(PathBuf::from(args.next().ok_or_else(usage)?)),
                "--profiles" => profiles = Some(PathBuf::from(args.next().ok_or_else(usage)?)),
                "--catalog-lock" => {
                    catalog_lock = Some(PathBuf::from(args.next().ok_or_else(usage)?))
                }
                "--signature" => signature = Some(PathBuf::from(args.next().ok_or_else(usage)?)),
                "--keyring" => keyring = Some(PathBuf::from(args.next().ok_or_else(usage)?)),
                "--recipes" => recipes = Some(PathBuf::from(args.next().ok_or_else(usage)?)),
                "--index" => index = Some(PathBuf::from(args.next().ok_or_else(usage)?)),
                "--recipes-git" => {
                    let url = args.next().ok_or_else(usage)?;
                    let revision = args.next().ok_or_else(usage)?;
                    recipes_git = Some((url, revision));
                }
                "--work" => work = Some(PathBuf::from(args.next().ok_or_else(usage)?)),
                "--artifacts" => artifacts = Some(PathBuf::from(args.next().ok_or_else(usage)?)),
                "--state" => state = Some(PathBuf::from(args.next().ok_or_else(usage)?)),
                "--root" => root = Some(PathBuf::from(args.next().ok_or_else(usage)?)),
                "--pkgbuild" => pkgbuild = Some(PathBuf::from(args.next().ok_or_else(usage)?)),
                "--pkgbuild-git" => {
                    let url = args.next().ok_or_else(usage)?;
                    let revision = args.next().ok_or_else(usage)?;
                    let path = PathBuf::from(args.next().ok_or_else(usage)?);
                    pkgbuild_git = Some((url, revision, path));
                }
                "--target" => target = Some(PathBuf::from(args.next().ok_or_else(usage)?)),
                "--target-signature" => {
                    target_signature = Some(PathBuf::from(args.next().ok_or_else(usage)?))
                }
                "--output" => output = Some(PathBuf::from(args.next().ok_or_else(usage)?)),
                "--allow-network" => allow_network = true,
                value if !value.starts_with('-') && package.is_none() => {
                    package = Some(value.into())
                }
                _ => return Err(usage()),
            }
        }

        if verb == "import-pkgbuild" {
            if pkgbuild.is_some() == pkgbuild_git.is_some() {
                return Err(
                    "import-pkgbuild requires exactly one of --pkgbuild or --pkgbuild-git".into(),
                );
            }
            let target_path = target.ok_or_else(usage)?;
            let target_signature_path = target_signature.ok_or_else(usage)?;
            let keyring_path = keyring.ok_or_else(usage)?;
            let output_path = output.ok_or_else(usage)?;
            let pkgbuild_bytes = if let Some(path) = pkgbuild {
                read_pkgbuild_file(&path).map_err(|error| error.to_string())?
            } else {
                let (url, revision, relative) = pkgbuild_git.expect("validated above");
                let work_root = work.ok_or_else(|| {
                    "--work is required when importing a remote PKGBUILD".to_string()
                })?;
                let mut fetcher =
                    HardwareProvisioner::new(work_root.clone(), work_root.join("import-artifacts"))
                        .map_err(render)?;
                fetcher.allow_network = allow_network;
                let repository = fetcher
                    .acquire_recipe_repository(&url, &revision, false)
                    .map_err(render)?;
                read_repository_pkgbuild(&repository, &relative)
                    .map_err(|error| error.to_string())?
            };
            let metadata = parse_pkgbuild(&pkgbuild_bytes).map_err(|error| error.to_string())?;
            let target_bytes = fs::read(target_path).map_err(|error| error.to_string())?;
            let signature =
                fs::read_to_string(target_signature_path).map_err(|error| error.to_string())?;
            let trusted = Keyring::load(&keyring_path).map_err(|error| error.to_string())?;
            trusted
                .verify_payload(&target_bytes, &signature, "package-index")
                .map_err(|error| error.to_string())?;
            let policy = parse_target_policy(&target_bytes).map_err(|error| error.to_string())?;
            let target = target_profile_for_package(&policy, &metadata.name)
                .map_err(|error| error.to_string())?;
            let recipe = build_recipe(&metadata, &target).map_err(|error| error.to_string())?;
            write_recipe_atomically(&output_path, &recipe.bytes)?;
            println!(
                "imported {}-{} metadata_sha256={} source_lock_sha256={}",
                metadata.name, metadata.version, recipe.metadata_sha256, recipe.source_lock_sha256
            );
            return Ok(());
        }

        let artifacts = artifacts.ok_or_else(usage)?;
        let state = state.ok_or_else(usage)?;
        let store = HostPackageStore::open(state.clone(), artifacts.clone()).map_err(render)?;

        match verb.as_str() {
            "remove" => {
                let package = package.ok_or_else(usage)?;
                if let Some(root) = root {
                    BinaryInstallStore::open(state, root)
                        .map_err(render)?
                        .remove(&package)
                        .map_err(render)?;
                    println!("removed {package} from target root");
                } else {
                    store.remove(&package).map_err(render)?;
                    println!("removed {package} from staged artifacts");
                }
            }
            "install" | "update" => {
                if let Some(index_path) = index {
                    let signature_path = signature.ok_or_else(usage)?;
                    let keyring_path = keyring.ok_or_else(usage)?;
                    let package = package.ok_or_else(usage)?;
                    let index_bytes = fs::read(index_path).map_err(|e| e.to_string())?;
                    let signature_text =
                        fs::read_to_string(signature_path).map_err(|e| e.to_string())?;
                    let trusted = Keyring::load(&keyring_path).map_err(|e| e.to_string())?;
                    let verified = verify_binary_index(&index_bytes, &signature_text, &trusted)
                        .map_err(render)?;
                    if verified
                        .index
                        .packages
                        .iter()
                        .find(|record| record.name == package)
                        .is_some_and(|record| {
                            !matches!(record.scope, arach_hwd::profile::PackageScope::System)
                        })
                    {
                        return Err(
                            "driver and firmware binaries require an HWD-signed plan".into()
                        );
                    }
                    let mut fetcher = BinaryProvisioner::new(artifacts.clone()).map_err(render)?;
                    fetcher.allow_network = allow_network;
                    if let Some(root) = root {
                        let receipt = if verb == "update" {
                            fetcher
                                .update_to_root(state, root, &verified, &package, None)
                                .map_err(render)?
                        } else {
                            fetcher
                                .install_to_root(state, root, &verified, &package, None)
                                .map_err(render)?
                        };
                        println!(
                            "{} {}-{} installed={} files={}",
                            verb,
                            receipt.package,
                            receipt.release,
                            receipt.artifact_sha256,
                            receipt.files.len()
                        );
                    } else {
                        let receipt = fetcher.fetch(&verified, &package, None).map_err(render)?;
                        if verb == "update" {
                            store
                                .update(std::slice::from_ref(&receipt))
                                .map_err(render)?;
                        } else {
                            store
                                .install(std::slice::from_ref(&receipt))
                                .map_err(render)?;
                        }
                        println!(
                            "{} {}-{} staged artifact={}",
                            verb, receipt.package, receipt.release, receipt.artifact_sha256
                        );
                    }
                    return Ok(());
                }
                let work = work.ok_or_else(usage)?;
                let plan_path = plan.ok_or_else(usage)?;
                let keyring_path = keyring.ok_or_else(usage)?;
                let recipe_root = if let Some(root) = recipes {
                    root
                } else if let Some((url, revision)) = recipes_git {
                    let mut fetcher = HardwareProvisioner::new(work.clone(), artifacts.clone())
                        .map_err(render)?;
                    fetcher.allow_network = allow_network;
                    fetcher
                        .acquire_recipe_repository(&url, &revision, false)
                        .map_err(render)?
                } else {
                    return Err(usage());
                };
                let text = fs::read_to_string(plan_path).map_err(|e| e.to_string())?;
                let plans = parse_plans(&text)?;
                let trusted = Keyring::load(&keyring_path).map_err(|e| e.to_string())?;
                let verified = if let Some(profile_path) = profile {
                    if plans.plan.len() != 1 {
                        return Err(
                            "a multi-device plan set requires --profiles and --catalog-lock".into(),
                        );
                    }
                    let signature_path = signature.ok_or_else(usage)?;
                    let profile_bytes = fs::read(profile_path).map_err(|e| e.to_string())?;
                    let signature_text =
                        fs::read_to_string(signature_path).map_err(|e| e.to_string())?;
                    vec![
                        verify_plan(
                            plans.plan.into_iter().next().expect("one plan"),
                            &profile_bytes,
                            &signature_text,
                            &trusted,
                        )
                        .map_err(render)?,
                    ]
                } else {
                    let profiles = profiles.ok_or_else(usage)?;
                    let catalog_lock = catalog_lock.ok_or_else(usage)?;
                    verify_catalog(&catalog_lock, &profiles, &keyring_path)
                        .map_err(|error| error.to_string())?;
                    let documents = load_profile_documents(&profiles, &trusted)?;
                    verify_plan_set(plans, &documents).map_err(render)?
                };
                let mut builder = HardwareProvisioner::new(work, artifacts).map_err(render)?;
                builder.allow_network = allow_network;
                let receipts = builder
                    .build_verified_set(&verified, &recipe_root)
                    .map_err(render)?;
                if let Some(target) = root {
                    if verb == "update" {
                        return Err(
                            "source hardware target updates require an explicit rollback plan"
                                .into(),
                        );
                    }
                    let installed = builder
                        .install_plan_set_to_root(state, target, &verified, &receipts)
                        .map_err(render)?;
                    for receipt in installed {
                        println!(
                            "{} {}-{} installed={} files={}",
                            verb,
                            receipt.package,
                            receipt.release,
                            receipt.artifact_sha256,
                            receipt.files.len()
                        );
                    }
                    return Ok(());
                } else if verb == "update" {
                    store.update(&receipts).map_err(render)?;
                } else {
                    store.install(&receipts).map_err(render)?;
                }
                for receipt in receipts {
                    println!(
                        "{} {}-{} artifact={}",
                        verb, receipt.package, receipt.release, receipt.artifact_sha256
                    );
                }
            }
            _ => return Err(usage()),
        }
        Ok(())
    }

    fn parse_plans(text: &str) -> Result<PlanSet, String> {
        if let Ok(set) = toml::from_str::<PlanSet>(text) {
            if set.plan.is_empty() {
                return Err("hardware plan set is empty".into());
            }
            return Ok(set);
        }
        let plan: ProvisionPlan = toml::from_str(text).map_err(|error| error.to_string())?;
        Ok(PlanSet {
            schema: arach_hwd::plan::PLAN_SCHEMA,
            plan: vec![plan],
        })
    }

    fn load_profile_documents(
        directory: &std::path::Path,
        keyring: &Keyring,
    ) -> Result<Vec<(Vec<u8>, String, Keyring)>, String> {
        fn walk(
            directory: &std::path::Path,
            paths: &mut Vec<std::path::PathBuf>,
        ) -> Result<(), String> {
            let mut entries = fs::read_dir(directory)
                .map_err(|error| format!("{}: {error}", directory.display()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?;
            entries.sort_by_key(|entry| entry.path());
            for entry in entries {
                let path = entry.path();
                let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
                if metadata.file_type().is_symlink() {
                    return Err(format!(
                        "symlink in hardware profile catalog: {}",
                        path.display()
                    ));
                }
                if metadata.is_dir() {
                    walk(&path, paths)?;
                } else if metadata.is_file()
                    && path
                        .extension()
                        .is_some_and(|extension| extension == "toml")
                {
                    paths.push(path);
                }
            }
            Ok(())
        }

        let mut paths = Vec::new();
        walk(directory, &mut paths)?;
        if paths.is_empty() {
            return Err("hardware profile catalog contains no profiles".into());
        }
        paths
            .into_iter()
            .map(|path| {
                let bytes = fs::read(&path).map_err(|error| error.to_string())?;
                let signature = fs::read_to_string(format!("{}.sig", path.display()))
                    .map_err(|error| error.to_string())?;
                keyring
                    .verify(&bytes, &signature)
                    .map_err(|error| error.to_string())?;
                Ok((bytes, signature, keyring.clone()))
            })
            .collect()
    }

    fn render(error: HardwareError) -> String {
        error.to_string()
    }

    fn usage() -> String {
        "usage: corinth <install|update> --plan PLAN (--profile PROFILE --signature SIG | --profiles DIR --catalog-lock LOCK) --keyring KEYRING --recipes DIR|--recipes-git URL REV --work DIR --artifacts DIR --state DIR [--root TARGET_ROOT] [--allow-network]\n       corinth <install|update> PACKAGE --index INDEX --signature SIG --keyring KEYRING --artifacts DIR --state DIR [--root TARGET_ROOT] [--allow-network]\n       corinth remove PACKAGE --state DIR --artifacts DIR [--root TARGET_ROOT]\n       corinth import-pkgbuild (--pkgbuild PKGBUILD | --pkgbuild-git URL REV PATH) --target TARGET --target-signature SIG --keyring KEYRING --output RECIPE [--work DIR] [--allow-network]".into()
    }

    fn write_recipe_atomically(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| "recipe output has no parent directory".to_string())?;
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        if let Ok(metadata) = fs::symlink_metadata(path) {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                return Err("recipe output must be a regular file".into());
            }
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| "recipe output has an invalid name".to_string())?;
        let temporary = parent.join(format!(".{name}.tmp-{}", std::process::id()));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .map_err(|error| error.to_string())?;
            file.write_all(bytes).map_err(|error| error.to_string())?;
            file.sync_all().map_err(|error| error.to_string())?;
            fs::rename(&temporary, path).map_err(|error| error.to_string())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

#[cfg(all(not(feature = "os-bin"), feature = "host-store"))]
fn main() {
    if let Err(error) = host_cli::run() {
        eprintln!("corinth: {error}");
        process::exit(64);
    }
}

#[cfg(all(not(feature = "os-bin"), feature = "host-store"))]
use std::process;

#[cfg(all(not(feature = "os-bin"), not(feature = "host-store")))]
fn main() {
    eprintln!("corinth: build with --features host-store for the host transaction client");
}
