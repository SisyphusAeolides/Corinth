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
    use std::fs;
    use std::path::PathBuf;

    use arach_hwd::plan::{PlanSet, ProvisionPlan};
    use arach_hwd::signature::Keyring;
    use corinth::binary::{BinaryProvisioner, verify_binary_index};
    use corinth::hardware::{HardwareError, HardwareProvisioner, HostPackageStore, verify_plan};

    pub fn run() -> Result<(), String> {
        let mut args = env::args().skip(1);
        let verb = args.next().ok_or_else(usage)?;
        let mut plan = None;
        let mut profile = None;
        let mut signature = None;
        let mut keyring = None;
        let mut recipes = None;
        let mut recipes_git = None;
        let mut index = None;
        let mut work = None;
        let mut artifacts = None;
        let mut state = None;
        let mut package: Option<String> = None;
        let mut allow_network = false;

        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--plan" => plan = Some(PathBuf::from(args.next().ok_or_else(usage)?)),
                "--profile" => profile = Some(PathBuf::from(args.next().ok_or_else(usage)?)),
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
                "--allow-network" => allow_network = true,
                value if !value.starts_with('-') && package.is_none() => {
                    package = Some(value.into())
                }
                _ => return Err(usage()),
            }
        }

        let artifacts = artifacts.ok_or_else(usage)?;
        let state = state.ok_or_else(usage)?;
        let store = HostPackageStore::open(state, artifacts.clone()).map_err(render)?;

        match verb.as_str() {
            "remove" => {
                let package = package.ok_or_else(usage)?;
                store.remove(&package).map_err(render)?;
                println!("removed {package}");
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
                        "{} {}-{} artifact={}",
                        verb, receipt.package, receipt.release, receipt.artifact_sha256
                    );
                    return Ok(());
                }
                let work = work.ok_or_else(usage)?;
                let plan_path = plan.ok_or_else(usage)?;
                let profile_path = profile.ok_or_else(usage)?;
                let signature_path = signature.ok_or_else(usage)?;
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
                let plan = parse_plan(&text)?;
                let profile_bytes = fs::read(profile_path).map_err(|e| e.to_string())?;
                let signature_text =
                    fs::read_to_string(signature_path).map_err(|e| e.to_string())?;
                let trusted = Keyring::load(&keyring_path).map_err(|e| e.to_string())?;
                let verified =
                    verify_plan(plan, &profile_bytes, &signature_text, &trusted).map_err(render)?;
                let mut builder = HardwareProvisioner::new(work, artifacts).map_err(render)?;
                builder.allow_network = allow_network;
                let receipts = builder
                    .build_verified(&verified, &recipe_root)
                    .map_err(render)?;
                if verb == "update" {
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

    fn parse_plan(text: &str) -> Result<ProvisionPlan, String> {
        if let Ok(set) = toml::from_str::<PlanSet>(text) {
            if set.plan.len() != 1 {
                return Err("host install expects exactly one plan".into());
            }
            return Ok(set.plan.into_iter().next().expect("one plan"));
        }
        toml::from_str(text).map_err(|error| error.to_string())
    }

    fn render(error: HardwareError) -> String {
        error.to_string()
    }

    fn usage() -> String {
        "usage: corinth <install|update> --plan PLAN --profile PROFILE --signature SIG --keyring KEYRING --recipes DIR|--recipes-git URL REV --work DIR --artifacts DIR --state DIR [--allow-network]\n       corinth <install|update> PACKAGE --index INDEX --signature SIG --keyring KEYRING --artifacts DIR --state DIR [--allow-network]\n       corinth remove PACKAGE --state DIR --artifacts DIR".into()
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
