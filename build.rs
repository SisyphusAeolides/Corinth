use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=native/corinth_policy.f90");
    if env::var_os("CARGO_FEATURE_FORTRAN_POLICY").is_none() {
        return;
    }
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"));
    let object = output.join("corinth_policy.o");
    let archive = output.join("libcorinth_policy.a");
    let compiler = env::var_os("FC").unwrap_or_else(|| "gfortran".into());
    run(
        Command::new(compiler)
            .arg("-c")
            .arg("-O2")
            .arg("-fPIC")
            .arg(format!("-J{}", output.display()))
            .arg("native/corinth_policy.f90")
            .arg("-o")
            .arg(&object),
        "Fortran build policy compilation",
    );
    run(
        Command::new("ar").arg("crs").arg(&archive).arg(&object),
        "Fortran build policy archive",
    );
    println!("cargo:rustc-link-search=native={}", output.display());
    println!("cargo:rustc-link-lib=static=corinth_policy");
}

fn run(command: &mut Command, description: &str) {
    let status = command
        .status()
        .unwrap_or_else(|error| panic!("failed to start {description}: {error}"));
    assert!(status.success(), "{description} failed with {status}");
}
