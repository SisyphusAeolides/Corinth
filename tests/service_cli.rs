#![cfg(feature = "host-store")]

use std::process::Command;

#[test]
fn simple_lifecycle_verbs_enter_the_signed_service_path() {
    let missing = format!("/tmp/corinth-missing-service-config-{}", std::process::id());
    for verb in ["search", "install", "update", "remove"] {
        let output = Command::new(env!("CARGO_BIN_EXE_corinth"))
            .args([verb, "demo", "--config", &missing, "--offline"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("repository resource unavailable"));
        assert!(!stderr.contains("usage: corinth"));
    }
}
