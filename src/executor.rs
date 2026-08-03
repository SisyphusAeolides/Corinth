#[cfg(feature = "host-store")]
use alloc::{format, string::String, vec::Vec};
#[cfg(feature = "host-store")]
use sha2::{Digest, Sha256};
#[cfg(feature = "host-store")]
use std::fs;
#[cfg(feature = "host-store")]
use std::path::Path;
#[cfg(feature = "host-store")]
use std::process::{Command, Stdio};

#[cfg(feature = "host-store")]
use crate::worker::{
    ReproducibilityEvidence, WorkerCapability, WorkerError, WorkerNetwork, WorkerOutputEvidence,
    WorkerRequest, WorkerRunEvidence,
};

#[cfg(feature = "host-store")]
fn hex_digest(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    let mut hex = String::with_capacity(64);
    for byte in hash {
        use core::fmt::Write;
        write!(&mut hex, "{:02x}", byte).unwrap();
    }
    hex
}

#[cfg(feature = "host-store")]
pub fn execute(
    request: &WorkerRequest,
    work_dir: &Path,
) -> Result<ReproducibilityEvidence, WorkerError> {
    request.validate()?;

    let request_json = serde_json::to_string(request).map_err(|_| WorkerError::InvalidInput)?;
    let request_sha256 = hex_digest(request_json.as_bytes());

    let mut runs = Vec::new();
    for _ in 0..request.reproducibility_runs {
        runs.push(run_once(request, work_dir)?);
    }

    let evidence = ReproducibilityEvidence {
        request_sha256,
        runs,
    };

    evidence.validate(request)?;

    Ok(evidence)
}

#[cfg(feature = "host-store")]
fn run_once(request: &WorkerRequest, work_dir: &Path) -> Result<WorkerRunEvidence, WorkerError> {
    let mut cmd = Command::new("bwrap");

    cmd.arg("--unshare-all")
        .arg("--die-with-parent")
        .arg("--dir")
        .arg("/work")
        .arg("--chdir")
        .arg("/work")
        .arg("--ro-bind")
        .arg("/usr")
        .arg("/usr")
        .arg("--symlink")
        .arg("usr/lib")
        .arg("/lib")
        .arg("--symlink")
        .arg("usr/lib64")
        .arg("/lib64")
        .arg("--symlink")
        .arg("usr/bin")
        .arg("/bin")
        .arg("--symlink")
        .arg("usr/sbin")
        .arg("/sbin");

    if request
        .capabilities
        .contains(&WorkerCapability::FixedOutputNetwork)
    {
        if let WorkerNetwork::FixedOutput { .. } = &request.network {
            cmd.arg("--share-net"); // Note: in reality bwrap would need more setup for network fetching.
        }
    }

    // Bind inputs
    if request.capabilities.contains(&WorkerCapability::ReadInputs) {
        for input in &request.inputs {
            let host_path = work_dir.join(&input.path);
            cmd.arg("--ro-bind")
                .arg(host_path)
                .arg(format!("/work/{}", input.path));
        }
    }

    // Bind tools
    if request
        .capabilities
        .contains(&WorkerCapability::ExecuteTools)
    {
        for tool in &request.tools {
            let host_path = work_dir.join(&tool.path);
            cmd.arg("--ro-bind")
                .arg(host_path)
                .arg(format!("/work/{}", tool.path));
        }
    }

    // We assume the first tool is the executable.
    if request.tools.is_empty() {
        return Err(WorkerError::InvalidTool);
    }
    cmd.arg(format!("/work/{}", request.tools[0].path));

    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let output = cmd.output().map_err(|_| WorkerError::InvalidTool)?;
    let stdout_sha256 = hex_digest(&output.stdout);
    let stderr_sha256 = hex_digest(&output.stderr);
    let measurement_sha256 = hex_digest(&[]); // Empty measurement for now, could be telemetry

    let mut outputs_evidence = Vec::new();
    if request
        .capabilities
        .contains(&WorkerCapability::WriteOutputs)
    {
        for expected_out in &request.outputs {
            let host_path = work_dir.join(&expected_out.path);
            if let Ok(meta) = fs::metadata(&host_path) {
                if let Ok(data) = fs::read(&host_path) {
                    outputs_evidence.push(WorkerOutputEvidence {
                        path: expected_out.path.clone(),
                        sha256: hex_digest(&data),
                        size: meta.len(),
                    });
                }
            }
        }
    }

    Ok(WorkerRunEvidence {
        measurement_sha256,
        stdout_sha256,
        stderr_sha256,
        outputs: outputs_evidence,
    })
}
