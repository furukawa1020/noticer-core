use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use quotient_forge_solver::{
    BoundedSolverRuntime, ProcessLimits, SolverKind, SolverMatrix, SolverPlatform, SolverRuntime,
};
use serde_json::Value;

fn matrix_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("configs/quotient_forge/solver_matrix_v1.json")
}

#[cfg(target_os = "windows")]
fn platform() -> SolverPlatform {
    SolverPlatform::WindowsX86_64
}
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn platform() -> SolverPlatform {
    SolverPlatform::LinuxX86_64
}

fn platform_name() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "windows-x86_64"
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        "linux-x86_64"
    }
}

fn invoke(case_id: &str, root: &Path, expected_sha256: &str) -> Value {
    let output = std::env::temp_dir().join(format!("qf-smt-{}-{case_id}.json", std::process::id()));
    let status = Command::new(env!("CARGO_BIN_EXE_quotient-forge-smt"))
        .args([
            case_id,
            "z3",
            root.to_str().unwrap(),
            matrix_path().to_str().unwrap(),
            expected_sha256,
            "4",
            "2",
            "2",
            "1",
            "0",
            "3",
            "1",
            "1729",
            "2000",
            output.to_str().unwrap(),
            platform_name(),
        ])
        .status()
        .unwrap();
    assert!(status.success());
    let value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    let _ = fs::remove_file(output);
    value
}

#[test]
fn unavailable_solver_is_not_run() {
    let root = std::env::temp_dir().join(format!("qf-smt-missing-{}", std::process::id()));
    let result = invoke("smt-missing", &root, &"0".repeat(64));
    assert_eq!(result["status"], "NOT_RUN");
    assert_eq!(result["solver_call_count"], 0);
}

#[test]
fn binary_digest_mismatch_fails_before_process_execution() {
    let root = std::env::temp_dir().join(format!("qf-smt-digest-{}", std::process::id()));
    let matrix = SolverMatrix::from_path(&matrix_path()).unwrap();
    let runtime =
        BoundedSolverRuntime::from_matrix(&matrix, &root, platform(), ProcessLimits::default())
            .unwrap();
    let program = PathBuf::from(runtime.program(SolverKind::Z3));
    fs::create_dir_all(program.parent().unwrap()).unwrap();
    fs::write(program, b"not-a-solver").unwrap();

    let result = invoke("smt-digest", &root, &"0".repeat(64));
    assert_eq!(result["status"], "INVALID_CASE");
    assert_eq!(result["solver_call_count"], 0);
    assert_eq!(result["checker_verdict"], "NOT_APPLICABLE");
    let _ = fs::remove_dir_all(root);
}
