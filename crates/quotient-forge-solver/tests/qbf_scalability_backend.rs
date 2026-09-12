use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn manifest_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("configs/quotient_forge/qbf_solver_manifest_v1.json")
}

#[test]
fn unavailable_receipt_is_not_run() {
    let root = std::env::temp_dir().join(format!("qf-qbf-missing-{}", std::process::id()));
    let output = std::env::temp_dir().join(format!("qf-qbf-result-{}.json", std::process::id()));
    let receipt = root.join("missing-install.json");
    let status = Command::new(env!("CARGO_BIN_EXE_quotient-forge-qbf"))
        .args([
            "qbf-missing",
            root.to_str().unwrap(),
            manifest_path().to_str().unwrap(),
            receipt.to_str().unwrap(),
            "4",
            "2",
            "2",
            "1",
            "0",
            "3",
            "1",
            "1729",
            "64",
            "2000",
            output.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());
    let result: Value = serde_json::from_slice(&std::fs::read(&output).unwrap()).unwrap();
    let _ = std::fs::remove_file(output);
    assert_eq!(result["backend_id"], "qbf");
    assert_eq!(result["status"], "NOT_RUN");
    assert_eq!(result["solver_call_count"], 0);
    assert_eq!(result["checker_verdict"], "NOT_APPLICABLE");
}
