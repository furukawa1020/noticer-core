use std::fs;
use std::process::Command;

use serde_json::Value;

fn run(case_id: &str, candidate_limit: &str) -> Value {
    let output = std::env::temp_dir().join(format!(
        "quotient-forge-cegis-{}-{case_id}.json",
        std::process::id()
    ));
    let status = Command::new(env!("CARGO_BIN_EXE_quotient-forge-cegis"))
        .args([
            case_id,
            "4",
            "2",
            "2",
            "1",
            "0",
            "3",
            "1",
            "1729",
            candidate_limit,
            "5000",
            output.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());
    let result = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    let _ = fs::remove_file(output);
    result
}

#[test]
fn cegis_worker_emits_an_independently_checked_candidate() {
    let result = run("cegis-smoke", "10000");
    assert_eq!(result["backend_id"], "cegis");
    assert_eq!(result["status"], "COMPLETED");
    assert_eq!(result["checker_verdict"], "VERIFIED");
    assert!(result["candidate_count"].as_u64().unwrap() > 0);
    assert_eq!(result["solver_call_count"], 0);
}

#[test]
fn candidate_exhaustion_never_becomes_success() {
    let result = run("cegis-limited", "0");
    assert_eq!(result["status"], "SOLVER_UNKNOWN");
    assert_eq!(result["checker_verdict"], "NOT_APPLICABLE");
    assert_eq!(result["candidate_count"], 0);
}
