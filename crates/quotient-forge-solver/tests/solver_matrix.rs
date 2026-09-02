use std::fs;
use std::path::{Path, PathBuf};

use quotient_forge_solver::{
    SolverId, SolverMatrix, SolverMatrixError, SolverPlatform, MAX_SOLVER_MATRIX_BYTES,
};

fn matrix_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("configs/quotient_forge/solver_matrix_v1.json")
}

fn matrix_value() -> serde_json::Value {
    serde_json::from_slice(&fs::read(matrix_path()).expect("matrix fixture"))
        .expect("valid JSON fixture")
}

#[test]
fn official_windows_and_linux_assets_are_pinned() {
    let matrix = SolverMatrix::from_path(&matrix_path()).expect("valid solver matrix");
    let z3_linux = matrix.asset(SolverId::Z3, SolverPlatform::LinuxX86_64);
    assert_eq!(matrix.solver(SolverId::Z3).version, "4.16.0");
    assert_eq!(
        z3_linux.sha256,
        "7288c49a5bd6dbafd7b0b0d1f65956b91672da24b08f09242919af159be3418e"
    );
    assert!(z3_linux
        .download_url
        .starts_with("https://github.com/Z3Prover/z3/"));

    let cvc5_windows = matrix.asset(SolverId::Cvc5, SolverPlatform::WindowsX86_64);
    assert_eq!(matrix.solver(SolverId::Cvc5).version, "1.3.4");
    assert_eq!(
        cvc5_windows.sha256,
        "279fe7e95810cfb62433fcfc2932f35325a665f32d3697ff33f75e31d5c6a179"
    );
    assert!(cvc5_windows
        .download_url
        .starts_with("https://github.com/cvc5/cvc5/"));
    assert_eq!(
        matrix.security_interpretation,
        "CANDIDATE_GENERATOR_NOT_SECURITY_ORACLE"
    );
}

#[test]
fn canonical_digest_ignores_input_whitespace_and_key_order() {
    let original = fs::read(matrix_path()).unwrap();
    let first = SolverMatrix::from_slice(&original).unwrap();
    let reordered = serde_json::to_vec(&matrix_value()).unwrap();
    let second = SolverMatrix::from_slice(&reordered).unwrap();
    assert_eq!(first, second);
    assert_eq!(
        first.canonical_bytes().unwrap(),
        second.canonical_bytes().unwrap()
    );
    assert_eq!(
        first.digest_sha256().unwrap(),
        second.digest_sha256().unwrap()
    );
    assert_eq!(first.digest_sha256().unwrap().len(), 64);
}

#[test]
fn unknown_fields_and_incomplete_solver_sets_fail_closed() {
    let mut value = matrix_value();
    value["unknown"] = serde_json::json!(true);
    assert!(matches!(
        SolverMatrix::from_slice(&serde_json::to_vec(&value).unwrap()),
        Err(SolverMatrixError::Json(_))
    ));

    let mut value = matrix_value();
    value["solvers"].as_array_mut().unwrap().pop();
    assert!(matches!(
        SolverMatrix::from_slice(&serde_json::to_vec(&value).unwrap()),
        Err(SolverMatrixError::Invalid(_))
    ));
}

#[test]
fn duplicate_platform_bad_hash_and_release_redirect_are_rejected() {
    let mut value = matrix_value();
    value["solvers"][0]["assets"][1]["platform"] = serde_json::json!("linux-x86_64");
    assert!(SolverMatrix::from_slice(&serde_json::to_vec(&value).unwrap()).is_err());

    let mut value = matrix_value();
    value["solvers"][0]["assets"][0]["sha256"] = serde_json::json!("A".repeat(64));
    assert!(SolverMatrix::from_slice(&serde_json::to_vec(&value).unwrap()).is_err());

    let mut value = matrix_value();
    value["solvers"][1]["assets"][0]["download_url"] =
        serde_json::json!("https://example.invalid/z3.zip");
    assert!(SolverMatrix::from_slice(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn path_escape_shell_argv_and_platform_suffix_are_rejected() {
    let mut value = matrix_value();
    value["solvers"][0]["assets"][0]["executable_path"] = serde_json::json!("../bin/cvc5");
    assert!(SolverMatrix::from_slice(&serde_json::to_vec(&value).unwrap()).is_err());

    let mut value = matrix_value();
    value["solvers"][0]["commands"]["solve"] = serde_json::json!(["cmd"]);
    assert!(SolverMatrix::from_slice(&serde_json::to_vec(&value).unwrap()).is_err());

    let mut value = matrix_value();
    value["solvers"][1]["assets"][1]["executable_path"] = serde_json::json!("bin/z3");
    assert!(SolverMatrix::from_slice(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn oversized_documents_are_rejected_before_parsing() {
    let encoded = vec![b' '; MAX_SOLVER_MATRIX_BYTES + 1];
    assert!(matches!(
        SolverMatrix::from_slice(&encoded),
        Err(SolverMatrixError::Invalid(_))
    ));
}
