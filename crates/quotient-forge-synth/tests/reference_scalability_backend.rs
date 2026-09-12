use std::fs;
use std::process::Command;

use quotient_forge_synth::scalability_reference::{
    materialize_reference_case, ScalabilityDimensions,
};
use serde_json::Value;

fn dimensions() -> ScalabilityDimensions {
    ScalabilityDimensions {
        plant_states: 8,
        machine_states: 3,
        horizon: 3,
        observers: 2,
        fault_states: 1,
        output_alphabet: 4,
        quotient_classes: 2,
    }
}

#[test]
fn materializer_reflects_every_declared_dimension() {
    let case = materialize_reference_case(dimensions()).unwrap();
    assert_eq!(case.problem.plant_states.len(), 8);
    assert_eq!(case.candidate.state_count, 3);
    assert_eq!(case.problem.horizon, 3);
    assert_eq!(case.problem.observers.len(), 2);
    assert_eq!(case.problem.faults.len(), 1);
    assert_eq!(case.problem.outputs.len(), 4);
    assert_eq!(case.problem.semantics.len(), 2);
    assert_eq!(case.problem.initial_pairs.len(), 2);
}

#[test]
fn materializer_rejects_vacuous_privacy_classes() {
    let mut invalid = dimensions();
    invalid.plant_states = 3;
    assert!(materialize_reference_case(invalid).is_err());
}

#[test]
fn production_binary_emits_checker_bound_result() {
    let output = std::env::temp_dir().join(format!(
        "quotient-forge-reference-{}-{}.json",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    let status = Command::new(env!("CARGO_BIN_EXE_quotient-forge-reference"))
        .args([
            "case-smoke",
            "8",
            "3",
            "3",
            "2",
            "1",
            "4",
            "2",
            "1729",
            output.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());
    let result: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    let _ = fs::remove_file(output);
    assert_eq!(result["schema"], "noticer.k7.backend-result.v1");
    assert_eq!(result["backend_id"], "reference");
    assert_eq!(result["case_id"], "case-smoke");
    assert_eq!(result["solver_call_count"], 0);
    assert_eq!(result["evidence_sha256"].as_str().unwrap().len(), 64);
    assert_ne!(result["checker_verdict"], "NOT_APPLICABLE");
}
