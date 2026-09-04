use std::collections::BTreeSet;
use std::time::Duration;

use quotient_forge_check::{
    CheckLimits, EnvironmentInput, InputId, Observer, ObserverId, PrivateHistoryId, Release,
    SemanticContract, SemanticId,
};
use quotient_forge_solver::{
    check_qbf_candidate, compile_bounded_safety_game, BoundedProcessOutput, QbfCandidateDecision,
    QbfCandidateDiagnostic, QbfCompilation, QbfCompileLimits, QbfIndependentCheckerStatus,
    QbfSolverMetadata, QbfSolverResultArtifact, QbfSolverRun, VariableRole,
    QBF_CANDIDATE_DECISION_SCHEMA_V1,
};
use quotient_forge_synth::{PlantPair, PlantState, PlantTransition, SynthesisProblem};
use sha2::{Digest, Sha256};

fn compile_fixture() -> (SynthesisProblem, QbfCompilation) {
    let problem = fixture();
    let compilation = compile_bounded_safety_game(
        &problem,
        QbfCompileLimits {
            max_machine_states: 1,
            max_table_assignments: 16,
            max_candidates: 8,
            max_scenarios: 8,
            seed: 41,
        },
    )
    .expect("compile bounded fixture");
    (problem, compilation)
}

#[test]
fn valid_assignment_is_deterministic_and_requires_checker_verification() {
    let (problem, compilation) = compile_fixture();
    let candidate = candidate_with_acceptance(&compilation, true);
    let stdout = complete_assignment(&compilation, candidate, true);
    let run = solver_run(&compilation, &stdout);

    let first = check_qbf_candidate(&run, &compilation, &problem, checker_limits());
    let second = check_qbf_candidate(&run, &compilation, &problem, checker_limits());

    assert_eq!(first, second);
    assert_eq!(first.artifact.decision, QbfCandidateDecision::Accepted);
    assert!(first.artifact.candidate_accepted);
    assert_eq!(first.artifact.candidate_id, Some(candidate));
    assert_eq!(
        first.artifact.checker.status,
        QbfIndependentCheckerStatus::Verified
    );
    assert_eq!(first.artifact.diagnostic, None);
    assert!(first.accepted_machine().is_some());
    assert_eq!(
        first
            .artifact
            .canonical_json_bytes()
            .expect("canonical decision"),
        second
            .artifact
            .canonical_json_bytes()
            .expect("canonical decision")
    );

    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/quotient_forge_qbf_candidate_decision_v1.schema.json"
    ))
    .expect("schema JSON");
    assert_eq!(schema["$id"], QBF_CANDIDATE_DECISION_SCHEMA_V1);
}

#[test]
fn false_sat_candidate_is_rejected_by_the_independent_checker() {
    let (problem, compilation) = compile_fixture();
    let candidate = candidate_with_acceptance(&compilation, false);
    let run = solver_run(
        &compilation,
        &complete_assignment(&compilation, candidate, true),
    );

    let checked = check_qbf_candidate(&run, &compilation, &problem, checker_limits());

    assert_eq!(checked.artifact.decision, QbfCandidateDecision::Rejected);
    assert!(!checked.artifact.candidate_accepted);
    assert_eq!(checked.artifact.candidate_id, Some(candidate));
    assert_eq!(
        checked.artifact.checker.status,
        QbfIndependentCheckerStatus::Counterexample
    );
    assert_eq!(
        checked.artifact.diagnostic,
        Some(QbfCandidateDiagnostic::CheckerCounterexample)
    );
    assert!(checked.accepted_machine().is_none());
    assert!(checked
        .artifact
        .canonical_json_bytes()
        .expect("canonical rejection")
        .ends_with(b"\n"));
}

#[test]
fn partial_duplicate_conflicting_and_out_of_range_models_fail_closed() {
    let (problem, compilation) = compile_fixture();
    let candidate = candidate_with_acceptance(&compilation, true);
    let selected_variable = machine_variable(&compilation, candidate);
    let complete = complete_literals(&compilation, candidate, true);
    let variable_count = compilation.qdimacs.metadata.variable_count;
    let cases = [
        (
            format!("s cnf 1 1 0\nV {selected_variable} 0\n"),
            QbfCandidateDiagnostic::MissingMachineAssignment,
        ),
        (
            format!("s cnf 1 1 0\nV {complete} {selected_variable} 0\n"),
            QbfCandidateDiagnostic::DuplicateAssignment,
        ),
        (
            format!("s cnf 1 1 0\nV {complete} -{selected_variable} 0\n"),
            QbfCandidateDiagnostic::ConflictingAssignment,
        ),
        (
            format!("s cnf 1 1 0\nV {} 0\n", variable_count + 1),
            QbfCandidateDiagnostic::AssignmentOutOfRange,
        ),
    ];

    for (stdout, expected) in cases {
        let run = solver_run(&compilation, &stdout);
        let checked = check_qbf_candidate(&run, &compilation, &problem, checker_limits());
        assert_eq!(checked.artifact.decision, QbfCandidateDecision::Rejected);
        assert_eq!(checked.artifact.diagnostic, Some(expected));
        assert!(checked.accepted_machine().is_none());
    }
}

#[test]
fn universal_values_never_enter_the_decoded_machine() {
    let (problem, compilation) = compile_fixture();
    let candidate = candidate_with_acceptance(&compilation, true);
    let positive = solver_run(
        &compilation,
        &complete_assignment(&compilation, candidate, true),
    );
    let negative = solver_run(
        &compilation,
        &complete_assignment(&compilation, candidate, false),
    );

    let positive = check_qbf_candidate(&positive, &compilation, &problem, checker_limits());
    let negative = check_qbf_candidate(&negative, &compilation, &problem, checker_limits());

    assert_eq!(positive.artifact.decision, QbfCandidateDecision::Accepted);
    assert_eq!(negative.artifact.decision, QbfCandidateDecision::Accepted);
    assert_eq!(
        positive.artifact.candidate_id,
        negative.artifact.candidate_id
    );
    assert_eq!(
        positive.accepted_machine().expect("positive machine"),
        negative.accepted_machine().expect("negative machine")
    );
    assert_ne!(
        positive.artifact.assignment_sha256,
        negative.artifact.assignment_sha256
    );
}

fn complete_assignment(
    compilation: &QbfCompilation,
    selected_candidate: u32,
    universal_value: bool,
) -> String {
    format!(
        "s cnf 1 1 0\nV {} 0\n",
        complete_literals(compilation, selected_candidate, universal_value)
    )
}

fn complete_literals(
    compilation: &QbfCompilation,
    selected_candidate: u32,
    universal_value: bool,
) -> String {
    compilation
        .qdimacs
        .metadata
        .variables
        .iter()
        .map(|variable| {
            let value = match variable.role {
                VariableRole::MachineChoice => variable.coordinates == [selected_candidate],
                VariableRole::PrivateHistoryLeft
                | VariableRole::PrivateHistoryRight
                | VariableRole::EnvironmentTrace
                | VariableRole::FaultTrace => universal_value,
                VariableRole::DependentWitness => true,
            };
            if value {
                variable.id.to_string()
            } else {
                format!("-{}", variable.id)
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn machine_variable(compilation: &QbfCompilation, candidate: u32) -> u32 {
    compilation
        .qdimacs
        .metadata
        .variables
        .iter()
        .find(|variable| {
            variable.role == VariableRole::MachineChoice && variable.coordinates == [candidate]
        })
        .expect("candidate variable")
        .id
}

fn candidate_with_acceptance(compilation: &QbfCompilation, accepted: bool) -> u32 {
    compilation
        .metadata
        .candidates
        .iter()
        .find(|candidate| {
            compilation
                .metadata
                .acceptance
                .iter()
                .filter(|record| record.candidate == candidate.id)
                .all(|record| record.accepted == accepted)
        })
        .expect("candidate with requested acceptance")
        .id
}

fn solver_run(compilation: &QbfCompilation, stdout: &str) -> QbfSolverRun {
    QbfSolverResultArtifact::from_output(
        QbfSolverMetadata {
            solver: "caqe".to_owned(),
            version: "4.0.2".to_owned(),
            platform: "linux-x86_64".to_owned(),
            source_revision: "62ee7692dada5236307f8652234ed7a743651eb7".to_owned(),
            source_sha256: sha256(b"source"),
            binary_sha256: sha256(b"binary"),
            manifest_sha256: sha256(b"manifest"),
            program: "bin/caqe".to_owned(),
            argv: vec!["--qdo".to_owned(), "query.qdimacs".to_owned()],
            timeout_ms: 1_000,
            seed: compilation.qdimacs.metadata.seed,
            bounds: compilation.qdimacs.metadata.bounds,
        },
        &compilation.qdimacs.document,
        BoundedProcessOutput::Completed {
            stdout: stdout.to_owned(),
            stderr: String::new(),
            success: false,
        },
    )
    .expect("solver result artifact")
}

fn checker_limits() -> CheckLimits {
    CheckLimits {
        max_nodes: 1_000,
        max_depth: 8,
        time_limit: Duration::from_secs(2),
    }
}

fn fixture() -> SynthesisProblem {
    let semantic = SemanticId::from("same-action");
    SynthesisProblem {
        horizon: 1,
        machine_symbol_count: 2,
        plant_states: vec![
            PlantState {
                id: 0,
                action_semantics: semantic.clone(),
                private_history: PrivateHistoryId::from("private-left"),
            },
            PlantState {
                id: 1,
                action_semantics: semantic.clone(),
                private_history: PrivateHistoryId::from("private-right"),
            },
        ],
        plant_transitions: vec![
            PlantTransition {
                from: 0,
                input: 0,
                to: 0,
                machine_symbol: 0,
            },
            PlantTransition {
                from: 1,
                input: 0,
                to: 1,
                machine_symbol: 1,
            },
        ],
        inputs: vec![EnvironmentInput {
            id: InputId::from("tick"),
            public_symbol: "tick".to_owned(),
            fault: None,
        }],
        semantics: vec![SemanticContract {
            id: semantic,
            obligations: Vec::new(),
        }],
        faults: Vec::new(),
        observers: vec![Observer {
            id: ObserverId::from("network"),
            visible_fields: BTreeSet::new(),
            observes_actions: false,
        }],
        initial_pairs: vec![PlantPair { left: 0, right: 1 }],
        outputs: vec![
            Release {
                emitted: false,
                fields: Default::default(),
                actions: Vec::new(),
            },
            Release {
                emitted: true,
                fields: Default::default(),
                actions: Vec::new(),
            },
        ],
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
