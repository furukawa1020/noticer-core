use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use quotient_forge_check::{
    CheckLimits, EnvironmentInput, InputId, Observer, ObserverId, PrivateHistoryId, Release,
    SemanticContract, SemanticId,
};
use quotient_forge_solver::{
    run_reduction_ablation, write_reduction_ablation, AblationBackend, AblationMetricDirection,
    AblationRunStatus, BackendComparisonConfig, DecisionConsistency, ReductionEvidenceBinding,
    RuntimeError, RuntimeOutput, SemanticGate, SolverKind, SolverRuntime, SolverSelection,
};
use quotient_forge_synth::{
    PlantPair, PlantState, PlantTransition, SynthesisLimits, SynthesisProblem,
};

fn sha256(value: u8) -> String {
    format!("{value:064x}")
}

fn problem(reduced: bool) -> SynthesisProblem {
    let semantic = SemanticId::from("same-action");
    SynthesisProblem {
        horizon: 1,
        machine_symbol_count: if reduced { 1 } else { 2 },
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
                machine_symbol: u32::from(!reduced),
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
        outputs: vec![Release::emitted()],
    }
}

fn evidence() -> ReductionEvidenceBinding {
    ReductionEvidenceBinding::new(sha256(1), sha256(2), sha256(3), sha256(4)).unwrap()
}

fn config() -> BackendComparisonConfig {
    BackendComparisonConfig {
        seed: 41,
        state_bound: 1,
        symmetry_breaking: true,
        run_smt: true,
        smt_selection: SolverSelection::Explicit(SolverKind::Cvc5),
        solver_timeout: Duration::from_secs(2),
        max_cegis_rounds: 8,
        qbf_truth_variable_limit: 128,
        exhaustive_limits: SynthesisLimits {
            max_states: 1,
            max_candidates: 100,
            time_limit: Duration::from_secs(2),
            checker_limits: CheckLimits {
                max_nodes: 1_000,
                max_depth: 8,
                time_limit: Duration::from_secs(2),
            },
            seed: 41,
        },
        checker_limits: CheckLimits {
            max_nodes: 1_000,
            max_depth: 8,
            time_limit: Duration::from_secs(2),
        },
    }
}

#[derive(Clone, Copy)]
enum RuntimeMode {
    Agree,
    Mismatch,
    Timeout,
    Unavailable,
}

struct RecordingRuntime {
    mode: RuntimeMode,
    calls: AtomicU64,
}

impl RecordingRuntime {
    fn new(mode: RuntimeMode) -> Self {
        Self {
            mode,
            calls: AtomicU64::new(0),
        }
    }
}

impl SolverRuntime for RecordingRuntime {
    fn version(&self, _solver: SolverKind) -> Result<String, RuntimeError> {
        if matches!(self.mode, RuntimeMode::Unavailable) {
            Err(RuntimeError::NotInstalled)
        } else {
            Ok("cvc5 test-runtime".to_owned())
        }
    }

    fn run(
        &self,
        _solver: SolverKind,
        script: &str,
        _timeout: Duration,
    ) -> Result<RuntimeOutput, RuntimeError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if matches!(self.mode, RuntimeMode::Timeout) {
            return Ok(RuntimeOutput::TimedOut);
        }
        let unreduced = script.contains("n_0_1");
        if matches!(self.mode, RuntimeMode::Mismatch) && !unreduced {
            return Ok(RuntimeOutput::Completed {
                stdout: "unsat".to_owned(),
                stderr: String::new(),
                success: true,
            });
        }
        let mut definitions = "(define-fun n_0_0 () Int 0) (define-fun o_0_0 () Int 0)".to_owned();
        if unreduced {
            definitions.push_str(" (define-fun n_0_1 () Int 0) (define-fun o_0_1 () Int 0)");
        }
        Ok(RuntimeOutput::Completed {
            stdout: format!("sat\n(model {definitions})"),
            stderr: String::new(),
            success: true,
        })
    }
}

fn run(runtime: &RecordingRuntime) -> quotient_forge_solver::ReductionAblationArtifact {
    run_reduction_ablation(
        "frozen-reduction-case-v1",
        &problem(false),
        &problem(true),
        1,
        evidence(),
        &config(),
        Some(runtime),
        None,
    )
    .unwrap()
}

#[test]
fn all_three_production_paths_run_both_toggles_and_agree() {
    let runtime = RecordingRuntime::new(RuntimeMode::Agree);
    let artifact = run(&runtime);

    assert_eq!(runtime.calls.load(Ordering::Relaxed), 2);
    assert_eq!(artifact.semantic_gate, SemanticGate::Pass);
    assert!(artifact.reduction_enabled);
    assert!(!artifact.performance_claimed);
    assert_eq!(
        artifact
            .structural_reduction
            .source_state_to_class
            .direction,
        AblationMetricDirection::Decreased
    );
    for backend in AblationBackend::ALL {
        let pair = artifact.backend(backend).unwrap();
        assert_eq!(pair.decision_consistency, DecisionConsistency::Agree);
        assert!(pair.candidate_checker_gate_passed);
    }
    let smt = artifact.backend(AblationBackend::Smt).unwrap();
    assert_eq!(smt.disabled.metrics.solver_calls.value, Some(1));
    assert_eq!(smt.enabled.metrics.solver_calls.value, Some(1));
    let qbf = artifact.backend(AblationBackend::Qbf).unwrap();
    assert_eq!(qbf.disabled.metrics.solver_calls.value, Some(1));
    artifact.validate().unwrap();
}

#[test]
fn conclusive_backend_mismatch_disables_reduction() {
    let artifact = run(&RecordingRuntime::new(RuntimeMode::Mismatch));
    let smt = artifact.backend(AblationBackend::Smt).unwrap();
    assert_eq!(smt.decision_consistency, DecisionConsistency::Disagree);
    assert_eq!(artifact.semantic_gate, SemanticGate::Disable);
    assert!(!artifact.reduction_enabled);
}

#[test]
fn unavailable_timeout_and_resource_exhaustion_remain_distinct() {
    let unavailable = run(&RecordingRuntime::new(RuntimeMode::Unavailable));
    assert_eq!(
        unavailable
            .backend(AblationBackend::Smt)
            .unwrap()
            .disabled
            .status,
        AblationRunStatus::SolverUnavailable
    );

    let timeout = run(&RecordingRuntime::new(RuntimeMode::Timeout));
    assert_eq!(
        timeout
            .backend(AblationBackend::Smt)
            .unwrap()
            .disabled
            .status,
        AblationRunStatus::Timeout
    );

    let mut constrained = config();
    constrained.qbf_truth_variable_limit = 1;
    let resource = run_reduction_ablation(
        "resource-case-v1",
        &problem(false),
        &problem(true),
        1,
        evidence(),
        &constrained,
        Some(&RecordingRuntime::new(RuntimeMode::Agree)),
        None,
    )
    .unwrap();
    assert_eq!(
        resource
            .backend(AblationBackend::Qbf)
            .unwrap()
            .disabled
            .status,
        AblationRunStatus::ResourceExhausted
    );
}

#[test]
fn manifest_contains_each_real_backend_toggle() {
    let artifact = run(&RecordingRuntime::new(RuntimeMode::Agree));
    let root =
        std::env::temp_dir().join(format!("noticer-reduction-ablation-{}", std::process::id()));
    let receipt = write_reduction_ablation(&root, &artifact).unwrap();
    assert!(receipt.manifest_path.is_file());
    assert_eq!(receipt.backend_paths.len(), 6);
    assert!(receipt.backend_paths.iter().all(|path| path.is_file()));
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&receipt.manifest_path).unwrap()).unwrap();
    assert_eq!(
        manifest["artifact_sha256"].as_str(),
        Some(artifact.artifact_sha256.as_str())
    );
    std::fs::remove_dir_all(root).unwrap();
}
