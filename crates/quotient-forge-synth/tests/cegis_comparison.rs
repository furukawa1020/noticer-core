use std::sync::atomic::{AtomicU64, Ordering};

use quotient_forge_synth::comparison::{
    write_comparison_artifact, BackendInconclusiveReason, BackendRunArtifact, BackendRunInput,
    CandidateHashRelation, CegisComparisonArtifact, ComparisonError, ComparisonMethod,
    ComparisonMetrics, ComparisonOutcome, CoreObservation, DecisionConsistency,
    FrozenComparisonBounds, FrozenComparisonCase, ResourceMeasurement, ResourceObservations,
    VerificationStatus,
};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

fn sha256(value: u8) -> String {
    format!("{value:064x}")
}

fn frozen_case() -> FrozenComparisonCase {
    FrozenComparisonCase {
        case_id: "small-frozen-case-v1".to_owned(),
        problem_sha256: sha256(240),
        seed: 41,
        bounds: FrozenComparisonBounds {
            machine_states: 2,
            trace_horizon: 4,
            candidate_limit: 128,
            wall_time_limit_ms: 10_000,
            memory_limit_bytes: 256 * 1024 * 1024,
        },
        checker_contract_sha256: sha256(230),
    }
}

fn method_value(method: ComparisonMethod) -> u8 {
    match method {
        ComparisonMethod::OneShot => 1,
        ComparisonMethod::NonIncrementalCegis => 2,
        ComparisonMethod::IncrementalCegis => 3,
    }
}

fn run(
    case: &FrozenComparisonCase,
    method: ComparisonMethod,
    verification_status: VerificationStatus,
    outcome: ComparisonOutcome,
    candidate: Option<String>,
) -> BackendRunArtifact {
    let checked = candidate.is_some();
    BackendRunArtifact::new(
        case,
        BackendRunInput {
            method,
            verification_status,
            outcome,
            checked_candidate_sha256: candidate,
            candidate_independently_checked: checked,
            checker_artifact_sha256: checked.then(|| sha256(40 + method_value(method))),
            backend_artifact_sha256: (verification_status == VerificationStatus::Verified)
                .then(|| sha256(50 + method_value(method))),
            session_artifact_sha256: (method != ComparisonMethod::OneShot)
                .then(|| sha256(60 + method_value(method))),
            metrics: ComparisonMetrics {
                solver_calls: 3,
                checker_calls: u64::from(checked),
                candidates: u64::from(checked),
                blockers: u64::from(checked),
                restarts: u64::from(method == ComparisonMethod::IncrementalCegis),
                core_rechecks: 0,
            },
            resources: ResourceObservations {
                wall_time_ms: ResourceMeasurement::observed(10 + u64::from(method_value(method))),
                peak_memory_bytes: ResourceMeasurement::not_verified(),
            },
            core: CoreObservation::not_requested(),
        },
    )
    .unwrap()
}

fn agreeing_runs(case: &FrozenComparisonCase) -> Vec<BackendRunArtifact> {
    ComparisonMethod::ALL
        .into_iter()
        .map(|method| {
            run(
                case,
                method,
                VerificationStatus::Verified,
                ComparisonOutcome::Sat,
                Some(sha256(9)),
            )
        })
        .collect()
}

#[test]
fn three_conclusive_methods_share_one_case_and_check_each_candidate() {
    let case = frozen_case();
    let artifact = CegisComparisonArtifact::build(case, agreeing_runs(&frozen_case())).unwrap();

    assert_eq!(
        artifact.decision_consistency,
        DecisionConsistency::AllConclusiveAgree
    );
    assert_eq!(
        artifact.candidate_hash_relation,
        CandidateHashRelation::AllEqual
    );
    assert!(artifact.comparison_accepted);
    assert!(!artifact.performance_claimed);
    assert!(artifact.backend_runs.iter().all(|run| {
        run.candidate_independently_checked
            && run.metrics.checker_calls > 0
            && run.checker_artifact_sha256.is_some()
    }));
    artifact.validate().unwrap();
}

#[test]
fn conclusive_disagreement_is_preserved_and_never_accepted() {
    let case = frozen_case();
    let mut runs = agreeing_runs(&case);
    runs[0] = run(
        &case,
        ComparisonMethod::OneShot,
        VerificationStatus::Verified,
        ComparisonOutcome::BoundedUnsat,
        None,
    );
    let artifact = CegisComparisonArtifact::build(case, runs).unwrap();

    assert_eq!(
        artifact.decision_consistency,
        DecisionConsistency::ConclusiveDisagreement
    );
    assert!(!artifact.comparison_accepted);
}

#[test]
fn timeout_resource_and_solver_absence_remain_distinct_incomplete_results() {
    let case = frozen_case();
    let runs = vec![
        run(
            &case,
            ComparisonMethod::OneShot,
            VerificationStatus::Verified,
            ComparisonOutcome::Sat,
            Some(sha256(9)),
        ),
        run(
            &case,
            ComparisonMethod::NonIncrementalCegis,
            VerificationStatus::Verified,
            ComparisonOutcome::Inconclusive {
                reason: BackendInconclusiveReason::Timeout,
            },
            None,
        ),
        run(
            &case,
            ComparisonMethod::IncrementalCegis,
            VerificationStatus::SolverUnavailable,
            ComparisonOutcome::Inconclusive {
                reason: BackendInconclusiveReason::SolverUnavailable,
            },
            None,
        ),
    ];
    let artifact = CegisComparisonArtifact::build(case, runs).unwrap();

    assert_eq!(
        artifact.decision_consistency,
        DecisionConsistency::Incomplete
    );
    assert!(!artifact.comparison_accepted);
    assert_eq!(
        artifact.backend_runs[1].outcome,
        ComparisonOutcome::Inconclusive {
            reason: BackendInconclusiveReason::Timeout,
        }
    );
    assert_eq!(
        artifact.backend_runs[2].verification_status,
        VerificationStatus::SolverUnavailable
    );
}

#[test]
fn mismatched_case_or_unchecked_sat_is_rejected() {
    let case = frozen_case();
    let mut other = frozen_case();
    other.seed += 1;
    let mut runs = agreeing_runs(&case);
    runs[2] = run(
        &other,
        ComparisonMethod::IncrementalCegis,
        VerificationStatus::Verified,
        ComparisonOutcome::Sat,
        Some(sha256(9)),
    );
    assert!(matches!(
        CegisComparisonArtifact::build(case.clone(), runs),
        Err(ComparisonError::CaseMismatch)
    ));

    let unchecked = BackendRunArtifact::new(
        &case,
        BackendRunInput {
            method: ComparisonMethod::OneShot,
            verification_status: VerificationStatus::Verified,
            outcome: ComparisonOutcome::Sat,
            checked_candidate_sha256: Some(sha256(9)),
            candidate_independently_checked: false,
            checker_artifact_sha256: None,
            backend_artifact_sha256: Some(sha256(10)),
            session_artifact_sha256: None,
            metrics: ComparisonMetrics::default(),
            resources: ResourceObservations {
                wall_time_ms: ResourceMeasurement::not_verified(),
                peak_memory_bytes: ResourceMeasurement::not_verified(),
            },
            core: CoreObservation::not_requested(),
        },
    );
    assert!(matches!(
        unchecked,
        Err(ComparisonError::UncheckedCandidate)
    ));
}

#[test]
fn manifest_writer_uses_three_fixed_backend_directories() {
    let case = frozen_case();
    let artifact = CegisComparisonArtifact::build(case.clone(), agreeing_runs(&case)).unwrap();
    let root = std::env::temp_dir().join(format!(
        "noticer-cegis-comparison-{}-{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    let receipt = write_comparison_artifact(&root, &artifact).unwrap();

    assert_eq!(receipt.manifest_path, root.join("manifest.json"));
    assert!(receipt.manifest_path.is_file());
    assert_eq!(receipt.backend_result_paths.len(), 3);
    for method in ComparisonMethod::ALL {
        assert!(root
            .join("backends")
            .join(method.directory_name())
            .join("result.json")
            .is_file());
    }
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&receipt.manifest_path).unwrap()).unwrap();
    assert_eq!(
        manifest["artifact_sha256"].as_str(),
        Some(artifact.artifact_sha256.as_str())
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn unobserved_resources_cannot_carry_claimed_values() {
    let case = frozen_case();
    let result = BackendRunArtifact::new(
        &case,
        BackendRunInput {
            method: ComparisonMethod::OneShot,
            verification_status: VerificationStatus::NotVerified,
            outcome: ComparisonOutcome::Inconclusive {
                reason: BackendInconclusiveReason::NotVerified,
            },
            checked_candidate_sha256: None,
            candidate_independently_checked: false,
            checker_artifact_sha256: None,
            backend_artifact_sha256: None,
            session_artifact_sha256: None,
            metrics: ComparisonMetrics::default(),
            resources: ResourceObservations {
                wall_time_ms: ResourceMeasurement {
                    status: quotient_forge_synth::comparison::ObservationStatus::NotVerified,
                    value: Some(1),
                },
                peak_memory_bytes: ResourceMeasurement::unsupported(),
            },
            core: CoreObservation::not_requested(),
        },
    );
    assert!(matches!(
        result,
        Err(ComparisonError::InvalidResourceObservation)
    ));
}
