use quotient_seal_benchmark::{
    build_family_split, evaluate_held_out_comparison, frozen_registry, generate_negative_families,
    generate_valid_families, BenchmarkComparisonError, BenchmarkGateVerdict, BenchmarkSplit,
    COMPARISON_CASE_COUNT, VALID_FAMILY_COUNT,
};

fn fixture() -> (
    quotient_seal_benchmark::BenchmarkRegistry,
    [quotient_seal_benchmark::ValidFamilyFixture; 8],
    [quotient_seal_benchmark::NegativeFamilyFixture; 8],
    quotient_seal_benchmark::FamilySplitPlan,
) {
    let registry = frozen_registry(0x4845_4c44_4f55_5431);
    let valid = generate_valid_families(&registry).unwrap();
    let negative = generate_negative_families(&registry, &valid).unwrap();
    let plan = build_family_split(17);
    (registry, valid, negative, plan)
}

#[test]
fn semantic_pairs_are_family_disjoint_and_balanced() {
    let (_, valid, negative, plan) = fixture();
    plan.validate().unwrap();
    for index in 0..VALID_FAMILY_COUNT {
        assert_eq!(
            plan.split_for(valid[index].family_id).unwrap(),
            plan.split_for(negative[index].family_id).unwrap()
        );
    }
    assert_eq!(
        plan.assignments
            .iter()
            .filter(|entry| entry.split == BenchmarkSplit::Development)
            .count(),
        8
    );
    assert_eq!(
        plan.assignments
            .iter()
            .filter(|entry| entry.split == BenchmarkSplit::Validation)
            .count(),
        4
    );
    assert_eq!(
        plan.assignments
            .iter()
            .filter(|entry| entry.split == BenchmarkSplit::HeldOut)
            .count(),
        4
    );
}

#[test]
fn all_sixty_four_cases_are_accounted_exactly_once() {
    let (registry, valid, negative, plan) = fixture();
    let artifact = evaluate_held_out_comparison(&registry, &valid, &negative, &plan).unwrap();

    assert_eq!(artifact.records.len(), COMPARISON_CASE_COUNT);
    for (index, record) in artifact.records.iter().enumerate() {
        assert!(!artifact.records[..index]
            .iter()
            .any(|earlier| earlier.case_id_sha256 == record.case_id_sha256));
    }
    assert_eq!(artifact.summary.case_count, 64);
    assert_eq!(artifact.summary.valid_case_count, 32);
    assert_eq!(artifact.summary.negative_case_count, 32);
    assert_eq!(artifact.summary.held_out_case_count, 16);
}

#[test]
fn baseline_escapes_are_not_counted_as_full_gate_success() {
    let (registry, valid, negative, plan) = fixture();
    let artifact = evaluate_held_out_comparison(&registry, &valid, &negative, &plan).unwrap();

    assert_eq!(artifact.summary.baseline_valid_correct, 32);
    assert_eq!(artifact.summary.baseline_negative_detected, 8);
    assert_eq!(artifact.summary.baseline_negative_escaped, 24);
    assert_eq!(artifact.summary.full_valid_correct, 32);
    assert_eq!(artifact.summary.full_negative_detected, 32);
    assert_eq!(artifact.summary.full_negative_escaped, 0);
    assert_eq!(artifact.summary.full_inconclusive, 0);
    assert_eq!(artifact.summary.gate_verdict, BenchmarkGateVerdict::Pass);
}

#[test]
fn baseline_and_full_results_are_bound_to_one_common_input() {
    let (registry, valid, negative, plan) = fixture();
    let artifact = evaluate_held_out_comparison(&registry, &valid, &negative, &plan).unwrap();
    for record in &artifact.records {
        assert_ne!(record.baseline_evidence_sha256, [0; 32]);
        assert_ne!(record.full_evidence_sha256, [0; 32]);
        assert_ne!(record.baseline_evidence_sha256, record.full_evidence_sha256);
    }
}

#[test]
fn split_leakage_and_artifact_tamper_fail_closed() {
    let (registry, valid, negative, mut plan) = fixture();
    plan.assignments[8].split = match plan.assignments[0].split {
        BenchmarkSplit::Development => BenchmarkSplit::HeldOut,
        BenchmarkSplit::Validation | BenchmarkSplit::HeldOut => BenchmarkSplit::Development,
    };
    plan.artifact_sha256 = plan.recomputed_sha256().unwrap();
    assert_eq!(
        plan.validate(),
        Err(BenchmarkComparisonError::PairLeakage { pair_index: 0 })
    );

    let plan = build_family_split(17);
    let mut artifact = evaluate_held_out_comparison(&registry, &valid, &negative, &plan).unwrap();
    artifact.summary.full_negative_escaped = 1;
    assert_eq!(
        artifact.verify_complete_recomputation(&registry, &valid, &negative, &plan),
        Err(BenchmarkComparisonError::ArtifactMismatch)
    );
}

#[test]
fn comparison_artifact_is_deterministic_and_fixture_labeled() {
    let (registry, valid, negative, plan) = fixture();
    let first = evaluate_held_out_comparison(&registry, &valid, &negative, &plan).unwrap();
    let second = evaluate_held_out_comparison(&registry, &valid, &negative, &plan).unwrap();
    assert_eq!(first, second);
    assert_eq!(
        first.canonical_json().unwrap(),
        second.canonical_json().unwrap()
    );
    assert_eq!(first.evidence_origin, "INJECTED_TEST_FIXTURE");
    assert_eq!(first.hardware_status, "NOT_VERIFIED");
    first
        .verify_complete_recomputation(&registry, &valid, &negative, &plan)
        .unwrap();
}
