use quotient_seal_benchmark::{
    frozen_registry, BenchmarkCaseInput, BenchmarkFamilyId, BenchmarkFamilyKind,
    BenchmarkInconclusiveReason, BenchmarkInputError, BenchmarkOutcome, EvaluatorKind,
    BENCHMARK_FAMILY_COUNT, HARDWARE_STATUS,
};

#[test]
fn frozen_registry_contains_eight_valid_and_eight_negative_families() {
    let registry = frozen_registry(0x5153_4245_4e43_4831);
    registry.validate().unwrap();

    assert_eq!(registry.families.len(), BENCHMARK_FAMILY_COUNT);
    assert_eq!(
        registry
            .families
            .iter()
            .filter(|family| family.family_kind == BenchmarkFamilyKind::Valid)
            .count(),
        8
    );
    assert_eq!(
        registry
            .families
            .iter()
            .filter(|family| family.family_kind == BenchmarkFamilyKind::Negative)
            .count(),
        8
    );
    assert_eq!(registry.hardware_status, HARDWARE_STATUS);
}

#[test]
fn registry_envelope_is_deterministic_and_round_trips() {
    let first = frozen_registry(7);
    let second = frozen_registry(7);

    assert_eq!(
        first.canonical_json().unwrap(),
        second.canonical_json().unwrap()
    );
    assert_eq!(first.encode().unwrap(), second.encode().unwrap());
    assert_eq!(
        first.artifact_sha256().unwrap(),
        second.artifact_sha256().unwrap()
    );
    assert_eq!(
        quotient_seal_benchmark::BenchmarkRegistry::decode(&first.encode().unwrap()).unwrap(),
        first
    );
}

#[test]
fn tamper_trailing_bytes_and_family_reordering_fail_closed() {
    let registry = frozen_registry(11);
    let mut tampered = registry.encode().unwrap();
    tampered[20] ^= 0xff;
    assert_eq!(
        quotient_seal_benchmark::BenchmarkRegistry::decode(&tampered),
        Err(BenchmarkInputError::Digest)
    );

    let mut trailing = registry.encode().unwrap();
    trailing.push(0);
    assert_eq!(
        quotient_seal_benchmark::BenchmarkRegistry::decode(&trailing),
        Err(BenchmarkInputError::Length)
    );

    let mut reordered = registry;
    reordered.families.swap(0, 1);
    assert_eq!(
        reordered.validate(),
        Err(BenchmarkInputError::FamilyOrder { index: 0 })
    );
}

#[test]
fn baseline_and_full_evaluator_consume_the_same_case_contract() {
    let registry = frozen_registry(13);
    let input = BenchmarkCaseInput {
        family_id: BenchmarkFamilyId::MedicalAlertClass,
        variant_id: 2,
        seed: 99,
        public_input_sha256: [1; 32],
        source_artifact_sha256: [2; 32],
    };
    input.validate(&registry).unwrap();

    let baseline = (EvaluatorKind::Baseline, input);
    let full = (EvaluatorKind::FullQuotientSeal, input);
    assert_eq!(baseline.1, full.1);
}

#[test]
fn unsupported_resource_bound_and_disagreement_are_never_conclusive() {
    for reason in [
        BenchmarkInconclusiveReason::Unsupported,
        BenchmarkInconclusiveReason::ResourceBound,
        BenchmarkInconclusiveReason::EngineDisagreement,
    ] {
        assert!(!BenchmarkOutcome::Inconclusive(reason).is_conclusive());
    }
    assert!(BenchmarkOutcome::Valid.is_conclusive());
    assert!(BenchmarkOutcome::Invalid.is_conclusive());
}
