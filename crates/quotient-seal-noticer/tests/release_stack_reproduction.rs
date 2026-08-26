use quotient_seal_noticer::{
    injected_reproduction_fixture_inputs, DifferentialEvidenceOrigin, ReleaseStackCaseVerdict,
    ReleaseStackComponentKind, ReleaseStackReproductionBundle, ReleaseStackReproductionError,
    ReleaseStackReproductionVerdict, RELEASE_STACK_REPRODUCTION_COMMAND,
    RELEASE_STACK_REPRODUCTION_SCHEMA,
};

#[test]
fn identical_inputs_produce_byte_identical_canonical_json() {
    let inputs = injected_reproduction_fixture_inputs().unwrap();
    let first = ReleaseStackReproductionBundle::build(inputs.clone()).unwrap();
    let second = ReleaseStackReproductionBundle::build(inputs.clone()).unwrap();

    assert_eq!(first.schema, RELEASE_STACK_REPRODUCTION_SCHEMA);
    assert_eq!(
        first.reproduction_command,
        RELEASE_STACK_REPRODUCTION_COMMAND
    );
    assert_eq!(first, second);
    assert_eq!(first.canonical_json(), second.canonical_json());
    assert_eq!(first.artifact_sha256, second.artifact_sha256);
    first.verify_complete_recomputation(&inputs).unwrap();
    first.verify_internal_recomputation().unwrap();
}

#[test]
fn counts_verdict_and_first_difference_are_recomputed() {
    let inputs = injected_reproduction_fixture_inputs().unwrap();
    let bundle = ReleaseStackReproductionBundle::build(inputs).unwrap();

    assert_eq!(
        bundle.summary.verdict,
        ReleaseStackReproductionVerdict::Complete
    );
    assert_eq!(bundle.summary.case_count, 2);
    assert_eq!(bundle.summary.match_count, 1);
    assert_eq!(bundle.summary.attack_rejected_count, 1);
    assert_eq!(bundle.summary.profile_unresolved_count, 0);
    assert_eq!(bundle.summary.invariant_violation_count, 0);
    assert_eq!(bundle.summary.action_count, 1);
    assert_eq!(bundle.summary.frame_count, 7);
    assert_eq!(bundle.summary.failure_count, 1);
    assert_eq!(
        bundle.summary.first_difference.unwrap().case_id_sha256,
        [52; 32]
    );
}

#[test]
fn tamper_missing_artifact_and_different_result_fail_closed() {
    let inputs = injected_reproduction_fixture_inputs().unwrap();
    let mut tampered = ReleaseStackReproductionBundle::build(inputs.clone()).unwrap();
    tampered.summary.match_count += 1;
    assert_eq!(
        tampered.verify_complete_recomputation(&inputs),
        Err(ReleaseStackReproductionError::ArtifactMismatch)
    );

    let mut missing = inputs.clone();
    missing.cases.clear();
    assert_eq!(
        ReleaseStackReproductionBundle::build(missing),
        Err(ReleaseStackReproductionError::MissingCases)
    );

    let original = ReleaseStackReproductionBundle::build(inputs.clone()).unwrap();
    let mut different = inputs;
    different.cases[0].verdict = ReleaseStackCaseVerdict::InvariantViolation;
    different.cases[0].failure_count = 1;
    different.cases[0].first_difference = different.cases[1].first_difference;
    different.cases[0].first_difference_module = different.cases[1].first_difference_module;
    assert_eq!(
        original.verify_complete_recomputation(&different),
        Err(ReleaseStackReproductionError::ArtifactMismatch)
    );
}

#[test]
fn forged_nested_engine_digest_is_rejected_against_external_inputs() {
    let inputs = injected_reproduction_fixture_inputs().unwrap();
    let mut forged = ReleaseStackReproductionBundle::build(inputs.clone()).unwrap();
    forged.differential.modules[0].engines.wasmi_sha256[0] ^= 0xff;
    forged.differential.artifact_sha256 = forged.differential.recomputed_sha256();
    forged.components[5].artifact_sha256 = forged.differential.artifact_sha256;
    forged.artifact_sha256 = forged.recomputed_sha256();

    assert!(forged.verify_internal_recomputation().is_ok());
    assert_eq!(
        forged.verify_complete_recomputation(&inputs),
        Err(ReleaseStackReproductionError::ArtifactMismatch)
    );
}

#[test]
fn component_order_cross_binding_and_case_order_are_enforced() {
    let mut wrong_component = injected_reproduction_fixture_inputs().unwrap();
    wrong_component.components.swap(0, 1);
    assert!(matches!(
        ReleaseStackReproductionBundle::build(wrong_component),
        Err(ReleaseStackReproductionError::UnexpectedComponent { index: 0, .. })
    ));

    let mut wrong_binding = injected_reproduction_fixture_inputs().unwrap();
    wrong_binding.components[1].artifact_sha256 = [99; 32];
    assert_eq!(
        ReleaseStackReproductionBundle::build(wrong_binding),
        Err(ReleaseStackReproductionError::CrossBindingMismatch(
            ReleaseStackComponentKind::CompositionContract
        ))
    );

    let mut wrong_cases = injected_reproduction_fixture_inputs().unwrap();
    wrong_cases.cases.swap(0, 1);
    assert_eq!(
        ReleaseStackReproductionBundle::build(wrong_cases),
        Err(ReleaseStackReproductionError::NonCanonicalCaseOrder)
    );
}

#[test]
fn machine_artifact_is_fixture_labeled_and_contains_no_private_material() {
    let inputs = injected_reproduction_fixture_inputs().unwrap();
    assert!(inputs
        .cases
        .iter()
        .all(|case| case.evidence_origin == DifferentialEvidenceOrigin::InjectedTestFixture));
    let bundle = ReleaseStackReproductionBundle::build(inputs).unwrap();
    let artifact = bundle.canonical_json();
    let summary = bundle.machine_summary_json();

    assert!(artifact.contains("INJECTED_TEST_FIXTURE"));
    assert!(artifact.contains("NOT_VERIFIED"));
    assert!(summary.contains("NOT_VERIFIED"));
    for forbidden in [
        "private_ingress_capability",
        "biosignal_sample",
        "subject_identifier",
        "raw_witness",
    ] {
        assert!(!artifact.contains(forbidden));
        assert!(!summary.contains(forbidden));
    }
}
