use quotient_seal_benchmark::{
    injected_benchmark_reproduction_inputs, BenchmarkGateVerdict,
    GenericBenchmarkReproductionBundle, GenericBenchmarkReproductionError,
    GENERIC_BENCHMARK_REPRODUCTION_COMMAND, GENERIC_BENCHMARK_REPRODUCTION_SCHEMA,
};

#[test]
fn identical_inputs_generate_byte_identical_bundle() {
    let inputs = injected_benchmark_reproduction_inputs().unwrap();
    let first = GenericBenchmarkReproductionBundle::build(inputs.clone()).unwrap();
    let second = GenericBenchmarkReproductionBundle::build(inputs.clone()).unwrap();

    assert_eq!(first.schema, GENERIC_BENCHMARK_REPRODUCTION_SCHEMA);
    assert_eq!(
        first.reproduction_command,
        GENERIC_BENCHMARK_REPRODUCTION_COMMAND
    );
    assert_eq!(first, second);
    assert_eq!(
        first.canonical_json().unwrap(),
        second.canonical_json().unwrap()
    );
    assert_eq!(first.artifact_sha256, second.artifact_sha256);
    first.verify_complete_recomputation(&inputs).unwrap();
    first.verify_internal_recomputation().unwrap();
}

#[test]
fn bundle_binds_all_families_cases_and_gate_counts() {
    let bundle = GenericBenchmarkReproductionBundle::build(
        injected_benchmark_reproduction_inputs().unwrap(),
    )
    .unwrap();
    let summary = bundle.machine_summary();

    assert_eq!(summary.family_count, 16);
    assert_eq!(summary.valid_family_count, 8);
    assert_eq!(summary.negative_family_count, 8);
    assert_eq!(summary.case_count, 64);
    assert_eq!(summary.held_out_case_count, 16);
    assert_eq!(summary.baseline_negative_escaped, 24);
    assert_eq!(summary.full_negative_escaped, 0);
    assert_eq!(summary.full_inconclusive, 0);
    assert_eq!(summary.gate_verdict, BenchmarkGateVerdict::Pass);
    assert!(bundle
        .component_digests
        .valid_family_sha256
        .iter()
        .all(|digest| *digest != [0; 32]));
    assert!(bundle
        .component_digests
        .negative_family_sha256
        .iter()
        .all(|digest| *digest != [0; 32]));
}

#[test]
fn missing_fixture_tamper_and_different_result_fail_closed() {
    let inputs = injected_benchmark_reproduction_inputs().unwrap();
    let mut missing = inputs.clone();
    missing.valid_families[0].variants.clear();
    assert_eq!(
        GenericBenchmarkReproductionBundle::build(missing),
        Err(GenericBenchmarkReproductionError::ValidFixtureMismatch)
    );

    let original = GenericBenchmarkReproductionBundle::build(inputs.clone()).unwrap();
    let mut different = inputs.clone();
    different.comparison.summary.full_negative_escaped = 1;
    assert_eq!(
        original.verify_complete_recomputation(&different),
        Err(GenericBenchmarkReproductionError::ComparisonMismatch)
    );

    let mut tampered = original;
    tampered.component_digests.registry_sha256[0] ^= 0xff;
    assert_eq!(
        tampered.verify_complete_recomputation(&inputs),
        Err(GenericBenchmarkReproductionError::ArtifactMismatch)
    );
}

#[test]
fn external_inputs_reject_a_self_consistent_reseeded_bundle() {
    let expected_inputs = injected_benchmark_reproduction_inputs().unwrap();
    let expected = GenericBenchmarkReproductionBundle::build(expected_inputs.clone()).unwrap();
    let mut changed_inputs = expected_inputs.clone();
    changed_inputs.source_tree_sha256 = [0x99; 32];
    let changed = GenericBenchmarkReproductionBundle::build(changed_inputs).unwrap();

    assert!(changed.verify_internal_recomputation().is_ok());
    assert_eq!(
        changed.verify_complete_recomputation(&expected_inputs),
        Err(GenericBenchmarkReproductionError::ArtifactMismatch)
    );
    assert_ne!(expected.artifact_sha256, changed.artifact_sha256);
}

#[test]
fn bundle_and_summary_are_fixture_labeled_without_private_material() {
    let bundle = GenericBenchmarkReproductionBundle::build(
        injected_benchmark_reproduction_inputs().unwrap(),
    )
    .unwrap();
    let artifact = String::from_utf8(bundle.canonical_json().unwrap()).unwrap();
    let summary = String::from_utf8(bundle.machine_summary_json().unwrap()).unwrap();

    assert!(artifact.contains("INJECTED_TEST_FIXTURE"));
    assert!(artifact.contains("NOT_VERIFIED"));
    assert!(summary.contains("NOT_VERIFIED"));
    for forbidden in [
        "private_value",
        "private_trace",
        "secret",
        "stable_identifier",
    ] {
        assert!(!artifact.contains(forbidden));
        assert!(!summary.contains(forbidden));
    }
}
