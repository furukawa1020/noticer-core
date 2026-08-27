use quotient_seal_benchmark::{
    execute_negative_family, frozen_registry, generate_negative_families, generate_valid_families,
    BenchmarkOutcome, NegativeFamilyError, NegativeMutationClass, NEGATIVE_FAMILY_COUNT,
    NEGATIVE_VARIANTS_PER_FAMILY,
};

#[test]
fn eight_negative_families_are_paired_one_to_one_with_valid_counterparts() {
    let registry = frozen_registry(0x4e45_4741_5449_5645);
    let valid = generate_valid_families(&registry).unwrap();
    let negative = generate_negative_families(&registry, &valid).unwrap();

    assert_eq!(negative.len(), NEGATIVE_FAMILY_COUNT);
    for (index, fixture) in negative.iter().enumerate() {
        for other in &negative[index + 1..] {
            assert_ne!(fixture.counterpart_family_id, other.counterpart_family_id);
            assert_ne!(fixture.mutation_class, other.mutation_class);
        }
    }
    for (index, fixture) in negative.iter().enumerate() {
        assert_eq!(fixture.counterpart_family_id, valid[index].family_id);
        assert_eq!(
            fixture.counterpart_source_sha256,
            valid[index].source_artifact_sha256
        );
        assert_eq!(fixture.variants.len(), NEGATIVE_VARIANTS_PER_FAMILY);
        fixture.validate().unwrap();
    }
}

#[test]
fn all_thirty_two_negative_cases_produce_typed_invalid_receipts() {
    let registry = frozen_registry(19);
    let valid = generate_valid_families(&registry).unwrap();
    let negative = generate_negative_families(&registry, &valid).unwrap();

    let mut count = 0;
    for fixture in &negative {
        for variant in &fixture.variants {
            let receipt = execute_negative_family(fixture, variant.input.variant_id).unwrap();
            assert_eq!(receipt.verdict, BenchmarkOutcome::Invalid);
            assert_eq!(receipt.first_difference, variant.expected_difference);
            assert_eq!(receipt.evidence_origin, "INJECTED_TEST_FIXTURE");
            assert_ne!(
                receipt.counterpart_source_sha256,
                receipt.mutated_source_sha256
            );
            receipt.verify(fixture).unwrap();
            count += 1;
        }
    }
    assert_eq!(count, NEGATIVE_FAMILY_COUNT * NEGATIVE_VARIANTS_PER_FAMILY);
}

#[test]
fn fixture_and_receipt_generation_are_byte_reproducible() {
    let registry = frozen_registry(23);
    let valid = generate_valid_families(&registry).unwrap();
    let first = generate_negative_families(&registry, &valid).unwrap();
    let second = generate_negative_families(&registry, &valid).unwrap();

    assert_eq!(first, second);
    for (left, right) in first.iter().zip(second.iter()) {
        assert_eq!(
            left.canonical_json().unwrap(),
            right.canonical_json().unwrap()
        );
        assert_eq!(
            left.artifact_sha256().unwrap(),
            right.artifact_sha256().unwrap()
        );
        assert_eq!(
            execute_negative_family(left, 0).unwrap(),
            execute_negative_family(right, 0).unwrap()
        );
    }
}

#[test]
fn every_requested_negative_class_is_present() {
    let registry = frozen_registry(29);
    let valid = generate_valid_families(&registry).unwrap();
    let negative = generate_negative_families(&registry, &valid).unwrap();
    let expected = [
        NegativeMutationClass::ExtraCall,
        NegativeMutationClass::PrivateTrap,
        NegativeMutationClass::ResourceLeak,
        NegativeMutationClass::ExportedMemory,
        NegativeMutationClass::ResetLeak,
        NegativeMutationClass::StateCorruption,
        NegativeMutationClass::DuplicateAction,
        NegativeMutationClass::HandoffCarryover,
    ];
    assert_eq!(negative.map(|fixture| fixture.mutation_class), expected);
}

#[test]
fn receipt_tamper_and_unknown_variant_fail_closed() {
    let registry = frozen_registry(31);
    let valid = generate_valid_families(&registry).unwrap();
    let negative = generate_negative_families(&registry, &valid).unwrap();
    let fixture = &negative[0];

    assert_eq!(
        execute_negative_family(fixture, 99),
        Err(NegativeFamilyError::UnknownVariant)
    );
    let mut receipt = execute_negative_family(fixture, 0).unwrap();
    receipt.host_call_count += 1;
    assert_eq!(
        receipt.verify(fixture),
        Err(NegativeFamilyError::ReceiptMismatch)
    );
}

#[test]
fn negative_artifacts_are_fixture_labeled_without_private_material() {
    let registry = frozen_registry(37);
    let valid = generate_valid_families(&registry).unwrap();
    let negative = generate_negative_families(&registry, &valid).unwrap();
    for fixture in &negative {
        let json = String::from_utf8(fixture.canonical_json().unwrap()).unwrap();
        assert!(json.contains("INJECTED_TEST_FIXTURE"));
        assert!(json.contains("NOT_VERIFIED"));
        for forbidden in [
            "private_value",
            "private_trace",
            "secret",
            "stable_identifier",
        ] {
            assert!(!json.contains(forbidden));
        }
    }
}
