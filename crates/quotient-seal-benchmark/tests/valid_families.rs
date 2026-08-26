use quotient_seal_benchmark::{
    execute_valid_family, frozen_registry, generate_valid_families, SyntheticPrivateHistory,
    ValidFamilyError, ValidPublicEvent, VALID_FAMILY_COUNT, VALID_VARIANTS_PER_FAMILY,
};

#[test]
fn all_eight_valid_families_have_four_deterministic_variants() {
    let registry = frozen_registry(0x5641_4c49_445f_5631);
    let first = generate_valid_families(&registry).unwrap();
    let second = generate_valid_families(&registry).unwrap();

    assert_eq!(first.len(), VALID_FAMILY_COUNT);
    assert_eq!(first, second);
    for fixture in &first {
        fixture.validate().unwrap();
        assert_eq!(fixture.variants.len(), VALID_VARIANTS_PER_FAMILY);
        assert_eq!(
            fixture.canonical_json().unwrap(),
            second
                .iter()
                .find(|other| other.family_id == fixture.family_id)
                .unwrap()
                .canonical_json()
                .unwrap()
        );
    }
}

#[test]
fn different_private_histories_with_same_action_semantics_are_byte_identical() {
    let fixtures = generate_valid_families(&frozen_registry(17)).unwrap();
    for fixture in &fixtures {
        for variant in &fixture.variants {
            let first = execute_valid_family(
                fixture,
                variant.input.variant_id,
                SyntheticPrivateHistory {
                    synthetic_bucket: 1,
                    allowed_action: variant.expected_action,
                },
            )
            .unwrap();
            let second = execute_valid_family(
                fixture,
                variant.input.variant_id,
                SyntheticPrivateHistory {
                    synthetic_bucket: u16::MAX,
                    allowed_action: variant.expected_action,
                },
            )
            .unwrap();
            assert_eq!(first, second);
            assert_eq!(
                first.canonical_json().unwrap(),
                second.canonical_json().unwrap()
            );
            first.verify(fixture).unwrap();
        }
    }
}

#[test]
fn every_receipt_contains_one_decision_slot_reset_and_handoff() {
    let fixtures = generate_valid_families(&frozen_registry(23)).unwrap();
    for fixture in &fixtures {
        for variant in &fixture.variants {
            let receipt = execute_valid_family(
                fixture,
                variant.input.variant_id,
                SyntheticPrivateHistory {
                    synthetic_bucket: 7,
                    allowed_action: variant.expected_action,
                },
            )
            .unwrap();
            assert_eq!(receipt.public_trace.len(), 5);
            assert_eq!(receipt.reset_count, 1);
            assert_eq!(receipt.handoff_count, 1);
            assert!(matches!(
                receipt.public_trace[1],
                ValidPublicEvent::DecisionSlot
            ));
            assert!(matches!(
                receipt.public_trace[3],
                ValidPublicEvent::ResetAck(_)
            ));
            assert!(matches!(
                receipt.public_trace[4],
                ValidPublicEvent::HandoffAck(_)
            ));
            assert_eq!(receipt.action_count, u32::from(variant.expected_action));
        }
    }
}

#[test]
fn action_semantics_mismatch_and_receipt_tamper_fail_closed() {
    let fixtures = generate_valid_families(&frozen_registry(29)).unwrap();
    let fixture = &fixtures[0];
    let variant = fixture.variants[0];
    assert_eq!(
        execute_valid_family(
            fixture,
            variant.input.variant_id,
            SyntheticPrivateHistory {
                synthetic_bucket: 1,
                allowed_action: !variant.expected_action,
            },
        ),
        Err(ValidFamilyError::ActionSemanticsMismatch)
    );

    let mut receipt = execute_valid_family(
        fixture,
        variant.input.variant_id,
        SyntheticPrivateHistory {
            synthetic_bucket: 2,
            allowed_action: variant.expected_action,
        },
    )
    .unwrap();
    receipt.final_public_state_sha256[0] ^= 0xff;
    assert_eq!(
        receipt.verify(fixture),
        Err(ValidFamilyError::ReceiptMismatch)
    );
}

#[test]
fn fixture_artifacts_do_not_serialize_private_history_values() {
    let fixtures = generate_valid_families(&frozen_registry(31)).unwrap();
    for fixture in &fixtures {
        let json = String::from_utf8(fixture.canonical_json().unwrap()).unwrap();
        assert!(json.contains("INJECTED_TEST_FIXTURE"));
        assert!(json.contains("NOT_VERIFIED"));
        for forbidden in [
            "synthetic_bucket",
            "private_value",
            "private_trace",
            "secret",
            "stable_identifier",
        ] {
            assert!(!json.contains(forbidden));
        }
    }
}
