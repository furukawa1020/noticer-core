use std::collections::BTreeSet;

use quotient_seal_noticer::{
    evaluate_release_stack_adversarial_matrix, verify_release_stack_adversarial_matrix,
    DeploymentProfile, Digest, Epoch, NoticerModuleBinding, NoticerModuleId, NoticerQsmManifest,
    P1ResourceEvidence, PolicyHash, ReleaseStackCompositionContract, ReleaseStackEvidenceOrigin,
    ReleaseStackMatrixError, ReleaseStackMatrixLimits, ReleaseStackMatrixOutcome,
    ReleaseStackMatrixProfile, WireServiceAlias, RELEASE_STACK_ADVERSARIAL_CASES,
    RELEASE_STACK_HARDWARE_STATUS,
};

fn digest(value: u8) -> Digest {
    Digest::new([value; 32])
}

fn contract(p1: bool) -> ReleaseStackCompositionContract {
    let entries = NoticerModuleId::ALL
        .iter()
        .enumerate()
        .map(|(index, module_id)| {
            let value = index as u8 + 1;
            let is_p1 = p1 && *module_id == NoticerModuleId::Aepa;
            NoticerModuleBinding {
                module_id: *module_id,
                deployment_profile: if is_p1 {
                    DeploymentProfile::P1SealedAdmission
                } else {
                    DeploymentProfile::P0PublicQuotientOnly
                },
                service_alias: WireServiceAlias([value; 8]),
                epoch: Epoch(u64::from(value)),
                policy_hash: PolicyHash([value; 32]),
                source_digest: digest(value),
                source_certificate_digest: digest(value + 10),
                generated_runtime_digest: digest(value + 20),
                qsm_capsule_digest: digest(value + 30),
                observer_registry_digest: digest(value + 40),
                p1_resource_evidence: is_p1.then_some(P1ResourceEvidence {
                    equivalence_certificate_digest: digest(91),
                    relation_binding_digest: digest(92),
                    checked_cases: 8,
                }),
            }
        })
        .collect();
    ReleaseStackCompositionContract::new(NoticerQsmManifest::new(entries).expect("manifest"))
        .expect("contract")
}

#[test]
fn exactly_42_cases_are_unique_and_evaluated_once() {
    let p0 = contract(false);
    let p1 = contract(true);
    let matrix = evaluate_release_stack_adversarial_matrix(
        &p0,
        &p1,
        None,
        101,
        ReleaseStackMatrixLimits::default(),
    )
    .expect("matrix");
    assert_eq!(matrix.expected_case_count, RELEASE_STACK_ADVERSARIAL_CASES);
    assert_eq!(matrix.evaluated_case_count, RELEASE_STACK_ADVERSARIAL_CASES);
    assert_eq!(matrix.cases.len(), RELEASE_STACK_ADVERSARIAL_CASES);
    let ids: BTreeSet<_> = matrix.cases.iter().map(|case| &case.case_id).collect();
    assert_eq!(ids.len(), RELEASE_STACK_ADVERSARIAL_CASES);
    verify_release_stack_adversarial_matrix(
        &p0,
        &p1,
        None,
        &matrix,
        ReleaseStackMatrixLimits::default(),
    )
    .expect("verify matrix");
}

#[test]
fn p0_matches_two_canonical_paths_and_rejects_all_19_injections() {
    let p0 = contract(false);
    let p1 = contract(true);
    let matrix = evaluate_release_stack_adversarial_matrix(
        &p0,
        &p1,
        None,
        101,
        ReleaseStackMatrixLimits::default(),
    )
    .expect("matrix");
    let p0_cases: Vec<_> = matrix
        .cases
        .iter()
        .filter(|case| case.profile == ReleaseStackMatrixProfile::P0)
        .collect();
    assert_eq!(p0_cases.len(), 21);
    assert_eq!(
        p0_cases
            .iter()
            .filter(|case| case.outcome == ReleaseStackMatrixOutcome::Match)
            .count(),
        2
    );
    assert_eq!(
        p0_cases
            .iter()
            .filter(|case| case.outcome == ReleaseStackMatrixOutcome::AttackRejected)
            .count(),
        19
    );
    assert!(p0_cases.iter().all(|case| {
        case.outcome != ReleaseStackMatrixOutcome::InvariantViolation
            && case.unauthorized_action_count == 0
    }));
    assert_eq!(matrix.authorized_action_count, 1);
    assert_eq!(matrix.unauthorized_action_count, 0);
}

#[test]
fn missing_p1_authorization_never_becomes_a_pass_or_p0_downgrade() {
    let p0 = contract(false);
    let p1 = contract(true);
    let matrix = evaluate_release_stack_adversarial_matrix(
        &p0,
        &p1,
        None,
        101,
        ReleaseStackMatrixLimits::default(),
    )
    .expect("matrix");
    let p1_cases: Vec<_> = matrix
        .cases
        .iter()
        .filter(|case| case.profile == ReleaseStackMatrixProfile::P1)
        .collect();
    assert_eq!(p1_cases.len(), 21);
    assert!(p1_cases.iter().all(|case| {
        case.outcome == ReleaseStackMatrixOutcome::ProfileUnresolved
            && case.authorized_action_count == 0
            && case.unauthorized_action_count == 0
    }));
    assert_eq!(matrix.match_count, 2);
    assert_eq!(matrix.attack_rejected_count, 19);
    assert_eq!(matrix.profile_unresolved_count, 21);
    assert_eq!(matrix.invariant_violation_count, 0);
}

#[test]
fn every_attack_is_labeled_as_an_injected_fixture() {
    let p0 = contract(false);
    let p1 = contract(true);
    let matrix = evaluate_release_stack_adversarial_matrix(
        &p0,
        &p1,
        None,
        101,
        ReleaseStackMatrixLimits::default(),
    )
    .expect("matrix");
    for case in &matrix.cases {
        let canonical =
            case.case_id.ends_with("CANONICAL_ACTION") || case.case_id.ends_with("CANONICAL_COVER");
        assert_eq!(
            case.evidence_origin,
            if canonical {
                ReleaseStackEvidenceOrigin::SpecificationPath
            } else {
                ReleaseStackEvidenceOrigin::InjectedTestFixture
            }
        );
    }
}

#[test]
fn matrix_is_deterministic_and_tampering_or_low_limits_fail_closed() {
    let p0 = contract(false);
    let p1 = contract(true);
    let first = evaluate_release_stack_adversarial_matrix(
        &p0,
        &p1,
        None,
        101,
        ReleaseStackMatrixLimits::default(),
    )
    .expect("first");
    let second = evaluate_release_stack_adversarial_matrix(
        &p0,
        &p1,
        None,
        101,
        ReleaseStackMatrixLimits::default(),
    )
    .expect("second");
    assert_eq!(first, second);

    let mut tampered = first.clone();
    tampered.cases[3].failure_count = 0;
    assert_eq!(
        verify_release_stack_adversarial_matrix(
            &p0,
            &p1,
            None,
            &tampered,
            ReleaseStackMatrixLimits::default(),
        ),
        Err(ReleaseStackMatrixError::NonCanonical)
    );
    assert_eq!(
        evaluate_release_stack_adversarial_matrix(
            &p0,
            &p1,
            None,
            101,
            ReleaseStackMatrixLimits { max_cases: 41 },
        ),
        Err(ReleaseStackMatrixError::CaseLimit {
            actual: 41,
            required: 42,
        })
    );
    assert_eq!(first.hardware_status, RELEASE_STACK_HARDWARE_STATUS);
    let public_debug = format!("{first:?}");
    for forbidden in [
        "raw_ppg",
        "private_baseline",
        "private_token_material",
        "replay_state",
    ] {
        assert!(!public_debug.contains(forbidden));
    }
}
