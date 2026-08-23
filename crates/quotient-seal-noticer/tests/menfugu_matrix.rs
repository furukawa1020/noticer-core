use std::collections::BTreeSet;

use noticer_protocol::{KeyId, WireServiceAlias};
use noticer_types::{ActionCode, Epoch, PolicyHash};
use quotient_seal_noticer::{
    compile_menfugu_p0, evaluate_menfugu_adversarial_matrix, menfugu_generated_runtime_digest,
    menfugu_observer_registry_digest, menfugu_source_certificate_digest,
    verify_menfugu_adversarial_execution, MenfuguActionClassification, MenfuguAdversarialMatrix,
    MenfuguAdversarialMatrixError, MenfuguAdversarialMatrixLimits, MenfuguAdversarialMatrixSeed,
    MenfuguCaseOutcome, MenfuguCompileLimits, MenfuguCompiledQsm, MenfuguEngineDigests,
    MenfuguK7Artifacts, MenfuguK7Binding, MenfuguProfileAxis, MenfuguPublicPolicyBinding,
    MenfuguPublicSourceArtifact, MenfuguScenarioAxis, MenfuguServiceCode,
};

const WIRE_ALIAS: WireServiceAlias = WireServiceAlias([0x31; 8]);
const CERTIFICATE: &[u8] = b"MENFUGU_K7_PUBLIC_CERTIFICATE_V1";
const RUNTIME: &[u8] = b"MENFUGU_K7_GENERATED_RUNTIME_V1";

fn policy() -> MenfuguPublicPolicyBinding {
    MenfuguPublicPolicyBinding {
        service_alias: WIRE_ALIAS,
        epoch: Epoch(11),
        policy_hash: PolicyHash([0x41; 32]),
        verifier_key_id: KeyId([0x51; 8]),
        allowed_action: ActionCode::MenfuguInflateSoft,
        pump_ticks: 20,
        maximum_pump_ticks: 25,
        cooldown_slots: 3,
        execution_period_slots: 4,
        execution_offset_slots: 1,
        public_deadline_slots: 2,
    }
}

fn compiled() -> MenfuguCompiledQsm {
    let source = MenfuguPublicSourceArtifact::canonical();
    let policy = policy();
    let k7 = MenfuguK7Binding {
        public_policy_digest: policy.digest().expect("policy digest"),
        source_digest: source.digest,
        source_certificate_digest: menfugu_source_certificate_digest(CERTIFICATE),
        generated_runtime_digest: menfugu_generated_runtime_digest(RUNTIME),
        qsm_capsule_digest: quotient_seal_noticer::Digest::new([0; 32]),
        observer_registry_digest: menfugu_observer_registry_digest(),
    };
    compile_menfugu_p0(
        &source,
        policy,
        &k7,
        &MenfuguK7Artifacts::new(CERTIFICATE.to_vec(), RUNTIME.to_vec()),
        &[MenfuguServiceCode {
            service_alias: WIRE_ALIAS,
            qsm_alias: 23,
        }],
        MenfuguCompileLimits::default(),
    )
    .expect("Menfugu P0 compile")
}

fn seed() -> MenfuguAdversarialMatrixSeed {
    MenfuguAdversarialMatrixSeed::new([0x91; 32]).expect("matrix seed")
}

fn engine_digests() -> MenfuguEngineDigests {
    MenfuguEngineDigests::new("1".repeat(64), "2".repeat(64), "3".repeat(64))
        .expect("engine digests")
}

#[test]
fn canonical_matrix_is_byte_identical_complete_and_uniquely_bound() {
    let compiled = compiled();
    let first = MenfuguAdversarialMatrix::canonical(
        &compiled,
        seed(),
        MenfuguAdversarialMatrixLimits::default(),
    )
    .expect("first matrix");
    let second = MenfuguAdversarialMatrix::canonical(
        &compiled,
        seed(),
        MenfuguAdversarialMatrixLimits::default(),
    )
    .expect("second matrix");
    assert_eq!(first, second);
    assert_eq!(first.canonical_bytes(), second.canonical_bytes());
    assert_eq!(first.matrix_digest(), second.matrix_digest());
    assert_eq!(first.cases().len(), 26);
    assert_eq!(
        first
            .cases()
            .iter()
            .map(|case| case.case_id())
            .collect::<BTreeSet<_>>()
            .len(),
        26
    );
    first
        .validate_against(&compiled, MenfuguAdversarialMatrixLimits::default())
        .expect("matrix validation");
}

#[test]
fn execution_is_reproducible_and_separates_profile_and_resource_unresolved() {
    let compiled = compiled();
    let matrix = MenfuguAdversarialMatrix::canonical(
        &compiled,
        seed(),
        MenfuguAdversarialMatrixLimits::default(),
    )
    .expect("matrix");
    let first = evaluate_menfugu_adversarial_matrix(
        &compiled,
        &matrix,
        MenfuguAdversarialMatrixLimits::default(),
        &engine_digests(),
    )
    .expect("first execution");
    let second = evaluate_menfugu_adversarial_matrix(
        &compiled,
        &matrix,
        MenfuguAdversarialMatrixLimits::default(),
        &engine_digests(),
    )
    .expect("second execution");
    assert_eq!(first, second);
    assert_eq!(first.match_cases, 11);
    assert_eq!(first.counterexample_cases, 0);
    assert_eq!(first.unresolved_cases, 15);
    assert_eq!(
        first.canonical_json().expect("first JSON"),
        second.canonical_json().expect("second JSON")
    );
    verify_menfugu_adversarial_execution(
        &first,
        &compiled,
        &matrix,
        MenfuguAdversarialMatrixLimits::default(),
        &engine_digests(),
    )
    .expect("full recomputation");
}

#[test]
fn action_counts_cover_fallback_and_duplicate_are_typed() {
    let compiled = compiled();
    let matrix = MenfuguAdversarialMatrix::canonical(
        &compiled,
        seed(),
        MenfuguAdversarialMatrixLimits::default(),
    )
    .expect("matrix");
    let execution = evaluate_menfugu_adversarial_matrix(
        &compiled,
        &matrix,
        MenfuguAdversarialMatrixLimits::default(),
        &engine_digests(),
    )
    .expect("execution");
    let find = |profile: MenfuguProfileAxis, scenario: MenfuguScenarioAxis| {
        execution
            .cases
            .iter()
            .find(|case| {
                case.profile_axis == profile.name() && case.scenario_axis == scenario.name()
            })
            .expect("canonical case")
    };

    let valid = find(
        MenfuguProfileAxis::P0PublicQuotientOnly,
        MenfuguScenarioAxis::ValidAction,
    );
    assert_eq!(
        valid.classification,
        MenfuguActionClassification::ExactlyOnce
    );
    assert_eq!(valid.observed_action_count, Some(1));

    let cover = find(
        MenfuguProfileAxis::P0PublicQuotientOnly,
        MenfuguScenarioAxis::Cover,
    );
    assert_eq!(
        cover.classification,
        MenfuguActionClassification::ZeroActionCoverFallback
    );
    assert_eq!(cover.observed_action_count, Some(0));
    assert_eq!(cover.observed_frame_count, Some(1));

    for scenario in [
        MenfuguScenarioAxis::Replay,
        MenfuguScenarioAxis::Expiry,
        MenfuguScenarioAxis::WrongService,
        MenfuguScenarioAxis::WrongPolicy,
        MenfuguScenarioAxis::WrongKey,
    ] {
        let rejected = find(MenfuguProfileAxis::P0PublicQuotientOnly, scenario);
        assert_eq!(rejected.observed_action_count, Some(0));
        assert_eq!(rejected.observed_failure_count, Some(1));
    }

    let duplicate = find(
        MenfuguProfileAxis::P0PublicQuotientOnly,
        MenfuguScenarioAxis::Duplicate,
    );
    assert_eq!(
        duplicate.classification,
        MenfuguActionClassification::ExactlyOnceDuplicateRejected
    );
    assert_eq!(duplicate.observed_action_count, Some(1));
    assert_eq!(duplicate.observed_failure_count, Some(1));

    let p1 = find(
        MenfuguProfileAxis::P1SealedAdmission,
        MenfuguScenarioAxis::ValidAction,
    );
    assert_eq!(p1.outcome, MenfuguCaseOutcome::ProfileUnresolved);
    assert!(p1.differential.is_none());
    assert!(p1.observed_action_count.is_none());
}

#[test]
fn seed_limit_and_artifact_tamper_fail_closed() {
    assert_eq!(
        MenfuguAdversarialMatrixSeed::new([0; 32]),
        Err(MenfuguAdversarialMatrixError::ZeroSeed)
    );
    let compiled = compiled();
    let too_small = MenfuguAdversarialMatrixLimits {
        max_cases: 25,
        max_commands_per_case: 8,
    };
    assert_eq!(
        MenfuguAdversarialMatrix::canonical(&compiled, seed(), too_small),
        Err(MenfuguAdversarialMatrixError::InvalidLimits)
    );

    let matrix = MenfuguAdversarialMatrix::canonical(
        &compiled,
        seed(),
        MenfuguAdversarialMatrixLimits::default(),
    )
    .expect("matrix");
    let mut execution = evaluate_menfugu_adversarial_matrix(
        &compiled,
        &matrix,
        MenfuguAdversarialMatrixLimits::default(),
        &engine_digests(),
    )
    .expect("execution");
    execution.cases[0].observed_action_count = Some(9);
    assert_eq!(
        execution.validate(),
        Err(MenfuguAdversarialMatrixError::ActionCount)
    );
}

#[test]
fn frozen_contract_forbids_downgrade_private_fields_and_false_hardware_claims() {
    let config = include_str!("../../../configs/quotient_seal/menfugu_attack_matrix_v1.yaml");
    let docs = include_str!("../../../docs/quotient_seal_menfugu_attack_matrix_v1.md");
    assert!(config.contains("required_case_count: 26"));
    assert!(config.contains("p1_to_p0_implicit_downgrade: FORBIDDEN"));
    assert!(config.contains("resource_exhaustion_as_match: FORBIDDEN"));
    assert!(config.contains("private_token_material: FORBIDDEN"));
    assert!(config.contains("hardware_status: NOT_VERIFIED"));
    assert!(docs.contains("Issue #200"));
    assert!(docs.contains("world-first"));
    assert!(docs.contains("Polar Verity Sense"));
    assert!(docs.contains("NOT_VERIFIED"));
}
