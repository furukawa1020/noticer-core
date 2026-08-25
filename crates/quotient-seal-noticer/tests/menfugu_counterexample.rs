use noticer_protocol::{KeyId, WireServiceAlias};
use noticer_types::{ActionCode, Epoch, PolicyHash};
use quotient_seal_noticer::{
    build_menfugu_counterexample_bundle, compile_menfugu_p0, menfugu_generated_runtime_digest,
    menfugu_observer_registry_digest, menfugu_source_certificate_digest,
    verify_menfugu_counterexample_bundle, MenfuguAdversarialMatrix, MenfuguAdversarialMatrixLimits,
    MenfuguAdversarialMatrixSeed, MenfuguCompileLimits, MenfuguCompiledQsm,
    MenfuguCounterexampleError, MenfuguDifferenceOrigin, MenfuguEngineDigests, MenfuguInjection,
    MenfuguK7Artifacts, MenfuguK7Binding, MenfuguProfileAxis, MenfuguPublicPolicyBinding,
    MenfuguPublicSourceArtifact, MenfuguScenarioAxis, MenfuguServiceCode, MenfuguShrinkOutcome,
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

fn matrix(compiled: &MenfuguCompiledQsm) -> MenfuguAdversarialMatrix {
    MenfuguAdversarialMatrix::canonical(
        compiled,
        MenfuguAdversarialMatrixSeed::new([0x91; 32]).expect("seed"),
        MenfuguAdversarialMatrixLimits::default(),
    )
    .expect("matrix")
}

fn cover_case_id(matrix: &MenfuguAdversarialMatrix) -> String {
    let case = matrix
        .cases()
        .iter()
        .find(|case| {
            case.profile() == MenfuguProfileAxis::P0PublicQuotientOnly
                && case.scenario() == MenfuguScenarioAxis::Cover
        })
        .expect("P0 cover case");
    case.case_id()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn engines() -> MenfuguEngineDigests {
    MenfuguEngineDigests::new("1".repeat(64), "2".repeat(64), "3".repeat(64))
        .expect("engine digests")
}

fn target_action() -> MenfuguInjection {
    MenfuguInjection::TargetOnlyAction {
        engine_index: 1,
        action: ActionCode::MenfuguInflateSoft as u32,
        slot: 0,
    }
}

#[test]
fn target_only_action_bundle_is_minimized_and_byte_reproducible() {
    let compiled = compiled();
    let matrix = matrix(&compiled);
    let case_id = cover_case_id(&matrix);
    let first = build_menfugu_counterexample_bundle(
        &compiled,
        &matrix,
        &case_id,
        target_action(),
        &engines(),
    )
    .expect("first bundle");
    let second = build_menfugu_counterexample_bundle(
        &compiled,
        &matrix,
        &case_id,
        target_action(),
        &engines(),
    )
    .expect("second bundle");
    assert_eq!(first, second);
    assert_eq!(first.original.input.commands.len(), 2);
    assert_eq!(first.minimized.input.commands.len(), 1);
    assert_eq!(
        first.first_typed_difference.origin,
        MenfuguDifferenceOrigin::TargetOnlyAction
    );
    assert_eq!(
        first.shrink_attempts[0].outcome,
        MenfuguShrinkOutcome::AcceptedSameTypedDifference
    );
    assert_eq!(
        first.shrink_attempts[1].outcome,
        MenfuguShrinkOutcome::RejectedEvaluationError
    );
    assert_eq!(
        first.canonical_json().expect("first JSON"),
        second.canonical_json().expect("second JSON")
    );
    assert_eq!(
        first.artifact_sha256().expect("first digest"),
        second.artifact_sha256().expect("second digest")
    );
    verify_menfugu_counterexample_bundle(&first, &compiled, &matrix, &engines())
        .expect("full bundle recomputation");
}

#[test]
fn extra_host_call_and_trap_have_distinct_typed_differences() {
    let compiled = compiled();
    let matrix = matrix(&compiled);
    let case_id = cover_case_id(&matrix);
    let extra_host = build_menfugu_counterexample_bundle(
        &compiled,
        &matrix,
        &case_id,
        MenfuguInjection::ExtraHostCall {
            engine_index: 0,
            action: ActionCode::MenfuguInflateSoft as u32,
            slot: 0,
        },
        &engines(),
    )
    .expect("extra host bundle");
    assert_eq!(
        extra_host.first_typed_difference.origin,
        MenfuguDifferenceOrigin::ExtraHostCall
    );

    let trap = build_menfugu_counterexample_bundle(
        &compiled,
        &matrix,
        &case_id,
        MenfuguInjection::TargetOnlyTrap { engine_index: 1 },
        &engines(),
    )
    .expect("trap bundle");
    assert_eq!(
        trap.first_typed_difference.origin,
        MenfuguDifferenceOrigin::TargetOnlyTrap
    );
    assert_ne!(
        extra_host.first_typed_difference,
        trap.first_typed_difference
    );
}

#[test]
fn tamper_wrong_case_and_invalid_injection_fail_closed() {
    let compiled = compiled();
    let matrix = matrix(&compiled);
    let case_id = cover_case_id(&matrix);
    let mut bundle = build_menfugu_counterexample_bundle(
        &compiled,
        &matrix,
        &case_id,
        target_action(),
        &engines(),
    )
    .expect("bundle");
    bundle.minimized.result_sha256.replace_range(0..1, "0");
    assert_eq!(
        bundle.validate(),
        Err(MenfuguCounterexampleError::ArtifactContract)
    );

    assert_eq!(
        build_menfugu_counterexample_bundle(
            &compiled,
            &matrix,
            &"0".repeat(64),
            target_action(),
            &engines(),
        ),
        Err(MenfuguCounterexampleError::CaseNotFound)
    );
    assert_eq!(
        build_menfugu_counterexample_bundle(
            &compiled,
            &matrix,
            &case_id,
            MenfuguInjection::TargetOnlyTrap { engine_index: 2 },
            &engines(),
        ),
        Err(MenfuguCounterexampleError::InjectionTarget)
    );
}

#[test]
fn bundle_contains_no_private_material_and_labels_injection() {
    let compiled = compiled();
    let matrix = matrix(&compiled);
    let bundle = build_menfugu_counterexample_bundle(
        &compiled,
        &matrix,
        &cover_case_id(&matrix),
        target_action(),
        &engines(),
    )
    .expect("bundle");
    let json = String::from_utf8(bundle.canonical_json().expect("JSON")).expect("UTF-8");
    assert!(json.contains("INJECTED_TEST_FIXTURE"));
    assert!(json.contains("TARGET_ONLY_ACTION_TEST_INSTRUMENTATION"));
    assert!(json.contains("NOT_VERIFIED"));
    for forbidden in [
        "token_id",
        "replay_set",
        "raw_ppg",
        "biosignal",
        "private_baseline",
        "private_evidence",
    ] {
        assert!(!json.contains(forbidden));
    }
}

#[test]
fn frozen_contract_forbids_false_scientific_and_hardware_claims() {
    let config = include_str!("../../../configs/quotient_seal/menfugu_counterexample_v1.yaml");
    let docs = include_str!("../../../docs/quotient_seal_menfugu_counterexample_v1.md");
    assert!(config.contains("shrink_order: DETERMINISTIC"));
    assert!(config.contains("full_bundle_recomputation: REQUIRED"));
    assert!(config.contains("injected_mismatch_origin: INJECTED_TEST_FIXTURE"));
    assert!(config.contains("injected_mismatch_scientific_result: FORBIDDEN"));
    assert!(config.contains("hardware_status: NOT_VERIFIED"));
    assert!(docs.contains("Issue #201"));
    assert!(docs.contains("world-first"));
    assert!(docs.contains("Polar Verity Sense"));
    assert!(docs.contains("NOT_VERIFIED"));
}
