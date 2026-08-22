use noticer_protocol::{KeyId, WireServiceAlias};
use noticer_types::{ActionCode, Epoch, PolicyHash};
use quotient_seal_context::{ContextCommand, ContextFamily};
use quotient_seal_engine::{
    ComparisonPoint, DifferentialOracle, DifferentialVerdict, ExecutionLimits,
    ExecutionTermination, HostOutcomeRecord, ObservableAxis, ObservableEvent, ScalarValue,
    TrapClass,
};
use quotient_seal_noticer::{
    build_menfugu_injected_fixture_artifact, compile_menfugu_p0, evaluate_menfugu_differential,
    evaluate_menfugu_differential_with_host_tape, menfugu_generated_runtime_digest,
    menfugu_observer_registry_digest, menfugu_source_certificate_digest, MenfuguCompileLimits,
    MenfuguCompiledQsm, MenfuguDifferentialEvidenceOrigin, MenfuguDifferentialVerdict,
    MenfuguEngineDigests, MenfuguK7Artifacts, MenfuguK7Binding, MenfuguPublicInput,
    MenfuguPublicPolicyBinding, MenfuguPublicSequence, MenfuguPublicSourceArtifact,
    MenfuguServiceCode,
};
use quotient_seal_small_step::{HostDirective, HostOutcome, PublicHostTape};

const WIRE_ALIAS: WireServiceAlias = WireServiceAlias([0x31; 8]);
const QSM_ALIAS: u32 = 23;
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
            qsm_alias: QSM_ALIAS,
        }],
        MenfuguCompileLimits::default(),
    )
    .expect("Menfugu P0 compile")
}

fn limits(max_host_calls: u64) -> ExecutionLimits {
    ExecutionLimits {
        fuel: 1_000_000,
        max_memory_pages: 2,
        max_host_calls,
        timeout_ms: 2_000,
    }
}

fn input_command(
    family: ContextFamily,
    input: MenfuguPublicInput,
    public_slot: u64,
) -> ContextCommand {
    ContextCommand {
        family,
        kind: family.command_kind(),
        service_alias: QSM_ALIAS,
        public_slot,
        fault: input as u8,
        payload_tag: 0,
    }
}

fn lifecycle_command(family: ContextFamily) -> ContextCommand {
    ContextCommand {
        family,
        kind: family.command_kind(),
        service_alias: 0,
        public_slot: 0,
        fault: 0,
        payload_tag: 0,
    }
}

fn commands() -> Vec<ContextCommand> {
    vec![
        input_command(ContextFamily::Tick, MenfuguPublicInput::Cover, 0),
        input_command(ContextFamily::Tick, MenfuguPublicInput::AuthorizedAction, 1),
        input_command(
            ContextFamily::CrossServiceReplay,
            MenfuguPublicInput::ReplayRejected,
            2,
        ),
        input_command(ContextFamily::Tick, MenfuguPublicInput::PumpStopped, 3),
        input_command(ContextFamily::Tick, MenfuguPublicInput::CooldownElapsed, 4),
        input_command(
            ContextFamily::ServiceCollusion,
            MenfuguPublicInput::WrongServiceRejected,
            5,
        ),
        lifecycle_command(ContextFamily::Reset),
        input_command(ContextFamily::Tick, MenfuguPublicInput::AuthorizedAction, 0),
        input_command(ContextFamily::Deadline, MenfuguPublicInput::Deadline, 1),
        lifecycle_command(ContextFamily::Handoff),
        input_command(ContextFamily::FaultTimeout, MenfuguPublicInput::Fault, 2),
        lifecycle_command(ContextFamily::Stop),
    ]
}

fn public_sequence(compiled: &MenfuguCompiledQsm, max_host_calls: u64) -> MenfuguPublicSequence {
    MenfuguPublicSequence::new(compiled, commands(), limits(max_host_calls), 32)
        .expect("Menfugu public sequence")
}

fn engine_digests() -> MenfuguEngineDigests {
    MenfuguEngineDigests::new("1".repeat(64), "2".repeat(64), "3".repeat(64))
        .expect("engine digests")
}

#[test]
fn actual_engines_match_source_and_artifact_is_byte_reproducible() {
    let compiled = compiled();
    let first_sequence = public_sequence(&compiled, 128);
    let second_sequence = public_sequence(&compiled, 128);
    assert_eq!(first_sequence, second_sequence);
    assert_eq!(first_sequence.digest(), second_sequence.digest());

    let first = evaluate_menfugu_differential(&compiled, &first_sequence, &engine_digests())
        .expect("first differential run");
    let second = evaluate_menfugu_differential(&compiled, &second_sequence, &engine_digests())
        .expect("second differential run");
    assert_eq!(first, second);
    assert_eq!(first.verdict, MenfuguDifferentialVerdict::Match);
    assert_eq!(
        first.source_refinement.verdict,
        MenfuguDifferentialVerdict::Match
    );
    assert_eq!(first.oracle.verdict, DifferentialVerdict::Match);
    assert_eq!(
        first.evidence_origin,
        MenfuguDifferentialEvidenceOrigin::ExecutedSoftware
    );
    assert!(first.injection_label.is_none());
    assert_eq!(first.source_transitions.len(), 56);
    assert_eq!(first.oracle.engines.len(), 2);
    assert_eq!(first.oracle.engines[0].input.engine.name, "wasmi");
    assert_eq!(first.oracle.engines[1].input.engine.name, "wasmtime");
    assert_eq!(
        first
            .oracle
            .reference
            .trace
            .iter()
            .filter(|event| matches!(event, ObservableEvent::EmitAction { .. }))
            .count(),
        2
    );
    assert_eq!(
        first.canonical_json().expect("first JSON"),
        second.canonical_json().expect("second JSON")
    );
    assert_eq!(
        first.artifact_sha256().expect("first digest"),
        second.artifact_sha256().expect("second digest")
    );
    first.validate().expect("differential artifact");
}

#[test]
fn target_only_action_extra_host_call_and_trap_are_typed_injected_fixtures() {
    let compiled = compiled();
    let sequence = public_sequence(&compiled, 128);
    let matched = evaluate_menfugu_differential(&compiled, &sequence, &engine_digests())
        .expect("matched differential");

    let mut target_only_engines = matched.oracle.engines.clone();
    let insertion = target_only_engines[1]
        .trace
        .iter()
        .position(|event| matches!(event, ObservableEvent::EmitFrame { .. }))
        .expect("frame event")
        + 1;
    target_only_engines[1].trace.insert(
        insertion,
        ObservableEvent::EmitAction {
            action: ActionCode::MenfuguInflateSoft as u32,
            slot: 0,
            return_code: 0,
        },
    );
    let oracle =
        DifferentialOracle::evaluate(matched.oracle.reference.clone(), target_only_engines)
            .expect("target-only oracle");
    let target_only =
        build_menfugu_injected_fixture_artifact(&matched, oracle, "TARGET_ONLY_ACTION")
            .expect("target-only fixture");
    assert_eq!(
        target_only.evidence_origin,
        MenfuguDifferentialEvidenceOrigin::InjectedTestFixture
    );
    assert_eq!(
        target_only.verdict,
        MenfuguDifferentialVerdict::Counterexample
    );
    assert!(target_only.oracle.counterexamples.iter().any(|difference| {
        matches!(
            difference.first_difference,
            ComparisonPoint::Trace {
                right_axis: Some(ObservableAxis::Output),
                ..
            }
        )
    }));

    let mut extra_host_engines = matched.oracle.engines.clone();
    extra_host_engines[0].trace.insert(
        1,
        ObservableEvent::HostImport {
            import: "qseal.emit_action".to_owned(),
            arguments: vec![
                ScalarValue::I32 {
                    bits: ActionCode::MenfuguInflateSoft as u32,
                },
                ScalarValue::I32 { bits: 0 },
            ],
            outcome: HostOutcomeRecord::Continue,
        },
    );
    let oracle = DifferentialOracle::evaluate(matched.oracle.reference.clone(), extra_host_engines)
        .expect("extra-host oracle");
    let extra_host = build_menfugu_injected_fixture_artifact(&matched, oracle, "EXTRA_HOST_CALL")
        .expect("extra-host fixture");
    assert!(extra_host.oracle.counterexamples.iter().any(|difference| {
        matches!(
            difference.first_difference,
            ComparisonPoint::Trace {
                right_axis: Some(ObservableAxis::HostImport),
                ..
            }
        )
    }));

    let mut trapped_engines = matched.oracle.engines.clone();
    trapped_engines[1].termination = ExecutionTermination::Trapped {
        class: TrapClass::Unreachable,
        engine_code: "INJECTED_TRAP".to_owned(),
        detail_sha256: "a".repeat(64),
    };
    let oracle = DifferentialOracle::evaluate(matched.oracle.reference.clone(), trapped_engines)
        .expect("trap oracle");
    let trapped = build_menfugu_injected_fixture_artifact(&matched, oracle, "TARGET_ONLY_TRAP")
        .expect("trap fixture");
    assert_eq!(trapped.verdict, MenfuguDifferentialVerdict::Counterexample);
    assert!(trapped.oracle.counterexamples.iter().any(|difference| {
        matches!(
            difference.first_difference,
            ComparisonPoint::Termination {
                right_axis: ObservableAxis::Trap,
                ..
            }
        )
    }));

    let json =
        String::from_utf8(target_only.canonical_json().expect("fixture JSON")).expect("UTF-8 JSON");
    assert!(json.contains("INJECTED_TEST_FIXTURE"));
    assert!(json.contains("TARGET_ONLY_ACTION"));
}

#[test]
fn resource_bound_is_unresolved_and_contract_tamper_fails_closed() {
    let compiled = compiled();
    let bounded = public_sequence(&compiled, 1);
    let unresolved = evaluate_menfugu_differential(&compiled, &bounded, &engine_digests())
        .expect("bounded differential");
    assert_eq!(unresolved.verdict, MenfuguDifferentialVerdict::Unresolved);
    assert_eq!(
        unresolved.source_refinement.verdict,
        MenfuguDifferentialVerdict::Unresolved
    );
    assert_ne!(unresolved.oracle.verdict, DifferentialVerdict::Match);
    unresolved.validate().expect("unresolved artifact");

    assert!(MenfuguEngineDigests::new("short", "2".repeat(64), "3".repeat(64)).is_err());
    let sequence = public_sequence(&compiled, 128);
    let wrong_tape = PublicHostTape::new(vec![HostDirective::new(
        "qseal.public_failure",
        HostOutcome::Continue,
    )]);
    assert!(evaluate_menfugu_differential_with_host_tape(
        &compiled,
        &sequence,
        &wrong_tape,
        &engine_digests(),
    )
    .is_err());

    let mut tampered = evaluate_menfugu_differential(&compiled, &sequence, &engine_digests())
        .expect("matched artifact");
    tampered.source_transitions[0].target_state ^= 1;
    assert!(tampered.validate().is_err());
}

#[test]
fn noncanonical_public_commands_fail_closed() {
    let compiled = compiled();
    let mut after_stop = commands();
    after_stop.push(input_command(
        ContextFamily::Tick,
        MenfuguPublicInput::Cover,
        3,
    ));
    assert!(MenfuguPublicSequence::new(&compiled, after_stop, limits(128), 32).is_err());

    let wrong_family = vec![input_command(
        ContextFamily::Tick,
        MenfuguPublicInput::WrongPolicyRejected,
        0,
    )];
    assert!(MenfuguPublicSequence::new(&compiled, wrong_family, limits(128), 32).is_err());

    let oversized_slot = vec![input_command(
        ContextFamily::Tick,
        MenfuguPublicInput::Cover,
        u64::from(u32::MAX) + 1,
    )];
    assert!(MenfuguPublicSequence::new(&compiled, oversized_slot, limits(128), 32).is_err());
}

#[test]
fn frozen_contract_labels_injection_and_unverified_boundaries() {
    let config = include_str!("../../../configs/quotient_seal/menfugu_differential_v1.yaml");
    let docs = include_str!("../../../docs/quotient_seal_menfugu_differential_v1.md");

    assert!(config.contains("target_only_action: COUNTEREXAMPLE"));
    assert!(config.contains("extra_host_call: COUNTEREXAMPLE"));
    assert!(config.contains("target_only_trap: COUNTEREXAMPLE"));
    assert!(config.contains("injected_mismatch_origin: INJECTED_TEST_FIXTURE"));
    assert!(config.contains("injected_mismatch_scientific_result: FORBIDDEN"));
    assert!(config.contains("resource_bound: UNRESOLVED"));
    assert!(config.contains("hardware_status: NOT_VERIFIED"));
    assert!(docs.contains("Issue #199"));
    assert!(docs.contains("world-first"));
    assert!(docs.contains("NOT_VERIFIED"));
}
