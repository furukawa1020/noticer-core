use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use noticer_aetp::PairwiseServiceAlias;
use noticer_protocol::WireServiceAlias;
use noticer_provenance::{AssuranceProfile, AssuranceProfileDigest, PipelineMeasurementHash};
use noticer_provenance_lease::LeaseVerifierKeyId;
use noticer_types::{ActionCode, Epoch, PolicyHash};
use quotient_forge_caqt::{
    Certificate, CertificateLimits, CostVector, DomainHashes, ExpectedContract, ObserverRecord,
    OutputRecord, RelationPair, TransitionRecord, FORMAT_VERSION,
};
use quotient_forge_codegen::{generate_package, CodegenConfig};
use quotient_seal_context::{ContextCommand, ContextFamily};
use quotient_seal_engine::{
    ComparisonPoint, DifferentialOracle, DifferentialVerdict, ExecutionLimits, HostOutcomeRecord,
    ObservableAxis, ObservableEvent, ScalarValue,
};
use quotient_seal_noticer::{
    build_aepa_injected_fixture_artifact, compile_aepa_p0, evaluate_aepa_differential,
    evaluate_aepa_differential_with_host_tape, verify_aepa_k7, AepaCompileLimits, AepaCompiledQsm,
    AepaDifferentialEvidenceOrigin, AepaDifferentialVerdict, AepaEngineDigests, AepaK7Binding,
    AepaPublicInput, AepaPublicPolicyBinding, AepaPublicSequence, AepaPublicSourceArtifact,
    AepaServiceCode,
};
use quotient_seal_small_step::{HostDirective, HostOutcome, PublicHostTape};

const WIRE_ALIAS: WireServiceAlias = WireServiceAlias([0x21; 8]);
const PAIRWISE_ALIAS: PairwiseServiceAlias = PairwiseServiceAlias([0x31; 32]);
const POLICY: PolicyHash = PolicyHash([0x41; 32]);
const PIPELINE: PipelineMeasurementHash = PipelineMeasurementHash([0x51; 32]);
const LEASE_KEY: LeaseVerifierKeyId = LeaseVerifierKeyId([0x61; 8]);
const ATV2_KEY: [u8; 8] = [0x71; 8];
const EPOCH: Epoch = Epoch(9);
const QSM_ALIAS: u32 = 17;
static TEMPORARY_DIRECTORY_ID: AtomicU64 = AtomicU64::new(0);

fn assurance() -> AssuranceProfileDigest {
    AssuranceProfile::lab_reference().digest()
}

fn fixture_source() -> AepaPublicSourceArtifact {
    let binding = AepaPublicPolicyBinding::new(
        WIRE_ALIAS,
        PAIRWISE_ALIAS,
        EPOCH,
        POLICY,
        LEASE_KEY,
        PIPELINE,
        assurance(),
        ATV2_KEY,
        100,
        104,
    )
    .expect("AEPA public policy binding");
    AepaPublicSourceArtifact::new(binding).expect("AEPA public source")
}

fn action_code() -> u32 {
    u32::from(ActionCode::RenderAmbientPulse as u16)
}

fn caqt_certificate() -> (Vec<u8>, ExpectedContract) {
    let action = action_code();
    let mut certificate = Certificate {
        version: FORMAT_VERSION,
        hashes: DomainHashes::zero(),
        state_count: 2,
        input_count: 1,
        observer_count: 1,
        state_bound: 2,
        claimed_cost: CostVector::default(),
        observers: vec![ObserverRecord {
            id: 0,
            sees_presence: true,
            sees_payload: true,
            sees_actions: true,
        }],
        outputs: vec![
            OutputRecord {
                id: 0,
                emitted: true,
                payload: b"aepa-differential".to_vec(),
                actions: vec![action],
            },
            OutputRecord {
                id: 1,
                emitted: true,
                payload: b"aepa-differential".to_vec(),
                actions: vec![action],
            },
        ],
        transitions: vec![
            TransitionRecord {
                from: 0,
                input: 0,
                to: 1,
                output: 0,
                authorized_actions: vec![action],
                required_action: Some(action),
                recoverable_fault_action: None,
            },
            TransitionRecord {
                from: 1,
                input: 0,
                to: 1,
                output: 1,
                authorized_actions: vec![action],
                required_action: Some(action),
                recoverable_fault_action: None,
            },
        ],
        relation: vec![RelationPair { left: 0, right: 1 }],
    };
    certificate.seal();
    let expected = ExpectedContract {
        version: FORMAT_VERSION,
        hashes: certificate.hashes,
        state_bound: certificate.state_bound,
        max_cost: certificate.claimed_cost,
    };
    (certificate.encode(), expected)
}

fn fixture_k7(source: &AepaPublicSourceArtifact) -> AepaK7Binding {
    let (certificate, expected) = caqt_certificate();
    let target = TemporaryDirectory::new("aepa-differential");
    generate_package(
        &certificate,
        expected,
        CertificateLimits::default(),
        &CodegenConfig {
            package_name: "generated-aepa-differential".to_owned(),
            quotient_inputs: 1,
            public_inputs: 1,
            fault_inputs: 1,
            max_payload_bytes: 64,
            max_actions: 8,
        },
        target.path(),
    )
    .expect("K7 generated package");
    let runtime =
        fs::read(target.path().join("codegen-manifest.toml")).expect("runtime manifest");
    verify_aepa_k7(
        source,
        &certificate,
        expected,
        CertificateLimits::default(),
        &runtime,
    )
    .expect("AEPA K7 binding")
}

fn compiled() -> AepaCompiledQsm {
    let source = fixture_source();
    let k7 = fixture_k7(&source);
    compile_aepa_p0(
        &source,
        &k7,
        &[AepaServiceCode {
            service_alias: WIRE_ALIAS,
            qsm_alias: QSM_ALIAS,
        }],
        AepaCompileLimits::default(),
    )
    .expect("AEPA P0 compile")
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
    input: AepaPublicInput,
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
        input_command(ContextFamily::Tick, AepaPublicInput::PublicTick, 0),
        input_command(
            ContextFamily::Tick,
            AepaPublicInput::ValidatedAdmission,
            1,
        ),
        input_command(ContextFamily::Tick, AepaPublicInput::PublicTick, 2),
        input_command(
            ContextFamily::CrossServiceReplay,
            AepaPublicInput::Replay,
            3,
        ),
        lifecycle_command(ContextFamily::Reset),
        input_command(
            ContextFamily::Tick,
            AepaPublicInput::ValidatedAdmission,
            0,
        ),
        input_command(ContextFamily::Deadline, AepaPublicInput::Expired, 1),
        lifecycle_command(ContextFamily::Handoff),
        input_command(ContextFamily::FaultTimeout, AepaPublicInput::Fault, 2),
        lifecycle_command(ContextFamily::Stop),
    ]
}

fn public_sequence(
    compiled: &AepaCompiledQsm,
    max_host_calls: u64,
) -> AepaPublicSequence {
    AepaPublicSequence::new(compiled, commands(), limits(max_host_calls), 32)
        .expect("AEPA public sequence")
}

fn engine_digests() -> AepaEngineDigests {
    AepaEngineDigests::new("1".repeat(64), "2".repeat(64), "3".repeat(64))
        .expect("engine digests")
}

#[test]
fn actual_three_engines_match_source_and_are_byte_reproducible() {
    let compiled = compiled();
    let first_sequence = public_sequence(&compiled, 128);
    let second_sequence = public_sequence(&compiled, 128);
    assert_eq!(first_sequence, second_sequence);
    assert_eq!(first_sequence.digest(), second_sequence.digest());

    let first = evaluate_aepa_differential(&compiled, &first_sequence, &engine_digests())
        .expect("first AEPA differential");
    let second = evaluate_aepa_differential(&compiled, &second_sequence, &engine_digests())
        .expect("second AEPA differential");
    assert_eq!(first, second);
    assert_eq!(first.verdict, AepaDifferentialVerdict::Match);
    assert_eq!(
        first.source_refinement.verdict,
        AepaDifferentialVerdict::Match
    );
    assert_eq!(first.oracle.verdict, DifferentialVerdict::Match);
    assert_eq!(
        first.evidence_origin,
        AepaDifferentialEvidenceOrigin::ExecutedSoftware
    );
    assert!(first.injection_label.is_none());
    assert_eq!(first.source_transitions.len(), 36);
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
    assert_eq!(first.canonical_json().unwrap(), second.canonical_json().unwrap());
    assert_eq!(
        first.artifact_sha256().unwrap(),
        second.artifact_sha256().unwrap()
    );
    first.validate().expect("AEPA differential artifact");
}

#[test]
fn target_only_admission_and_extra_host_call_are_typed_injected_counterexamples() {
    let compiled = compiled();
    let sequence = public_sequence(&compiled, 128);
    let matched = evaluate_aepa_differential(&compiled, &sequence, &engine_digests())
        .expect("matched AEPA differential");

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
            action: action_code(),
            slot: 0,
            return_code: 0,
        },
    );
    let target_only_oracle =
        DifferentialOracle::evaluate(matched.oracle.reference.clone(), target_only_engines)
            .expect("target-only oracle");
    assert_eq!(
        target_only_oracle.verdict,
        DifferentialVerdict::Counterexample
    );
    let target_only = build_aepa_injected_fixture_artifact(
        &matched,
        target_only_oracle,
        "TARGET_ONLY_ADMISSION",
    )
    .expect("target-only fixture artifact");
    assert_eq!(
        target_only.evidence_origin,
        AepaDifferentialEvidenceOrigin::InjectedTestFixture
    );
    assert_eq!(
        target_only.verdict,
        AepaDifferentialVerdict::Counterexample
    );
    assert!(target_only
        .oracle
        .counterexamples
        .iter()
        .any(|counterexample| matches!(
            counterexample.first_difference,
            ComparisonPoint::Trace {
                left_axis: Some(ObservableAxis::Return),
                right_axis: Some(ObservableAxis::Output),
                ..
            }
        )));
    let json = String::from_utf8(target_only.canonical_json().unwrap()).unwrap();
    assert!(json.contains("INJECTED_TEST_FIXTURE"));
    assert!(json.contains("TARGET_ONLY_ADMISSION"));

    let mut extra_host_engines = matched.oracle.engines.clone();
    extra_host_engines[0].trace.insert(
        1,
        ObservableEvent::HostImport {
            import: "qseal.emit_action".to_owned(),
            arguments: vec![
                ScalarValue::I32 {
                    bits: action_code(),
                },
                ScalarValue::I32 { bits: 0 },
            ],
            outcome: HostOutcomeRecord::Continue,
        },
    );
    let extra_host_oracle =
        DifferentialOracle::evaluate(matched.oracle.reference.clone(), extra_host_engines)
            .expect("extra-host oracle");
    let extra_host = build_aepa_injected_fixture_artifact(
        &matched,
        extra_host_oracle,
        "EXTRA_HOST_CALL",
    )
    .expect("extra-host fixture artifact");
    assert_eq!(
        extra_host.verdict,
        AepaDifferentialVerdict::Counterexample
    );
    assert!(extra_host
        .oracle
        .counterexamples
        .iter()
        .any(|counterexample| matches!(
            counterexample.first_difference,
            ComparisonPoint::Trace {
                right_axis: Some(ObservableAxis::HostImport),
                ..
            }
        )));
}

#[test]
fn resource_unresolved_digest_tamper_and_host_shape_remain_distinct() {
    let compiled = compiled();
    let bounded = public_sequence(&compiled, 1);
    let unresolved = evaluate_aepa_differential(&compiled, &bounded, &engine_digests())
        .expect("bounded AEPA differential");
    assert_eq!(unresolved.verdict, AepaDifferentialVerdict::Unresolved);
    assert_eq!(
        unresolved.source_refinement.verdict,
        AepaDifferentialVerdict::Unresolved
    );
    assert_ne!(unresolved.oracle.verdict, DifferentialVerdict::Match);
    unresolved.validate().expect("unresolved artifact");

    assert!(AepaEngineDigests::new("short", "2".repeat(64), "3".repeat(64)).is_err());

    let sequence = public_sequence(&compiled, 128);
    let wrong_tape = PublicHostTape::new(vec![HostDirective::new(
        "qseal.public_failure",
        HostOutcome::Continue,
    )]);
    assert!(evaluate_aepa_differential_with_host_tape(
        &compiled,
        &sequence,
        &wrong_tape,
        &engine_digests(),
    )
    .is_err());

    let mut tampered = evaluate_aepa_differential(&compiled, &sequence, &engine_digests())
        .expect("matched artifact");
    tampered.source_transitions[0].target_state ^= 1;
    assert!(tampered.validate().is_err());

    let mut origin_tamper = evaluate_aepa_differential(&compiled, &sequence, &engine_digests())
        .expect("matched artifact");
    origin_tamper.evidence_origin = AepaDifferentialEvidenceOrigin::InjectedTestFixture;
    assert!(origin_tamper.validate().is_err());
    assert!(build_aepa_injected_fixture_artifact(
        &origin_tamper,
        origin_tamper.oracle.clone(),
        "lowercase-label",
    )
    .is_err());
}

#[test]
fn noncanonical_public_commands_fail_closed() {
    let compiled = compiled();
    let mut after_stop = commands();
    after_stop.push(input_command(
        ContextFamily::Tick,
        AepaPublicInput::PublicTick,
        3,
    ));
    assert!(AepaPublicSequence::new(&compiled, after_stop, limits(128), 32).is_err());

    let wrong_family = vec![input_command(
        ContextFamily::Tick,
        AepaPublicInput::WrongBinding,
        0,
    )];
    assert!(AepaPublicSequence::new(&compiled, wrong_family, limits(128), 32).is_err());

    let oversized_slot = vec![input_command(
        ContextFamily::Tick,
        AepaPublicInput::PublicTick,
        u64::from(u32::MAX) + 1,
    )];
    assert!(AepaPublicSequence::new(&compiled, oversized_slot, limits(128), 32).is_err());
}

#[test]
fn frozen_contract_labels_injection_and_keeps_p1_hardware_unverified() {
    let config = include_str!("../../../configs/quotient_seal/aepa_differential_v1.yaml");
    let docs = include_str!("../../../docs/quotient_seal_aepa_differential_v1.md");

    assert!(config.contains("target_only_admission: COUNTEREXAMPLE"));
    assert!(config.contains("extra_host_call: COUNTEREXAMPLE"));
    assert!(config.contains("injected_mismatch_origin: INJECTED_TEST_FIXTURE"));
    assert!(config.contains("injected_mismatch_scientific_result: FORBIDDEN"));
    assert!(config.contains("resource_bound: UNRESOLVED"));
    assert!(config.contains("hardware_status: NOT_VERIFIED"));
    assert!(docs.contains("Issue #191"));
    assert!(docs.contains("Issue #190"));
    assert!(docs.contains("Issue #189"));
    assert!(docs.contains("world-first"));
    assert!(docs.contains("NOT_VERIFIED"));
}

struct TemporaryDirectory(PathBuf);

impl TemporaryDirectory {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let id = TEMPORARY_DIRECTORY_ID.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "quotient-seal-{label}-{}-{nonce}-{id}",
            std::process::id()
        )))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
