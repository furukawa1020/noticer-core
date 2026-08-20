use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use noticer_transport_sim::PublicLossTape;
use quotient_forge_caqt::{
    Certificate, CertificateLimits, CostVector, DomainHashes, ExpectedContract, ObserverRecord,
    OutputRecord, RelationPair, TransitionRecord, FORMAT_VERSION,
};
use quotient_forge_codegen::{generate_package, CodegenConfig};
use quotient_seal_context::{ContextCommand, ContextFamily};
use quotient_seal_engine::{
    ComparisonPoint, DifferentialOracle, DifferentialVerdict, ExecutionLimits, ObservableAxis,
    ObservableEvent,
};
use quotient_seal_noticer::{
    compile_aplot_p0, evaluate_aplot_differential, evaluate_aplot_differential_with_host_tape,
    verify_aplot_k7, AplotCompileLimits, AplotCompiledQsm, AplotDifferentialArtifact,
    AplotDifferentialVerdict, AplotEngineDigests, AplotExpectedEventKind, AplotFrameInput,
    AplotPublicEventKind, AplotPublicSequence, AplotPublicSourceArtifact, AplotServiceCode, Epoch,
    PolicyHash, WireServiceAlias,
};
use quotient_seal_small_step::{HostDirective, HostOutcome, PublicHostTape};

const SERVICE_ALIAS: WireServiceAlias = WireServiceAlias([0x31; 8]);
const POLICY_HASH: PolicyHash = PolicyHash([0x41; 32]);
const EPOCH: Epoch = Epoch(9);
const QSM_ALIAS: u32 = 17;
static TEMPORARY_DIRECTORY_ID: AtomicU64 = AtomicU64::new(0);

fn frame(public_bucket: u32, sequence: u32, start_tick: u64, dropped: &[u8]) -> AplotFrameInput {
    AplotFrameInput {
        public_bucket,
        sequence,
        start_tick,
        fragment_cadence_ticks: 2,
        deadline_tick: start_tick + 50,
        loss_tape: PublicLossTape::from_indices(dropped).expect("public loss tape"),
        reconnect_ticks: vec![start_tick + 7, start_tick + 21],
    }
}

fn source() -> AplotPublicSourceArtifact {
    AplotPublicSourceArtifact::new(
        SERVICE_ALIAS,
        EPOCH,
        POLICY_HASH,
        8,
        200,
        vec![frame(2, 1, 100, &[1, 7]), frame(1, 4, 200, &[0, 19])],
    )
    .expect("APLOT public source")
}

fn caqt_certificate() -> (Vec<u8>, ExpectedContract) {
    let action = 7;
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
                payload: b"fixed-aplot-event".to_vec(),
                actions: vec![action],
            },
            OutputRecord {
                id: 1,
                emitted: true,
                payload: b"fixed-aplot-event".to_vec(),
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

fn compiled() -> AplotCompiledQsm {
    let source = source();
    let (certificate, expected) = caqt_certificate();
    let target = TemporaryDirectory::new("aplot-differential");
    generate_package(
        &certificate,
        expected,
        CertificateLimits::default(),
        &CodegenConfig {
            package_name: "generated-aplot-differential-source".to_owned(),
            quotient_inputs: 1,
            public_inputs: 1,
            fault_inputs: 1,
            max_payload_bytes: 64,
            max_actions: 8,
        },
        target.path(),
    )
    .expect("K7 package");
    let runtime = fs::read(target.path().join("codegen-manifest.toml")).expect("codegen manifest");
    let k7 = verify_aplot_k7(
        &source,
        &certificate,
        expected,
        CertificateLimits::default(),
        &runtime,
    )
    .expect("APLOT K7 binding");
    compile_aplot_p0(
        &source,
        &k7,
        &[AplotServiceCode {
            service_alias: SERVICE_ALIAS,
            qsm_alias: QSM_ALIAS,
        }],
        AplotCompileLimits::default(),
    )
    .expect("APLOT P0 compile")
}

fn command(family: ContextFamily, service_alias: u32, public_slot: u64) -> ContextCommand {
    ContextCommand {
        family,
        kind: family.command_kind(),
        service_alias,
        public_slot,
        fault: 0,
        payload_tag: 0,
    }
}

fn commands(compiled: &AplotCompiledQsm) -> Vec<ContextCommand> {
    let mut commands = compiled
        .events()
        .iter()
        .map(|event| {
            let family = if event.kind == AplotPublicEventKind::Deadline {
                ContextFamily::Deadline
            } else {
                ContextFamily::Tick
            };
            command(family, event.qsm_alias, event.public_step)
        })
        .collect::<Vec<_>>();
    commands.push(command(ContextFamily::Handoff, 0, 0));
    commands.push(command(ContextFamily::Reset, 0, 0));
    commands.push(command(ContextFamily::Stop, 0, 0));
    commands
}

fn limits(max_host_calls: u64) -> ExecutionLimits {
    ExecutionLimits {
        fuel: 5_000_000,
        max_memory_pages: 2,
        max_host_calls,
        timeout_ms: 5_000,
    }
}

fn public_sequence(compiled: &AplotCompiledQsm, max_host_calls: u64) -> AplotPublicSequence {
    let commands = commands(compiled);
    AplotPublicSequence::new(
        compiled,
        commands.clone(),
        limits(max_host_calls),
        commands.len(),
    )
    .expect("APLOT public sequence")
}

fn engine_digests() -> AplotEngineDigests {
    AplotEngineDigests::new("1".repeat(64), "2".repeat(64), "3".repeat(64)).expect("engine digests")
}

#[test]
fn source_small_step_wasmi_and_wasmtime_match_byte_identically() {
    let compiled = compiled();
    let sequence = public_sequence(&compiled, 128);
    let first = evaluate_aplot_differential(&compiled, &sequence, &engine_digests())
        .expect("first APLOT differential");
    let second = evaluate_aplot_differential(&compiled, &sequence, &engine_digests())
        .expect("second APLOT differential");

    assert_eq!(first.verdict, AplotDifferentialVerdict::Match, "{first:#?}");
    assert_eq!(first.oracle.verdict, DifferentialVerdict::Match);
    assert_eq!(
        first.source_refinement.verdict,
        AplotDifferentialVerdict::Match
    );
    assert_eq!(first.source_events.len(), compiled.events().len());
    assert_eq!(
        first.oracle.reference.input.engine.name,
        "quotient-seal-small-step"
    );
    assert_eq!(first.oracle.engines[0].input.engine.name, "wasmi");
    assert_eq!(first.oracle.engines[1].input.engine.name, "wasmtime");
    assert_eq!(first.hardware_status, "NOT_VERIFIED");
    assert_eq!(
        first.canonical_json().expect("first canonical JSON"),
        second.canonical_json().expect("second canonical JSON")
    );
    assert_eq!(
        first.artifact_sha256().expect("first artifact digest"),
        second.artifact_sha256().expect("second artifact digest")
    );

    assert_eq!(
        first
            .source_events
            .iter()
            .filter(|event| event.kind == AplotExpectedEventKind::FragmentAttempt)
            .count(),
        40
    );
    assert_eq!(
        first
            .source_events
            .iter()
            .filter(|event| event.kind == AplotExpectedEventKind::Reconnect)
            .count(),
        4
    );
    assert_eq!(
        first
            .source_events
            .iter()
            .filter(|event| event.kind == AplotExpectedEventKind::Deadline)
            .count(),
        2
    );
    assert!(first
        .source_events
        .iter()
        .all(|event| event.qsm_alias == QSM_ALIAS));
}

#[test]
fn typed_counterexample_unresolved_and_input_tamper_remain_distinct() {
    let compiled = compiled();
    let sequence = public_sequence(&compiled, 128);
    let matched = evaluate_aplot_differential(&compiled, &sequence, &engine_digests())
        .expect("matched APLOT differential");

    let mut engines = matched.oracle.engines.clone();
    let ObservableEvent::ApiCall { export, .. } = &mut engines[1].trace[0] else {
        panic!("first Wasmtime event must be an API call");
    };
    *export = "qseal.public.counterexample".to_owned();
    let counterexample_oracle =
        DifferentialOracle::evaluate(matched.oracle.reference.clone(), engines)
            .expect("typed counterexample oracle");
    assert_eq!(
        counterexample_oracle.verdict,
        DifferentialVerdict::Counterexample
    );
    assert!(counterexample_oracle
        .counterexamples
        .iter()
        .any(|counterexample| {
            matches!(
                counterexample.first_difference,
                ComparisonPoint::Trace {
                    index: 0,
                    left_axis: Some(ObservableAxis::Return),
                    right_axis: Some(ObservableAxis::Return),
                    ..
                }
            )
        }));
    let counterexample = AplotDifferentialArtifact {
        verdict: AplotDifferentialVerdict::Counterexample,
        oracle: counterexample_oracle,
        ..matched.clone()
    };
    counterexample
        .validate()
        .expect("counterexample artifact contract");

    let bounded = public_sequence(&compiled, 1);
    let unresolved = evaluate_aplot_differential(&compiled, &bounded, &engine_digests())
        .expect("bounded differential");
    assert_eq!(unresolved.verdict, AplotDifferentialVerdict::Unresolved);
    assert!(unresolved.source_reference.is_none());
    assert_ne!(unresolved.oracle.verdict, DifferentialVerdict::Match);
    unresolved.validate().expect("unresolved artifact contract");

    let mut digest_tamper = matched.clone();
    digest_tamper.oracle.engines[0]
        .input
        .engine
        .executable_sha256 = "4".repeat(64);
    assert!(digest_tamper.validate().is_err());

    let wrong_tape = PublicHostTape::new(vec![HostDirective::new(
        "qseal.public_failure",
        HostOutcome::Continue,
    )]);
    assert!(evaluate_aplot_differential_with_host_tape(
        &compiled,
        &sequence,
        &wrong_tape,
        &engine_digests(),
    )
    .is_err());
}

#[test]
fn retry_command_and_invalid_engine_digest_fail_closed() {
    let compiled = compiled();
    let retry = command(ContextFamily::Retry, QSM_ALIAS, 0);
    assert!(AplotPublicSequence::new(&compiled, vec![retry], limits(8), 1).is_err());
    assert!(AplotEngineDigests::new("short", "2".repeat(64), "3".repeat(64)).is_err());
}

#[test]
fn frozen_contract_keeps_adversarial_radio_and_hardware_unverified() {
    let config = include_str!("../../../configs/quotient_seal/aplot_differential_v1.yaml");
    let docs = include_str!("../../../docs/quotient_seal_aplot_differential_v1.md");

    assert!(config.contains("retry_command_family: REJECT"));
    assert!(config.contains("host_injected_reconnect: DISTINCT_FROM_SOURCE_RECONNECT"));
    assert!(config.contains("first_typed_difference: REQUIRED_ON_COUNTEREXAMPLE"));
    assert!(config.contains("resource_bound: UNRESOLVED"));
    assert!(config.contains("hardware_status: NOT_VERIFIED"));
    assert!(docs.contains("Issue #180"));
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
