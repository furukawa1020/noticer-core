use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use noticer_aetp::{
    ActionObligation, ActionSemantics, BucketId, ChannelSchedule, PublicContext, PublicNetworkTape,
    ScheduleRandomTape, ServiceBinding,
};
use noticer_protocol::WireServiceAlias;
use noticer_types::{ActionCode, LogicalSlot, PolicyHash};
use quotient_forge_caqt::{
    Certificate, CertificateLimits, CostVector, DomainHashes, ExpectedContract, ObserverRecord,
    OutputRecord, RelationPair, TransitionRecord, FORMAT_VERSION,
};
use quotient_forge_codegen::{generate_package, CodegenConfig};
use quotient_seal_context::{CommandKind, ContextCommand, ContextFamily};
use quotient_seal_engine::{
    ExecutionLimits, ExecutionTermination, ObservableEvent, ENGINE_ADAPTER_CONTRACT_VERSION,
};
use quotient_seal_noticer::{
    compile_aets_p0, evaluate_aets_source_reference, verify_aets_k7, AetsCompileLimits,
    AetsCompiledQsm, AetsPublicSequence, AetsPublicSourceArtifact, AetsReferenceError,
    AetsReferenceUnresolved, AetsReferenceVerdict, AetsServiceCode, AETS_SOURCE_REFERENCE_VERSION,
};

const SERVICE: ServiceBinding = ServiceBinding([0x11; 16]);
const SERVICE_ALIAS: WireServiceAlias = WireServiceAlias([0x31; 8]);
const POLICY_HASH: PolicyHash = PolicyHash([0x41; 32]);

fn compiled() -> AetsCompiledQsm {
    let semantics = ActionSemantics::new(vec![ActionObligation {
        service: SERVICE,
        action: ActionCode::RenderAmbientPulse,
        public_bucket: BucketId(0),
        admission_cutoff: LogicalSlot(100),
        release_window_start: LogicalSlot(100),
        release_deadline: LogicalSlot(100),
        max_uses: 1,
        policy_hash: POLICY_HASH,
    }])
    .expect("AETS semantics");
    let source = AetsPublicSourceArtifact::new(
        &semantics,
        &PublicContext {
            schedule: ChannelSchedule {
                buckets: 1,
                slots_per_bucket: 4,
                frame_interval_ms: 250,
                fixed_plaintext_size: 160,
                fixed_ciphertext_size: 236,
            },
            network: PublicNetworkTape {
                services: vec![SERVICE],
                public_epoch: 9,
                start_slot: LogicalSlot(100),
            },
        },
        ScheduleRandomTape([0x51; 32]),
        SERVICE_ALIAS,
        POLICY_HASH,
    )
    .expect("AETS source");
    let (certificate, expected) = caqt_certificate();
    let target = TemporaryDirectory::new("aets-reference");
    generate_package(
        &certificate,
        expected,
        CertificateLimits::default(),
        &CodegenConfig {
            package_name: "generated-aets-reference-source".to_owned(),
            quotient_inputs: 1,
            public_inputs: 1,
            fault_inputs: 1,
            max_payload_bytes: 64,
            max_actions: 8,
        },
        target.path(),
    )
    .expect("K7 package");
    let runtime_manifest =
        fs::read(target.path().join("codegen-manifest.toml")).expect("codegen manifest");
    let k7 = verify_aets_k7(
        &source,
        &certificate,
        expected,
        CertificateLimits::default(),
        &runtime_manifest,
    )
    .expect("AETS K7 binding");
    compile_aets_p0(
        &source,
        &k7,
        &[AetsServiceCode {
            service: SERVICE,
            qsm_alias: 11,
        }],
        AetsCompileLimits::default(),
    )
    .expect("AETS QSM")
}

fn caqt_certificate() -> (Vec<u8>, ExpectedContract) {
    let action = u32::from(ActionCode::RenderAmbientPulse as u16);
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
                payload: b"fixed-slot".to_vec(),
                actions: vec![action],
            },
            OutputRecord {
                id: 1,
                emitted: true,
                payload: b"fixed-slot".to_vec(),
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

fn limits(host_calls: u64) -> ExecutionLimits {
    ExecutionLimits {
        fuel: 100_000,
        max_memory_pages: 2,
        max_host_calls: host_calls,
        timeout_ms: 5_000,
    }
}

fn command(
    family: ContextFamily,
    service_alias: u32,
    public_slot: u64,
    fault: u8,
) -> ContextCommand {
    ContextCommand {
        family,
        kind: family.command_kind(),
        service_alias,
        public_slot,
        fault,
        payload_tag: 0,
    }
}

fn lifecycle_commands() -> Vec<ContextCommand> {
    vec![
        command(ContextFamily::Tick, 11, 100, 0),
        command(ContextFamily::Handoff, 0, 0, 0),
        command(ContextFamily::Reset, 0, 0, 0),
        command(ContextFamily::Deadline, 11, 104, 0),
        command(ContextFamily::FaultTimeout, 11, 101, 1),
        command(ContextFamily::Stop, 0, 0, 0),
    ]
}

#[test]
fn lifecycle_sequence_produces_complete_source_reference_trace() {
    let compiled = compiled();
    let sequence = AetsPublicSequence::new(&compiled, lifecycle_commands(), limits(8), 16)
        .expect("canonical sequence");
    assert_eq!(sequence.host_tape().directives().len(), 5);
    let AetsReferenceVerdict::Executed(artifact) =
        evaluate_aets_source_reference(&compiled, &sequence).expect("reference evaluation")
    else {
        panic!("reference must execute");
    };
    let run = artifact.run();
    assert_eq!(run.input.engine.name, "noticer-aets-source-reference");
    assert_eq!(run.input.engine.version, AETS_SOURCE_REFERENCE_VERSION);
    assert_eq!(
        run.input.engine.adapter_contract_version,
        ENGINE_ADAPTER_CONTRACT_VERSION
    );
    assert_eq!(
        run.input.engine.configuration["reference_kind"],
        "SOURCE_DERIVED_EXPECTATION_NOT_INTERPRETER"
    );
    assert_eq!(run.termination, ExecutionTermination::Terminated);
    assert!(run.trace.iter().any(|event| matches!(
        event,
        ObservableEvent::EmitAction { action, slot, .. }
            if *action == u32::from(ActionCode::RenderAmbientPulse as u16) && *slot == 100
    )));
    assert!(run
        .trace
        .iter()
        .any(|event| matches!(event, ObservableEvent::Handoff { value: 1 })));
    assert!(run
        .trace
        .iter()
        .any(|event| matches!(event, ObservableEvent::Reset { return_code: 0 })));
    assert!(run
        .trace
        .iter()
        .any(|event| matches!(event, ObservableEvent::PublicFailure { code: 0x0a002 })));
    assert!(run
        .trace
        .iter()
        .any(|event| matches!(event, ObservableEvent::PublicFailure { code: 1 })));
    assert_eq!(
        run.trace
            .iter()
            .filter(|event| matches!(event, ObservableEvent::PublicState { .. }))
            .count(),
        5
    );
}

#[test]
fn sequence_and_reference_artifacts_are_byte_deterministic() {
    let compiled = compiled();
    let first = AetsPublicSequence::new(&compiled, lifecycle_commands(), limits(8), 16)
        .expect("first sequence");
    let second = AetsPublicSequence::new(&compiled, lifecycle_commands(), limits(8), 16)
        .expect("second sequence");
    assert_eq!(first, second);
    let first_artifact = evaluate_aets_source_reference(&compiled, &first).expect("first artifact");
    let second_artifact =
        evaluate_aets_source_reference(&compiled, &second).expect("second artifact");
    assert_eq!(first_artifact, second_artifact);
}

#[test]
fn host_call_bound_is_unresolved_never_executed() {
    let compiled = compiled();
    let sequence = AetsPublicSequence::new(&compiled, lifecycle_commands(), limits(4), 16)
        .expect("bounded sequence");
    assert_eq!(
        evaluate_aets_source_reference(&compiled, &sequence).expect("bounded verdict"),
        AetsReferenceVerdict::Unresolved(AetsReferenceUnresolved::HostCallBound {
            required: 5,
            limit: 4,
        })
    );
}

#[test]
fn malformed_commands_and_commands_after_stop_fail_closed() {
    let compiled = compiled();
    let mut payload = command(ContextFamily::Tick, 11, 100, 0);
    payload.payload_tag = 1;
    assert!(matches!(
        AetsPublicSequence::new(&compiled, vec![payload], limits(8), 16),
        Err(AetsReferenceError::NonCanonicalCommand)
    ));

    let bad_fault = command(ContextFamily::FaultTimeout, 11, 101, 2);
    assert!(matches!(
        AetsPublicSequence::new(&compiled, vec![bad_fault], limits(8), 16),
        Err(AetsReferenceError::NonCanonicalCommand)
    ));

    let commands = vec![
        command(ContextFamily::Stop, 0, 0, 0),
        command(ContextFamily::Tick, 11, 100, 0),
    ];
    assert!(matches!(
        AetsPublicSequence::new(&compiled, commands, limits(8), 16),
        Err(AetsReferenceError::CommandAfterStop)
    ));

    let mut wrong_kind = command(ContextFamily::Reset, 0, 0, 0);
    wrong_kind.kind = CommandKind::PublicCall;
    assert!(matches!(
        AetsPublicSequence::new(&compiled, vec![wrong_kind], limits(8), 16),
        Err(AetsReferenceError::NonCanonicalCommand)
    ));
}

#[test]
fn unknown_service_is_an_explicit_public_failure() {
    let compiled = compiled();
    let sequence = AetsPublicSequence::new(
        &compiled,
        vec![command(ContextFamily::ServiceCollusion, 999, 100, 0)],
        limits(2),
        4,
    )
    .expect("adversarial public sequence");
    let AetsReferenceVerdict::Executed(artifact) =
        evaluate_aets_source_reference(&compiled, &sequence).expect("reference")
    else {
        panic!("reference must execute");
    };
    assert!(artifact
        .run()
        .trace
        .iter()
        .any(|event| matches!(event, ObservableEvent::PublicFailure { code: 0x0a001 })));
    assert!(!artifact
        .run()
        .trace
        .iter()
        .any(|event| matches!(event, ObservableEvent::EmitFrame { .. })));
}

#[test]
fn frozen_contract_forbids_interpreter_and_hardware_mislabeling() {
    let config = include_str!("../../../configs/quotient_seal/aets_reference_v1.yaml");
    let docs = include_str!("../../../docs/quotient_seal_aets_reference_v1.md");
    assert!(config.contains("SOURCE_DERIVED_EXPECTATION_NOT_INTERPRETER"));
    assert!(config.contains("small_step_promotion: REQUIRES_EXACT_TRACE_MATCH_IN_K8_13B3B"));
    assert!(config.contains("private_ingress: FORBIDDEN"));
    assert!(config.contains("hardware_status: NOT_VERIFIED"));
    assert!(docs.contains("must not be relabeled as `quotient-seal-small-step`"));
}

struct TemporaryDirectory(PathBuf);

impl TemporaryDirectory {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        Self(std::env::temp_dir().join(format!(
            "quotient-seal-{label}-{}-{nonce}",
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
