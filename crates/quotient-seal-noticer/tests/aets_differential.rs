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
use quotient_seal_context::{ContextCommand, ContextFamily};
use quotient_seal_engine::{
    DifferentialOracle, DifferentialVerdict, ExecutionLimits, ObservableAxis, ObservableEvent,
};
use quotient_seal_noticer::{
    compile_aets_p0, evaluate_aets_differential, verify_aets_k7, AetsCompileLimits,
    AetsCompiledQsm, AetsDifferentialArtifact, AetsDifferentialError, AetsDifferentialVerdict,
    AetsEngineDigests, AetsPublicSequence, AetsPublicSourceArtifact, AetsServiceCode,
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
    let target = TemporaryDirectory::new("aets-differential");
    generate_package(
        &certificate,
        expected,
        CertificateLimits::default(),
        &CodegenConfig {
            package_name: "generated-aets-differential-source".to_owned(),
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

fn engine_digests() -> AetsEngineDigests {
    AetsEngineDigests::new("1".repeat(64), "2".repeat(64), "3".repeat(64))
        .expect("fixture engine digests")
}

#[test]
fn actual_three_engine_match_and_typed_counterexample_are_canonical() {
    let compiled = compiled();
    let sequence = AetsPublicSequence::new(&compiled, lifecycle_commands(), limits(8), 16)
        .expect("canonical sequence");
    let matched = evaluate_aets_differential(&compiled, &sequence, &engine_digests())
        .expect("differential evaluation");

    assert_eq!(
        matched.verdict,
        AetsDifferentialVerdict::Match,
        "{matched:#?}"
    );
    assert_eq!(
        matched.source_refinement.verdict,
        AetsDifferentialVerdict::Match
    );
    assert_eq!(matched.oracle.verdict, DifferentialVerdict::Match);
    assert_eq!(
        matched.oracle.reference.input.engine.name,
        "quotient-seal-small-step"
    );
    assert_eq!(matched.oracle.engines[0].input.engine.name, "wasmi");
    assert_eq!(matched.oracle.engines[1].input.engine.name, "wasmtime");
    assert_eq!(matched.hardware_status, "NOT_VERIFIED");
    assert_eq!(
        matched.canonical_json().expect("first canonical JSON"),
        matched.canonical_json().expect("second canonical JSON")
    );

    let mut engines = matched.oracle.engines.clone();
    let ObservableEvent::ApiCall { export, .. } = &mut engines[1].trace[0] else {
        panic!("first event must be an API call");
    };
    *export = "qseal.public.counterexample".to_owned();
    let oracle = DifferentialOracle::evaluate(matched.oracle.reference.clone(), engines)
        .expect("counterexample oracle");
    assert_eq!(oracle.verdict, DifferentialVerdict::Counterexample);
    assert_eq!(oracle.counterexamples.len(), 2);
    assert!(oracle.counterexamples.iter().all(|counterexample| matches!(
        counterexample.first_difference,
        quotient_seal_engine::ComparisonPoint::Trace {
            index: 0,
            left_axis: Some(ObservableAxis::Return),
            right_axis: Some(ObservableAxis::Return),
            ..
        }
    )));

    let counterexample = AetsDifferentialArtifact {
        verdict: AetsDifferentialVerdict::Counterexample,
        oracle,
        ..matched
    };
    counterexample.validate().expect("counterexample artifact");
    assert!(!counterexample
        .canonical_json()
        .expect("counterexample JSON")
        .is_empty());
}

#[test]
fn host_call_bound_is_saved_as_unresolved_for_all_engines() {
    let compiled = compiled();
    let sequence = AetsPublicSequence::new(&compiled, lifecycle_commands(), limits(4), 16)
        .expect("bounded sequence");
    let artifact = evaluate_aets_differential(&compiled, &sequence, &engine_digests())
        .expect("bounded differential evaluation");

    assert_eq!(artifact.verdict, AetsDifferentialVerdict::Unresolved);
    assert_eq!(
        artifact.source_refinement.verdict,
        AetsDifferentialVerdict::Unresolved
    );
    assert!(artifact.source_reference.is_none());
    assert_eq!(artifact.oracle.verdict, DifferentialVerdict::Unresolved);
    assert_eq!(artifact.oracle.engines.len(), 2);
    assert!(!artifact.oracle.unresolved.is_empty());
    artifact.validate().expect("unresolved artifact");
    assert!(!artifact
        .canonical_json()
        .expect("unresolved JSON")
        .is_empty());
}

#[test]
fn executable_identity_and_frozen_claim_boundaries_fail_closed() {
    assert!(matches!(
        AetsEngineDigests::new("short", "2".repeat(64), "3".repeat(64)),
        Err(AetsDifferentialError::InvalidExecutableDigest { .. })
    ));
    let config = include_str!("../../../configs/quotient_seal/aets_differential_v1.yaml");
    let docs = include_str!("../../../docs/quotient_seal_aets_differential_v1.md");
    assert!(config.contains("SOURCE_DERIVED_EXPECTATION_NOT_INTERPRETER"));
    assert!(config.contains("first_typed_difference: REQUIRED_ON_COUNTEREXAMPLE"));
    assert!(config.contains("private_ingress: FORBIDDEN"));
    assert!(config.contains("hardware_status: NOT_VERIFIED"));
    assert!(docs.contains("world-first claim is made"));
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
