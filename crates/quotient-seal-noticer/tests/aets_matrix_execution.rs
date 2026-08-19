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
    DifferentialOracle, DifferentialVerdict, ExecutionLimits, ExecutionTermination,
    ObservableEvent, TrapClass,
};
use quotient_seal_noticer::{
    compile_aets_p0, evaluate_aets_adversarial_matrix, evaluate_aets_differential_with_host_tape,
    verify_aets_k7, AetsAdversarialCaseSpec, AetsAdversarialMatrix, AetsCompileLimits,
    AetsCompiledQsm, AetsDifferentialError, AetsDifferentialVerdict, AetsEngineDigests,
    AetsHostAxis, AetsHostInjection, AetsMatrixLimits, AetsMatrixSeed, AetsPublicSequence,
    AetsPublicSourceArtifact, AetsResourceAxis, AetsScenarioAxis, AetsServiceCode,
};
use quotient_seal_small_step::{HostDirective, HostOutcome, PublicHostTape};

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
    let target = TemporaryDirectory::new("aets-matrix-execution");
    generate_package(
        &certificate,
        expected,
        CertificateLimits::default(),
        &CodegenConfig {
            package_name: "generated-aets-matrix-execution-source".to_owned(),
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

fn limits(fuel: u64, memory: u32, host_calls: u64) -> ExecutionLimits {
    ExecutionLimits {
        fuel,
        max_memory_pages: memory,
        max_host_calls: host_calls,
        timeout_ms: 5_000,
    }
}

fn nominal_limits() -> ExecutionLimits {
    limits(100_000, 2, 4)
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

fn commands(family: ContextFamily, alias: u32, slot: u64, fault: u8) -> Vec<ContextCommand> {
    vec![
        command(family, alias, slot, fault),
        command(ContextFamily::Stop, 0, 0, 0),
    ]
}

fn spec(
    scenario: AetsScenarioAxis,
    host: AetsHostAxis,
    resource: AetsResourceAxis,
    commands: Vec<ContextCommand>,
    limits: ExecutionLimits,
) -> AetsAdversarialCaseSpec {
    AetsAdversarialCaseSpec::new(scenario, host, resource, commands, limits)
}

fn matrix(compiled: &AetsCompiledQsm) -> AetsAdversarialMatrix {
    let specs = vec![
        spec(
            AetsScenarioAxis::Normal,
            AetsHostAxis::Continue,
            AetsResourceAxis::Nominal,
            commands(ContextFamily::Tick, 11, 100, 0),
            nominal_limits(),
        ),
        spec(
            AetsScenarioAxis::PublicFaultTimeout,
            AetsHostAxis::Timeout,
            AetsResourceAxis::Nominal,
            commands(ContextFamily::Tick, 11, 101, 0),
            nominal_limits(),
        ),
        spec(
            AetsScenarioAxis::PublicFaultReconnect,
            AetsHostAxis::Reconnect,
            AetsResourceAxis::Nominal,
            commands(ContextFamily::Tick, 11, 101, 0),
            nominal_limits(),
        ),
        spec(
            AetsScenarioAxis::PublicFaultLoss,
            AetsHostAxis::Loss,
            AetsResourceAxis::Nominal,
            commands(ContextFamily::Tick, 11, 101, 0),
            nominal_limits(),
        ),
        spec(
            AetsScenarioAxis::DeadlineAt,
            AetsHostAxis::Terminate,
            AetsResourceAxis::Nominal,
            commands(ContextFamily::Deadline, 11, 100, 0),
            nominal_limits(),
        ),
        spec(
            AetsScenarioAxis::Reset,
            AetsHostAxis::Timeout,
            AetsResourceAxis::Nominal,
            commands(ContextFamily::Reset, 0, 0, 0),
            nominal_limits(),
        ),
        spec(
            AetsScenarioAxis::Normal,
            AetsHostAxis::Continue,
            AetsResourceAxis::HostCallBoundary,
            commands(ContextFamily::Tick, 11, 100, 0),
            limits(100_000, 2, 1),
        ),
        spec(
            AetsScenarioAxis::UnknownService,
            AetsHostAxis::Continue,
            AetsResourceAxis::FuelBoundary,
            commands(ContextFamily::ServiceCollusion, 999, 100, 0),
            limits(1, 2, 2),
        ),
        spec(
            AetsScenarioAxis::Handoff,
            AetsHostAxis::Continue,
            AetsResourceAxis::MemoryBoundary,
            commands(ContextFamily::Handoff, 0, 0, 0),
            limits(100_000, 1, 2),
        ),
        spec(
            AetsScenarioAxis::DeadlineBefore,
            AetsHostAxis::Continue,
            AetsResourceAxis::Nominal,
            commands(ContextFamily::Deadline, 11, 99, 0),
            nominal_limits(),
        ),
        spec(
            AetsScenarioAxis::DeadlineAfter,
            AetsHostAxis::Continue,
            AetsResourceAxis::Nominal,
            commands(ContextFamily::Deadline, 11, 104, 0),
            nominal_limits(),
        ),
    ];
    AetsAdversarialMatrix::new(
        compiled,
        AetsMatrixSeed::new([0x81; 32]),
        specs,
        AetsMatrixLimits::default(),
    )
    .expect("adversarial matrix")
}

fn engine_digests() -> AetsEngineDigests {
    AetsEngineDigests::new("1".repeat(64), "2".repeat(64), "3".repeat(64))
        .expect("fixture engine digests")
}

#[test]
fn public_faults_deadlines_unknown_service_and_resources_are_not_conflated() {
    let compiled = compiled();
    let matrix = matrix(&compiled);
    let first = evaluate_aets_adversarial_matrix(
        &compiled,
        &matrix,
        AetsMatrixLimits::default(),
        &engine_digests(),
    )
    .expect("first matrix execution");
    let second = evaluate_aets_adversarial_matrix(
        &compiled,
        &matrix,
        AetsMatrixLimits::default(),
        &engine_digests(),
    )
    .expect("second matrix execution");

    assert_eq!(first, second);
    assert_eq!(
        first.canonical_json().expect("first canonical JSON"),
        second.canonical_json().expect("second canonical JSON")
    );
    assert_eq!(first.verdict, AetsDifferentialVerdict::Unresolved);
    assert!(first.match_cases >= 8);
    assert!(first.unresolved_cases >= 2);
    assert_eq!(first.counterexample_cases, 0);
    assert_eq!(first.cases.len(), matrix.cases().len());
    assert!(first
        .cases
        .windows(2)
        .all(|pair| pair[0].case_id_sha256 < pair[1].case_id_sha256));
    assert!(first.cases.iter().all(|case| {
        case.differential.oracle.engines.len() == 2
            && case.differential.oracle.reference.input.engine.name == "quotient-seal-small-step"
    }));

    for (scenario, host, expected_code) in [
        ("PUBLIC_FAULT_TIMEOUT", "TIMEOUT", "HOST_TIMEOUT"),
        ("PUBLIC_FAULT_RECONNECT", "RECONNECT", "HOST_RECONNECT"),
        ("PUBLIC_FAULT_LOSS", "LOSS", "HOST_LOSS"),
    ] {
        let case = first
            .cases
            .iter()
            .find(|case| case.scenario_axis == scenario && case.host_axis == host)
            .expect("fault case");
        assert!(matches!(case.injection, AetsHostInjection::Applied { .. }));
        assert_eq!(case.verdict, AetsDifferentialVerdict::Match);
        assert_eq!(case.differential.oracle.verdict, DifferentialVerdict::Match);
        assert!(matches!(
            &case.differential.oracle.reference.termination,
            ExecutionTermination::Trapped {
                class: TrapClass::HostFault,
                engine_code,
                ..
            } if engine_code == expected_code
        ));
    }

    let terminated = first
        .cases
        .iter()
        .find(|case| case.host_axis == "TERMINATE")
        .expect("terminate case");
    assert_eq!(terminated.verdict, AetsDifferentialVerdict::Match);
    assert_eq!(
        terminated.differential.oracle.reference.termination,
        ExecutionTermination::Terminated
    );

    let not_applicable = first
        .cases
        .iter()
        .find(|case| case.scenario_axis == "RESET")
        .expect("no-import case");
    assert_eq!(not_applicable.injection, AetsHostInjection::NotApplicable);
    assert_eq!(not_applicable.verdict, AetsDifferentialVerdict::Unresolved);
    assert_eq!(
        not_applicable.differential.verdict,
        AetsDifferentialVerdict::Match
    );
    assert!(first.cases.iter().any(|case| {
        case.resource_axis == "HOST_CALL_BOUNDARY"
            && case.verdict == AetsDifferentialVerdict::Unresolved
    }));
    assert!(first.cases.iter().any(|case| {
        case.resource_axis == "FUEL_BOUNDARY" && case.verdict == AetsDifferentialVerdict::Unresolved
    }));
}

#[test]
fn counterexample_case_remains_distinct_inside_an_unresolved_matrix() {
    let compiled = compiled();
    let matrix = matrix(&compiled);
    let mut artifact = evaluate_aets_adversarial_matrix(
        &compiled,
        &matrix,
        AetsMatrixLimits::default(),
        &engine_digests(),
    )
    .expect("matrix execution");
    let case = artifact
        .cases
        .iter_mut()
        .find(|case| case.verdict == AetsDifferentialVerdict::Match)
        .expect("match case");
    let mut engines = case.differential.oracle.engines.clone();
    let ObservableEvent::ApiCall { export, .. } = &mut engines[1].trace[0] else {
        panic!("first event must be API call");
    };
    *export = "qseal.public.matrix-counterexample".to_owned();
    case.differential.oracle =
        DifferentialOracle::evaluate(case.differential.oracle.reference.clone(), engines)
            .expect("counterexample oracle");
    case.differential.verdict = AetsDifferentialVerdict::Counterexample;
    case.verdict = AetsDifferentialVerdict::Counterexample;
    artifact.match_cases -= 1;
    artifact.counterexample_cases += 1;

    assert_eq!(artifact.verdict, AetsDifferentialVerdict::Unresolved);
    artifact.validate().expect("mixed matrix artifact");
    assert!(!artifact
        .canonical_json()
        .expect("mixed canonical JSON")
        .is_empty());
}

#[test]
fn injected_tape_must_preserve_import_count_and_order() {
    let compiled = compiled();
    let sequence = AetsPublicSequence::new(
        &compiled,
        commands(ContextFamily::Tick, 11, 100, 0),
        nominal_limits(),
        8,
    )
    .expect("sequence");
    let wrong = PublicHostTape::new(vec![
        HostDirective::new("qseal.public_failure", HostOutcome::Continue),
        HostDirective::new("qseal.emit_action", HostOutcome::Continue),
    ]);
    assert!(matches!(
        evaluate_aets_differential_with_host_tape(&compiled, &sequence, &wrong, &engine_digests(),),
        Err(AetsDifferentialError::HostTapeShape)
    ));
}

#[test]
fn frozen_execution_contract_keeps_private_and_hardware_nonclaims_explicit() {
    let config = include_str!("../../../configs/quotient_seal/aets_matrix_execution_v1.yaml");
    let docs = include_str!("../../../docs/quotient_seal_aets_matrix_execution_v1.md");
    assert!(config.contains("point: FIRST_PUBLIC_HOST_IMPORT"));
    assert!(config.contains("no_import: UNRESOLVED_NOT_APPLICABLE"));
    assert!(config.contains("private_ingress: FORBIDDEN"));
    assert!(config.contains("hardware_status: NOT_VERIFIED"));
    assert!(docs.contains("world-first claim"));
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
