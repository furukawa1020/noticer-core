use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
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
    build_atv2_counterexample_bundle, compile_atv2_p0, evaluate_atv2_adversarial_matrix,
    evaluate_atv2_differential_with_host_tape, shrink_atv2_counterexample,
    verify_atv2_counterexample_bundle_with, verify_atv2_k7, Atv2AdversarialCaseSpec,
    Atv2AdversarialMatrix, Atv2CompileLimits, Atv2CompiledQsm, Atv2CounterexampleError,
    Atv2CounterexampleInput, Atv2DifferentialError, Atv2DifferentialVerdict, Atv2EngineDigests,
    Atv2HostAxis, Atv2HostInjection, Atv2MatrixCaseArtifact, Atv2MatrixLimits, Atv2MatrixSeed,
    Atv2PublicSequence, Atv2PublicSourceArtifact, Atv2ResourceAxis, Atv2ScenarioAxis,
    Atv2ServiceCode, Atv2ShrinkOutcome,
};
use quotient_seal_small_step::{HostDirective, HostOutcome, PublicHostTape};

const SERVICE: ServiceBinding = ServiceBinding([0x11; 16]);
const SERVICE_ALIAS: WireServiceAlias = WireServiceAlias([0x31; 8]);
const POLICY_HASH: PolicyHash = PolicyHash([0x41; 32]);
static TEMPORARY_DIRECTORY_ID: AtomicU64 = AtomicU64::new(0);

fn compiled() -> Atv2CompiledQsm {
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
    .expect("ATV2 semantics");
    let token_plan = noticer_release::TokenPlan::from_action_semantics(&semantics, vec![SERVICE])
        .expect("ATv2 token plan");
    let source = Atv2PublicSourceArtifact::new(
        &token_plan,
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
    .expect("ATV2 source");
    let (certificate, expected) = caqt_certificate();
    let target = TemporaryDirectory::new("atv2-matrix-execution");
    generate_package(
        &certificate,
        expected,
        CertificateLimits::default(),
        &CodegenConfig {
            package_name: "generated-atv2-matrix-execution-source".to_owned(),
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
    let k7 = verify_atv2_k7(
        &source,
        &certificate,
        expected,
        CertificateLimits::default(),
        &runtime_manifest,
    )
    .expect("ATV2 K7 binding");
    compile_atv2_p0(
        &source,
        &k7,
        &[Atv2ServiceCode {
            service: SERVICE,
            qsm_alias: 11,
        }],
        Atv2CompileLimits::default(),
    )
    .expect("ATV2 QSM")
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
    scenario: Atv2ScenarioAxis,
    host: Atv2HostAxis,
    resource: Atv2ResourceAxis,
    commands: Vec<ContextCommand>,
    limits: ExecutionLimits,
) -> Atv2AdversarialCaseSpec {
    Atv2AdversarialCaseSpec::new(scenario, host, resource, commands, limits)
}

fn matrix(compiled: &Atv2CompiledQsm) -> Atv2AdversarialMatrix {
    let specs = vec![
        spec(
            Atv2ScenarioAxis::Normal,
            Atv2HostAxis::Continue,
            Atv2ResourceAxis::Nominal,
            commands(ContextFamily::Tick, 11, 100, 0),
            nominal_limits(),
        ),
        spec(
            Atv2ScenarioAxis::PublicFaultTimeout,
            Atv2HostAxis::Timeout,
            Atv2ResourceAxis::Nominal,
            commands(ContextFamily::Tick, 11, 101, 0),
            nominal_limits(),
        ),
        spec(
            Atv2ScenarioAxis::PublicFaultReconnect,
            Atv2HostAxis::Reconnect,
            Atv2ResourceAxis::Nominal,
            commands(ContextFamily::Tick, 11, 101, 0),
            nominal_limits(),
        ),
        spec(
            Atv2ScenarioAxis::PublicFaultLoss,
            Atv2HostAxis::Loss,
            Atv2ResourceAxis::Nominal,
            commands(ContextFamily::Tick, 11, 101, 0),
            nominal_limits(),
        ),
        spec(
            Atv2ScenarioAxis::DeadlineAt,
            Atv2HostAxis::Terminate,
            Atv2ResourceAxis::Nominal,
            commands(ContextFamily::Deadline, 11, 100, 0),
            nominal_limits(),
        ),
        spec(
            Atv2ScenarioAxis::Reset,
            Atv2HostAxis::Timeout,
            Atv2ResourceAxis::Nominal,
            commands(ContextFamily::Reset, 0, 0, 0),
            nominal_limits(),
        ),
        spec(
            Atv2ScenarioAxis::Normal,
            Atv2HostAxis::Continue,
            Atv2ResourceAxis::HostCallBoundary,
            commands(ContextFamily::Tick, 11, 100, 0),
            limits(100_000, 2, 1),
        ),
        spec(
            Atv2ScenarioAxis::UnknownService,
            Atv2HostAxis::Continue,
            Atv2ResourceAxis::FuelBoundary,
            commands(ContextFamily::ServiceCollusion, 999, 100, 0),
            limits(1, 2, 2),
        ),
        spec(
            Atv2ScenarioAxis::Handoff,
            Atv2HostAxis::Continue,
            Atv2ResourceAxis::MemoryBoundary,
            commands(ContextFamily::Handoff, 0, 0, 0),
            limits(100_000, 1, 2),
        ),
        spec(
            Atv2ScenarioAxis::DeadlineBefore,
            Atv2HostAxis::Continue,
            Atv2ResourceAxis::Nominal,
            commands(ContextFamily::Deadline, 11, 99, 0),
            nominal_limits(),
        ),
        spec(
            Atv2ScenarioAxis::DeadlineAfter,
            Atv2HostAxis::Continue,
            Atv2ResourceAxis::Nominal,
            commands(ContextFamily::Deadline, 11, 104, 0),
            nominal_limits(),
        ),
    ];
    Atv2AdversarialMatrix::new(
        compiled,
        Atv2MatrixSeed::new([0x81; 32]),
        specs,
        Atv2MatrixLimits::default(),
    )
    .expect("adversarial matrix")
}

fn engine_digests() -> Atv2EngineDigests {
    Atv2EngineDigests::new("1".repeat(64), "2".repeat(64), "3".repeat(64))
        .expect("fixture engine digests")
}

#[test]
fn public_faults_deadlines_unknown_service_and_resources_are_not_conflated() {
    let compiled = compiled();
    let matrix = matrix(&compiled);
    let first = evaluate_atv2_adversarial_matrix(
        &compiled,
        &matrix,
        Atv2MatrixLimits::default(),
        &engine_digests(),
    )
    .expect("first matrix execution");
    let second = evaluate_atv2_adversarial_matrix(
        &compiled,
        &matrix,
        Atv2MatrixLimits::default(),
        &engine_digests(),
    )
    .expect("second matrix execution");

    assert_eq!(first, second);
    assert_eq!(
        first.canonical_json().expect("first canonical JSON"),
        second.canonical_json().expect("second canonical JSON")
    );
    assert_eq!(first.verdict, Atv2DifferentialVerdict::Unresolved);
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
        assert!(matches!(case.injection, Atv2HostInjection::Applied { .. }));
        assert_eq!(case.verdict, Atv2DifferentialVerdict::Match);
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
    assert_eq!(terminated.verdict, Atv2DifferentialVerdict::Match);
    assert_eq!(
        terminated.differential.oracle.reference.termination,
        ExecutionTermination::Terminated
    );

    let not_applicable = first
        .cases
        .iter()
        .find(|case| case.scenario_axis == "RESET")
        .expect("no-import case");
    assert_eq!(not_applicable.injection, Atv2HostInjection::NotApplicable);
    assert_eq!(not_applicable.verdict, Atv2DifferentialVerdict::Unresolved);
    assert_eq!(
        not_applicable.differential.verdict,
        Atv2DifferentialVerdict::Match
    );
    assert!(first.cases.iter().any(|case| {
        case.resource_axis == "HOST_CALL_BOUNDARY"
            && case.verdict == Atv2DifferentialVerdict::Unresolved
    }));
    assert!(first.cases.iter().any(|case| {
        case.resource_axis == "FUEL_BOUNDARY" && case.verdict == Atv2DifferentialVerdict::Unresolved
    }));
}

#[test]
fn counterexample_case_remains_distinct_inside_an_unresolved_matrix() {
    let compiled = compiled();
    let matrix = matrix(&compiled);
    let mut artifact = evaluate_atv2_adversarial_matrix(
        &compiled,
        &matrix,
        Atv2MatrixLimits::default(),
        &engine_digests(),
    )
    .expect("matrix execution");
    let case = artifact
        .cases
        .iter_mut()
        .find(|case| case.verdict == Atv2DifferentialVerdict::Match)
        .expect("match case");
    let mut engines = case.differential.oracle.engines.clone();
    let ObservableEvent::ApiCall { export, .. } = &mut engines[1].trace[0] else {
        panic!("first event must be API call");
    };
    *export = "qseal.public.matrix-counterexample".to_owned();
    case.differential.oracle =
        DifferentialOracle::evaluate(case.differential.oracle.reference.clone(), engines)
            .expect("counterexample oracle");
    case.differential.verdict = Atv2DifferentialVerdict::Counterexample;
    case.verdict = Atv2DifferentialVerdict::Counterexample;
    artifact.match_cases -= 1;
    artifact.counterexample_cases += 1;

    assert_eq!(artifact.verdict, Atv2DifferentialVerdict::Unresolved);
    artifact.validate().expect("mixed matrix artifact");
    assert!(!artifact
        .canonical_json()
        .expect("mixed canonical JSON")
        .is_empty());
}

#[test]
fn injected_tape_must_preserve_import_count_and_order() {
    let compiled = compiled();
    let sequence = Atv2PublicSequence::new(
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
        evaluate_atv2_differential_with_host_tape(&compiled, &sequence, &wrong, &engine_digests(),),
        Err(Atv2DifferentialError::HostTapeShape)
    ));
}

#[test]
fn frozen_execution_contract_keeps_private_and_hardware_nonclaims_explicit() {
    let config = include_str!("../../../configs/quotient_seal/atv2_adversarial_bundle_v1.yaml");
    let docs = include_str!("../../../docs/quotient_seal_atv2_adversarial_bundle_v1.md");
    assert!(config.contains("point: FIRST_PUBLIC_HOST_IMPORT"));
    assert!(config.contains("no_import: UNRESOLVED_NOT_APPLICABLE"));
    assert!(config.contains("private_ingress: FORBIDDEN"));
    assert!(config.contains("hardware_status: NOT_VERIFIED"));
    assert!(docs.contains("world-first claim"));
}

fn injected_counterexample(
    compiled: &Atv2CompiledQsm,
    seed: Atv2MatrixSeed,
    input: &Atv2CounterexampleInput,
) -> Result<Atv2MatrixCaseArtifact, String> {
    let candidate_matrix = Atv2AdversarialMatrix::new(
        compiled,
        seed,
        vec![input.to_case_spec()],
        Atv2MatrixLimits::default(),
    )
    .map_err(|error| error.to_string())?;
    let execution = evaluate_atv2_adversarial_matrix(
        compiled,
        &candidate_matrix,
        Atv2MatrixLimits::default(),
        &engine_digests(),
    )
    .map_err(|error| error.to_string())?;
    let mut case = execution
        .cases
        .into_iter()
        .next()
        .ok_or_else(|| "missing injected case".to_owned())?;
    let mut engines = case.differential.oracle.engines.clone();
    let wasmtime = engines
        .iter_mut()
        .find(|run| run.input.engine.name == "wasmtime")
        .ok_or_else(|| "missing Wasmtime participant".to_owned())?;
    let ObservableEvent::ApiCall { export, .. } = wasmtime
        .trace
        .first_mut()
        .ok_or_else(|| "missing Wasmtime trace".to_owned())?
    else {
        return Err("first Wasmtime event is not an API call".to_owned());
    };
    *export = "qseal.public.injected-counterexample".to_owned();
    case.differential.oracle =
        DifferentialOracle::evaluate(case.differential.oracle.reference.clone(), engines)
            .map_err(|error| error.to_string())?;
    case.differential.verdict = Atv2DifferentialVerdict::Counterexample;
    case.verdict = Atv2DifferentialVerdict::Counterexample;
    case.differential
        .validate()
        .map_err(|error| error.to_string())?;
    Ok(case)
}

#[test]
fn counterexample_shrink_and_recomputation_are_byte_identical() {
    let compiled = compiled();
    let seed = Atv2MatrixSeed::new([0x91; 32]);
    let input = Atv2CounterexampleInput::new(
        Atv2ScenarioAxis::Normal,
        Atv2HostAxis::Continue,
        Atv2ResourceAxis::Nominal,
        commands(ContextFamily::Tick, 11, 104, 0),
        nominal_limits(),
    )
    .expect("counterexample input");
    let observed = injected_counterexample(&compiled, seed, &input).expect("observed mismatch");
    let matrix_digest = "a".repeat(64);
    let first = shrink_atv2_counterexample(
        matrix_digest.clone(),
        input.clone(),
        observed.clone(),
        |candidate| injected_counterexample(&compiled, seed, candidate),
    )
    .expect("first shrink");
    let second = shrink_atv2_counterexample(
        matrix_digest.clone(),
        input.clone(),
        observed.clone(),
        |candidate| injected_counterexample(&compiled, seed, candidate),
    )
    .expect("second shrink");

    assert_eq!(first, second);
    assert_eq!(
        first.canonical_json().expect("first canonical JSON"),
        second.canonical_json().expect("second canonical JSON")
    );
    assert_ne!(
        first.original.input.input_sha256,
        first.minimized.input.input_sha256
    );
    assert_eq!(
        first.minimized.input.commands.len(),
        first.original.input.commands.len()
    );
    assert!(first
        .attempts
        .iter()
        .any(|attempt| attempt.outcome == Atv2ShrinkOutcome::Preserved));
    verify_atv2_counterexample_bundle_with(&first, matrix_digest, input, observed, |candidate| {
        injected_counterexample(&compiled, seed, candidate)
    })
    .expect("full bundle recomputation");
}

#[test]
fn counterexample_bundle_tamper_and_non_counterexample_fail_closed() {
    let compiled = compiled();
    let matrix = matrix(&compiled);
    let execution = evaluate_atv2_adversarial_matrix(
        &compiled,
        &matrix,
        Atv2MatrixLimits::default(),
        &engine_digests(),
    )
    .expect("matrix execution");
    let matching = execution
        .cases
        .iter()
        .find(|case| case.verdict == Atv2DifferentialVerdict::Match)
        .expect("matching case");
    assert!(matches!(
        build_atv2_counterexample_bundle(
            &compiled,
            &matrix,
            &execution,
            &matching.case_id_sha256,
            Atv2MatrixLimits::default(),
            &engine_digests(),
        ),
        Err(Atv2CounterexampleError::OriginalNotCounterexample)
    ));

    let seed = Atv2MatrixSeed::new([0x92; 32]);
    let input = Atv2CounterexampleInput::new(
        Atv2ScenarioAxis::Normal,
        Atv2HostAxis::Continue,
        Atv2ResourceAxis::Nominal,
        commands(ContextFamily::Tick, 11, 100, 0),
        nominal_limits(),
    )
    .expect("counterexample input");
    let observed = injected_counterexample(&compiled, seed, &input).expect("observed mismatch");
    let mut bundle = shrink_atv2_counterexample("b".repeat(64), input, observed, |candidate| {
        injected_counterexample(&compiled, seed, candidate)
    })
    .expect("counterexample bundle");
    bundle.minimized.result_sha256.replace_range(0..1, "0");
    assert!(bundle.validate().is_err());
}

#[test]
fn frozen_counterexample_contract_keeps_nonclaims_explicit() {
    let config = include_str!("../../../configs/quotient_seal/atv2_adversarial_bundle_v1.yaml");
    let docs = include_str!("../../../docs/quotient_seal_atv2_adversarial_bundle_v1.md");
    assert!(config.contains("original_reproduction: BYTE_IDENTICAL_REQUIRED"));
    assert!(config.contains("verification: FULL_BUNDLE_RECOMPUTATION"));
    assert!(config.contains("private_ingress: FORBIDDEN"));
    assert!(config.contains("hardware_status: NOT_VERIFIED"));
    assert!(docs.contains("world-first"));
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
