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
use quotient_seal_engine::{DifferentialOracle, ExecutionLimits, ObservableEvent};
use quotient_seal_noticer::{
    compile_aplot_p0, evaluate_aplot_adversarial_matrix, shrink_aplot_counterexample,
    verify_aplot_counterexample_bundle_with, verify_aplot_k7, AplotAdversarialCaseSpec,
    AplotAdversarialMatrix, AplotCompileLimits, AplotCompiledQsm, AplotCounterexampleInput,
    AplotDifferentialVerdict, AplotEngineDigests, AplotFrameInput, AplotHostAxis,
    AplotHostInjection, AplotMatrixCaseArtifact, AplotMatrixExecutionArtifact, AplotMatrixLimits,
    AplotMatrixSeed, AplotPublicEventKind, AplotPublicSourceArtifact, AplotResourceAxis,
    AplotScenarioAxis, AplotServiceCode, AplotShrinkOutcome, Epoch, PolicyHash, WireServiceAlias,
    APLOT_PUBLIC_LOSS, APLOT_PUBLIC_RECONNECT,
};

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
    let target = TemporaryDirectory::new("aplot-adversarial");
    generate_package(
        &certificate,
        expected,
        CertificateLimits::default(),
        &CodegenConfig {
            package_name: "generated-aplot-adversarial-source".to_owned(),
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

fn stop() -> ContextCommand {
    command(ContextFamily::Stop, 0, 0, 0)
}

fn event_command(compiled: &AplotCompiledQsm, public_step: u64) -> ContextCommand {
    let event = &compiled.events()[public_step as usize];
    let family = if event.kind == AplotPublicEventKind::Deadline {
        ContextFamily::Deadline
    } else {
        ContextFamily::Tick
    };
    command(family, event.qsm_alias, event.public_step, 0)
}

fn through(compiled: &AplotCompiledQsm, last_step: u64) -> Vec<ContextCommand> {
    let mut commands = (0..=last_step)
        .map(|step| event_command(compiled, step))
        .collect::<Vec<_>>();
    commands.push(stop());
    commands
}

fn nominal_limits() -> ExecutionLimits {
    ExecutionLimits {
        fuel: 5_000_000,
        max_memory_pages: 2,
        max_host_calls: 256,
        timeout_ms: 5_000,
    }
}

fn spec(
    scenario: AplotScenarioAxis,
    host: AplotHostAxis,
    resource: AplotResourceAxis,
    commands: Vec<ContextCommand>,
    limits: ExecutionLimits,
) -> AplotAdversarialCaseSpec {
    AplotAdversarialCaseSpec::new(scenario, host, resource, commands, limits)
}

fn matrix(compiled: &AplotCompiledQsm) -> AplotAdversarialMatrix {
    let loss_step = compiled
        .events()
        .iter()
        .find(|event| event.declared_fault_code == APLOT_PUBLIC_LOSS)
        .expect("declared loss")
        .public_step;
    let reconnect_step = compiled
        .events()
        .iter()
        .find(|event| event.declared_fault_code == APLOT_PUBLIC_RECONNECT)
        .expect("declared reconnect")
        .public_step;
    let deadline_step = compiled
        .events()
        .iter()
        .find(|event| event.kind == AplotPublicEventKind::Deadline)
        .expect("deadline")
        .public_step;
    let after_deadline = deadline_step
        .checked_add(1)
        .filter(|step| (*step as usize) < compiled.events().len())
        .expect("event after first deadline");

    let mut duplicate = through(compiled, 0);
    duplicate.insert(1, event_command(compiled, 0));
    let mut secret_retry = through(compiled, 1);
    secret_retry.insert(2, event_command(compiled, 1));
    let mut reset = through(compiled, 0);
    reset.insert(1, command(ContextFamily::Reset, 0, 0, 0));
    reset.insert(2, event_command(compiled, 0));
    let mut handoff = through(compiled, 0);
    handoff.insert(1, command(ContextFamily::Handoff, 0, 0, 0));

    let mut timeout = through(compiled, 0);
    timeout[0] = command(ContextFamily::Tick, QSM_ALIAS, 0, 0);
    let mut capacity_limits = nominal_limits();
    capacity_limits.max_host_calls = 1;
    let mut fuel_limits = nominal_limits();
    fuel_limits.fuel = 1;
    let mut memory_limits = nominal_limits();
    memory_limits.max_memory_pages = 1;

    let specs = vec![
        spec(
            AplotScenarioAxis::Normal,
            AplotHostAxis::Continue,
            AplotResourceAxis::Nominal,
            through(compiled, 0),
            nominal_limits(),
        ),
        spec(
            AplotScenarioAxis::DeclaredLoss,
            AplotHostAxis::Continue,
            AplotResourceAxis::Nominal,
            through(compiled, loss_step),
            nominal_limits(),
        ),
        spec(
            AplotScenarioAxis::DeclaredReconnect,
            AplotHostAxis::Continue,
            AplotResourceAxis::Nominal,
            through(compiled, reconnect_step),
            nominal_limits(),
        ),
        spec(
            AplotScenarioAxis::PublicFaultTimeout,
            AplotHostAxis::Timeout,
            AplotResourceAxis::Nominal,
            timeout.clone(),
            nominal_limits(),
        ),
        spec(
            AplotScenarioAxis::PublicFaultReconnect,
            AplotHostAxis::Reconnect,
            AplotResourceAxis::Nominal,
            timeout.clone(),
            nominal_limits(),
        ),
        spec(
            AplotScenarioAxis::PublicFaultLoss,
            AplotHostAxis::Loss,
            AplotResourceAxis::Nominal,
            timeout,
            nominal_limits(),
        ),
        spec(
            AplotScenarioAxis::DuplicateStep,
            AplotHostAxis::Continue,
            AplotResourceAxis::Nominal,
            duplicate,
            nominal_limits(),
        ),
        spec(
            AplotScenarioAxis::CapacityBoundary,
            AplotHostAxis::Continue,
            AplotResourceAxis::HostCallBoundary,
            through(compiled, loss_step),
            capacity_limits,
        ),
        spec(
            AplotScenarioAxis::SecretRetryAttempt,
            AplotHostAxis::Continue,
            AplotResourceAxis::Nominal,
            secret_retry,
            nominal_limits(),
        ),
        spec(
            AplotScenarioAxis::Reset,
            AplotHostAxis::Continue,
            AplotResourceAxis::Nominal,
            reset,
            nominal_limits(),
        ),
        spec(
            AplotScenarioAxis::Handoff,
            AplotHostAxis::Continue,
            AplotResourceAxis::Nominal,
            handoff,
            nominal_limits(),
        ),
        spec(
            AplotScenarioAxis::DeadlineBefore,
            AplotHostAxis::Continue,
            AplotResourceAxis::FuelBoundary,
            through(compiled, deadline_step - 1),
            fuel_limits,
        ),
        spec(
            AplotScenarioAxis::DeadlineAt,
            AplotHostAxis::Continue,
            AplotResourceAxis::Nominal,
            through(compiled, deadline_step),
            nominal_limits(),
        ),
        spec(
            AplotScenarioAxis::DeadlineAfter,
            AplotHostAxis::Continue,
            AplotResourceAxis::MemoryBoundary,
            through(compiled, after_deadline),
            memory_limits,
        ),
        spec(
            AplotScenarioAxis::UnknownService,
            AplotHostAxis::Continue,
            AplotResourceAxis::Nominal,
            vec![command(ContextFamily::Tick, 999, 0, 0), stop()],
            nominal_limits(),
        ),
    ];
    AplotAdversarialMatrix::new(
        compiled,
        AplotMatrixSeed::new([0x81; 32]),
        specs,
        AplotMatrixLimits::default(),
    )
    .expect("APLOT adversarial matrix")
}

fn engine_digests() -> AplotEngineDigests {
    AplotEngineDigests::new("1".repeat(64), "2".repeat(64), "3".repeat(64)).expect("engine digests")
}

#[test]
fn fifteen_axis_matrix_is_canonical_and_faults_remain_distinct() {
    let compiled = compiled();
    let first_matrix = matrix(&compiled);
    let second_matrix = matrix(&compiled);
    assert_eq!(first_matrix, second_matrix);
    assert_eq!(first_matrix.cases().len(), 15);
    assert_eq!(
        first_matrix
            .canonical_bytes()
            .expect("first canonical matrix"),
        second_matrix
            .canonical_bytes()
            .expect("second canonical matrix")
    );
    assert_eq!(
        AplotAdversarialMatrix::from_bytes(
            &first_matrix
                .canonical_bytes()
                .expect("canonical matrix bytes"),
            AplotMatrixLimits::default(),
        )
        .expect("matrix decode"),
        first_matrix
    );

    let first = evaluate_aplot_adversarial_matrix(
        &compiled,
        &first_matrix,
        AplotMatrixLimits::default(),
        &engine_digests(),
    )
    .expect("first matrix execution");
    let second = evaluate_aplot_adversarial_matrix(
        &compiled,
        &second_matrix,
        AplotMatrixLimits::default(),
        &engine_digests(),
    )
    .expect("second matrix execution");
    assert_eq!(first, second);
    assert_eq!(
        first.canonical_json().expect("first canonical JSON"),
        second.canonical_json().expect("second canonical JSON")
    );
    assert_eq!(first.cases.len(), 15);
    assert_eq!(first.verdict, AplotDifferentialVerdict::Unresolved);
    assert!(first.match_cases >= 11);
    assert!(first.unresolved_cases >= 2);
    assert_eq!(first.counterexample_cases, 0);

    for (scenario, host) in [
        ("PUBLIC_FAULT_TIMEOUT", "TIMEOUT"),
        ("PUBLIC_FAULT_RECONNECT", "RECONNECT"),
        ("PUBLIC_FAULT_LOSS", "LOSS"),
    ] {
        let case = first
            .cases
            .iter()
            .find(|case| case.scenario_axis == scenario && case.host_axis == host)
            .expect("host fault case");
        assert!(matches!(case.injection, AplotHostInjection::Applied { .. }));
        assert_eq!(case.verdict, AplotDifferentialVerdict::Match);
    }

    let capacity = case(&first, "CAPACITY_BOUNDARY");
    assert_eq!(capacity.resource_axis, "HOST_CALL_BOUNDARY");
    assert_eq!(capacity.verdict, AplotDifferentialVerdict::Unresolved);
    let fuel = case(&first, "DEADLINE_BEFORE");
    assert_eq!(fuel.resource_axis, "FUEL_BOUNDARY");
    assert_eq!(fuel.verdict, AplotDifferentialVerdict::Unresolved);

    for scenario in ["DUPLICATE_STEP", "SECRET_RETRY_ATTEMPT"] {
        let retry = case(&first, scenario);
        assert_eq!(retry.verdict, AplotDifferentialVerdict::Match);
        let frame_count = retry
            .differential
            .oracle
            .reference
            .trace
            .iter()
            .filter(|event| matches!(event, ObservableEvent::EmitFrame { .. }))
            .count();
        assert_eq!(
            frame_count,
            if scenario == "DUPLICATE_STEP" { 1 } else { 2 }
        );
    }
    assert!(first.cases.iter().all(|case| {
        case.differential
            .oracle
            .reference
            .trace
            .iter()
            .all(|event| !matches!(event, ObservableEvent::EmitAction { .. }))
    }));
}

fn case<'a>(
    artifact: &'a AplotMatrixExecutionArtifact,
    scenario: &str,
) -> &'a AplotMatrixCaseArtifact {
    artifact
        .cases
        .iter()
        .find(|case| case.scenario_axis == scenario)
        .expect("scenario case")
}

fn injected_counterexample(
    compiled: &AplotCompiledQsm,
    seed: AplotMatrixSeed,
    input: &AplotCounterexampleInput,
) -> Result<AplotMatrixCaseArtifact, String> {
    let candidate_matrix = AplotAdversarialMatrix::new(
        compiled,
        seed,
        vec![input.to_case_spec()],
        AplotMatrixLimits::default(),
    )
    .map_err(|error| error.to_string())?;
    let execution = evaluate_aplot_adversarial_matrix(
        compiled,
        &candidate_matrix,
        AplotMatrixLimits::default(),
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
    case.differential.verdict = AplotDifferentialVerdict::Counterexample;
    case.verdict = AplotDifferentialVerdict::Counterexample;
    case.differential
        .validate()
        .map_err(|error| error.to_string())?;
    Ok(case)
}

#[test]
fn injected_counterexample_shrinks_and_full_bundle_recomputes() {
    let compiled = compiled();
    let seed = AplotMatrixSeed::new([0x91; 32]);
    let input = AplotCounterexampleInput::new(
        AplotScenarioAxis::Normal,
        AplotHostAxis::Continue,
        AplotResourceAxis::Nominal,
        through(&compiled, 3),
        nominal_limits(),
    )
    .expect("counterexample input");
    let observed = injected_counterexample(&compiled, seed, &input).expect("observed mismatch");
    let matrix_digest = "a".repeat(64);
    let first = shrink_aplot_counterexample(
        matrix_digest.clone(),
        input.clone(),
        observed.clone(),
        |candidate| injected_counterexample(&compiled, seed, candidate),
    )
    .expect("first shrink");
    let second = shrink_aplot_counterexample(
        matrix_digest.clone(),
        input.clone(),
        observed.clone(),
        |candidate| injected_counterexample(&compiled, seed, candidate),
    )
    .expect("second shrink");

    assert_eq!(first, second);
    assert_eq!(
        first.canonical_json().expect("first bundle JSON"),
        second.canonical_json().expect("second bundle JSON")
    );
    assert_ne!(
        first.original.input.input_sha256,
        first.minimized.input.input_sha256
    );
    assert!(first
        .attempts
        .iter()
        .any(|attempt| attempt.outcome == AplotShrinkOutcome::Preserved));
    verify_aplot_counterexample_bundle_with(&first, matrix_digest, input, observed, |candidate| {
        injected_counterexample(&compiled, seed, candidate)
    })
    .expect("full bundle recomputation");
}

#[test]
fn retry_command_and_bundle_tamper_fail_closed() {
    let compiled = compiled();
    let retry_commands = vec![command(ContextFamily::Retry, QSM_ALIAS, 0, 0), stop()];
    assert!(AplotAdversarialMatrix::new(
        &compiled,
        AplotMatrixSeed::new([0x92; 32]),
        vec![spec(
            AplotScenarioAxis::SecretRetryAttempt,
            AplotHostAxis::Continue,
            AplotResourceAxis::Nominal,
            retry_commands.clone(),
            nominal_limits(),
        )],
        AplotMatrixLimits::default(),
    )
    .is_err());
    assert!(AplotCounterexampleInput::new(
        AplotScenarioAxis::SecretRetryAttempt,
        AplotHostAxis::Continue,
        AplotResourceAxis::Nominal,
        retry_commands,
        nominal_limits(),
    )
    .is_err());

    let seed = AplotMatrixSeed::new([0x93; 32]);
    let input = AplotCounterexampleInput::new(
        AplotScenarioAxis::Normal,
        AplotHostAxis::Continue,
        AplotResourceAxis::Nominal,
        through(&compiled, 2),
        nominal_limits(),
    )
    .expect("counterexample input");
    let observed = injected_counterexample(&compiled, seed, &input).expect("observed mismatch");
    let mut bundle = shrink_aplot_counterexample("b".repeat(64), input, observed, |candidate| {
        injected_counterexample(&compiled, seed, candidate)
    })
    .expect("counterexample bundle");
    bundle.minimized.result_sha256.replace_range(0..1, "0");
    assert!(bundle.validate().is_err());
}

#[test]
fn frozen_bundle_contract_keeps_injection_radio_and_hardware_nonclaims() {
    let config = include_str!("../../../configs/quotient_seal/aplot_adversarial_bundle_v1.yaml");
    let docs = include_str!("../../../docs/quotient_seal_aplot_adversarial_bundle_v1.md");

    assert!(config.contains("secret_retry_encoding: DUPLICATE_PUBLIC_STEP"));
    assert!(config.contains("fault_resource_conflation: FORBIDDEN"));
    assert!(config.contains("verification: FULL_BUNDLE_RECOMPUTATION"));
    assert!(config.contains("TEST_INSTRUMENTATION_NOT_SCIENTIFIC_RESULT"));
    assert!(config.contains("hardware_status: NOT_VERIFIED"));
    assert!(docs.contains("科学的"));
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
