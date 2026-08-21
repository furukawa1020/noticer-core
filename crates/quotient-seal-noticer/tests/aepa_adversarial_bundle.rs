use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use noticer_aetp::PairwiseServiceAlias;
use noticer_protocol::WireServiceAlias;
use noticer_provenance::{AssuranceProfile, PipelineMeasurementHash};
use noticer_provenance_lease::LeaseVerifierKeyId;
use noticer_types::{ActionCode, Epoch, PolicyHash};
use quotient_forge_caqt::{
    artifact_digest, Certificate, CertificateLimits, CostVector, Digest, DomainHashes,
    ExpectedContract, ObserverRecord, OutputRecord, RelationPair, TransitionRecord, FORMAT_VERSION,
};
use quotient_forge_codegen::{generate_package, CodegenConfig};
use quotient_seal_abi::DeploymentProfile;
use quotient_seal_context::{
    ContextCommand, ContextFamily, EventKind, ProductCheckReport, ProductVerdict, RelationBinding,
    TargetEvent,
};
use quotient_seal_engine::ExecutionLimits;
use quotient_seal_noticer::{
    build_aepa_counterexample_bundle, compile_aepa_p0, evaluate_aepa_adversarial_matrix,
    prove_aepa_p1_resource_equality, revalidate_aepa_p1_resource_witness,
    verify_aepa_adversarial_execution, verify_aepa_counterexample_bundle, verify_aepa_k7,
    AepaAdversarialCaseSpec, AepaAdversarialMatrix, AepaAdversarialMatrixError,
    AepaAdversarialMatrixLimits, AepaAdversarialMatrixSeed, AepaCaseOutcome, AepaCompileLimits,
    AepaCompiledQsm, AepaCounterexampleError, AepaDifferentialEvidenceOrigin,
    AepaDifferentialVerdict, AepaEngineDigests, AepaK7Binding, AepaP1ResourceWitness,
    AepaP1Revalidation, AepaProfileAxis, AepaPublicInput, AepaPublicPolicyBinding,
    AepaPublicSourceArtifact, AepaScenarioAxis, AepaServiceCode, AepaShrinkOutcome,
    NoticerModuleBinding, NoticerModuleId, NoticerQsmManifest, P1ResourceEvidence,
};
use quotient_seal_relation::{RelationValidationReport, RelationVerdict};
use quotient_seal_resource::{ResourceAxis, ResourceCase, ResourceLimits};

const WIRE_ALIAS: WireServiceAlias = WireServiceAlias([0x21; 8]);
const PAIRWISE_ALIAS: PairwiseServiceAlias = PairwiseServiceAlias([0x31; 32]);
const POLICY: PolicyHash = PolicyHash([0x41; 32]);
const PIPELINE: PipelineMeasurementHash = PipelineMeasurementHash([0x51; 32]);
const LEASE_KEY: LeaseVerifierKeyId = LeaseVerifierKeyId([0x61; 8]);
const ATV2_KEY: [u8; 8] = [0x71; 8];
const EPOCH: Epoch = Epoch(9);
const WINDOW_START: u32 = 100;
const WINDOW_END: u32 = 104;
const QSM_ALIAS: u32 = 17;
const PRIVATE_SENTINEL: u64 = 0xded0_beef_cafe_7711;
static TEMPORARY_DIRECTORY_ID: AtomicU64 = AtomicU64::new(0);

#[test]
fn eighteen_case_matrix_crosses_real_p0_and_p1_gates_reproducibly() {
    let fixture = fixture();
    let first_matrix = matrix(&fixture.compiled);
    let second_matrix = matrix(&fixture.compiled);
    assert_eq!(first_matrix, second_matrix);
    assert_eq!(first_matrix.cases().len(), 18);
    assert_eq!(
        first_matrix.canonical_bytes(),
        second_matrix.canonical_bytes()
    );

    let first = execute(&fixture, &first_matrix).expect("first AEPA adversarial execution");
    let second = execute(&fixture, &second_matrix).expect("second AEPA adversarial execution");
    assert_eq!(first, second);
    assert_eq!(
        first.canonical_json().expect("first canonical JSON"),
        second.canonical_json().expect("second canonical JSON")
    );
    assert_eq!(first.match_cases, 12);
    assert_eq!(first.counterexample_cases, 2);
    assert_eq!(first.unresolved_cases, 4);
    assert_eq!(first.verdict, AepaDifferentialVerdict::Counterexample);
    assert_eq!(
        first
            .cases
            .iter()
            .filter(|case| case.profile_axis == "P0_PUBLIC_QUOTIENT_ONLY")
            .count(),
        9
    );
    assert_eq!(
        first
            .cases
            .iter()
            .filter(|case| case.profile_axis == "P1_SEALED_ADMISSION")
            .count(),
        9
    );

    for scenario in [
        "REPLAY",
        "EXPIRY",
        "DOWNGRADE",
        "WRONG_BINDING",
        "DUPLICATE",
    ] {
        let cases = first
            .cases
            .iter()
            .filter(|case| case.scenario_axis == scenario)
            .collect::<Vec<_>>();
        assert_eq!(cases.len(), 2);
        assert!(cases
            .iter()
            .all(|case| case.outcome == AepaCaseOutcome::SemanticMatch));
        assert!(cases
            .iter()
            .all(|case| case.verdict == AepaDifferentialVerdict::Match));
    }
    for scenario in ["FUEL_BOUNDARY", "HOST_CALL_BOUNDARY"] {
        let cases = first
            .cases
            .iter()
            .filter(|case| case.scenario_axis == scenario)
            .collect::<Vec<_>>();
        assert_eq!(cases.len(), 2);
        assert!(cases
            .iter()
            .all(|case| case.outcome == AepaCaseOutcome::ResourceUnresolved));
        assert!(cases
            .iter()
            .all(|case| case.verdict == AepaDifferentialVerdict::Unresolved));
    }
    for target_only in first
        .cases
        .iter()
        .filter(|case| case.scenario_axis == "TARGET_ONLY_ADMISSION")
    {
        assert_eq!(
            target_only.differential.evidence_origin,
            AepaDifferentialEvidenceOrigin::InjectedTestFixture
        );
        assert_eq!(
            target_only.differential.injection_label.as_deref(),
            Some("TARGET_ONLY_ADMISSION_TEST_INSTRUMENTATION")
        );
        assert_eq!(target_only.verdict, AepaDifferentialVerdict::Counterexample);
    }

    verify_aepa_adversarial_execution(
        &first,
        &fixture.source,
        &fixture.k7,
        &fixture.compiled,
        &fixture.p0_manifest,
        &fixture.p1_manifest,
        &fixture.revalidation,
        WINDOW_START + 1,
        &first_matrix,
        AepaAdversarialMatrixLimits::default(),
        &engine_digests(),
    )
    .expect("full adversarial execution recomputation");
}

#[test]
fn target_only_counterexample_shrinks_and_full_bundle_recomputes() {
    let fixture = fixture();
    let matrix = matrix(&fixture.compiled);
    let execution = execute(&fixture, &matrix).expect("AEPA adversarial execution");
    let target_case = matrix
        .cases()
        .iter()
        .find(|case| {
            case.profile() == AepaProfileAxis::P1SealedAdmission
                && case.scenario() == AepaScenarioAxis::TargetOnlyAdmission
        })
        .expect("P1 target-only case");
    let case_id = hex(target_case.case_id().as_bytes());

    let first =
        build_bundle(&fixture, &matrix, &execution, &case_id).expect("first counterexample bundle");
    let second = build_bundle(&fixture, &matrix, &execution, &case_id)
        .expect("second counterexample bundle");
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
        .any(|attempt| attempt.outcome == AepaShrinkOutcome::Preserved));
    assert_eq!(first.original_case_id_sha256, case_id);
    assert_eq!(first.hardware_status, "NOT_VERIFIED");
    assert!(
        !String::from_utf8(first.canonical_json().expect("bundle JSON"))
            .expect("UTF-8 bundle")
            .contains(&PRIVATE_SENTINEL.to_string())
    );

    verify_aepa_counterexample_bundle(
        &first,
        &fixture.source,
        &fixture.k7,
        &fixture.compiled,
        &fixture.p0_manifest,
        &fixture.p1_manifest,
        &fixture.revalidation,
        WINDOW_START + 1,
        &matrix,
        &execution,
        &case_id,
        AepaAdversarialMatrixLimits::default(),
        &engine_digests(),
    )
    .expect("full counterexample bundle recomputation");
}

#[test]
fn matrix_profile_tamper_scenario_mismatch_and_bundle_tamper_fail_closed() {
    let fixture = fixture();
    let mut specs = specs();
    specs.pop();
    assert_eq!(
        AepaAdversarialMatrix::new(
            &fixture.compiled,
            seed(),
            specs,
            AepaAdversarialMatrixLimits::default(),
        ),
        Err(AepaAdversarialMatrixError::CaseCoverage)
    );

    let mismatched = AepaAdversarialCaseSpec::new(
        AepaProfileAxis::P0PublicQuotientOnly,
        AepaScenarioAxis::Replay,
        normal_commands(),
        nominal_limits(),
    );
    assert!(quotient_seal_noticer::evaluate_aepa_adversarial_case_spec(
        &fixture.source,
        &fixture.k7,
        &fixture.compiled,
        &fixture.p0_manifest,
        &fixture.p1_manifest,
        &fixture.revalidation,
        WINDOW_START + 1,
        seed(),
        mismatched,
        AepaAdversarialMatrixLimits::default(),
        &engine_digests(),
    )
    .is_err());

    let matrix = matrix(&fixture.compiled);
    assert!(matches!(
        evaluate_aepa_adversarial_matrix(
            &fixture.source,
            &fixture.k7,
            &fixture.compiled,
            &fixture.p0_manifest,
            &fixture.p0_manifest,
            &fixture.revalidation,
            WINDOW_START + 1,
            &matrix,
            AepaAdversarialMatrixLimits::default(),
            &engine_digests(),
        ),
        Err(AepaAdversarialMatrixError::ProfileAuthorization(_))
    ));

    let execution = execute(&fixture, &matrix).expect("AEPA adversarial execution");
    let target_case = matrix
        .cases()
        .iter()
        .find(|case| case.scenario() == AepaScenarioAxis::TargetOnlyAdmission)
        .expect("target-only case");
    let case_id = hex(target_case.case_id().as_bytes());
    let mut bundle =
        build_bundle(&fixture, &matrix, &execution, &case_id).expect("counterexample bundle");
    bundle.minimized.result_sha256.replace_range(0..1, "0");
    assert_eq!(
        bundle.validate(),
        Err(AepaCounterexampleError::ArtifactContract)
    );
}

#[test]
fn frozen_contract_marks_injection_and_hardware_as_unverified() {
    let config = include_str!("../../../configs/quotient_seal/aepa_adversarial_bundle_v1.yaml");
    let docs = include_str!("../../../docs/quotient_seal_aepa_adversarial_bundle_v1.md");

    assert!(config.contains("required_case_count: 18"));
    assert!(config.contains("fault_resource_conflation: FORBIDDEN"));
    assert!(config.contains("verification: FULL_BUNDLE_RECOMPUTATION"));
    assert!(config.contains("injected_mismatch_origin: INJECTED_TEST_FIXTURE"));
    assert!(config.contains("polar_verity_sense_status: NOT_VERIFIED"));
    assert!(docs.contains("Issue #189"));
    assert!(docs.contains("Polar Verity Sense"));
    assert!(docs.contains("world-first"));
    assert!(docs.contains("NOT_VERIFIED"));
}

struct Fixture {
    source: AepaPublicSourceArtifact,
    k7: AepaK7Binding,
    compiled: AepaCompiledQsm,
    p0_manifest: NoticerQsmManifest,
    p1_manifest: NoticerQsmManifest,
    revalidation: AepaP1Revalidation,
}

fn fixture() -> Fixture {
    let source = fixture_source();
    let k7 = fixture_k7(&source);
    let compiled = compile_aepa_p0(
        &source,
        &k7,
        &[AepaServiceCode {
            service_alias: WIRE_ALIAS,
            qsm_alias: QSM_ALIAS,
        }],
        AepaCompileLimits::default(),
    )
    .expect("AEPA P0 compile");
    let relation = valid_relation(compiled.binding().target_ir_digest);
    let context = accepted_context(relation_binding(&relation));
    let private_cases = equal_resource_cases();
    let witness = prove_aepa_p1_resource_equality(
        &source,
        &k7,
        &compiled,
        &relation,
        &context,
        &private_cases,
        ResourceLimits::default(),
        WINDOW_START,
        WINDOW_END,
    )
    .expect("strict P1 resource witness");
    let revalidation = revalidate_aepa_p1_resource_witness(
        &witness,
        &source,
        &k7,
        &compiled,
        &relation,
        &context,
        &private_cases,
        ResourceLimits::default(),
    )
    .expect("fresh P1 resource revalidation");
    let p0_manifest = manifest(
        &source,
        &k7,
        &compiled,
        DeploymentProfile::P0PublicQuotientOnly,
        None,
    );
    let p1_manifest = manifest(
        &source,
        &k7,
        &compiled,
        DeploymentProfile::P1SealedAdmission,
        Some(&witness),
    );
    Fixture {
        source,
        k7,
        compiled,
        p0_manifest,
        p1_manifest,
        revalidation,
    }
}

fn fixture_source() -> AepaPublicSourceArtifact {
    let binding = AepaPublicPolicyBinding::new(
        WIRE_ALIAS,
        PAIRWISE_ALIAS,
        EPOCH,
        POLICY,
        LEASE_KEY,
        PIPELINE,
        AssuranceProfile::lab_reference().digest(),
        ATV2_KEY,
        WINDOW_START,
        WINDOW_END,
    )
    .expect("AEPA public policy binding");
    AepaPublicSourceArtifact::new(binding).expect("AEPA public source")
}

fn fixture_k7(source: &AepaPublicSourceArtifact) -> AepaK7Binding {
    let action = u32::from(ActionCode::RenderAmbientPulse as u16);
    let (certificate, expected) = caqt_certificate(action);
    let target = TemporaryDirectory::new("aepa-adversarial-bundle");
    generate_package(
        &certificate,
        expected,
        CertificateLimits::default(),
        &CodegenConfig {
            package_name: "generated-aepa-adversarial-bundle".to_owned(),
            quotient_inputs: 1,
            public_inputs: 1,
            fault_inputs: 1,
            max_payload_bytes: 64,
            max_actions: 8,
        },
        target.path(),
    )
    .expect("K7 generated package");
    let runtime = fs::read(target.path().join("codegen-manifest.toml")).expect("runtime manifest");
    verify_aepa_k7(
        source,
        &certificate,
        expected,
        CertificateLimits::default(),
        &runtime,
    )
    .expect("AEPA K7 binding")
}

fn caqt_certificate(required_action: u32) -> (Vec<u8>, ExpectedContract) {
    let actions = vec![required_action];
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
                payload: b"aepa-public-admission".to_vec(),
                actions: actions.clone(),
            },
            OutputRecord {
                id: 1,
                emitted: true,
                payload: b"aepa-public-admission".to_vec(),
                actions: actions.clone(),
            },
        ],
        transitions: vec![
            TransitionRecord {
                from: 0,
                input: 0,
                to: 1,
                output: 0,
                authorized_actions: actions.clone(),
                required_action: Some(required_action),
                recoverable_fault_action: None,
            },
            TransitionRecord {
                from: 1,
                input: 0,
                to: 1,
                output: 1,
                authorized_actions: actions,
                required_action: Some(required_action),
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

fn seed() -> AepaAdversarialMatrixSeed {
    AepaAdversarialMatrixSeed::new([0x91; 32]).expect("matrix seed")
}

fn matrix(compiled: &AepaCompiledQsm) -> AepaAdversarialMatrix {
    AepaAdversarialMatrix::new(
        compiled,
        seed(),
        specs(),
        AepaAdversarialMatrixLimits::default(),
    )
    .expect("AEPA adversarial matrix")
}

fn specs() -> Vec<AepaAdversarialCaseSpec> {
    AepaProfileAxis::ALL
        .iter()
        .copied()
        .flat_map(|profile| {
            AepaScenarioAxis::ALL.iter().copied().map(move |scenario| {
                let (commands, limits) = scenario_input(scenario);
                AepaAdversarialCaseSpec::new(profile, scenario, commands, limits)
            })
        })
        .collect()
}

fn scenario_input(scenario: AepaScenarioAxis) -> (Vec<ContextCommand>, ExecutionLimits) {
    match scenario {
        AepaScenarioAxis::Normal => (normal_commands(), nominal_limits()),
        AepaScenarioAxis::Replay => (
            vec![
                input_command(ContextFamily::Tick, AepaPublicInput::ValidatedAdmission, 0),
                input_command(
                    ContextFamily::CrossServiceReplay,
                    AepaPublicInput::Replay,
                    1,
                ),
                stop(),
            ],
            nominal_limits(),
        ),
        AepaScenarioAxis::Expiry => (
            vec![
                input_command(ContextFamily::Deadline, AepaPublicInput::Expired, 0),
                stop(),
            ],
            nominal_limits(),
        ),
        AepaScenarioAxis::Downgrade => (
            vec![
                input_command(
                    ContextFamily::ServiceCollusion,
                    AepaPublicInput::Downgrade,
                    0,
                ),
                stop(),
            ],
            nominal_limits(),
        ),
        AepaScenarioAxis::WrongBinding => (
            vec![
                input_command(
                    ContextFamily::ServiceCollusion,
                    AepaPublicInput::WrongBinding,
                    0,
                ),
                stop(),
            ],
            nominal_limits(),
        ),
        AepaScenarioAxis::Duplicate => {
            let admission =
                input_command(ContextFamily::Tick, AepaPublicInput::ValidatedAdmission, 0);
            (vec![admission.clone(), admission, stop()], nominal_limits())
        }
        AepaScenarioAxis::TargetOnlyAdmission => (
            vec![
                input_command(ContextFamily::Tick, AepaPublicInput::PublicTick, 0),
                input_command(ContextFamily::Tick, AepaPublicInput::PublicTick, 1),
                input_command(ContextFamily::Tick, AepaPublicInput::ValidatedAdmission, 2),
                stop(),
            ],
            nominal_limits(),
        ),
        AepaScenarioAxis::FuelBoundary => {
            let mut limits = nominal_limits();
            limits.fuel = 1;
            (normal_commands(), limits)
        }
        AepaScenarioAxis::HostCallBoundary => {
            let mut limits = nominal_limits();
            limits.max_host_calls = 1;
            (normal_commands(), limits)
        }
    }
}

fn normal_commands() -> Vec<ContextCommand> {
    vec![
        input_command(ContextFamily::Tick, AepaPublicInput::ValidatedAdmission, 0),
        stop(),
    ]
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

fn stop() -> ContextCommand {
    ContextCommand {
        family: ContextFamily::Stop,
        kind: ContextFamily::Stop.command_kind(),
        service_alias: 0,
        public_slot: 0,
        fault: 0,
        payload_tag: 0,
    }
}

fn nominal_limits() -> ExecutionLimits {
    ExecutionLimits {
        fuel: 1_000_000,
        max_memory_pages: 2,
        max_host_calls: 128,
        timeout_ms: 2_000,
    }
}

fn engine_digests() -> AepaEngineDigests {
    AepaEngineDigests::new("1".repeat(64), "2".repeat(64), "3".repeat(64)).expect("engine digests")
}

fn execute(
    fixture: &Fixture,
    matrix: &AepaAdversarialMatrix,
) -> Result<quotient_seal_noticer::AepaAdversarialExecutionArtifact, AepaAdversarialMatrixError> {
    evaluate_aepa_adversarial_matrix(
        &fixture.source,
        &fixture.k7,
        &fixture.compiled,
        &fixture.p0_manifest,
        &fixture.p1_manifest,
        &fixture.revalidation,
        WINDOW_START + 1,
        matrix,
        AepaAdversarialMatrixLimits::default(),
        &engine_digests(),
    )
}

fn build_bundle(
    fixture: &Fixture,
    matrix: &AepaAdversarialMatrix,
    execution: &quotient_seal_noticer::AepaAdversarialExecutionArtifact,
    case_id: &str,
) -> Result<quotient_seal_noticer::AepaCounterexampleBundle, AepaCounterexampleError> {
    build_aepa_counterexample_bundle(
        &fixture.source,
        &fixture.k7,
        &fixture.compiled,
        &fixture.p0_manifest,
        &fixture.p1_manifest,
        &fixture.revalidation,
        WINDOW_START + 1,
        matrix,
        execution,
        case_id,
        AepaAdversarialMatrixLimits::default(),
        &engine_digests(),
    )
}

fn manifest(
    source: &AepaPublicSourceArtifact,
    k7: &AepaK7Binding,
    compiled: &AepaCompiledQsm,
    profile: DeploymentProfile,
    witness: Option<&AepaP1ResourceWitness>,
) -> NoticerQsmManifest {
    let evidence = witness.map(|witness| P1ResourceEvidence {
        equivalence_certificate_digest: witness.digest(),
        relation_binding_digest: witness.relation_binding_digest(),
        checked_cases: witness.checked_cases(),
    });
    let entries = NoticerModuleId::ALL
        .iter()
        .copied()
        .map(|module_id| {
            let code = module_id as u8;
            if module_id == NoticerModuleId::Aepa {
                NoticerModuleBinding {
                    module_id,
                    deployment_profile: profile,
                    service_alias: source.binding().wire_service_alias(),
                    epoch: source.binding().epoch(),
                    policy_hash: source.binding().policy_hash(),
                    source_digest: source.digest(),
                    source_certificate_digest: k7.certificate_digest(),
                    generated_runtime_digest: k7.generated_runtime_digest(),
                    qsm_capsule_digest: compiled.binding().capsule_digest,
                    observer_registry_digest: compiled.binding().observer_registry_digest,
                    p1_resource_evidence: evidence,
                }
            } else {
                NoticerModuleBinding {
                    module_id,
                    deployment_profile: DeploymentProfile::P0PublicQuotientOnly,
                    service_alias: WireServiceAlias([code; 8]),
                    epoch: Epoch(u64::from(code)),
                    policy_hash: PolicyHash([code; 32]),
                    source_digest: dummy_digest(module_id, 1),
                    source_certificate_digest: dummy_digest(module_id, 2),
                    generated_runtime_digest: dummy_digest(module_id, 3),
                    qsm_capsule_digest: dummy_digest(module_id, 4),
                    observer_registry_digest: dummy_digest(module_id, 5),
                    p1_resource_evidence: None,
                }
            }
        })
        .collect();
    NoticerQsmManifest::new(entries).expect("Noticer manifest")
}

fn valid_relation(target_ir_digest: Digest) -> RelationVerdict {
    RelationVerdict::Valid(Box::new(RelationValidationReport {
        relation_digest: digest(0x81),
        inductive_digest: digest(0x82),
        target_ir_digest,
        reachable_states: 2,
        checked_source_steps: 2,
        checked_lifecycle_calls: 1,
        checked_two_run_cases: 1,
        checked_observer_events: 2,
    }))
}

fn relation_binding(verdict: &RelationVerdict) -> RelationBinding {
    let RelationVerdict::Valid(report) = verdict else {
        panic!("test fixture must be valid");
    };
    RelationBinding::from_report(report)
}

fn accepted_context(binding: RelationBinding) -> ProductVerdict {
    ProductVerdict::Accept(Box::new(ProductCheckReport {
        binding,
        observer_profiles: 7,
        context_families: 12,
        private_pairs: 1,
        visited_product_states: 4,
        checked_edges: 8,
        maximum_shortest_prefix: 2,
        declared_product_bound: 64,
        induction_closed: true,
    }))
}

fn equal_resource_cases() -> Vec<ResourceCase> {
    let events = resource_events(PRIVATE_SENTINEL);
    vec![resource_case(events.clone(), events)]
}

fn resource_case(left: Vec<TargetEvent>, right: Vec<TargetEvent>) -> ResourceCase {
    let mut left_trace = vec![public_action()];
    left_trace.extend(left);
    let mut right_trace = vec![public_action()];
    right_trace.extend(right);
    ResourceCase {
        pair: RelationPair { left: 1, right: 2 },
        left_trace,
        right_trace,
    }
}

fn public_action() -> TargetEvent {
    TargetEvent {
        kind: EventKind::Action,
        label: 10,
        slot: 0,
        value: 7,
    }
}

fn resource_events(private_value: u64) -> Vec<TargetEvent> {
    [
        ResourceAxis::Opcode,
        ResourceAxis::Branch,
        ResourceAxis::MemoryAddress,
        ResourceAxis::Import,
        ResourceAxis::Fuel,
        ResourceAxis::MemoryPages,
    ]
    .iter()
    .copied()
    .map(|axis| {
        let kind = match axis {
            ResourceAxis::Opcode => EventKind::Instruction,
            ResourceAxis::Branch => EventKind::Control,
            ResourceAxis::MemoryAddress => EventKind::MemoryAccess,
            ResourceAxis::Import => EventKind::HostCall,
            ResourceAxis::Fuel => EventKind::Resource,
            ResourceAxis::MemoryPages => EventKind::MemoryGrow,
        };
        TargetEvent {
            kind,
            label: u32::from(axis as u8) + 1,
            slot: u64::from(axis as u8),
            value: private_value.wrapping_add(u64::from(axis as u8)),
        }
    })
    .collect()
}

fn dummy_digest(module: NoticerModuleId, field: u8) -> Digest {
    artifact_digest(b"noticer-aepa-adversarial-test", &[module as u8, field])
}

const fn digest(seed: u8) -> Digest {
    Digest::new([seed; 32])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct TemporaryDirectory(PathBuf);

impl TemporaryDirectory {
    fn new(label: &str) -> Self {
        let sequence = TEMPORARY_DIRECTORY_ID.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        Self(std::env::temp_dir().join(format!(
            "noticer-core-{label}-{}-{nanos}-{sequence}",
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
