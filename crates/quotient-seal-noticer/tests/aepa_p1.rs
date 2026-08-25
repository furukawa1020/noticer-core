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
    EventKind, ProductCheckReport, ProductVerdict, RelationBinding, TargetEvent,
};
use quotient_seal_noticer::{
    authorize_aepa_profile, compile_aepa_p0, evaluate_release_stack_profile,
    execute_canonical_release_path, issue_aepa_p1_resource_witness,
    prove_aepa_p1_resource_equality, revalidate_aepa_p1_resource_witness, verify_aepa_k7,
    verify_release_stack_profile, AepaCompileLimits, AepaCompiledQsm, AepaK7Binding, AepaP1Error,
    AepaP1ResourceWitness, AepaPublicPolicyBinding, AepaPublicSourceArtifact, AepaServiceCode,
    NoticerModuleBinding, NoticerModuleId, NoticerQsmManifest, P1ResourceEvidence, ReleasePathKind,
    ReleaseStackCompositionContract, ReleaseStackProfileUnresolvedReason,
    ReleaseStackProfileVerdict, ReleaseStackPublicInput,
};
use quotient_seal_relation::{RelationValidationReport, RelationVerdict};
use quotient_seal_resource::{
    check_resource_strict, ResourceAxis, ResourceCase, ResourceLimits, ResourceVerdict,
};

const WIRE_ALIAS: WireServiceAlias = WireServiceAlias([0x21; 8]);
const PAIRWISE_ALIAS: PairwiseServiceAlias = PairwiseServiceAlias([0x31; 32]);
const POLICY: PolicyHash = PolicyHash([0x41; 32]);
const PIPELINE: PipelineMeasurementHash = PipelineMeasurementHash([0x51; 32]);
const LEASE_KEY: LeaseVerifierKeyId = LeaseVerifierKeyId([0x61; 8]);
const ATV2_KEY: [u8; 8] = [0x71; 8];
const EPOCH: Epoch = Epoch(9);
const WINDOW_START: u32 = 100;
const WINDOW_END: u32 = 104;
const PRIVATE_SENTINEL: u64 = 0xded0_beef_cafe_7711;
static TEMPORARY_DIRECTORY_ID: AtomicU64 = AtomicU64::new(0);

#[test]
fn strict_witness_is_reproducible_and_authorizes_p1() {
    let fixture = fixture();
    let cases = equal_cases(PRIVATE_SENTINEL);
    let first = prove_witness(&fixture, &cases).expect("strict P1 witness");
    let second = prove_witness(&fixture, &cases).expect("reproduced P1 witness");

    assert_eq!(first, second);
    assert_eq!(first.canonical_bytes(), second.canonical_bytes());
    assert_eq!(first.checked_cases(), 1);
    assert!(first.checked_resource_events() >= 12);
    assert_eq!(first.validity_window(), (WINDOW_START, WINDOW_END));
    assert!(!first
        .canonical_bytes()
        .windows(size_of::<u64>())
        .any(|window| window == PRIVATE_SENTINEL.to_le_bytes().as_slice()));

    let fresh = revalidate(&fixture, &cases, &first).expect("fresh strict revalidation");
    let manifest = manifest(&fixture, DeploymentProfile::P1SealedAdmission, Some(&first));
    let authorization = authorize_aepa_profile(
        DeploymentProfile::P1SealedAdmission,
        &manifest,
        &fixture.source,
        &fixture.k7,
        &fixture.compiled,
        Some(&fresh),
        WINDOW_START + 1,
    )
    .expect("P1 authorization");

    assert_eq!(
        authorization.profile(),
        DeploymentProfile::P1SealedAdmission
    );
    assert_eq!(authorization.witness_digest(), Some(first.digest()));
    assert_eq!(authorization.public_step(), WINDOW_START + 1);
    assert_ne!(authorization.authorization_digest(), Digest::zero());
}

#[test]
fn release_stack_reuses_fresh_aepa_authorization_without_downgrade() {
    let fixture = fixture();
    let cases = equal_cases(PRIVATE_SENTINEL);
    let witness = prove_witness(&fixture, &cases).expect("strict P1 witness");
    let fresh = revalidate(&fixture, &cases, &witness).expect("fresh strict revalidation");
    let manifest = manifest(
        &fixture,
        DeploymentProfile::P1SealedAdmission,
        Some(&witness),
    );
    let public_step = WINDOW_START + 1;
    let authorization = authorize_aepa_profile(
        DeploymentProfile::P1SealedAdmission,
        &manifest,
        &fixture.source,
        &fixture.k7,
        &fixture.compiled,
        Some(&fresh),
        public_step,
    )
    .expect("sealed AEPA authorization");
    let contract = ReleaseStackCompositionContract::new(manifest).expect("composition");
    let input =
        ReleaseStackPublicInput::new(ReleasePathKind::Action, u64::from(public_step), Some(7))
            .expect("public input");
    let path = execute_canonical_release_path(&contract, input).expect("release path");

    let accepted = evaluate_release_stack_profile(
        &contract,
        &path,
        DeploymentProfile::P1SealedAdmission,
        public_step,
        Some(&authorization),
    )
    .expect("stack profile");
    assert_eq!(accepted.verdict, ReleaseStackProfileVerdict::Authorized);
    assert_eq!(
        accepted.effective_profile,
        Some(DeploymentProfile::P1SealedAdmission)
    );
    assert_eq!(accepted.manifest_evidence_digest, Some(witness.digest()));
    verify_release_stack_profile(&contract, &path, &accepted, Some(&authorization))
        .expect("verify stack profile");

    let stale = evaluate_release_stack_profile(
        &contract,
        &path,
        DeploymentProfile::P1SealedAdmission,
        public_step + 1,
        Some(&authorization),
    )
    .expect("stale profile result");
    assert_eq!(stale.verdict, ReleaseStackProfileVerdict::ProfileUnresolved);
    assert_eq!(stale.effective_profile, None);
    assert_eq!(
        stale.unresolved_reason,
        Some(ReleaseStackProfileUnresolvedReason::AuthorizationStepMismatch)
    );
}

#[test]
fn missing_stale_mismatched_and_implicit_upgrade_paths_fail_closed() {
    let fixture = fixture();
    let cases = equal_cases(PRIVATE_SENTINEL);
    let witness = prove_witness(&fixture, &cases).expect("strict P1 witness");
    let fresh = revalidate(&fixture, &cases, &witness).expect("fresh strict revalidation");
    let p1_manifest = manifest(
        &fixture,
        DeploymentProfile::P1SealedAdmission,
        Some(&witness),
    );

    let accepted_without_witness = (WINDOW_START..WINDOW_END)
        .filter(|public_step| {
            authorize_aepa_profile(
                DeploymentProfile::P1SealedAdmission,
                &p1_manifest,
                &fixture.source,
                &fixture.k7,
                &fixture.compiled,
                None,
                *public_step,
            )
            .is_ok()
        })
        .count();
    assert_eq!(accepted_without_witness, 0);

    assert_eq!(
        authorize_aepa_profile(
            DeploymentProfile::P1SealedAdmission,
            &p1_manifest,
            &fixture.source,
            &fixture.k7,
            &fixture.compiled,
            Some(&fresh),
            WINDOW_END,
        ),
        Err(AepaP1Error::StaleWitness {
            public_step: WINDOW_END
        })
    );

    let changed_cases = equal_cases(PRIVATE_SENTINEL.wrapping_add(1));
    assert_eq!(
        revalidate(&fixture, &changed_cases, &witness),
        Err(AepaP1Error::WitnessMismatch)
    );

    let mismatched_manifest = manifest_with_evidence(
        &fixture,
        DeploymentProfile::P1SealedAdmission,
        Some(P1ResourceEvidence {
            equivalence_certificate_digest: dummy_digest(NoticerModuleId::Aepa, 91),
            relation_binding_digest: witness.relation_binding_digest(),
            checked_cases: witness.checked_cases(),
        }),
    );
    assert_eq!(
        authorize_aepa_profile(
            DeploymentProfile::P1SealedAdmission,
            &mismatched_manifest,
            &fixture.source,
            &fixture.k7,
            &fixture.compiled,
            Some(&fresh),
            WINDOW_START,
        ),
        Err(AepaP1Error::ManifestEvidenceMismatch)
    );

    let p0_manifest = manifest(&fixture, DeploymentProfile::P0PublicQuotientOnly, None);
    assert_eq!(
        authorize_aepa_profile(
            DeploymentProfile::P1SealedAdmission,
            &p0_manifest,
            &fixture.source,
            &fixture.k7,
            &fixture.compiled,
            Some(&fresh),
            WINDOW_START,
        ),
        Err(AepaP1Error::ProfileMismatch)
    );
    assert_eq!(
        authorize_aepa_profile(
            DeploymentProfile::P0PublicQuotientOnly,
            &p0_manifest,
            &fixture.source,
            &fixture.k7,
            &fixture.compiled,
            Some(&fresh),
            WINDOW_START,
        ),
        Err(AepaP1Error::UnexpectedP1Witness)
    );
}

#[test]
fn normalized_counterexample_and_inconclusive_verdicts_never_issue_witnesses() {
    let fixture = fixture();
    let cases = equal_cases(PRIVATE_SENTINEL);
    let strict = check_resource_strict(
        &fixture.relation,
        &fixture.context,
        &cases,
        ResourceLimits::default(),
    );
    let ResourceVerdict::Strict(report) = strict else {
        panic!("fixture must produce strict resource equality");
    };
    assert_eq!(
        issue_aepa_p1_resource_witness(
            &fixture.source,
            &fixture.k7,
            &fixture.compiled,
            &cases,
            ResourceVerdict::Normalized(report),
            WINDOW_START,
            WINDOW_END,
        ),
        Err(AepaP1Error::NormalizationForbidden)
    );

    let divergent = divergent_cases();
    assert!(matches!(
        prove_witness(&fixture, &divergent),
        Err(AepaP1Error::ResourceCounterexample { .. })
    ));

    let inconclusive = check_resource_strict(
        &fixture.relation,
        &fixture.context,
        &[],
        ResourceLimits::default(),
    );
    assert_eq!(
        issue_aepa_p1_resource_witness(
            &fixture.source,
            &fixture.k7,
            &fixture.compiled,
            &[],
            inconclusive,
            WINDOW_START,
            WINDOW_END,
        ),
        Err(AepaP1Error::ResourceInconclusive)
    );
}

struct Fixture {
    source: AepaPublicSourceArtifact,
    k7: AepaK7Binding,
    compiled: AepaCompiledQsm,
    relation: RelationVerdict,
    context: ProductVerdict,
}

fn fixture() -> Fixture {
    let source = fixture_source();
    let k7 = fixture_k7(&source);
    let compiled = compile_aepa_p0(
        &source,
        &k7,
        &[AepaServiceCode {
            service_alias: WIRE_ALIAS,
            qsm_alias: 17,
        }],
        AepaCompileLimits::default(),
    )
    .expect("AEPA P0 compile");
    let relation = valid_relation(compiled.binding().target_ir_digest);
    let context = accepted_context(relation_binding(&relation));
    Fixture {
        source,
        k7,
        compiled,
        relation,
        context,
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
    let target = TemporaryDirectory::new("aepa-p1-resource-gate");
    generate_package(
        &certificate,
        expected,
        CertificateLimits::default(),
        &CodegenConfig {
            package_name: "generated-aepa-p1-resource-gate".to_owned(),
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

fn prove_witness(
    fixture: &Fixture,
    cases: &[ResourceCase],
) -> Result<AepaP1ResourceWitness, AepaP1Error> {
    prove_aepa_p1_resource_equality(
        &fixture.source,
        &fixture.k7,
        &fixture.compiled,
        &fixture.relation,
        &fixture.context,
        cases,
        ResourceLimits::default(),
        WINDOW_START,
        WINDOW_END,
    )
}

fn revalidate(
    fixture: &Fixture,
    cases: &[ResourceCase],
    witness: &AepaP1ResourceWitness,
) -> Result<quotient_seal_noticer::AepaP1Revalidation, AepaP1Error> {
    revalidate_aepa_p1_resource_witness(
        witness,
        &fixture.source,
        &fixture.k7,
        &fixture.compiled,
        &fixture.relation,
        &fixture.context,
        cases,
        ResourceLimits::default(),
    )
}

fn manifest(
    fixture: &Fixture,
    profile: DeploymentProfile,
    witness: Option<&AepaP1ResourceWitness>,
) -> NoticerQsmManifest {
    manifest_with_evidence(
        fixture,
        profile,
        witness.map(|witness| P1ResourceEvidence {
            equivalence_certificate_digest: witness.digest(),
            relation_binding_digest: witness.relation_binding_digest(),
            checked_cases: witness.checked_cases(),
        }),
    )
}

fn manifest_with_evidence(
    fixture: &Fixture,
    profile: DeploymentProfile,
    evidence: Option<P1ResourceEvidence>,
) -> NoticerQsmManifest {
    let entries = NoticerModuleId::ALL
        .iter()
        .copied()
        .map(|module_id| {
            let code = module_id as u8;
            if module_id == NoticerModuleId::Aepa {
                NoticerModuleBinding {
                    module_id,
                    deployment_profile: profile,
                    service_alias: fixture.source.binding().wire_service_alias(),
                    epoch: fixture.source.binding().epoch(),
                    policy_hash: fixture.source.binding().policy_hash(),
                    source_digest: fixture.source.digest(),
                    source_certificate_digest: fixture.k7.certificate_digest(),
                    generated_runtime_digest: fixture.k7.generated_runtime_digest(),
                    qsm_capsule_digest: fixture.compiled.binding().capsule_digest,
                    observer_registry_digest: fixture.compiled.binding().observer_registry_digest,
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

fn equal_cases(private_value: u64) -> Vec<ResourceCase> {
    let events = resource_events(private_value);
    vec![resource_case(events.clone(), events)]
}

fn divergent_cases() -> Vec<ResourceCase> {
    vec![resource_case(
        resource_events(PRIVATE_SENTINEL),
        resource_events(PRIVATE_SENTINEL.wrapping_add(1)),
    )]
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
    artifact_digest(b"noticer-aepa-p1-resource-test", &[module as u8, field])
}

const fn digest(seed: u8) -> Digest {
    Digest::new([seed; 32])
}

struct TemporaryDirectory(PathBuf);

impl TemporaryDirectory {
    fn new(label: &str) -> Self {
        let sequence = TEMPORARY_DIRECTORY_ID.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "noticer-core-{label}-{}-{nanos}-{sequence}",
            std::process::id()
        ));
        Self(path)
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
