use std::collections::BTreeSet;
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
    artifact_digest, Certificate, CertificateLimits, CostVector, DomainHashes, ExpectedContract,
    ObserverRecord, OutputRecord, RelationPair, TransitionRecord, FORMAT_VERSION,
};
use quotient_forge_codegen::{generate_package, CodegenConfig};
use quotient_seal_abi::DeploymentProfile;
use quotient_seal_noticer::{
    bind_aepa_compiled_manifest, compile_aepa_p0, verify_aepa_k7, AepaCompileError,
    AepaCompileLimits, AepaCompiledQsm, AepaK7Binding, AepaLoweredTransition, AepaPublicInput,
    AepaPublicOutput, AepaPublicPolicyBinding, AepaPublicSourceArtifact, AepaPublicState,
    AepaServiceCode, NoticerModuleBinding, NoticerModuleId, NoticerQsmManifest,
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
const QSM_ALIAS: u32 = 17;
static TEMPORARY_DIRECTORY_ID: AtomicU64 = AtomicU64::new(0);

fn assurance() -> AssuranceProfileDigest {
    AssuranceProfile::lab_reference().digest()
}

fn fixture_source(wire_alias: WireServiceAlias) -> AepaPublicSourceArtifact {
    let binding = AepaPublicPolicyBinding::new(
        wire_alias,
        PAIRWISE_ALIAS,
        EPOCH,
        POLICY,
        LEASE_KEY,
        PIPELINE,
        assurance(),
        ATV2_KEY,
        WINDOW_START,
        WINDOW_END,
    )
    .expect("AEPA public policy binding");
    AepaPublicSourceArtifact::new(binding).expect("AEPA public source")
}

fn action_code() -> u32 {
    u32::from(ActionCode::RenderAmbientPulse as u16)
}

fn caqt_certificate(required_action: Option<u32>) -> (Vec<u8>, ExpectedContract) {
    let actions = required_action.into_iter().collect::<Vec<_>>();
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
                required_action,
                recoverable_fault_action: None,
            },
            TransitionRecord {
                from: 1,
                input: 0,
                to: 1,
                output: 1,
                authorized_actions: actions,
                required_action,
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

fn fixture_k7(source: &AepaPublicSourceArtifact, required_action: Option<u32>) -> AepaK7Binding {
    let (certificate, expected) = caqt_certificate(required_action);
    let target = TemporaryDirectory::new("aepa-p0-compiler");
    generate_package(
        &certificate,
        expected,
        CertificateLimits::default(),
        &CodegenConfig {
            package_name: "generated-aepa-p0-compiler".to_owned(),
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

fn service_code() -> AepaServiceCode {
    AepaServiceCode {
        service_alias: WIRE_ALIAS,
        qsm_alias: QSM_ALIAS,
    }
}

fn compile_fixture(source: &AepaPublicSourceArtifact, k7: &AepaK7Binding) -> AepaCompiledQsm {
    compile_aepa_p0(source, k7, &[service_code()], AepaCompileLimits::default())
        .expect("AEPA P0 compile")
}

fn dummy_digest(module: NoticerModuleId, field: u8) -> quotient_forge_caqt::Digest {
    artifact_digest(b"noticer-aepa-compiler-test", &[module as u8, field])
}

fn manifest(
    source: &AepaPublicSourceArtifact,
    k7: &AepaK7Binding,
    compiled: &AepaCompiledQsm,
) -> NoticerQsmManifest {
    let entries = NoticerModuleId::ALL
        .iter()
        .copied()
        .map(|module_id| {
            let code = module_id as u8;
            if module_id == NoticerModuleId::Aepa {
                NoticerModuleBinding {
                    module_id,
                    deployment_profile: DeploymentProfile::P0PublicQuotientOnly,
                    service_alias: source.binding().wire_service_alias(),
                    epoch: source.binding().epoch(),
                    policy_hash: source.binding().policy_hash(),
                    source_digest: source.digest(),
                    source_certificate_digest: k7.certificate_digest(),
                    generated_runtime_digest: k7.generated_runtime_digest(),
                    qsm_capsule_digest: compiled.binding().capsule_digest,
                    observer_registry_digest: compiled.binding().observer_registry_digest,
                    p1_resource_evidence: None,
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

fn transition(
    compiled: &AepaCompiledQsm,
    state: AepaPublicState,
    input: AepaPublicInput,
) -> AepaLoweredTransition {
    compiled
        .transitions()
        .iter()
        .copied()
        .find(|transition| transition.source_state == state && transition.public_input == input)
        .expect("lowered transition")
}

#[test]
fn compile_is_byte_identical_and_refines_all_transitions() {
    let source = fixture_source(WIRE_ALIAS);
    let k7 = fixture_k7(&source, Some(action_code()));
    let first = compile_fixture(&source, &k7);
    let second = compile_fixture(&source, &k7);

    assert_eq!(first, second);
    assert_eq!(first.wasm(), second.wasm());
    assert_eq!(first.capsule(), second.capsule());
    assert_eq!(first.compiler_manifest(), second.compiler_manifest());
    assert_eq!(first.transitions().len(), 36);
    assert!(first.refines(&source));
    assert_eq!(first.admission_action(), action_code());
    assert_eq!(first.service_code(), service_code());

    let source_steps = source
        .transitions()
        .iter()
        .map(|step| (step.from(), step.input(), step.to(), step.output()))
        .collect::<BTreeSet<_>>();
    let target_steps = first
        .transitions()
        .iter()
        .map(|step| {
            (
                step.source_state,
                step.public_input,
                step.target_state,
                step.public_output,
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(source_steps, target_steps);
    assert_eq!(first.binding().source_digest, source.digest());
    assert_eq!(first.binding().certificate_digest, k7.certificate_digest());
    assert_eq!(
        first.binding().generated_runtime_digest,
        k7.generated_runtime_digest()
    );
    assert!(quotient_seal_capsule::QsmCapsule::decode(
        first.capsule(),
        quotient_seal_capsule::QsmContainerLimits::default(),
    )
    .is_ok());

    let manifest = String::from_utf8_lossy(first.compiler_manifest());
    for required in [
        "aepa.action_code",
        "aepa.admission_window_end",
        "aepa.assurance_profile_digest",
        "aepa.lease_verifier_key_id",
        "aepa.pipeline_measurement_hash",
        "aepa.transition_digest",
        "CHECKED_ALL_36_SOURCE_TRANSITIONS",
        "NOT_VERIFIED",
    ] {
        assert!(manifest.contains(required));
    }
}

#[test]
fn reset_handoff_fault_and_expiry_are_lowered_without_gaps() {
    let source = fixture_source(WIRE_ALIAS);
    let k7 = fixture_k7(&source, Some(action_code()));
    let compiled = compile_fixture(&source, &k7);

    let admitted = transition(
        &compiled,
        AepaPublicState::Waiting,
        AepaPublicInput::ValidatedAdmission,
    );
    assert_eq!(admitted.target_state, AepaPublicState::Admitted);
    assert_eq!(admitted.public_output, AepaPublicOutput::AdmitOnce);

    let duplicate = transition(
        &compiled,
        AepaPublicState::Admitted,
        AepaPublicInput::ValidatedAdmission,
    );
    assert_eq!(duplicate.target_state, AepaPublicState::CoverRequired);
    assert_eq!(duplicate.public_output, AepaPublicOutput::Reject);

    let expired = transition(
        &compiled,
        AepaPublicState::Waiting,
        AepaPublicInput::Expired,
    );
    assert_eq!(expired.target_state, AepaPublicState::CoverRequired);
    assert_eq!(expired.public_output, AepaPublicOutput::Reject);

    for state in AepaPublicState::ALL {
        for input in [AepaPublicInput::Reset, AepaPublicInput::Handoff] {
            let lowered = transition(&compiled, state, input);
            assert_eq!(lowered.target_state, AepaPublicState::Waiting);
            assert_eq!(lowered.public_output, AepaPublicOutput::Cover);
        }
        let fault = transition(&compiled, state, AepaPublicInput::Fault);
        assert_eq!(fault.target_state, AepaPublicState::Faulted);
        assert_eq!(fault.public_output, AepaPublicOutput::Fault);
    }
}

#[test]
fn registry_capsule_binding_and_tamper_fail_closed() {
    let source = fixture_source(WIRE_ALIAS);
    let k7 = fixture_k7(&source, Some(action_code()));
    let compiled = compile_fixture(&source, &k7);
    let registry = manifest(&source, &k7, &compiled);
    let binding = bind_aepa_compiled_manifest(&registry, &source, &k7, &compiled)
        .expect("compiled AEPA registry binding");
    assert_eq!(binding.source_digest, source.digest());
    assert_eq!(binding.capsule_digest, compiled.binding().capsule_digest);
    assert_eq!(binding.module_digest, compiled.binding().module_digest);
    assert_eq!(binding.abi_digest, compiled.binding().abi_digest);

    let mut entries = registry.entries().to_vec();
    let aepa = entries
        .iter_mut()
        .find(|entry| entry.module_id == NoticerModuleId::Aepa)
        .expect("AEPA registry entry");
    aepa.qsm_capsule_digest = dummy_digest(NoticerModuleId::Aepa, 99);
    let tampered = NoticerQsmManifest::new(entries).expect("tampered registry shape");
    assert_eq!(
        bind_aepa_compiled_manifest(&tampered, &source, &k7, &compiled),
        Err(AepaCompileError::ArtifactDigestMismatch {
            field: "registry_capsule"
        })
    );
}

#[test]
fn unsupported_action_mapping_and_resource_limits_fail_closed() {
    let source = fixture_source(WIRE_ALIAS);
    let k7 = fixture_k7(&source, Some(action_code()));
    let compile = |codes: &[AepaServiceCode], limits| compile_aepa_p0(&source, &k7, codes, limits);

    assert!(compile(&[], AepaCompileLimits::default()).is_err());
    assert!(compile(
        &[AepaServiceCode {
            service_alias: WireServiceAlias([0x99; 8]),
            qsm_alias: QSM_ALIAS,
        }],
        AepaCompileLimits::default(),
    )
    .is_err());
    assert!(compile(
        &[AepaServiceCode {
            service_alias: WIRE_ALIAS,
            qsm_alias: 0,
        }],
        AepaCompileLimits::default(),
    )
    .is_err());
    for limits in [
        AepaCompileLimits {
            max_states: 3,
            ..AepaCompileLimits::default()
        },
        AepaCompileLimits {
            max_public_inputs: 8,
            ..AepaCompileLimits::default()
        },
        AepaCompileLimits {
            max_transitions: 35,
            ..AepaCompileLimits::default()
        },
        AepaCompileLimits {
            max_wasm_bytes: 8,
            ..AepaCompileLimits::default()
        },
        AepaCompileLimits {
            max_capsule_bytes: 64,
            ..AepaCompileLimits::default()
        },
    ] {
        assert!(compile(&[service_code()], limits).is_err());
    }

    let no_action_k7 = fixture_k7(&source, None);
    assert_eq!(
        compile_aepa_p0(
            &source,
            &no_action_k7,
            &[service_code()],
            AepaCompileLimits::default(),
        ),
        Err(AepaCompileError::UnsupportedActionSemantics)
    );

    let other_source = fixture_source(WireServiceAlias([0x22; 8]));
    let other_k7 = fixture_k7(&other_source, Some(action_code()));
    assert_eq!(
        compile_aepa_p0(
            &source,
            &other_k7,
            &[service_code()],
            AepaCompileLimits::default(),
        ),
        Err(AepaCompileError::K7SourceMismatch)
    );
}

#[test]
fn generated_surface_and_frozen_contract_exclude_private_ingress() {
    let source = fixture_source(WIRE_ALIAS);
    let k7 = fixture_k7(&source, Some(action_code()));
    let compiled = compile_fixture(&source, &k7);
    let wasm_text = String::from_utf8_lossy(compiled.wasm());
    for required in ["qseal", "emit_frame", "emit_action", "public_failure"] {
        assert!(wasm_text.contains(required));
    }
    for forbidden in [
        "private",
        "biosignal",
        "baseline",
        "appraisal",
        "evidence_permit",
        "lease_bytes",
        "nonce",
        "attestation",
    ] {
        assert!(!wasm_text.contains(forbidden));
    }

    let config = include_str!("../../../configs/quotient_seal/aepa_p0_compiler_v1.yaml");
    let docs = include_str!("../../../docs/quotient_seal_aepa_p0_compiler_v1.md");
    assert!(config.contains("source_target_refinement: CHECKED_ALL_36_TRANSITIONS"));
    assert!(config.contains("private_import: FORBIDDEN"));
    assert!(config.contains("resource_bound: NOT_SUCCESS"));
    assert!(config.contains("three_engine_equivalence: NOT_VERIFIED"));
    assert!(config.contains("hardware_status: NOT_VERIFIED"));
    assert!(docs.contains("Issue #187"));
    assert!(docs.contains("Issue #191"));
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
