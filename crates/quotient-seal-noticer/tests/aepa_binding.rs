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
    bind_aepa_k7_manifest, verify_aepa_k7, AepaBindingError, AepaK7Binding, AepaPublicInput,
    AepaPublicOutput, AepaPublicPolicyBinding, AepaPublicSourceArtifact, AepaPublicState,
    NoticerModuleBinding, NoticerModuleId, NoticerQsmManifest, P1ResourceEvidence,
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
static TEMPORARY_DIRECTORY_ID: AtomicU64 = AtomicU64::new(0);

fn assurance() -> AssuranceProfileDigest {
    AssuranceProfile::lab_reference().digest()
}

fn policy_binding() -> AepaPublicPolicyBinding {
    AepaPublicPolicyBinding::new(
        WIRE_ALIAS,
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
    .expect("AEPA public policy binding")
}

fn source() -> AepaPublicSourceArtifact {
    AepaPublicSourceArtifact::new(policy_binding()).expect("AEPA public source")
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
                payload: b"aepa-public-admission".to_vec(),
                actions: vec![action],
            },
            OutputRecord {
                id: 1,
                emitted: true,
                payload: b"aepa-public-admission".to_vec(),
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

fn runtime_manifest(
    certificate: &[u8],
    expected: ExpectedContract,
) -> (TemporaryDirectory, Vec<u8>) {
    let target = TemporaryDirectory::new("aepa-source-binding");
    generate_package(
        certificate,
        expected,
        CertificateLimits::default(),
        &CodegenConfig {
            package_name: "generated-aepa-source-binding".to_owned(),
            quotient_inputs: 1,
            public_inputs: 1,
            fault_inputs: 1,
            max_payload_bytes: 64,
            max_actions: 8,
        },
        target.path(),
    )
    .expect("K7 generated package");
    let bytes = fs::read(target.path().join("codegen-manifest.toml")).expect("runtime manifest");
    (target, bytes)
}

fn dummy_digest(module: NoticerModuleId, field: u8) -> quotient_forge_caqt::Digest {
    artifact_digest(b"noticer-aepa-binding-test", &[module as u8, field])
}

fn manifest(source: &AepaPublicSourceArtifact, k7: &AepaK7Binding) -> NoticerQsmManifest {
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
                    qsm_capsule_digest: dummy_digest(module_id, 4),
                    observer_registry_digest: dummy_digest(module_id, 5),
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

#[test]
fn public_source_is_canonical_total_and_admits_once() {
    let first = source();
    let second = source();
    assert_eq!(first, second);
    assert_eq!(first.canonical_bytes(), second.canonical_bytes());
    assert_eq!(first.digest(), second.digest());
    assert_eq!(first.transitions().len(), 4 * 9);

    let pairs = first
        .transitions()
        .iter()
        .map(|transition| (transition.from(), transition.input()))
        .collect::<BTreeSet<_>>();
    assert_eq!(pairs.len(), 4 * 9);

    let first_admission = first
        .transitions()
        .iter()
        .find(|transition| {
            transition.from() == AepaPublicState::Waiting
                && transition.input() == AepaPublicInput::ValidatedAdmission
        })
        .expect("first validated admission");
    assert_eq!(first_admission.to(), AepaPublicState::Admitted);
    assert_eq!(first_admission.output(), AepaPublicOutput::AdmitOnce);

    for input in [
        AepaPublicInput::Replay,
        AepaPublicInput::Expired,
        AepaPublicInput::Downgrade,
        AepaPublicInput::WrongBinding,
    ] {
        let rejected = first
            .transitions()
            .iter()
            .find(|transition| {
                transition.from() == AepaPublicState::Waiting && transition.input() == input
            })
            .expect("rejected public fault");
        assert_eq!(rejected.to(), AepaPublicState::CoverRequired);
        assert_eq!(rejected.output(), AepaPublicOutput::Reject);
    }

    let duplicate = first
        .transitions()
        .iter()
        .find(|transition| {
            transition.from() == AepaPublicState::Admitted
                && transition.input() == AepaPublicInput::ValidatedAdmission
        })
        .expect("duplicate admission");
    assert_eq!(duplicate.to(), AepaPublicState::CoverRequired);
    assert_eq!(duplicate.output(), AepaPublicOutput::Reject);
}

#[test]
fn invalid_binding_reset_handoff_and_fault_fail_closed() {
    assert_eq!(
        AepaPublicPolicyBinding::new(
            WireServiceAlias([0; 8]),
            PAIRWISE_ALIAS,
            EPOCH,
            POLICY,
            LEASE_KEY,
            PIPELINE,
            assurance(),
            ATV2_KEY,
            WINDOW_START,
            WINDOW_END,
        ),
        Err(AepaBindingError::InvalidPublicBinding)
    );
    assert_eq!(
        AepaPublicPolicyBinding::new(
            WIRE_ALIAS,
            PAIRWISE_ALIAS,
            Epoch(u64::from(u32::MAX) + 1),
            POLICY,
            LEASE_KEY,
            PIPELINE,
            assurance(),
            ATV2_KEY,
            WINDOW_START,
            WINDOW_END,
        ),
        Err(AepaBindingError::InvalidPublicBinding)
    );
    assert_eq!(
        AepaPublicPolicyBinding::new(
            WIRE_ALIAS,
            PAIRWISE_ALIAS,
            EPOCH,
            POLICY,
            LEASE_KEY,
            PIPELINE,
            assurance(),
            ATV2_KEY,
            WINDOW_END,
            WINDOW_END,
        ),
        Err(AepaBindingError::InvalidPublicBinding)
    );

    let source = source();
    for state in AepaPublicState::ALL {
        for input in [AepaPublicInput::Reset, AepaPublicInput::Handoff] {
            let transition = source
                .transitions()
                .iter()
                .find(|transition| transition.from() == state && transition.input() == input)
                .expect("reset or handoff");
            assert_eq!(transition.to(), AepaPublicState::Waiting);
            assert_eq!(transition.output(), AepaPublicOutput::Cover);
        }
        let fault = source
            .transitions()
            .iter()
            .find(|transition| {
                transition.from() == state && transition.input() == AepaPublicInput::Fault
            })
            .expect("fault transition");
        assert_eq!(fault.to(), AepaPublicState::Faulted);
        assert_eq!(fault.output(), AepaPublicOutput::Fault);
    }
}

#[test]
fn real_k7_certificate_runtime_and_registry_are_bound() {
    let source = source();
    let (certificate, expected) = caqt_certificate();
    let (_target, runtime) = runtime_manifest(&certificate, expected);
    let first = verify_aepa_k7(
        &source,
        &certificate,
        expected,
        CertificateLimits::default(),
        &runtime,
    )
    .expect("AEPA K7 binding");
    let second = verify_aepa_k7(
        &source,
        &certificate,
        expected,
        CertificateLimits::default(),
        &runtime,
    )
    .expect("repeat AEPA K7 binding");
    assert_eq!(first, second);
    assert_eq!(first.input_axes(), (1, 1, 1));
    assert_eq!(first.source_certificate(), certificate);

    let registry = manifest(&source, &first);
    let bound = bind_aepa_k7_manifest(&registry, &source, &first).expect("AEPA registry binding");
    assert_eq!(bound.source_digest, source.digest());
    assert_eq!(bound.certificate_digest, first.certificate_digest());
    assert_eq!(
        bound.generated_runtime_digest,
        first.generated_runtime_digest()
    );
}

#[test]
fn runtime_registry_tamper_and_p1_upgrade_fail_closed() {
    let source = source();
    let (certificate, expected) = caqt_certificate();
    let (_target, runtime) = runtime_manifest(&certificate, expected);
    let k7 = verify_aepa_k7(
        &source,
        &certificate,
        expected,
        CertificateLimits::default(),
        &runtime,
    )
    .expect("AEPA K7 binding");
    let digest: String = k7
        .certificate_digest()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let replacement = if digest.starts_with('0') { '1' } else { '0' };
    let tampered_runtime = String::from_utf8(runtime.clone())
        .expect("UTF-8 runtime")
        .replacen(&digest, &format!("{replacement}{}", &digest[1..]), 1)
        .into_bytes();
    assert_eq!(
        verify_aepa_k7(
            &source,
            &certificate,
            expected,
            CertificateLimits::default(),
            &tampered_runtime,
        ),
        Err(AepaBindingError::CodegenCertificateMismatch)
    );

    let registry = manifest(&source, &k7);
    let mut entries = registry.entries().to_vec();
    entries[NoticerModuleId::Aepa as usize - 1].source_digest =
        dummy_digest(NoticerModuleId::Aepa, 9);
    let tampered_registry = NoticerQsmManifest::new(entries).expect("tampered registry shape");
    assert_eq!(
        bind_aepa_k7_manifest(&tampered_registry, &source, &k7),
        Err(AepaBindingError::DigestMismatch { field: "source" })
    );

    let mut entries = registry.entries().to_vec();
    let aepa = &mut entries[NoticerModuleId::Aepa as usize - 1];
    aepa.deployment_profile = DeploymentProfile::P1SealedAdmission;
    aepa.p1_resource_evidence = Some(P1ResourceEvidence {
        equivalence_certificate_digest: dummy_digest(NoticerModuleId::Aepa, 10),
        relation_binding_digest: dummy_digest(NoticerModuleId::Aepa, 11),
        checked_cases: 1,
    });
    let p1_registry = NoticerQsmManifest::new(entries).expect("valid P1 registry shape");
    assert_eq!(
        bind_aepa_k7_manifest(&p1_registry, &source, &k7),
        Err(AepaBindingError::ProfileNotP0)
    );
}

#[test]
fn frozen_contract_erases_private_lease_and_hardware_claims() {
    let config = include_str!("../../../configs/quotient_seal/aepa_source_binding_v1.yaml");
    let docs = include_str!("../../../docs/quotient_seal_aepa_source_v1.md");
    let cargo = include_str!("../Cargo.toml");

    assert!(config.contains("validated_admission_semantics: POST_VALIDATION_PUBLIC_SYMBOL_ONLY"));
    assert!(config.contains("provenance_lease_bytes"));
    assert!(config.contains("lease_nonce"));
    assert!(config.contains("private_resource_trace"));
    assert!(config.contains("p1_admission: FORBIDDEN"));
    assert!(config.contains("hardware_status: NOT_VERIFIED"));
    assert!(docs.contains("world-first"));
    assert!(docs.contains("NOT_VERIFIED"));
    assert!(cargo.contains("noticer-provenance.workspace = true"));
    assert!(cargo.contains("noticer-provenance-lease.workspace = true"));
    assert!(!cargo.contains("noticer-provenance-verifier.workspace = true"));
    assert!(!cargo.contains("noticer-evidence.workspace = true"));
    assert!(!cargo.contains("noticer-acquisition-core.workspace = true"));
    assert!(!cargo.contains("noticer-token.workspace = true"));
    assert!(!cargo.contains("noticer-crypto.workspace = true"));
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
