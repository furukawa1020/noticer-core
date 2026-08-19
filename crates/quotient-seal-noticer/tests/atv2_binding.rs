use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use noticer_aetp::{
    ActionObligation, ActionSemantics, BucketId, ChannelSchedule, PublicContext, PublicNetworkTape,
    ScheduleRandomTape, ServiceBinding,
};
use noticer_protocol::{FrameKind, WireServiceAlias, ENVELOPE_SIZE};
use noticer_release::TokenPlan;
use noticer_types::{ActionCode, Epoch, LogicalSlot, PolicyHash};
use quotient_forge_caqt::{
    artifact_digest, Certificate, CertificateLimits, CostVector, DomainHashes, ExpectedContract,
    ObserverRecord, OutputRecord, RelationPair, TransitionRecord, FORMAT_VERSION,
};
use quotient_forge_codegen::{generate_package, CodegenConfig};
use quotient_seal_abi::DeploymentProfile;
use quotient_seal_noticer::{
    bind_atv2_k7_manifest, verify_atv2_k7, Atv2BindingError, Atv2PublicSourceArtifact,
    NoticerModuleBinding, NoticerModuleId, NoticerQsmManifest,
};

const SERVICE: ServiceBinding = ServiceBinding([0x21; 16]);
const ALIAS: WireServiceAlias = WireServiceAlias([0x31; 8]);
const POLICY: PolicyHash = PolicyHash([0x41; 32]);

fn semantics(policy: PolicyHash) -> ActionSemantics {
    ActionSemantics::new(vec![ActionObligation {
        service: SERVICE,
        action: ActionCode::RenderAmbientPulse,
        public_bucket: BucketId(0),
        admission_cutoff: LogicalSlot(100),
        release_window_start: LogicalSlot(100),
        release_deadline: LogicalSlot(103),
        max_uses: 1,
        policy_hash: policy,
    }])
    .expect("ATv2 semantics")
}

fn context(ciphertext_size: u16) -> PublicContext {
    PublicContext {
        schedule: ChannelSchedule {
            buckets: 1,
            slots_per_bucket: 4,
            frame_interval_ms: 250,
            fixed_plaintext_size: 160,
            fixed_ciphertext_size: ciphertext_size,
        },
        network: PublicNetworkTape {
            services: vec![SERVICE],
            public_epoch: 9,
            start_slot: LogicalSlot(100),
        },
    }
}

fn source() -> Atv2PublicSourceArtifact {
    let plan = TokenPlan::from_action_semantics(&semantics(POLICY), vec![SERVICE])
        .expect("ATv2 token plan");
    Atv2PublicSourceArtifact::new(
        &plan,
        &context(ENVELOPE_SIZE as u16),
        ScheduleRandomTape([0x51; 32]),
        ALIAS,
        POLICY,
    )
    .expect("ATv2 public source")
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
                payload: b"fixed-frame".to_vec(),
                actions: vec![action],
            },
            OutputRecord {
                id: 1,
                emitted: true,
                payload: b"fixed-frame".to_vec(),
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
    let target = TemporaryDirectory::new("atv2-source-binding");
    generate_package(
        certificate,
        expected,
        CertificateLimits::default(),
        &CodegenConfig {
            package_name: "generated-atv2-source-binding".to_owned(),
            quotient_inputs: 1,
            public_inputs: 1,
            fault_inputs: 1,
            max_payload_bytes: 64,
            max_actions: 8,
        },
        target.path(),
    )
    .expect("K7 generated package");
    let bytes =
        fs::read(target.path().join("codegen-manifest.toml")).expect("generated runtime manifest");
    (target, bytes)
}

fn dummy_digest(module: NoticerModuleId, field: u8) -> quotient_forge_caqt::Digest {
    artifact_digest(b"noticer-atv2-binding-test", &[module as u8, field])
}

fn manifest(
    source: &Atv2PublicSourceArtifact,
    k7: &quotient_seal_noticer::Atv2K7Binding,
) -> NoticerQsmManifest {
    let entries = NoticerModuleId::ALL
        .iter()
        .copied()
        .map(|module_id| {
            let code = module_id as u8;
            if module_id == NoticerModuleId::Atv2FramePlanner {
                NoticerModuleBinding {
                    module_id,
                    deployment_profile: DeploymentProfile::P0PublicQuotientOnly,
                    service_alias: source.service_alias(),
                    epoch: source.epoch(),
                    policy_hash: source.policy_hash(),
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
fn public_source_is_canonical_and_projects_fixed_shape_only() {
    let first = source();
    let second = source();
    assert_eq!(first, second);
    assert_eq!(first.canonical_bytes(), second.canonical_bytes());
    assert_eq!(first.digest(), second.digest());
    assert_eq!(first.frames().len(), 4);
    assert_eq!(
        first
            .frames()
            .iter()
            .filter(|frame| frame.kind() == FrameKind::Action)
            .count(),
        1
    );
    assert_eq!(
        first
            .frames()
            .iter()
            .filter(|frame| frame.kind() == FrameKind::Cover)
            .count(),
        3
    );
    assert_eq!(
        first.public_context().schedule.fixed_ciphertext_size,
        ENVELOPE_SIZE as u16
    );
    assert_ne!(first.frame_plan_digest(), first.digest());
}

#[test]
fn invalid_shape_service_and_policy_fail_closed() {
    let plan = TokenPlan::from_action_semantics(&semantics(POLICY), vec![SERVICE])
        .expect("ATv2 token plan");
    assert_eq!(
        Atv2PublicSourceArtifact::new(
            &plan,
            &context(235),
            ScheduleRandomTape([0x51; 32]),
            ALIAS,
            POLICY,
        ),
        Err(Atv2BindingError::FrameShape)
    );
    assert_eq!(
        Atv2PublicSourceArtifact::new(
            &plan,
            &context(ENVELOPE_SIZE as u16),
            ScheduleRandomTape([0x51; 32]),
            ALIAS,
            PolicyHash([0x99; 32]),
        ),
        Err(Atv2BindingError::PolicyMismatch)
    );
    let other = ServiceBinding([0x88; 16]);
    let mut wrong_context = context(ENVELOPE_SIZE as u16);
    wrong_context.network.services = vec![other];
    assert_eq!(
        Atv2PublicSourceArtifact::new(
            &plan,
            &wrong_context,
            ScheduleRandomTape([0x51; 32]),
            ALIAS,
            POLICY,
        ),
        Err(Atv2BindingError::ServiceSetMismatch)
    );
}

#[test]
fn real_k7_certificate_runtime_and_registry_are_bound() {
    let source = source();
    let (certificate, expected) = caqt_certificate();
    let (_target, runtime) = runtime_manifest(&certificate, expected);
    let first = verify_atv2_k7(
        &source,
        &certificate,
        expected,
        CertificateLimits::default(),
        &runtime,
    )
    .expect("ATv2 K7 binding");
    let second = verify_atv2_k7(
        &source,
        &certificate,
        expected,
        CertificateLimits::default(),
        &runtime,
    )
    .expect("repeat ATv2 K7 binding");
    assert_eq!(first, second);
    assert_eq!(first.input_axes(), (1, 1, 1));
    assert_eq!(first.source_certificate(), certificate);

    let registry = manifest(&source, &first);
    let bound = bind_atv2_k7_manifest(&registry, &source, &first).expect("ATv2 registry binding");
    assert_eq!(bound.source_digest, source.digest());
    assert_eq!(bound.certificate_digest, first.certificate_digest());
    assert_eq!(
        bound.generated_runtime_digest,
        first.generated_runtime_digest()
    );
}

#[test]
fn certificate_runtime_and_registry_tamper_fail_closed() {
    let source = source();
    let (certificate, expected) = caqt_certificate();
    let (_target, runtime) = runtime_manifest(&certificate, expected);
    let k7 = verify_atv2_k7(
        &source,
        &certificate,
        expected,
        CertificateLimits::default(),
        &runtime,
    )
    .expect("ATv2 K7 binding");
    let digest: String = k7
        .certificate_digest()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let replacement = if digest.starts_with('0') { '1' } else { '0' };
    let tampered = String::from_utf8(runtime.clone())
        .expect("UTF-8 runtime")
        .replacen(&digest, &format!("{replacement}{}", &digest[1..]), 1)
        .into_bytes();
    assert_eq!(
        verify_atv2_k7(
            &source,
            &certificate,
            expected,
            CertificateLimits::default(),
            &tampered,
        ),
        Err(Atv2BindingError::CodegenCertificateMismatch)
    );

    let registry = manifest(&source, &k7);
    let mut entries = registry.entries().to_vec();
    entries[NoticerModuleId::Atv2FramePlanner as usize - 1].source_digest =
        dummy_digest(NoticerModuleId::Atv2FramePlanner, 9);
    let tampered_registry = NoticerQsmManifest::new(entries).expect("tampered registry shape");
    assert_eq!(
        bind_atv2_k7_manifest(&tampered_registry, &source, &k7),
        Err(Atv2BindingError::DigestMismatch { field: "source" })
    );
}

#[test]
fn frozen_contract_excludes_token_keys_private_ingress_and_hardware_claims() {
    let config = include_str!("../../../configs/quotient_seal/atv2_source_binding_v1.yaml");
    let docs = include_str!("../../../docs/quotient_seal_atv2_source_binding_v1.md");
    let cargo = include_str!("../Cargo.toml");
    assert!(config.contains("issuer: PUBLIC_SHAPE_ONLY"));
    assert!(config.contains("token_bytes: FORBIDDEN"));
    assert!(config.contains("private_ingress: FORBIDDEN"));
    assert!(config.contains("hardware_status: NOT_VERIFIED"));
    assert!(docs.contains("world-first"));
    assert!(cargo.contains("noticer-release = { workspace = true, default-features = false }"));
    assert!(cargo.contains("noticer-trace-shaper.workspace = true"));
    assert!(!cargo.contains("noticer-token.workspace = true"));
    assert!(!cargo.contains("noticer-crypto.workspace = true"));
    assert!(!cargo.contains("noticer-evidence.workspace = true"));
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
