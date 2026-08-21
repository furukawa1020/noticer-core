use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use noticer_aetp::{
    ActionObligation, ActionSemantics, BucketId, ChannelSchedule, PublicContext, PublicNetworkTape,
    ScheduleRandomTape, ServiceBinding,
};
use noticer_protocol::WireServiceAlias;
use noticer_types::{ActionCode, Epoch, LogicalSlot, PolicyHash};
use quotient_forge_caqt::{
    verify, Certificate, CertificateLimits, CertificateVerdict, CostVector, Digest, DomainHashes,
    ExpectedContract, ObserverRecord, OutputRecord, RelationPair, TransitionRecord, FORMAT_VERSION,
};
use quotient_forge_codegen::{generate_package, CodegenConfig};
use quotient_seal_abi::DeploymentProfile;
use quotient_seal_noticer::{
    aets_observer_registry_digest, aets_qsm_capsule_digest, bind_aets_p0, codegen_manifest_digest,
    AetsArtifactSet, AetsBindingError, AetsPublicSourceArtifact, NoticerModuleBinding,
    NoticerModuleId, NoticerQsmManifest, P1ResourceEvidence, AETS_PUBLIC_SOURCE_FORMAT_VERSION,
};

static TEMPORARY_DIRECTORY_ID: AtomicU64 = AtomicU64::new(0);

const SERVICE_ALIAS: WireServiceAlias = WireServiceAlias([0x31; 8]);
const POLICY_HASH: PolicyHash = PolicyHash([0x41; 32]);
const EPOCH: Epoch = Epoch(9);
const QSM_CAPSULE: &[u8] = b"AETS-QSM-CAPSULE-V1";
const OBSERVER_REGISTRY: &[u8] = b"AETS-OBSERVER-REGISTRY-V1";

struct Fixture {
    source: AetsPublicSourceArtifact,
    certificate: Vec<u8>,
    expected_contract: ExpectedContract,
    runtime_manifest: Vec<u8>,
    manifest: NoticerQsmManifest,
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

fn source_with_order(reverse: bool) -> AetsPublicSourceArtifact {
    let first = ServiceBinding([0x11; 16]);
    let second = ServiceBinding([0x22; 16]);
    let mut obligations = vec![
        ActionObligation {
            service: first,
            action: ActionCode::RenderAmbientPulse,
            public_bucket: BucketId(0),
            admission_cutoff: LogicalSlot(100),
            release_window_start: LogicalSlot(100),
            release_deadline: LogicalSlot(103),
            max_uses: 1,
            policy_hash: POLICY_HASH,
        },
        ActionObligation {
            service: second,
            action: ActionCode::MenfuguInflateSoft,
            public_bucket: BucketId(1),
            admission_cutoff: LogicalSlot(103),
            release_window_start: LogicalSlot(104),
            release_deadline: LogicalSlot(107),
            max_uses: 1,
            policy_hash: POLICY_HASH,
        },
    ];
    let mut services = vec![first, second];
    if reverse {
        obligations.reverse();
        services.reverse();
    }
    let semantics = ActionSemantics::new(obligations).expect("public semantics");
    let context = PublicContext {
        schedule: ChannelSchedule {
            buckets: 2,
            slots_per_bucket: 4,
            frame_interval_ms: 250,
            fixed_plaintext_size: 160,
            fixed_ciphertext_size: 236,
        },
        network: PublicNetworkTape {
            services,
            public_epoch: u32::try_from(EPOCH.0).expect("test epoch"),
            start_slot: LogicalSlot(100),
        },
    };
    AetsPublicSourceArtifact::new(
        &semantics,
        &context,
        ScheduleRandomTape([0x51; 32]),
        SERVICE_ALIAS,
        POLICY_HASH,
    )
    .expect("canonical AETS source")
}

fn module_bindings(
    source: &AetsPublicSourceArtifact,
    certificate_digest: Digest,
    runtime_digest: Digest,
) -> Vec<NoticerModuleBinding> {
    NoticerModuleId::ALL
        .into_iter()
        .enumerate()
        .map(|(index, module_id)| {
            let seed = u8::try_from(index + 1).expect("five modules");
            let is_aets = module_id == NoticerModuleId::Aets;
            NoticerModuleBinding {
                module_id,
                deployment_profile: DeploymentProfile::P0PublicQuotientOnly,
                service_alias: SERVICE_ALIAS,
                epoch: EPOCH,
                policy_hash: POLICY_HASH,
                source_digest: if is_aets {
                    source.digest()
                } else {
                    Digest::new([seed; 32])
                },
                source_certificate_digest: if is_aets {
                    certificate_digest
                } else {
                    Digest::new([seed.saturating_add(10); 32])
                },
                generated_runtime_digest: if is_aets {
                    runtime_digest
                } else {
                    Digest::new([seed.saturating_add(20); 32])
                },
                qsm_capsule_digest: if is_aets {
                    aets_qsm_capsule_digest(QSM_CAPSULE)
                } else {
                    Digest::new([seed.saturating_add(30); 32])
                },
                observer_registry_digest: if is_aets {
                    aets_observer_registry_digest(OBSERVER_REGISTRY)
                } else {
                    Digest::new([seed.saturating_add(40); 32])
                },
                p1_resource_evidence: None,
            }
        })
        .collect()
}

fn fixture() -> Fixture {
    let source = source_with_order(false);
    let (certificate, expected_contract) = caqt_certificate();
    let target = TemporaryDirectory::new("aets-binding");
    let config = CodegenConfig {
        package_name: "generated-aets-runtime".to_owned(),
        quotient_inputs: 1,
        public_inputs: 1,
        fault_inputs: 1,
        max_payload_bytes: 64,
        max_actions: 8,
    };
    let generated = generate_package(
        &certificate,
        expected_contract,
        CertificateLimits::default(),
        &config,
        target.path(),
    )
    .expect("verified K7 generated package");
    let runtime_manifest =
        fs::read(target.path().join("codegen-manifest.toml")).expect("codegen manifest");
    assert_eq!(
        generated.manifest_digest,
        codegen_manifest_digest(&runtime_manifest)
    );
    let certificate_digest = match verify(
        &certificate,
        expected_contract,
        CertificateLimits::default(),
    ) {
        CertificateVerdict::Valid(report) => report.certificate_digest,
        verdict => panic!("fixture certificate rejected: {verdict:?}"),
    };
    let manifest = NoticerQsmManifest::new(module_bindings(
        &source,
        certificate_digest,
        generated.manifest_digest,
    ))
    .expect("Noticer QSM manifest");
    Fixture {
        source,
        certificate,
        expected_contract,
        runtime_manifest,
        manifest,
    }
}

fn bind(
    fixture: &Fixture,
    certificate: &[u8],
    runtime_manifest: &[u8],
    qsm_capsule: &[u8],
    observer_registry: &[u8],
) -> Result<quotient_seal_noticer::AetsP0Binding, AetsBindingError> {
    bind_aets_p0(
        &fixture.manifest,
        &fixture.source,
        AetsArtifactSet {
            certificate,
            expected_contract: fixture.expected_contract,
            certificate_limits: CertificateLimits::default(),
            generated_runtime_manifest: runtime_manifest,
            qsm_capsule,
            observer_registry,
        },
    )
}

#[test]
fn public_source_is_canonical_across_service_and_obligation_order() {
    let left = source_with_order(false);
    let right = source_with_order(true);
    assert_eq!(
        AETS_PUBLIC_SOURCE_FORMAT_VERSION,
        "noticer-aets-public-source/v1"
    );
    assert_eq!(left.canonical_bytes(), right.canonical_bytes());
    assert_eq!(left.digest(), right.digest());
}

#[test]
fn real_k7_certificate_and_codegen_manifest_bind_to_aets_registry_entry() {
    let fixture = fixture();
    let binding = bind(
        &fixture,
        &fixture.certificate,
        &fixture.runtime_manifest,
        QSM_CAPSULE,
        OBSERVER_REGISTRY,
    )
    .expect("complete AETS binding");
    let entry = fixture.manifest.binding(NoticerModuleId::Aets);
    assert_eq!(binding.source_digest, entry.source_digest);
    assert_eq!(binding.certificate_digest, entry.source_certificate_digest);
    assert_eq!(
        binding.generated_runtime_digest,
        entry.generated_runtime_digest
    );
    assert_eq!(binding.qsm_capsule_digest, entry.qsm_capsule_digest);
    assert_eq!(
        binding.observer_registry_digest,
        entry.observer_registry_digest
    );
}

#[test]
fn every_bound_artifact_tamper_fails_closed() {
    let fixture = fixture();

    let mut certificate = fixture.certificate.clone();
    let last = certificate.len() - 1;
    certificate[last] ^= 1;
    assert!(matches!(
        bind(
            &fixture,
            &certificate,
            &fixture.runtime_manifest,
            QSM_CAPSULE,
            OBSERVER_REGISTRY,
        ),
        Err(AetsBindingError::CertificateRejected(_))
    ));

    let mut runtime_manifest = fixture.runtime_manifest.clone();
    runtime_manifest.push(b'\n');
    assert!(matches!(
        bind(
            &fixture,
            &fixture.certificate,
            &runtime_manifest,
            QSM_CAPSULE,
            OBSERVER_REGISTRY,
        ),
        Err(AetsBindingError::ArtifactDigestMismatch {
            artifact: "generated_runtime"
        })
    ));

    assert!(matches!(
        bind(
            &fixture,
            &fixture.certificate,
            &fixture.runtime_manifest,
            b"changed-capsule",
            OBSERVER_REGISTRY,
        ),
        Err(AetsBindingError::ArtifactDigestMismatch {
            artifact: "qsm_capsule"
        })
    ));
    assert!(matches!(
        bind(
            &fixture,
            &fixture.certificate,
            &fixture.runtime_manifest,
            QSM_CAPSULE,
            b"changed-observer-registry",
        ),
        Err(AetsBindingError::ArtifactDigestMismatch {
            artifact: "observer_registry"
        })
    ));
}

#[test]
fn codegen_manifest_must_name_the_independently_verified_certificate() {
    let fixture = fixture();
    let mut text = String::from_utf8(fixture.runtime_manifest.clone()).expect("UTF-8 manifest");
    let marker = "certificate_digest = \"";
    let index = text.find(marker).expect("certificate digest") + marker.len();
    text.replace_range(index..index + 1, "0");
    assert!(matches!(
        bind(
            &fixture,
            &fixture.certificate,
            text.as_bytes(),
            QSM_CAPSULE,
            OBSERVER_REGISTRY,
        ),
        Err(AetsBindingError::CodegenCertificateMismatch)
    ));
}

#[test]
fn p1_registry_entry_is_rejected_by_aets_p0_binding() {
    let fixture = fixture();
    let entry = fixture.manifest.binding(NoticerModuleId::Aets);
    let mut bindings = module_bindings(
        &fixture.source,
        entry.source_certificate_digest,
        entry.generated_runtime_digest,
    );
    let aets = bindings
        .iter_mut()
        .find(|binding| binding.module_id == NoticerModuleId::Aets)
        .expect("AETS binding");
    aets.deployment_profile = DeploymentProfile::P1SealedAdmission;
    aets.p1_resource_evidence = Some(P1ResourceEvidence {
        equivalence_certificate_digest: Digest::new([0x61; 32]),
        relation_binding_digest: Digest::new([0x62; 32]),
        checked_cases: 1,
    });
    let manifest = NoticerQsmManifest::new(bindings).expect("valid P1 registry");
    assert!(matches!(
        bind_aets_p0(
            &manifest,
            &fixture.source,
            AetsArtifactSet {
                certificate: &fixture.certificate,
                expected_contract: fixture.expected_contract,
                certificate_limits: CertificateLimits::default(),
                generated_runtime_manifest: &fixture.runtime_manifest,
                qsm_capsule: QSM_CAPSULE,
                observer_registry: OBSERVER_REGISTRY,
            },
        ),
        Err(AetsBindingError::ProfileNotP0)
    ));
}

#[test]
fn production_dependency_boundary_excludes_private_ingress_crates() {
    let cargo = include_str!("../Cargo.toml");
    for forbidden in [
        "noticer-acquisition-core",
        "noticer-evidence",
        "noticer-ppg-features",
        "noticer-baseline",
    ] {
        assert!(
            !cargo.contains(forbidden),
            "forbidden dependency: {forbidden}"
        );
    }
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
