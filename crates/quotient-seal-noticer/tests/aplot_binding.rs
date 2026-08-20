use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use noticer_transport_core::{FRAGMENT_SIZE, TOTAL_FRAGMENT_COUNT};
use noticer_transport_sim::PublicLossTape;
use quotient_forge_caqt::{
    Certificate, CertificateLimits, CostVector, DomainHashes, ExpectedContract, ObserverRecord,
    OutputRecord, RelationPair, TransitionRecord, FORMAT_VERSION,
};
use quotient_forge_codegen::{generate_package, CodegenConfig};
use quotient_seal_noticer::{
    bind_aplot_k7_manifest, verify_aplot_k7, AplotFrameInput, AplotPublicSourceArtifact,
    DeploymentProfile, Digest, Epoch, NoticerModuleBinding, NoticerModuleId, NoticerQsmManifest,
    PolicyHash, WireServiceAlias, APLOT_APPLICATION_RETRY_COUNT,
};

const SERVICE_ALIAS: WireServiceAlias = WireServiceAlias([0x31; 8]);
const POLICY_HASH: PolicyHash = PolicyHash([0x41; 32]);
const EPOCH: Epoch = Epoch(9);
static TEMPORARY_DIRECTORY_ID: AtomicU64 = AtomicU64::new(0);

fn loss(indices: &[u8]) -> PublicLossTape {
    PublicLossTape::from_indices(indices).expect("public loss tape")
}

fn frame(public_bucket: u32, sequence: u32, start_tick: u64, dropped: &[u8]) -> AplotFrameInput {
    AplotFrameInput {
        public_bucket,
        sequence,
        start_tick,
        fragment_cadence_ticks: 2,
        deadline_tick: start_tick + 50,
        loss_tape: loss(dropped),
        reconnect_ticks: vec![start_tick + 7, start_tick + 21],
    }
}

fn source_artifact(frames: Vec<AplotFrameInput>) -> AplotPublicSourceArtifact {
    AplotPublicSourceArtifact::new(SERVICE_ALIAS, EPOCH, POLICY_HASH, 8, 200, frames)
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
                payload: b"fixed-aplot-slot".to_vec(),
                actions: vec![action],
            },
            OutputRecord {
                id: 1,
                emitted: true,
                payload: b"fixed-aplot-slot".to_vec(),
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

fn runtime_manifest(certificate: &[u8], expected: ExpectedContract) -> Vec<u8> {
    let target = TemporaryDirectory::new("aplot-binding");
    generate_package(
        certificate,
        expected,
        CertificateLimits::default(),
        &CodegenConfig {
            package_name: "generated-aplot-binding-source".to_owned(),
            quotient_inputs: 1,
            public_inputs: 1,
            fault_inputs: 1,
            max_payload_bytes: 64,
            max_actions: 8,
        },
        target.path(),
    )
    .expect("K7 package");
    fs::read(target.path().join("codegen-manifest.toml")).expect("codegen manifest")
}

fn digest(value: u8) -> Digest {
    Digest::new([value; 32])
}

fn placeholder_binding(module_id: NoticerModuleId, value: u8) -> NoticerModuleBinding {
    NoticerModuleBinding {
        module_id,
        deployment_profile: DeploymentProfile::P0PublicQuotientOnly,
        service_alias: WireServiceAlias([value; 8]),
        epoch: Epoch(u64::from(value)),
        policy_hash: PolicyHash([value; 32]),
        source_digest: digest(value),
        source_certificate_digest: digest(value.wrapping_add(10)),
        generated_runtime_digest: digest(value.wrapping_add(20)),
        qsm_capsule_digest: digest(value.wrapping_add(30)),
        observer_registry_digest: digest(value.wrapping_add(40)),
        p1_resource_evidence: None,
    }
}

#[test]
fn canonical_source_and_fragment_schedule_are_order_independent() {
    let first = source_artifact(vec![frame(2, 1, 100, &[1, 7]), frame(1, 4, 200, &[0, 19])]);
    let second = source_artifact(vec![frame(1, 4, 200, &[0, 19]), frame(2, 1, 100, &[1, 7])]);

    assert_eq!(first, second);
    assert_eq!(first.canonical_bytes(), second.canonical_bytes());
    assert_eq!(first.digest(), second.digest());
    assert_eq!(first.schedule_digest(), second.schedule_digest());
    assert_eq!(first.frames().len(), 2);
    assert_eq!(first.fragment_slots().len(), 2 * TOTAL_FRAGMENT_COUNT);
    assert_eq!(FRAGMENT_SIZE, 20);
    assert_eq!(
        first.application_retry_count(),
        APLOT_APPLICATION_RETRY_COUNT
    );
    assert_eq!(APLOT_APPLICATION_RETRY_COUNT, 0);
}

#[test]
fn invalid_public_shape_and_secret_dependent_retry_axes_fail_closed() {
    assert!(AplotPublicSourceArtifact::new(
        WireServiceAlias([0; 8]),
        EPOCH,
        POLICY_HASH,
        8,
        200,
        vec![frame(1, 1, 100, &[])],
    )
    .is_err());
    assert!(AplotPublicSourceArtifact::new(
        SERVICE_ALIAS,
        EPOCH,
        POLICY_HASH,
        0,
        200,
        vec![frame(1, 1, 100, &[])],
    )
    .is_err());
    assert!(AplotPublicSourceArtifact::new(
        SERVICE_ALIAS,
        EPOCH,
        POLICY_HASH,
        8,
        0,
        vec![frame(1, 1, 100, &[])],
    )
    .is_err());

    let mut zero_cadence = frame(1, 1, 100, &[]);
    zero_cadence.fragment_cadence_ticks = 0;
    assert!(AplotPublicSourceArtifact::new(
        SERVICE_ALIAS,
        EPOCH,
        POLICY_HASH,
        8,
        200,
        vec![zero_cadence],
    )
    .is_err());

    let duplicate = frame(1, 1, 100, &[]);
    assert!(AplotPublicSourceArtifact::new(
        SERVICE_ALIAS,
        EPOCH,
        POLICY_HASH,
        8,
        200,
        vec![duplicate.clone(), duplicate],
    )
    .is_err());

    let mut duplicate_reconnect = frame(1, 2, 100, &[]);
    duplicate_reconnect.reconnect_ticks = vec![107, 107];
    assert!(AplotPublicSourceArtifact::new(
        SERVICE_ALIAS,
        EPOCH,
        POLICY_HASH,
        8,
        200,
        vec![duplicate_reconnect],
    )
    .is_err());
}

#[test]
fn k7_certificate_runtime_and_registry_binding_reject_tamper() {
    let source = source_artifact(vec![frame(1, 1, 100, &[2, 5])]);
    let (certificate, expected) = caqt_certificate();
    let runtime = runtime_manifest(&certificate, expected);
    let k7 = verify_aplot_k7(
        &source,
        &certificate,
        expected,
        CertificateLimits::default(),
        &runtime,
    )
    .expect("APLOT K7 binding");

    let mut bindings: Vec<_> = NoticerModuleId::ALL
        .iter()
        .enumerate()
        .map(|(index, module_id)| placeholder_binding(*module_id, index as u8 + 1))
        .collect();
    let aplot = bindings
        .iter_mut()
        .find(|binding| binding.module_id == NoticerModuleId::Aplot)
        .expect("APLOT registry entry");
    aplot.deployment_profile = DeploymentProfile::P0PublicQuotientOnly;
    aplot.service_alias = SERVICE_ALIAS;
    aplot.epoch = EPOCH;
    aplot.policy_hash = POLICY_HASH;
    aplot.source_digest = source.digest();
    aplot.source_certificate_digest = k7.certificate_digest();
    aplot.generated_runtime_digest = k7.generated_runtime_digest();
    aplot.p1_resource_evidence = None;
    let manifest = NoticerQsmManifest::new(bindings.clone()).expect("Noticer QSM manifest");

    let _sealed = bind_aplot_k7_manifest(&manifest, &source, &k7).expect("sealed APLOT binding");

    let changed_source = source_artifact(vec![frame(1, 1, 101, &[2, 5])]);
    assert!(bind_aplot_k7_manifest(&manifest, &changed_source, &k7).is_err());

    let mut certificate_tamper = certificate.clone();
    certificate_tamper[0] ^= 1;
    assert!(verify_aplot_k7(
        &source,
        &certificate_tamper,
        expected,
        CertificateLimits::default(),
        &runtime,
    )
    .is_err());

    let mut runtime_tamper = runtime.clone();
    runtime_tamper.push(b'!');
    let tampered_runtime_k7 = verify_aplot_k7(
        &source,
        &certificate,
        expected,
        CertificateLimits::default(),
        &runtime_tamper,
    )
    .expect("tampered runtime receives a distinct binding");
    assert!(bind_aplot_k7_manifest(&manifest, &source, &tampered_runtime_k7).is_err());

    let aplot = bindings
        .iter_mut()
        .find(|binding| binding.module_id == NoticerModuleId::Aplot)
        .expect("APLOT registry entry");
    aplot.source_digest = digest(0xf1);
    let registry_tamper = NoticerQsmManifest::new(bindings).expect("tampered registry");
    assert!(bind_aplot_k7_manifest(&registry_tamper, &source, &k7).is_err());
}

#[test]
fn frozen_contract_excludes_private_fields_and_keeps_hardware_unverified() {
    let config = include_str!("../../../configs/quotient_seal/aplot_source_v1.yaml");
    let docs = include_str!("../../../docs/quotient_seal_aplot_source_v1.md");

    for forbidden in [
        "envelope_bytes",
        "fragment_payload_bytes",
        "transport_id_key",
    ] {
        assert!(config.contains(forbidden));
    }
    assert!(config.contains("application_retry_count: 0"));
    assert!(config.contains("hardware_status: NOT_VERIFIED"));
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
