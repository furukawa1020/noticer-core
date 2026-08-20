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
use quotient_seal_noticer::{
    compile_aplot_p0, verify_aplot_k7, AplotCompileLimits, AplotFrameInput, AplotK7Binding,
    AplotPublicEventKind, AplotPublicSourceArtifact, AplotServiceCode, Epoch, PolicyHash,
    WireServiceAlias, APLOT_PUBLIC_DEADLINE, APLOT_PUBLIC_LOSS, APLOT_PUBLIC_RECONNECT,
};

const SERVICE_ALIAS: WireServiceAlias = WireServiceAlias([0x31; 8]);
const POLICY_HASH: PolicyHash = PolicyHash([0x41; 32]);
const EPOCH: Epoch = Epoch(9);
const QSM_ALIAS: u32 = 17;
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

fn fixture_source() -> AplotPublicSourceArtifact {
    source_artifact(vec![frame(2, 1, 100, &[1, 7]), frame(1, 4, 200, &[0, 19])])
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

fn k7(source: &AplotPublicSourceArtifact) -> AplotK7Binding {
    let (certificate, expected) = caqt_certificate();
    let target = TemporaryDirectory::new("aplot-compiler");
    generate_package(
        &certificate,
        expected,
        CertificateLimits::default(),
        &CodegenConfig {
            package_name: "generated-aplot-compiler-source".to_owned(),
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
    verify_aplot_k7(
        source,
        &certificate,
        expected,
        CertificateLimits::default(),
        &runtime,
    )
    .expect("APLOT K7 binding")
}

fn service_code() -> AplotServiceCode {
    AplotServiceCode {
        service_alias: SERVICE_ALIAS,
        qsm_alias: QSM_ALIAS,
    }
}

#[test]
fn compile_is_byte_identical_and_event_order_is_canonical() {
    let first_source = fixture_source();
    let second_source =
        source_artifact(vec![frame(1, 4, 200, &[0, 19]), frame(2, 1, 100, &[1, 7])]);
    assert_eq!(first_source, second_source);
    let k7 = k7(&first_source);

    let first = compile_aplot_p0(
        &first_source,
        &k7,
        &[service_code()],
        AplotCompileLimits::default(),
    )
    .expect("first APLOT compile");
    let second = compile_aplot_p0(
        &second_source,
        &k7,
        &[service_code()],
        AplotCompileLimits::default(),
    )
    .expect("second APLOT compile");

    assert_eq!(first, second);
    assert_eq!(first.wasm(), second.wasm());
    assert_eq!(first.capsule(), second.capsule());
    assert_eq!(first.compiler_manifest(), second.compiler_manifest());
    assert_eq!(first.events().len(), 46);
    assert!(first
        .events()
        .iter()
        .enumerate()
        .all(|(step, event)| event.public_step == step as u64));
    assert!(first.events().windows(2).all(|pair| {
        let left = (
            pair[0].scheduled_tick,
            pair[0].kind.code(),
            pair[0].frame_ordinal,
            pair[0].fragment_ordinal.unwrap_or(u8::MAX),
        );
        let right = (
            pair[1].scheduled_tick,
            pair[1].kind.code(),
            pair[1].frame_ordinal,
            pair[1].fragment_ordinal.unwrap_or(u8::MAX),
        );
        left <= right
    }));

    assert_eq!(
        first
            .events()
            .iter()
            .filter(|event| event.kind == AplotPublicEventKind::FragmentAttempt)
            .count(),
        40
    );
    assert_eq!(
        first
            .events()
            .iter()
            .filter(|event| event.declared_fault_code == APLOT_PUBLIC_LOSS)
            .count(),
        4
    );
    assert_eq!(
        first
            .events()
            .iter()
            .filter(|event| event.declared_fault_code == APLOT_PUBLIC_RECONNECT)
            .count(),
        4
    );
    assert_eq!(
        first
            .events()
            .iter()
            .filter(|event| event.declared_fault_code == APLOT_PUBLIC_DEADLINE)
            .count(),
        2
    );
    assert_eq!(first.binding().source_digest, first_source.digest());
    assert_eq!(
        first.binding().schedule_digest,
        first_source.schedule_digest()
    );
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
        "aplot.application_retry_count",
        "aplot.event_count",
        "aplot.schedule_digest",
        "hardware.status",
        "p1.status",
        "NOT_VERIFIED",
    ] {
        assert!(manifest.contains(required));
    }
}

#[test]
fn mapping_binding_and_resource_limits_fail_closed() {
    let source = fixture_source();
    let k7 = k7(&source);
    let compile =
        |codes: &[AplotServiceCode], limits| compile_aplot_p0(&source, &k7, codes, limits);

    assert!(compile(&[], AplotCompileLimits::default()).is_err());
    assert!(compile(
        &[
            service_code(),
            AplotServiceCode {
                service_alias: SERVICE_ALIAS,
                qsm_alias: QSM_ALIAS + 1,
            },
        ],
        AplotCompileLimits::default(),
    )
    .is_err());
    assert!(compile(
        &[AplotServiceCode {
            service_alias: WireServiceAlias([0x99; 8]),
            qsm_alias: QSM_ALIAS,
        }],
        AplotCompileLimits::default(),
    )
    .is_err());
    assert!(compile(
        &[AplotServiceCode {
            service_alias: SERVICE_ALIAS,
            qsm_alias: 0,
        }],
        AplotCompileLimits::default(),
    )
    .is_err());
    assert!(compile(
        &[service_code()],
        AplotCompileLimits {
            max_frames: 1,
            ..AplotCompileLimits::default()
        },
    )
    .is_err());
    assert!(compile(
        &[service_code()],
        AplotCompileLimits {
            max_events: 45,
            ..AplotCompileLimits::default()
        },
    )
    .is_err());
    assert!(compile(
        &[service_code()],
        AplotCompileLimits {
            max_wasm_bytes: 8,
            ..AplotCompileLimits::default()
        },
    )
    .is_err());
    assert!(compile(
        &[service_code()],
        AplotCompileLimits {
            max_capsule_bytes: 64,
            ..AplotCompileLimits::default()
        },
    )
    .is_err());

    let changed_source = source_artifact(vec![frame(1, 1, 300, &[])]);
    assert!(compile_aplot_p0(
        &changed_source,
        &k7,
        &[service_code()],
        AplotCompileLimits::default(),
    )
    .is_err());
}

#[test]
fn generated_surface_has_no_private_import_or_retry_event() {
    let source = fixture_source();
    let k7 = k7(&source);
    let compiled = compile_aplot_p0(
        &source,
        &k7,
        &[service_code()],
        AplotCompileLimits::default(),
    )
    .expect("APLOT compile");
    let wasm_text = String::from_utf8_lossy(compiled.wasm());

    assert!(wasm_text.contains("qseal"));
    assert!(wasm_text.contains("emit_frame"));
    assert!(wasm_text.contains("public_failure"));
    for forbidden in [
        "private",
        "baseline",
        "biosignal",
        "fragment_payload",
        "transport_id_key",
        "retry",
    ] {
        assert!(!wasm_text.contains(forbidden));
    }
    assert!(compiled.events().iter().all(|event| matches!(
        event.kind,
        AplotPublicEventKind::FragmentAttempt
            | AplotPublicEventKind::Reconnect
            | AplotPublicEventKind::Deadline
    )));
}

#[test]
fn frozen_contract_keeps_refinement_radio_and_hardware_unverified() {
    let config = include_str!("../../../configs/quotient_seal/aplot_p0_compiler_v1.yaml");
    let docs = include_str!("../../../docs/quotient_seal_aplot_p0_compiler_v1.md");

    assert!(config.contains("application_retry_count: 0"));
    assert!(config.contains("private_import: FORBIDDEN"));
    assert!(config.contains("source_target_refinement: NOT_VERIFIED"));
    assert!(config.contains("hardware_status: NOT_VERIFIED"));
    assert!(docs.contains("Issue #179"));
    assert!(docs.contains("Issue #180"));
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
