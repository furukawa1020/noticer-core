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
    let compiler_k7 = &first;
    let compiler_services = source
        .frames()
        .iter()
        .map(|frame| frame.identity().service)
        .collect::<std::collections::BTreeSet<_>>();
    let compiler_codes = compiler_services
        .iter()
        .copied()
        .enumerate()
        .map(|(index, service)| quotient_seal_noticer::Atv2ServiceCode {
            service,
            qsm_alias: u32::try_from(index + 1).expect("service code fits u32"),
        })
        .collect::<Vec<_>>();
    let compiled_first = quotient_seal_noticer::compile_atv2_p0(
        &source,
        compiler_k7,
        &compiler_codes,
        quotient_seal_noticer::Atv2CompileLimits::default(),
    )
    .expect("ATv2 public plan compiles");
    let mut reversed_codes = compiler_codes.clone();
    reversed_codes.reverse();
    let compiled_second = quotient_seal_noticer::compile_atv2_p0(
        &source,
        compiler_k7,
        &reversed_codes,
        quotient_seal_noticer::Atv2CompileLimits::default(),
    )
    .expect("mapping order is canonicalized");
    assert_eq!(compiled_first, compiled_second);
    let make_command =
        |family: quotient_seal_context::ContextFamily, service_alias: u32, public_slot: u64| {
            quotient_seal_context::ContextCommand {
                family,
                kind: family.command_kind(),
                service_alias,
                public_slot,
                fault: 0,
                payload_tag: 0,
            }
        };
    let mut differential_commands = compiled_first
        .placements()
        .iter()
        .map(|placement| {
            make_command(
                quotient_seal_context::ContextFamily::Tick,
                placement.qsm_alias,
                placement.absolute_slot,
            )
        })
        .collect::<Vec<_>>();
    differential_commands.push(make_command(
        quotient_seal_context::ContextFamily::Handoff,
        0,
        0,
    ));
    differential_commands.push(make_command(
        quotient_seal_context::ContextFamily::Reset,
        0,
        0,
    ));
    differential_commands.push(make_command(
        quotient_seal_context::ContextFamily::Stop,
        0,
        0,
    ));
    let execution_limits = quotient_seal_engine::ExecutionLimits {
        fuel: 1_000_000,
        max_memory_pages: 2,
        max_host_calls: u64::try_from(compiled_first.placements().len() * 2 + 8)
            .expect("host call bound fits u64"),
        timeout_ms: 5_000,
    };
    let sequence = quotient_seal_noticer::Atv2PublicSequence::new(
        &compiled_first,
        differential_commands.clone(),
        execution_limits,
        differential_commands.len(),
    )
    .expect("ATv2 differential sequence");
    let engine_digests = quotient_seal_noticer::Atv2EngineDigests::new(
        "1".repeat(64),
        "2".repeat(64),
        "3".repeat(64),
    )
    .expect("engine digests");
    let matched = quotient_seal_noticer::evaluate_atv2_differential(
        &compiled_first,
        &sequence,
        &engine_digests,
    )
    .expect("ATv2 three-engine differential");
    assert_eq!(
        matched.verdict,
        quotient_seal_noticer::Atv2DifferentialVerdict::Match,
        "{matched:#?}"
    );
    assert_eq!(
        matched.oracle.verdict,
        quotient_seal_engine::DifferentialVerdict::Match
    );
    assert_eq!(
        matched.source_frames.len(),
        compiled_first.placements().len()
    );
    assert!(matched.source_frames.iter().any(|frame| {
        frame.kind == quotient_seal_noticer::Atv2ExpectedFrameKind::Cover && frame.action.is_none()
    }));
    assert!(matched.source_frames.iter().any(|frame| {
        frame.kind == quotient_seal_noticer::Atv2ExpectedFrameKind::Action && frame.action.is_some()
    }));
    assert_eq!(
        matched.oracle.reference.input.engine.name,
        "quotient-seal-small-step"
    );
    assert_eq!(matched.oracle.engines[0].input.engine.name, "wasmi");
    assert_eq!(matched.oracle.engines[1].input.engine.name, "wasmtime");
    assert_eq!(matched.hardware_status, "NOT_VERIFIED");
    assert_eq!(
        matched.canonical_json().expect("first canonical artifact"),
        quotient_seal_noticer::evaluate_atv2_differential(
            &compiled_first,
            &sequence,
            &engine_digests,
        )
        .expect("second ATv2 differential")
        .canonical_json()
        .expect("second canonical artifact")
    );

    let mut engines = matched.oracle.engines.clone();
    let quotient_seal_engine::ObservableEvent::ApiCall { export, .. } = &mut engines[1].trace[0]
    else {
        panic!("first engine event must be an API call");
    };
    *export = "qseal.public.counterexample".to_owned();
    let counterexample_oracle = quotient_seal_engine::DifferentialOracle::evaluate(
        matched.oracle.reference.clone(),
        engines,
    )
    .expect("typed counterexample oracle");
    assert_eq!(
        counterexample_oracle.verdict,
        quotient_seal_engine::DifferentialVerdict::Counterexample
    );
    assert!(counterexample_oracle
        .counterexamples
        .iter()
        .any(|counterexample| matches!(
            counterexample.first_difference,
            quotient_seal_engine::ComparisonPoint::Trace {
                index: 0,
                left_axis: Some(quotient_seal_engine::ObservableAxis::Return),
                right_axis: Some(quotient_seal_engine::ObservableAxis::Return),
                ..
            }
        )));
    let counterexample = quotient_seal_noticer::Atv2DifferentialArtifact {
        verdict: quotient_seal_noticer::Atv2DifferentialVerdict::Counterexample,
        oracle: counterexample_oracle,
        ..matched.clone()
    };
    counterexample
        .validate()
        .expect("counterexample artifact remains canonical");

    let mut digest_tamper = matched.clone();
    digest_tamper.oracle.engines[0]
        .input
        .engine
        .executable_sha256 = "4".repeat(64);
    assert!(digest_tamper.validate().is_err());
    let mut kind_tamper = matched.clone();
    let action_frame = kind_tamper
        .source_frames
        .iter_mut()
        .find(|frame| frame.action.is_some())
        .expect("action frame fixture");
    action_frame.kind = quotient_seal_noticer::Atv2ExpectedFrameKind::Cover;
    assert!(kind_tamper.validate().is_err());

    let bounded_limits = quotient_seal_engine::ExecutionLimits {
        max_host_calls: 1,
        ..execution_limits
    };
    let bounded_sequence = quotient_seal_noticer::Atv2PublicSequence::new(
        &compiled_first,
        differential_commands.clone(),
        bounded_limits,
        differential_commands.len(),
    )
    .expect("bounded ATv2 sequence");
    let unresolved = quotient_seal_noticer::evaluate_atv2_differential(
        &compiled_first,
        &bounded_sequence,
        &engine_digests,
    )
    .expect("bounded differential artifact");
    assert_eq!(
        unresolved.verdict,
        quotient_seal_noticer::Atv2DifferentialVerdict::Unresolved
    );
    assert!(unresolved.source_reference.is_none());
    assert_ne!(
        unresolved.oracle.verdict,
        quotient_seal_engine::DifferentialVerdict::Match
    );
    unresolved.validate().expect("unresolved artifact contract");

    assert!(
        quotient_seal_noticer::Atv2EngineDigests::new("short", "2".repeat(64), "3".repeat(64),)
            .is_err()
    );
    let differential_config =
        include_str!("../../../configs/quotient_seal/atv2_differential_v1.yaml");
    let differential_docs = include_str!("../../../docs/quotient_seal_atv2_differential_v1.md");
    assert!(differential_config.contains("cover_action_conflation: FORBIDDEN"));
    assert!(differential_config.contains("first_typed_difference: REQUIRED_ON_COUNTEREXAMPLE"));
    assert!(differential_config.contains("hardware_status: NOT_VERIFIED"));
    assert!(differential_docs.contains("world-first"));
    assert_eq!(compiled_first.placements().len(), source.frames().len());
    assert_eq!(compiled_first.binding().source_digest, source.digest());
    assert_eq!(
        compiled_first.binding().frame_plan_digest,
        source.frame_plan_digest()
    );
    assert_eq!(
        compiled_first.binding().certificate_digest,
        compiler_k7.certificate_digest()
    );
    assert!(compiled_first
        .placements()
        .iter()
        .all(|placement| placement.absolute_slot <= i64::MAX as u64));
    assert_eq!(
        compiled_first
            .placements()
            .iter()
            .filter(|placement| placement.action.is_some())
            .count(),
        source
            .frames()
            .iter()
            .filter(|frame| frame.kind() == noticer_protocol::FrameKind::Action)
            .count()
    );
    let manifest_text = String::from_utf8_lossy(compiled_first.compiler_manifest());
    assert!(manifest_text.contains("atv2.frame_bytes"));
    assert!(manifest_text.contains("236"));
    assert!(manifest_text.contains("hardware.status"));
    assert!(manifest_text.contains("NOT_VERIFIED"));
    assert!(quotient_seal_capsule::QsmCapsule::decode(
        compiled_first.capsule(),
        quotient_seal_capsule::QsmContainerLimits::default(),
    )
    .is_ok());

    assert!(quotient_seal_noticer::compile_atv2_p0(
        &source,
        compiler_k7,
        &[],
        quotient_seal_noticer::Atv2CompileLimits::default(),
    )
    .is_err());
    let mut zero_code = compiler_codes.clone();
    zero_code[0].qsm_alias = 0;
    assert!(quotient_seal_noticer::compile_atv2_p0(
        &source,
        compiler_k7,
        &zero_code,
        quotient_seal_noticer::Atv2CompileLimits::default(),
    )
    .is_err());
    if compiler_codes.len() > 1 {
        let mut duplicate_code = compiler_codes.clone();
        duplicate_code[1].qsm_alias = duplicate_code[0].qsm_alias;
        assert!(quotient_seal_noticer::compile_atv2_p0(
            &source,
            compiler_k7,
            &duplicate_code,
            quotient_seal_noticer::Atv2CompileLimits::default(),
        )
        .is_err());
    }
    assert!(quotient_seal_noticer::compile_atv2_p0(
        &source,
        compiler_k7,
        &compiler_codes,
        quotient_seal_noticer::Atv2CompileLimits {
            max_frames: 0,
            ..quotient_seal_noticer::Atv2CompileLimits::default()
        },
    )
    .is_err());
    assert!(quotient_seal_noticer::compile_atv2_p0(
        &source,
        compiler_k7,
        &compiler_codes,
        quotient_seal_noticer::Atv2CompileLimits {
            max_wasm_bytes: 8,
            ..quotient_seal_noticer::Atv2CompileLimits::default()
        },
    )
    .is_err());
    assert!(quotient_seal_noticer::compile_atv2_p0(
        &source,
        compiler_k7,
        &compiler_codes,
        quotient_seal_noticer::Atv2CompileLimits {
            max_capsule_bytes: 64,
            ..quotient_seal_noticer::Atv2CompileLimits::default()
        },
    )
    .is_err());
    let mut tampered_capsule = compiled_first.capsule().to_vec();
    let last = tampered_capsule.len() - 1;
    tampered_capsule[last] ^= 0x01;
    assert!(quotient_seal_capsule::QsmCapsule::decode(
        &tampered_capsule,
        quotient_seal_capsule::QsmContainerLimits::default(),
    )
    .is_err());
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
