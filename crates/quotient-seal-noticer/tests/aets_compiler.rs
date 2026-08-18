use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use noticer_aetp::{
    ActionObligation, ActionSemantics, BucketId, ChannelSchedule, PublicContext, PublicNetworkTape,
    ScheduleRandomTape, ServiceBinding,
};
use noticer_protocol::WireServiceAlias;
use noticer_types::{ActionCode, Epoch, LogicalSlot, PolicyHash};
use quotient_forge_caqt::{
    Certificate, CertificateLimits, CostVector, Digest, DomainHashes, ExpectedContract,
    ObserverRecord, OutputRecord, RelationPair, TransitionRecord, FORMAT_VERSION,
};
use quotient_forge_codegen::{generate_package, CodegenConfig};
use quotient_seal_abi::{
    validate_wasm_abi, AbiManifest, AbiVerdict, DeploymentProfile, WasmSurfaceLimits,
};
use quotient_seal_capsule::{QsmCapsule, QsmContainerLimits, QsmSectionTag, OBSERVER_REGISTRY_V1};
use quotient_seal_noticer::{
    bind_aets_p0, compile_aets_p0, verify_aets_k7, AetsArtifactSet, AetsCompileError,
    AetsCompileLimits, AetsCompiledQsm, AetsK7Binding, AetsPublicSourceArtifact, AetsServiceCode,
    NoticerModuleBinding, NoticerModuleId, NoticerQsmManifest, AETS_QSM_COMPILER_VERSION,
};

const SERVICE_ALIAS: WireServiceAlias = WireServiceAlias([0x31; 8]);
const POLICY_HASH: PolicyHash = PolicyHash([0x41; 32]);
const EPOCH: Epoch = Epoch(9);

struct Fixture {
    source: AetsPublicSourceArtifact,
    k7: AetsK7Binding,
    certificate: Vec<u8>,
    expected_contract: ExpectedContract,
    runtime_manifest: Vec<u8>,
    service_codes: Vec<AetsServiceCode>,
}

fn fixture() -> Fixture {
    let first = ServiceBinding([0x11; 16]);
    let second = ServiceBinding([0x22; 16]);
    let semantics = ActionSemantics::new(vec![
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
    ])
    .expect("AETS semantics");
    let context = PublicContext {
        schedule: ChannelSchedule {
            buckets: 2,
            slots_per_bucket: 4,
            frame_interval_ms: 250,
            fixed_plaintext_size: 160,
            fixed_ciphertext_size: 236,
        },
        network: PublicNetworkTape {
            services: vec![first, second],
            public_epoch: u32::try_from(EPOCH.0).expect("test epoch"),
            start_slot: LogicalSlot(100),
        },
    };
    let source = AetsPublicSourceArtifact::new(
        &semantics,
        &context,
        ScheduleRandomTape([0x51; 32]),
        SERVICE_ALIAS,
        POLICY_HASH,
    )
    .expect("AETS source");
    let (certificate, expected_contract) = caqt_certificate();
    let target = TemporaryDirectory::new("aets-compiler");
    generate_package(
        &certificate,
        expected_contract,
        CertificateLimits::default(),
        &CodegenConfig {
            package_name: "generated-aets-qsm-source".to_owned(),
            quotient_inputs: 1,
            public_inputs: 1,
            fault_inputs: 1,
            max_payload_bytes: 64,
            max_actions: 8,
        },
        target.path(),
    )
    .expect("K7 package");
    let runtime_manifest =
        fs::read(target.path().join("codegen-manifest.toml")).expect("codegen manifest");
    let k7 = verify_aets_k7(
        &source,
        &certificate,
        expected_contract,
        CertificateLimits::default(),
        &runtime_manifest,
    )
    .expect("AETS K7 binding");
    Fixture {
        source,
        k7,
        certificate,
        expected_contract,
        runtime_manifest,
        service_codes: vec![
            AetsServiceCode {
                service: first,
                qsm_alias: 11,
            },
            AetsServiceCode {
                service: second,
                qsm_alias: 22,
            },
        ],
    }
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

fn compile(fixture: &Fixture, codes: &[AetsServiceCode]) -> AetsCompiledQsm {
    compile_aets_p0(
        &fixture.source,
        &fixture.k7,
        codes,
        AetsCompileLimits::default(),
    )
    .expect("AETS P0 compile")
}

#[test]
fn compile_is_byte_identical_and_mapping_order_independent() {
    let fixture = fixture();
    let first = compile(&fixture, &fixture.service_codes);
    let mut reversed = fixture.service_codes.clone();
    reversed.reverse();
    let second = compile(&fixture, &reversed);

    assert_eq!(AETS_QSM_COMPILER_VERSION, "noticer-aets-qsm-compiler/v1");
    assert_eq!(first.wasm_module(), second.wasm_module());
    assert_eq!(first.capsule(), second.capsule());
    assert_eq!(first.module_digest(), second.module_digest());
    assert_eq!(first.capsule_digest(), second.capsule_digest());
}

#[test]
fn output_passes_p0_abi_and_structural_capsule_validation() {
    let fixture = fixture();
    let compiled = compile(&fixture, &fixture.service_codes);
    assert!(matches!(
        validate_wasm_abi(
            compiled.wasm_module(),
            AbiManifest::canonical(DeploymentProfile::P0PublicQuotientOnly),
            WasmSurfaceLimits::default(),
        ),
        AbiVerdict::Valid(_)
    ));
    let capsule = QsmCapsule::decode(compiled.capsule(), QsmContainerLimits::default())
        .expect("canonical capsule");
    assert_eq!(
        capsule.section(QsmSectionTag::WasmModule).payload(),
        compiled.wasm_module()
    );
    assert_eq!(
        capsule.section(QsmSectionTag::WasmModule).digest,
        compiled.module_digest()
    );
    assert_eq!(capsule.digest(), compiled.capsule_digest());
    assert_eq!(compiled.source_digest(), fixture.source.digest());
}

#[test]
fn compiled_capsule_binds_back_to_the_noticer_registry() {
    let fixture = fixture();
    let compiled = compile(&fixture, &fixture.service_codes);
    let bindings = NoticerModuleId::ALL
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
                    fixture.source.digest()
                } else {
                    Digest::new([seed; 32])
                },
                source_certificate_digest: if is_aets {
                    fixture.k7.certificate_digest()
                } else {
                    Digest::new([seed + 10; 32])
                },
                generated_runtime_digest: if is_aets {
                    fixture.k7.generated_runtime_digest()
                } else {
                    Digest::new([seed + 20; 32])
                },
                qsm_capsule_digest: if is_aets {
                    compiled.registry_capsule_digest()
                } else {
                    Digest::new([seed + 30; 32])
                },
                observer_registry_digest: if is_aets {
                    compiled.observer_registry_digest()
                } else {
                    Digest::new([seed + 40; 32])
                },
                p1_resource_evidence: None,
            }
        })
        .collect();
    let manifest = NoticerQsmManifest::new(bindings).expect("Noticer registry");
    let bound = bind_aets_p0(
        &manifest,
        &fixture.source,
        AetsArtifactSet {
            certificate: &fixture.certificate,
            expected_contract: fixture.expected_contract,
            certificate_limits: CertificateLimits::default(),
            generated_runtime_manifest: &fixture.runtime_manifest,
            qsm_capsule: compiled.capsule(),
            observer_registry: OBSERVER_REGISTRY_V1,
        },
    )
    .expect("compiled capsule registry binding");
    assert_eq!(bound.qsm_capsule_digest, compiled.registry_capsule_digest());
    assert_eq!(
        bound.observer_registry_digest,
        compiled.observer_registry_digest()
    );
}

#[test]
fn missing_zero_duplicate_and_colliding_service_mappings_fail_closed() {
    let fixture = fixture();
    assert!(matches!(
        compile_aets_p0(
            &fixture.source,
            &fixture.k7,
            &fixture.service_codes[..1],
            AetsCompileLimits::default(),
        ),
        Err(AetsCompileError::InvalidServiceMapping)
    ));

    let mut zero = fixture.service_codes.clone();
    zero[0].qsm_alias = 0;
    assert!(matches!(
        compile_aets_p0(
            &fixture.source,
            &fixture.k7,
            &zero,
            AetsCompileLimits::default(),
        ),
        Err(AetsCompileError::InvalidServiceMapping)
    ));

    let mut collision = fixture.service_codes.clone();
    collision[1].qsm_alias = collision[0].qsm_alias;
    assert!(matches!(
        compile_aets_p0(
            &fixture.source,
            &fixture.k7,
            &collision,
            AetsCompileLimits::default(),
        ),
        Err(AetsCompileError::InvalidServiceMapping)
    ));

    let mut duplicate = fixture.service_codes.clone();
    duplicate.push(fixture.service_codes[0]);
    assert!(matches!(
        compile_aets_p0(
            &fixture.source,
            &fixture.k7,
            &duplicate,
            AetsCompileLimits::default(),
        ),
        Err(AetsCompileError::InvalidServiceMapping)
    ));
}

#[test]
fn compiler_resource_limits_and_capsule_mutation_fail_closed() {
    let fixture = fixture();
    assert!(matches!(
        compile_aets_p0(
            &fixture.source,
            &fixture.k7,
            &fixture.service_codes,
            AetsCompileLimits {
                max_actions: 0,
                ..AetsCompileLimits::default()
            },
        ),
        Err(AetsCompileError::ActionLimit)
    ));
    assert!(matches!(
        compile_aets_p0(
            &fixture.source,
            &fixture.k7,
            &fixture.service_codes,
            AetsCompileLimits {
                max_wasm_bytes: 1,
                ..AetsCompileLimits::default()
            },
        ),
        Err(AetsCompileError::WasmSize { .. })
    ));

    let compiled = compile(&fixture, &fixture.service_codes);
    let mut mutant = compiled.capsule().to_vec();
    let last = mutant.len() - 1;
    mutant[last] ^= 1;
    assert!(QsmCapsule::decode(&mutant, QsmContainerLimits::default()).is_err());
}

#[test]
fn frozen_files_keep_semantic_and_hardware_nonclaims_explicit() {
    let config = include_str!("../../../configs/quotient_seal/aets_compiler_v1.yaml");
    let docs = include_str!("../../../docs/quotient_seal_aets_compiler_v1.md");
    assert!(config.contains("semantic_backend_status: PENDING_K8_13B3"));
    assert!(config.contains("private_ingress: FORBIDDEN"));
    assert!(config.contains("hardware_status: NOT_VERIFIED"));
    assert!(docs.contains("does not claim semantic backend acceptance"));
    assert!(!docs.contains("world-first"));
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
