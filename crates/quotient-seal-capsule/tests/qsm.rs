use std::fs;
use std::path::PathBuf;
use std::process::Command;

use quotient_forge_caqt::{
    artifact_digest, Certificate, CostVector, Digest, DomainHashes, InductiveCertificate,
};
use quotient_seal_abi::{AbiManifest, DeploymentProfile};
use quotient_seal_capsule::{
    build_qsm, check_qsm, BackendFailure, CompilerManifest, CompilerManifestEntry, QsmBuildInput,
    QsmCapsule, QsmContainerLimits, QsmHardBounds, QsmInconclusive, QsmResourceBounds,
    QsmResourceMode, QsmSectionTag, QsmVerdict, RecomputedSemantics, SemanticRecomputeInput,
    SemanticRecomputer, HARDWARE_STATUS, OBSERVER_REGISTRY_V1, QSM_SECTION_COUNT,
};
use quotient_seal_context::{
    ProductCheckReport, ProductVerdict, RelationBinding, CONTEXT_FAMILY_COUNT,
};
use quotient_seal_relation::{
    RelationCertificate, RelationLimits, RelationValidationReport, RelationVerdict,
};
use quotient_seal_resource::{NormalizationOverhead, ResourceReport, ResourceVerdict};
use quotient_seal_target_ir::{parse_and_lower, target_ir_hash, ConsensusVerdict, ParserLimits};

const RELATION_DIGEST_DOMAIN: &[u8] = b"noticer-core/quotient-seal/relation-certificate/v1";
const CHILD_PATH_ENV: &str = "QSEAL_CAPSULE_CHILD_PATH";
const CONTAINER_HEADER_BYTES: usize = 24;
const SECTION_HEADER_BYTES: usize = 44;

#[derive(Clone, Copy, Debug, Default)]
struct AcceptingBackend;

impl SemanticRecomputer for AcceptingBackend {
    fn recompute(
        &self,
        input: SemanticRecomputeInput<'_>,
    ) -> Result<RecomputedSemantics, BackendFailure> {
        let target_digest = target_ir_hash(input.target_ir);
        let relation_certificate =
            RelationCertificate::decode(input.relation_certificate, RelationLimits::default())
                .map_err(|_| BackendFailure::Protocol)?;
        let relation_digest = artifact_digest(RELATION_DIGEST_DOMAIN, input.relation_certificate);
        let relation_report = RelationValidationReport {
            relation_digest,
            inductive_digest: relation_certificate.inductive_digest,
            target_ir_digest: target_digest,
            reachable_states: 1,
            checked_source_steps: 1,
            checked_lifecycle_calls: 1,
            checked_two_run_cases: 1,
            checked_observer_events: 1,
        };
        let binding = RelationBinding::from_report(&relation_report);
        let context_report = ProductCheckReport {
            binding,
            observer_profiles: 7,
            context_families: CONTEXT_FAMILY_COUNT,
            private_pairs: 1,
            visited_product_states: 1,
            checked_edges: 1,
            maximum_shortest_prefix: 1,
            declared_product_bound: 1,
            induction_closed: true,
        };
        let resource_report = ResourceReport {
            pre_binding: binding,
            post_binding: binding,
            checked_cases: 1,
            checked_resource_events: 1,
            candidate_digest: None,
            overhead: NormalizationOverhead::default(),
        };

        Ok(RecomputedSemantics {
            parser_consensus: ConsensusVerdict::Valid(target_digest),
            relation: RelationVerdict::Valid(Box::new(relation_report)),
            context: ProductVerdict::Accept(Box::new(context_report)),
            resource: ResourceVerdict::Strict(Box::new(resource_report)),
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct UnavailableBackend;

impl SemanticRecomputer for UnavailableBackend {
    fn recompute(
        &self,
        _input: SemanticRecomputeInput<'_>,
    ) -> Result<RecomputedSemantics, BackendFailure> {
        Err(BackendFailure::Unavailable)
    }
}

#[test]
fn canonical_capsule_is_byte_identical_and_semantically_accepted() {
    let first = capsule("fixture-a");
    let second = capsule("fixture-a");

    assert_eq!(first, second);
    let decoded = QsmCapsule::decode(&first, QsmContainerLimits::default())
        .expect("canonical capsule must decode");
    for tag in QsmSectionTag::ALL {
        assert!(!decoded.section(tag).payload().is_empty());
    }

    let QsmVerdict::Valid(report) =
        check_qsm(&first, &AcceptingBackend, QsmContainerLimits::default())
    else {
        panic!("canonical capsule must pass independent checks");
    };
    assert_eq!(report.resource_mode, QsmResourceMode::Strict);
    assert_eq!(report.checked_context_families, CONTEXT_FAMILY_COUNT);
    assert_eq!(report.hardware_status, HARDWARE_STATUS);
    assert_eq!(report.hardware_status, "NOT_VERIFIED");
}

#[test]
fn every_section_rejects_a_one_bit_payload_mutation() {
    let original = capsule("mutation-fixture");
    let mut offset = CONTAINER_HEADER_BYTES;

    for _ in 0..QSM_SECTION_COUNT {
        let length = u64::from_le_bytes(
            original[offset + 4..offset + 12]
                .try_into()
                .expect("section length field"),
        );
        let payload_start = offset + SECTION_HEADER_BYTES;
        let payload_end = payload_start + usize::try_from(length).expect("fixture section length");
        assert!(payload_start < payload_end);

        let mut mutant = original.clone();
        mutant[payload_start] ^= 0x01;
        assert!(matches!(
            check_qsm(&mutant, &AcceptingBackend, QsmContainerLimits::default()),
            QsmVerdict::Invalid(_)
        ));
        offset = payload_end;
    }

    assert_eq!(offset, original.len());
}

#[test]
fn version_order_length_trailing_and_hard_bounds_fail_closed() {
    let original = capsule("boundary-fixture");

    let mut unknown_version = original.clone();
    unknown_version[8..10].copy_from_slice(&2_u16.to_le_bytes());
    assert_decode_rejected(&unknown_version);

    let mut unknown_section = original.clone();
    unknown_section[CONTAINER_HEADER_BYTES..CONTAINER_HEADER_BYTES + 2]
        .copy_from_slice(&u16::MAX.to_le_bytes());
    assert_decode_rejected(&unknown_section);

    let mut oversized_length = original.clone();
    oversized_length[CONTAINER_HEADER_BYTES + 4..CONTAINER_HEADER_BYTES + 12]
        .copy_from_slice(&u64::MAX.to_le_bytes());
    assert_decode_rejected(&oversized_length);

    let mut trailing = original.clone();
    trailing.push(0);
    assert_decode_rejected(&trailing);

    let tight_limits = QsmContainerLimits {
        max_capsule_bytes: original.len() - 1,
        ..QsmContainerLimits::default()
    };
    assert!(QsmCapsule::decode(&original, tight_limits).is_err());

    let mut input = build_input("excessive-bound");
    input.resource_bounds.max_wasm_bytes = QsmHardBounds::default().0.max_wasm_bytes + 1;
    assert!(build_qsm(input, QsmContainerLimits::default()).is_err());
}

#[test]
fn unavailable_semantic_backend_is_inconclusive_never_valid() {
    assert_eq!(
        check_qsm(
            &capsule("backend-unavailable"),
            &UnavailableBackend,
            QsmContainerLimits::default()
        ),
        QsmVerdict::Inconclusive(QsmInconclusive::Backend(BackendFailure::Unavailable))
    );
}

#[test]
fn compiler_manifest_is_evidence_not_semantic_authority() {
    let alpha = capsule("compiler-alpha");
    let beta = capsule("compiler-beta");
    assert_ne!(alpha, beta);

    let alpha_report = valid_report(&alpha);
    let beta_report = valid_report(&beta);
    assert_ne!(
        alpha_report.compiler_manifest_digest,
        beta_report.compiler_manifest_digest
    );
    assert_eq!(alpha_report.target_ir_digest, beta_report.target_ir_digest);
    assert_eq!(alpha_report.relation_binding, beta_report.relation_binding);

    let forbidden = CompilerManifest::new(vec![CompilerManifestEntry {
        key: "baseline".to_owned(),
        value: "private".to_owned(),
    }]);
    assert!(forbidden.is_err());
}

#[test]
fn valid_capsule_is_accepted_in_an_independent_process() {
    let path = child_fixture_path();
    fs::write(&path, capsule("independent-process")).expect("write child fixture");

    let output = Command::new(std::env::current_exe().expect("current test executable"))
        .args(["--exact", "independent_process_entry", "--nocapture"])
        .env(CHILD_PATH_ENV, &path)
        .output()
        .expect("spawn independent checker process");
    let _ = fs::remove_file(&path);

    assert!(
        output.status.success(),
        "child checker failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn independent_process_entry() {
    let Some(path) = std::env::var_os(CHILD_PATH_ENV) else {
        return;
    };
    let bytes = fs::read(path).expect("read child fixture");
    assert!(matches!(
        check_qsm(&bytes, &AcceptingBackend, QsmContainerLimits::default()),
        QsmVerdict::Valid(_)
    ));
}

#[test]
fn frozen_files_record_the_fail_closed_and_nonclaim_boundaries() {
    let config = include_str!("../../../configs/quotient_seal/capsule_v1.yaml");
    let schema = include_str!("../../../schemas/quotient_seal_capsule_v1.schema.json");
    let docs = include_str!("../../../docs/quotient_seal_capsule.md");
    let gitignore = include_str!("../../../.gitignore");

    for needle in [
        "compiler_manifest_trusted: false",
        "semantic_backend_required: true",
        "hardware_status: NOT_VERIFIED",
    ] {
        assert!(config.contains(needle));
    }
    assert!(schema.contains("quotient_seal_capsule_v1"));
    assert!(schema.contains("priority_or_world_first"));
    assert!(docs.contains("INCONCLUSIVE"));
    assert!(docs.contains("NOT_VERIFIED"));
    assert!(docs.contains("優先権や世界初を断定しない"));
    assert!(gitignore.lines().any(|line| line == "*.qseal"));
}

fn valid_report(bytes: &[u8]) -> Box<quotient_seal_capsule::QsmReport> {
    match check_qsm(bytes, &AcceptingBackend, QsmContainerLimits::default()) {
        QsmVerdict::Valid(report) => report,
        verdict => panic!("expected valid capsule, got {verdict:?}"),
    }
}

fn assert_decode_rejected(bytes: &[u8]) {
    assert!(QsmCapsule::decode(bytes, QsmContainerLimits::default()).is_err());
    assert!(matches!(
        check_qsm(bytes, &AcceptingBackend, QsmContainerLimits::default()),
        QsmVerdict::Invalid(_)
    ));
}

fn capsule(toolchain: &str) -> Vec<u8> {
    build_qsm(build_input(toolchain), QsmContainerLimits::default())
        .expect("fixture capsule must build")
}

fn build_input(toolchain: &str) -> QsmBuildInput {
    let wasm_module = abi_v1_module();
    let target_ir = parse_and_lower(&wasm_module, ParserLimits::default())
        .expect("ABI fixture must lower to target IR");
    let target_ir_digest = target_ir_hash(&target_ir);
    let inductive_digest = Digest::new([0x33; 32]);
    let relation_certificate = RelationCertificate {
        version: 1,
        inductive_digest,
        target_ir_digest,
        k7_manifest_digest: Digest::new([0x44; 32]),
        quotient_inputs: 1,
        public_inputs: 1,
        fault_inputs: 1,
        action_deadline_steps: 0,
        records: Vec::new(),
    }
    .encode();

    QsmBuildInput {
        resource_bounds: QsmResourceBounds::default(),
        source_certificate: source_certificate(),
        wasm_module,
        abi_manifest: AbiManifest::canonical(DeploymentProfile::P1SealedAdmission),
        relation_certificate,
        robust_certificate: b"robust-certificate-v1".to_vec(),
        resource_certificate: b"resource-certificate-v1".to_vec(),
        compiler_manifest: CompilerManifest::new(vec![CompilerManifestEntry {
            key: "toolchain".to_owned(),
            value: toolchain.to_owned(),
        }])
        .expect("fixture compiler manifest"),
    }
}

fn source_certificate() -> Vec<u8> {
    let base = Certificate {
        version: 1,
        hashes: DomainHashes::zero(),
        state_count: 1,
        input_count: 1,
        observer_count: 7,
        state_bound: 1,
        claimed_cost: CostVector {
            states: 1,
            emitting_transitions: 0,
            payload_bytes: 0,
            action_emissions: 0,
        },
        observers: Vec::new(),
        outputs: Vec::new(),
        transitions: Vec::new(),
        relation: Vec::new(),
    }
    .encode();
    InductiveCertificate {
        version: 1,
        bound_hashes: DomainHashes::zero(),
        base_digest: artifact_digest(b"noticer-core/qseal/test-base/v1", &base),
        base_certificate: base,
        initial_pairs: Vec::new(),
        invariant: Vec::new(),
        closure: Vec::new(),
    }
    .encode()
}

fn abi_v1_module() -> Vec<u8> {
    let mut module = b"\0asm\x01\0\0\0".to_vec();
    let mut types = Vec::new();
    push_u32(&mut types, 7);
    push_type(&mut types, &[0x7f, 0x7e], &[0x7f]);
    push_type(&mut types, &[0x7f, 0x7f], &[0x7f]);
    push_type(&mut types, &[0x7f], &[0x7f]);
    push_type(&mut types, &[0x7f, 0x7e, 0x7f], &[0x7f]);
    push_type(&mut types, &[], &[0x7f]);
    push_type(&mut types, &[], &[0x7e]);
    push_type(&mut types, &[0x7e], &[0x7f]);
    push_section(&mut module, 1, &types);

    let mut imports = Vec::new();
    push_u32(&mut imports, 3);
    push_import(&mut imports, "qseal", "emit_frame", 0);
    push_import(&mut imports, "qseal", "emit_action", 1);
    push_import(&mut imports, "qseal", "public_failure", 2);
    push_section(&mut module, 2, &imports);

    let mut functions = Vec::new();
    push_u32(&mut functions, 5);
    for index in [3_u32, 4, 5, 4, 6] {
        push_u32(&mut functions, index);
    }
    push_section(&mut module, 3, &functions);
    push_section(&mut module, 5, &[1, 1, 1, 1]);

    let mut exports = Vec::new();
    push_u32(&mut exports, 4);
    push_export(&mut exports, "qseal.public.tick", 3);
    push_export(&mut exports, "qseal.public.reset", 4);
    push_export(&mut exports, "qseal.public.handoff", 5);
    push_export(&mut exports, "qseal.public.status", 6);
    push_section(&mut module, 7, &exports);

    let mut code = Vec::new();
    push_u32(&mut code, 5);
    for result_opcode in [0x41_u8, 0x41, 0x42, 0x41, 0x41] {
        let body = [0x00, result_opcode, 0x00, 0x0b];
        push_u32(&mut code, body.len() as u32);
        code.extend_from_slice(&body);
    }
    push_section(&mut module, 10, &code);
    module
}

fn push_type(target: &mut Vec<u8>, params: &[u8], results: &[u8]) {
    target.push(0x60);
    push_u32(target, params.len() as u32);
    target.extend_from_slice(params);
    push_u32(target, results.len() as u32);
    target.extend_from_slice(results);
}

fn push_import(target: &mut Vec<u8>, module: &str, name: &str, type_index: u32) {
    push_name(target, module);
    push_name(target, name);
    target.push(0);
    push_u32(target, type_index);
}

fn push_export(target: &mut Vec<u8>, name: &str, function_index: u32) {
    push_name(target, name);
    target.push(0);
    push_u32(target, function_index);
}

fn push_name(target: &mut Vec<u8>, value: &str) {
    push_u32(target, value.len() as u32);
    target.extend_from_slice(value.as_bytes());
}

fn push_section(module: &mut Vec<u8>, id: u8, payload: &[u8]) {
    module.push(id);
    push_u32(module, payload.len() as u32);
    module.extend_from_slice(payload);
}

fn push_u32(target: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        target.push(byte);
        if value == 0 {
            return;
        }
    }
}

fn child_fixture_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "quotient-seal-capsule-{}-independent.qseal",
        std::process::id()
    ))
}

#[test]
fn observer_registry_is_the_frozen_o0_through_o6_sequence() {
    assert_eq!(
        OBSERVER_REGISTRY_V1,
        b"QSOR\x01\x00\x07\x00\x00\x01\x02\x03\x04\x05\x06"
    );
}
