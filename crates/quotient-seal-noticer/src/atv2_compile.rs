use crate::{Atv2K7Binding, Atv2PublicSourceArtifact, Digest};
use noticer_aetp::ServiceBinding;
use noticer_protocol::FrameKind;
use noticer_types::ActionCode;
use quotient_forge_caqt::artifact_digest;
use quotient_seal_abi::{
    quotient_seal_abi_v1_hash, validate_wasm_abi, AbiManifest, AbiVerdict, DeploymentProfile,
    WasmSurfaceLimits, ABI_VERSION,
};
use quotient_seal_capsule::{
    build_qsm, CompilerManifest, CompilerManifestEntry, QsmBuildInput, QsmCapsule,
    QsmContainerLimits, QsmResourceBounds, OBSERVER_REGISTRY_V1,
};
use quotient_seal_relation::{RelationCertificate, RelationRecord, RELATION_FORMAT_VERSION};
use quotient_seal_target_ir::{parse_and_lower, target_ir_hash, ParserLimits};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const ATV2_QSM_COMPILER_VERSION: u16 = 1;
pub const ATV2_FIXED_CIPHERTEXT_BYTES: u16 = 236;

const COMPILER_ID: &str = "noticer.atv2-p0-compiler.v1";
const MODULE_DIGEST_DOMAIN: &[u8] = b"noticer-core/atv2/p0-module/v1";
const MANIFEST_DIGEST_DOMAIN: &[u8] = b"noticer-core/atv2/p0-compiler-manifest/v1";
const OBSERVER_DIGEST_DOMAIN: &[u8] = b"noticer-core/atv2/p0-observer-registry/v1";
const ROBUST_PENDING: &[u8] = b"ATV2_ROBUST_CERTIFICATE_PENDING_K8_13C4_NOT_VERIFIED_V1";
const RESOURCE_PENDING: &[u8] = b"ATV2_RESOURCE_CERTIFICATE_PENDING_NOT_VERIFIED_V1";
const UNKNOWN_PUBLIC_FRAME: i32 = 0x4101;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Atv2ServiceCode {
    pub service: ServiceBinding,
    pub qsm_alias: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Atv2CompileLimits {
    pub max_services: usize,
    pub max_frames: usize,
    pub max_actions: usize,
    pub max_wasm_bytes: usize,
    pub max_capsule_bytes: usize,
}

impl Default for Atv2CompileLimits {
    fn default() -> Self {
        Self {
            max_services: 64,
            max_frames: 4_096,
            max_actions: 1_024,
            max_wasm_bytes: 1_048_576,
            max_capsule_bytes: 2_097_152,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Atv2FramePlacement {
    pub service: ServiceBinding,
    pub qsm_alias: u32,
    pub absolute_slot: u64,
    pub public_bucket: u32,
    pub slot_in_bucket: u16,
    pub sequence: u32,
    pub kind: FrameKind,
    pub action: Option<ActionCode>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Atv2P0Binding {
    pub source_digest: Digest,
    pub frame_plan_digest: Digest,
    pub certificate_digest: Digest,
    pub generated_runtime_digest: Digest,
    pub module_digest: Digest,
    pub target_ir_digest: Digest,
    pub abi_digest: Digest,
    pub compiler_manifest_digest: Digest,
    pub capsule_digest: Digest,
    pub observer_registry_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Atv2CompiledQsm {
    wasm: Vec<u8>,
    capsule: Vec<u8>,
    compiler_manifest: Vec<u8>,
    service_codes: Vec<Atv2ServiceCode>,
    placements: Vec<Atv2FramePlacement>,
    binding: Atv2P0Binding,
}

impl Atv2CompiledQsm {
    #[must_use]
    pub fn wasm(&self) -> &[u8] {
        &self.wasm
    }

    #[must_use]
    pub fn capsule(&self) -> &[u8] {
        &self.capsule
    }

    #[must_use]
    pub fn compiler_manifest(&self) -> &[u8] {
        &self.compiler_manifest
    }

    #[must_use]
    pub fn service_codes(&self) -> &[Atv2ServiceCode] {
        &self.service_codes
    }

    #[must_use]
    pub fn placements(&self) -> &[Atv2FramePlacement] {
        &self.placements
    }

    #[must_use]
    pub const fn binding(&self) -> Atv2P0Binding {
        self.binding
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum Atv2CompileError {
    #[error("K7 binding does not match the ATv2 source")]
    K7SourceMismatch,
    #[error("ATv2 source has no public service")]
    EmptyServiceSet,
    #[error("service count {actual} exceeds limit {limit}")]
    ServiceLimit { actual: usize, limit: usize },
    #[error("frame count {actual} exceeds limit {limit}")]
    FrameLimit { actual: usize, limit: usize },
    #[error("action count {actual} exceeds limit {limit}")]
    ActionLimit { actual: usize, limit: usize },
    #[error("service mapping is missing or contains an unknown service")]
    ServiceMappingCoverage,
    #[error("service mapping contains a duplicate service")]
    DuplicateServiceMapping,
    #[error("service mapping contains QSM alias zero")]
    ZeroQsmAlias,
    #[error("service mapping contains a duplicate QSM alias")]
    DuplicateQsmAlias,
    #[error("an action frame has no unique public action obligation")]
    ActionMapping,
    #[error("ATv2 source does not use the fixed 236-byte ciphertext shape")]
    FrameShape,
    #[error("a public slot cannot be represented by the P0 i64 ABI")]
    SlotRange,
    #[error("WAT lowering failed: {0}")]
    Wat(String),
    #[error("Wasm size {actual} exceeds limit {limit}")]
    WasmLimit { actual: usize, limit: usize },
    #[error("generated module violates the canonical P0 ABI: {0}")]
    Abi(String),
    #[error("generated module cannot be lowered to canonical target IR: {0}")]
    TargetIr(String),
    #[error("compiler manifest is invalid: {0}")]
    CompilerManifest(String),
    #[error("QSM capsule build failed: {0}")]
    CapsuleBuild(String),
    #[error("QSM capsule decode failed: {0}")]
    CapsuleDecode(String),
    #[error("QSM capsule digest changed during binding")]
    CapsuleBinding,
}

pub fn compile_atv2_p0(
    source: &Atv2PublicSourceArtifact,
    k7: &Atv2K7Binding,
    service_codes: &[Atv2ServiceCode],
    limits: Atv2CompileLimits,
) -> Result<Atv2CompiledQsm, Atv2CompileError> {
    if k7.source_digest() != source.digest() {
        return Err(Atv2CompileError::K7SourceMismatch);
    }
    if source.public_context().schedule.fixed_ciphertext_size != ATV2_FIXED_CIPHERTEXT_BYTES {
        return Err(Atv2CompileError::FrameShape);
    }
    if source.frames().len() > limits.max_frames {
        return Err(Atv2CompileError::FrameLimit {
            actual: source.frames().len(),
            limit: limits.max_frames,
        });
    }

    let expected_services = source
        .frames()
        .iter()
        .map(|frame| frame.identity().service)
        .collect::<BTreeSet<_>>();
    if expected_services.is_empty() {
        return Err(Atv2CompileError::EmptyServiceSet);
    }
    if expected_services.len() > limits.max_services {
        return Err(Atv2CompileError::ServiceLimit {
            actual: expected_services.len(),
            limit: limits.max_services,
        });
    }
    let canonical_codes = canonicalize_service_codes(service_codes, &expected_services)?;
    let code_by_service = canonical_codes
        .iter()
        .map(|entry| (entry.service, entry.qsm_alias))
        .collect::<BTreeMap<_, _>>();

    let mut action_by_bucket = BTreeMap::new();
    for planned in source.token_plan().actions() {
        let obligation = planned.obligation();
        let bucket = u32::try_from(obligation.public_bucket.0)
            .map_err(|_| Atv2CompileError::ActionMapping)?;
        if action_by_bucket
            .insert((obligation.service, bucket), obligation.action)
            .is_some()
        {
            return Err(Atv2CompileError::ActionMapping);
        }
    }
    if action_by_bucket.len() > limits.max_actions {
        return Err(Atv2CompileError::ActionLimit {
            actual: action_by_bucket.len(),
            limit: limits.max_actions,
        });
    }

    let mut matched_actions = BTreeSet::new();
    let mut placements = Vec::with_capacity(source.frames().len());
    for frame in source.frames() {
        let identity = frame.identity();
        if identity.absolute_slot.0 > i64::MAX as u64 {
            return Err(Atv2CompileError::SlotRange);
        }
        let action = match frame.kind() {
            FrameKind::Cover => None,
            FrameKind::Action => {
                let key = (identity.service, identity.public_bucket);
                let action = action_by_bucket
                    .get(&key)
                    .copied()
                    .ok_or(Atv2CompileError::ActionMapping)?;
                if !matched_actions.insert(key) {
                    return Err(Atv2CompileError::ActionMapping);
                }
                Some(action)
            }
        };
        placements.push(Atv2FramePlacement {
            service: identity.service,
            qsm_alias: code_by_service[&identity.service],
            absolute_slot: identity.absolute_slot.0,
            public_bucket: identity.public_bucket,
            slot_in_bucket: identity.slot_in_bucket,
            sequence: identity.sequence,
            kind: frame.kind(),
            action,
        });
    }
    if matched_actions.len() != action_by_bucket.len() {
        return Err(Atv2CompileError::ActionMapping);
    }
    placements.sort_by_key(|item| (item.absolute_slot, item.service));

    let wat = render_wat(&placements);
    let wasm = wat::parse_str(&wat).map_err(|error| Atv2CompileError::Wat(error.to_string()))?;
    if wasm.len() > limits.max_wasm_bytes {
        return Err(Atv2CompileError::WasmLimit {
            actual: wasm.len(),
            limit: limits.max_wasm_bytes,
        });
    }

    let abi_manifest = AbiManifest {
        version: ABI_VERSION,
        profile: DeploymentProfile::P0PublicQuotientOnly,
        abi_hash: quotient_seal_abi_v1_hash(),
    };
    match validate_wasm_abi(
        &wasm,
        abi_manifest,
        WasmSurfaceLimits {
            max_bytes: limits.max_wasm_bytes,
            ..WasmSurfaceLimits::default()
        },
    ) {
        AbiVerdict::Valid(_) => {}
        other => return Err(Atv2CompileError::Abi(format!("{other:?}"))),
    }

    let target_ir = parse_and_lower(
        &wasm,
        ParserLimits {
            max_module_bytes: limits.max_wasm_bytes,
            ..ParserLimits::default()
        },
    )
    .map_err(|error| Atv2CompileError::TargetIr(format!("{error:?}")))?;
    let target_ir_digest = target_ir_hash(&target_ir);
    let module_digest = artifact_digest(MODULE_DIGEST_DOMAIN, &wasm);

    let compiler_manifest = build_compiler_manifest(source, k7, module_digest, target_ir_digest)?;
    let compiler_manifest_bytes = compiler_manifest.encode();
    let relation_certificate = build_relation_certificate(k7, target_ir_digest);
    let container_limits = QsmContainerLimits {
        max_capsule_bytes: limits.max_capsule_bytes,
        ..QsmContainerLimits::default()
    };
    let capsule = build_qsm(
        QsmBuildInput {
            resource_bounds: QsmResourceBounds::default(),
            source_certificate: k7.certificate().encode(),
            wasm_module: wasm.clone(),
            abi_manifest,
            relation_certificate: relation_certificate.encode(),
            robust_certificate: ROBUST_PENDING.to_vec(),
            resource_certificate: RESOURCE_PENDING.to_vec(),
            compiler_manifest,
        },
        container_limits,
    )
    .map_err(|error| Atv2CompileError::CapsuleBuild(format!("{error:?}")))?;
    let decoded = QsmCapsule::decode(&capsule, container_limits)
        .map_err(|error| Atv2CompileError::CapsuleDecode(format!("{error:?}")))?;
    let capsule_digest = decoded.digest();
    let rebound = QsmCapsule::decode(&capsule, container_limits)
        .map_err(|error| Atv2CompileError::CapsuleDecode(format!("{error:?}")))?;
    if rebound.digest() != capsule_digest {
        return Err(Atv2CompileError::CapsuleBinding);
    }

    let binding = Atv2P0Binding {
        source_digest: source.digest(),
        frame_plan_digest: source.frame_plan_digest(),
        certificate_digest: k7.certificate_digest(),
        generated_runtime_digest: k7.generated_runtime_digest(),
        module_digest,
        target_ir_digest,
        abi_digest: quotient_seal_abi_v1_hash(),
        compiler_manifest_digest: artifact_digest(MANIFEST_DIGEST_DOMAIN, &compiler_manifest_bytes),
        capsule_digest,
        observer_registry_digest: artifact_digest(OBSERVER_DIGEST_DOMAIN, OBSERVER_REGISTRY_V1),
    };

    Ok(Atv2CompiledQsm {
        wasm,
        capsule,
        compiler_manifest: compiler_manifest_bytes,
        service_codes: canonical_codes,
        placements,
        binding,
    })
}

fn canonicalize_service_codes(
    service_codes: &[Atv2ServiceCode],
    expected: &BTreeSet<ServiceBinding>,
) -> Result<Vec<Atv2ServiceCode>, Atv2CompileError> {
    if service_codes.len() != expected.len() {
        return Err(Atv2CompileError::ServiceMappingCoverage);
    }
    let mut by_service = BTreeMap::new();
    let mut aliases = BTreeSet::new();
    for entry in service_codes {
        if entry.qsm_alias == 0 {
            return Err(Atv2CompileError::ZeroQsmAlias);
        }
        if by_service.insert(entry.service, entry.qsm_alias).is_some() {
            return Err(Atv2CompileError::DuplicateServiceMapping);
        }
        if !aliases.insert(entry.qsm_alias) {
            return Err(Atv2CompileError::DuplicateQsmAlias);
        }
    }
    if by_service.keys().copied().collect::<BTreeSet<_>>() != *expected {
        return Err(Atv2CompileError::ServiceMappingCoverage);
    }
    Ok(by_service
        .into_iter()
        .map(|(service, qsm_alias)| Atv2ServiceCode { service, qsm_alias })
        .collect())
}

fn build_compiler_manifest(
    source: &Atv2PublicSourceArtifact,
    k7: &Atv2K7Binding,
    module_digest: Digest,
    target_ir_digest: Digest,
) -> Result<CompilerManifest, Atv2CompileError> {
    let schedule = source.public_context().schedule;
    let entries = vec![
        entry("atv2.epoch", source.epoch().0.to_string()),
        entry(
            "atv2.frame_bytes",
            schedule.fixed_ciphertext_size.to_string(),
        ),
        entry(
            "atv2.frame_interval_ms",
            schedule.frame_interval_ms.to_string(),
        ),
        entry(
            "atv2.frame_plan_digest",
            digest_hex(source.frame_plan_digest()),
        ),
        entry("atv2.policy_hash", bytes_hex(&source.policy_hash().0)),
        entry("atv2.service_alias", bytes_hex(&source.service_alias().0)),
        entry("atv2.source_digest", digest_hex(source.digest())),
        entry("compiler.id", COMPILER_ID.to_string()),
        entry("hardware.status", "NOT_VERIFIED".to_string()),
        entry("k7.certificate_digest", digest_hex(k7.certificate_digest())),
        entry(
            "k7.generated_runtime_digest",
            digest_hex(k7.generated_runtime_digest()),
        ),
        entry("module.digest", digest_hex(module_digest)),
        entry("relation.status", "PENDING_K8_13C3".to_string()),
        entry("target_ir.digest", digest_hex(target_ir_digest)),
    ];
    CompilerManifest::new(entries)
        .map_err(|error| Atv2CompileError::CompilerManifest(format!("{error:?}")))
}

fn build_relation_certificate(k7: &Atv2K7Binding, target_ir_digest: Digest) -> RelationCertificate {
    let records = (0..k7.certificate().state_count)
        .map(|source_state| RelationRecord {
            source_state,
            entry_pcs: vec![0],
            exit_pcs: vec![0],
            globals: Vec::new(),
            memory: Vec::new(),
            allowed_writes: Vec::new(),
        })
        .collect();
    RelationCertificate {
        version: RELATION_FORMAT_VERSION,
        inductive_digest: k7.certificate_digest(),
        target_ir_digest,
        k7_manifest_digest: k7.generated_runtime_digest(),
        quotient_inputs: 1,
        public_inputs: 1,
        fault_inputs: 1,
        action_deadline_steps: 0,
        records,
    }
}

fn render_wat(placements: &[Atv2FramePlacement]) -> String {
    let mut frame_checks = String::new();
    let mut action_checks = String::new();
    for placement in placements {
        let condition = format!(
            "(i32.and (i32.eq (local.get $service) (i32.const {})) (i64.eq (local.get $slot) (i64.const {})))",
            placement.qsm_alias, placement.absolute_slot
        );
        frame_checks.push_str(&format!(
            "    (if {condition} (then (local.set $valid (i32.const 1))))\n"
        ));
        if let Some(action) = placement.action {
            action_checks.push_str(&format!(
                "    (if {condition} (then (local.set $action (i32.const {}))))\n",
                action as u8
            ));
        }
    }
    format!(
        r#"(module
  (import "qseal" "emit_frame" (func $emit_frame (param i32 i64) (result i32)))
  (import "qseal" "emit_action" (func $emit_action (param i32 i32) (result i32)))
  (import "qseal" "public_failure" (func $public_failure (param i32) (result i32)))
  (global $cursor (mut i64) (i64.const -1))
  (func $is_frame (param $service i32) (param $slot i64) (result i32)
    (local $valid i32)
{frame_checks}    (local.get $valid))
  (func $action_code (param $service i32) (param $slot i64) (result i32)
    (local $action i32)
{action_checks}    (local.get $action))
  (func (export "qseal.public.tick") (param $service i32) (param $slot i64) (param $fault i32) (result i32)
    (local $result i32)
    (local $action i32)
    (if (i32.eqz (call $is_frame (local.get $service) (local.get $slot)))
      (then (return (call $public_failure (i32.const {UNKNOWN_PUBLIC_FRAME})))))
    (local.set $result (call $emit_frame (local.get $service) (local.get $slot)))
    (if (i32.ne (local.get $result) (i32.const 0))
      (then (return (local.get $result))))
    (global.set $cursor (local.get $slot))
    (if (i32.ne (local.get $fault) (i32.const 0))
      (then (return (call $public_failure (local.get $fault)))))
    (local.set $action (call $action_code (local.get $service) (local.get $slot)))
    (if (result i32) (i32.eqz (local.get $action))
      (then (i32.const 0))
      (else (call $emit_action (local.get $service) (local.get $action)))))
  (func (export "qseal.public.reset") (result i32)
    (global.set $cursor (i64.const -1))
    (i32.const 0))
  (func (export "qseal.public.handoff") (result i64)
    (global.get $cursor))
  (func (export "qseal.public.status") (result i32)
    (i32.const 0)))
"#
    )
}

fn entry(key: &str, value: String) -> CompilerManifestEntry {
    CompilerManifestEntry {
        key: key.to_string(),
        value,
    }
}

fn digest_hex(digest: Digest) -> String {
    bytes_hex(digest.as_bytes())
}

fn bytes_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}
