use crate::{AplotK7Binding, AplotPublicSourceArtifact, Digest, WireServiceAlias};
use noticer_transport_core::{FRAGMENT_SIZE, TOTAL_FRAGMENT_COUNT};
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
use thiserror::Error;

pub const APLOT_QSM_COMPILER_VERSION: u16 = 1;
pub const APLOT_FRAGMENT_ATTEMPT_KIND: u8 = 1;
pub const APLOT_RECONNECT_KIND: u8 = 2;
pub const APLOT_DEADLINE_KIND: u8 = 3;
pub const APLOT_PUBLIC_LOSS: i32 = 0x5201;
pub const APLOT_PUBLIC_RECONNECT: i32 = 0x5202;
pub const APLOT_PUBLIC_DEADLINE: i32 = 0x5203;

const COMPILER_ID: &str = "noticer.aplot-p0-compiler.v1";
const MODULE_DIGEST_DOMAIN: &[u8] = b"noticer-core/aplot/p0-module/v1";
const MANIFEST_DIGEST_DOMAIN: &[u8] = b"noticer-core/aplot/p0-compiler-manifest/v1";
const OBSERVER_DIGEST_DOMAIN: &[u8] = b"noticer-core/aplot/p0-observer-registry/v1";
const ROBUST_PENDING: &[u8] = b"APLOT_ROBUST_CERTIFICATE_PENDING_K8_13D4_NOT_VERIFIED_V1";
const RESOURCE_PENDING: &[u8] = b"APLOT_RESOURCE_CERTIFICATE_PENDING_NOT_VERIFIED_V1";
const UNKNOWN_PUBLIC_EVENT: i32 = 0x52fe;
const OUT_OF_ORDER_EVENT: i32 = 0x52ff;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AplotServiceCode {
    pub service_alias: WireServiceAlias,
    pub qsm_alias: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AplotCompileLimits {
    pub max_frames: usize,
    pub max_events: usize,
    pub max_wasm_bytes: usize,
    pub max_capsule_bytes: usize,
}

impl Default for AplotCompileLimits {
    fn default() -> Self {
        Self {
            max_frames: 1_024,
            max_events: 8_192,
            max_wasm_bytes: 1_048_576,
            max_capsule_bytes: 2_097_152,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AplotPublicEventKind {
    FragmentAttempt,
    Reconnect,
    Deadline,
}

impl AplotPublicEventKind {
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::FragmentAttempt => APLOT_FRAGMENT_ATTEMPT_KIND,
            Self::Reconnect => APLOT_RECONNECT_KIND,
            Self::Deadline => APLOT_DEADLINE_KIND,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AplotEventPlacement {
    pub public_step: u64,
    pub scheduled_tick: u64,
    pub qsm_alias: u32,
    pub frame_ordinal: u32,
    pub public_bucket: u32,
    pub sequence: u32,
    pub kind: AplotPublicEventKind,
    pub fragment_ordinal: Option<u8>,
    pub fragment_index: Option<u8>,
    pub delivered: Option<bool>,
    pub declared_fault_code: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AplotP0Binding {
    pub source_digest: Digest,
    pub schedule_digest: Digest,
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
pub struct AplotCompiledQsm {
    wasm: Vec<u8>,
    capsule: Vec<u8>,
    compiler_manifest: Vec<u8>,
    service_code: AplotServiceCode,
    events: Vec<AplotEventPlacement>,
    binding: AplotP0Binding,
}

impl AplotCompiledQsm {
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
    pub const fn service_code(&self) -> AplotServiceCode {
        self.service_code
    }

    #[must_use]
    pub fn events(&self) -> &[AplotEventPlacement] {
        &self.events
    }

    #[must_use]
    pub const fn binding(&self) -> AplotP0Binding {
        self.binding
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AplotCompileError {
    #[error("K7 binding does not match the APLOT source")]
    K7SourceMismatch,
    #[error("K7 binding does not match the APLOT public schedule")]
    K7ScheduleMismatch,
    #[error("APLOT service mapping must contain exactly the source service alias")]
    ServiceMappingCoverage,
    #[error("APLOT service mapping contains QSM alias zero")]
    ZeroQsmAlias,
    #[error("frame count {actual} exceeds limit {limit}")]
    FrameLimit { actual: usize, limit: usize },
    #[error("event count {actual} exceeds limit {limit}")]
    EventLimit { actual: usize, limit: usize },
    #[error("APLOT source contains a retry or variable fragment shape")]
    EventShape,
    #[error("APLOT event step cannot be represented by the P0 i64 ABI")]
    StepRange,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingEvent {
    scheduled_tick: u64,
    qsm_alias: u32,
    frame_ordinal: u32,
    public_bucket: u32,
    sequence: u32,
    kind: AplotPublicEventKind,
    fragment_ordinal: Option<u8>,
    fragment_index: Option<u8>,
    delivered: Option<bool>,
    declared_fault_code: i32,
}

pub fn compile_aplot_p0(
    source: &AplotPublicSourceArtifact,
    k7: &AplotK7Binding,
    service_codes: &[AplotServiceCode],
    limits: AplotCompileLimits,
) -> Result<AplotCompiledQsm, AplotCompileError> {
    if k7.source_digest() != source.digest() {
        return Err(AplotCompileError::K7SourceMismatch);
    }
    if k7.schedule_digest() != source.schedule_digest() {
        return Err(AplotCompileError::K7ScheduleMismatch);
    }
    if source.frames().len() > limits.max_frames {
        return Err(AplotCompileError::FrameLimit {
            actual: source.frames().len(),
            limit: limits.max_frames,
        });
    }
    if source.application_retry_count() != 0 {
        return Err(AplotCompileError::EventShape);
    }
    let [service_code] = service_codes else {
        return Err(AplotCompileError::ServiceMappingCoverage);
    };
    if service_code.service_alias != source.service_alias() {
        return Err(AplotCompileError::ServiceMappingCoverage);
    }
    if service_code.qsm_alias == 0 {
        return Err(AplotCompileError::ZeroQsmAlias);
    }

    let events = lower_events(source, *service_code, limits.max_events)?;
    let wat = render_wat(&events, service_code.qsm_alias);
    let wasm = wat::parse_str(&wat).map_err(|error| AplotCompileError::Wat(error.to_string()))?;
    if wasm.len() > limits.max_wasm_bytes {
        return Err(AplotCompileError::WasmLimit {
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
        other => return Err(AplotCompileError::Abi(format!("{other:?}"))),
    }

    let target_ir = parse_and_lower(
        &wasm,
        ParserLimits {
            max_module_bytes: limits.max_wasm_bytes,
            ..ParserLimits::default()
        },
    )
    .map_err(|error| AplotCompileError::TargetIr(format!("{error:?}")))?;
    let target_ir_digest = target_ir_hash(&target_ir);
    let module_digest = artifact_digest(MODULE_DIGEST_DOMAIN, &wasm);

    let compiler_manifest =
        build_compiler_manifest(source, k7, events.len(), module_digest, target_ir_digest)?;
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
    .map_err(|error| AplotCompileError::CapsuleBuild(format!("{error:?}")))?;
    let decoded = QsmCapsule::decode(&capsule, container_limits)
        .map_err(|error| AplotCompileError::CapsuleDecode(format!("{error:?}")))?;
    let capsule_digest = decoded.digest();
    let rebound = QsmCapsule::decode(&capsule, container_limits)
        .map_err(|error| AplotCompileError::CapsuleDecode(format!("{error:?}")))?;
    if rebound.digest() != capsule_digest {
        return Err(AplotCompileError::CapsuleBinding);
    }

    let binding = AplotP0Binding {
        source_digest: source.digest(),
        schedule_digest: source.schedule_digest(),
        certificate_digest: k7.certificate_digest(),
        generated_runtime_digest: k7.generated_runtime_digest(),
        module_digest,
        target_ir_digest,
        abi_digest: quotient_seal_abi_v1_hash(),
        compiler_manifest_digest: artifact_digest(MANIFEST_DIGEST_DOMAIN, &compiler_manifest_bytes),
        capsule_digest,
        observer_registry_digest: artifact_digest(OBSERVER_DIGEST_DOMAIN, OBSERVER_REGISTRY_V1),
    };

    Ok(AplotCompiledQsm {
        wasm,
        capsule,
        compiler_manifest: compiler_manifest_bytes,
        service_code: *service_code,
        events,
        binding,
    })
}

fn lower_events(
    source: &AplotPublicSourceArtifact,
    service_code: AplotServiceCode,
    max_events: usize,
) -> Result<Vec<AplotEventPlacement>, AplotCompileError> {
    let expected_slots = source
        .frames()
        .len()
        .checked_mul(TOTAL_FRAGMENT_COUNT)
        .ok_or(AplotCompileError::EventShape)?;
    if source.fragment_slots().len() != expected_slots {
        return Err(AplotCompileError::EventShape);
    }

    let mut pending = Vec::with_capacity(
        expected_slots
            .checked_add(source.frames().len())
            .ok_or(AplotCompileError::EventShape)?,
    );
    for slot in source.fragment_slots() {
        if usize::from(slot.fragment_bytes) != FRAGMENT_SIZE
            || usize::try_from(slot.frame_ordinal)
                .ok()
                .filter(|ordinal| *ordinal < source.frames().len())
                .is_none()
        {
            return Err(AplotCompileError::EventShape);
        }
        pending.push(PendingEvent {
            scheduled_tick: slot.scheduled_tick,
            qsm_alias: service_code.qsm_alias,
            frame_ordinal: slot.frame_ordinal,
            public_bucket: slot.public_bucket,
            sequence: slot.sequence,
            kind: AplotPublicEventKind::FragmentAttempt,
            fragment_ordinal: Some(slot.ordinal),
            fragment_index: Some(slot.fragment_index),
            delivered: Some(slot.delivered),
            declared_fault_code: if slot.delivered { 0 } else { APLOT_PUBLIC_LOSS },
        });
    }
    for (ordinal, frame) in source.frames().iter().enumerate() {
        let frame_ordinal = u32::try_from(ordinal).map_err(|_| AplotCompileError::EventShape)?;
        for reconnect_tick in frame.reconnect_ticks() {
            pending.push(PendingEvent {
                scheduled_tick: *reconnect_tick,
                qsm_alias: service_code.qsm_alias,
                frame_ordinal,
                public_bucket: frame.public_bucket(),
                sequence: frame.sequence(),
                kind: AplotPublicEventKind::Reconnect,
                fragment_ordinal: None,
                fragment_index: None,
                delivered: None,
                declared_fault_code: APLOT_PUBLIC_RECONNECT,
            });
        }
        pending.push(PendingEvent {
            scheduled_tick: frame.deadline_tick(),
            qsm_alias: service_code.qsm_alias,
            frame_ordinal,
            public_bucket: frame.public_bucket(),
            sequence: frame.sequence(),
            kind: AplotPublicEventKind::Deadline,
            fragment_ordinal: None,
            fragment_index: None,
            delivered: None,
            declared_fault_code: APLOT_PUBLIC_DEADLINE,
        });
    }
    if pending.len() > max_events {
        return Err(AplotCompileError::EventLimit {
            actual: pending.len(),
            limit: max_events,
        });
    }
    pending.sort_by_key(|event| {
        (
            event.scheduled_tick,
            event.kind.code(),
            event.frame_ordinal,
            event.fragment_ordinal.unwrap_or(u8::MAX),
        )
    });

    pending
        .into_iter()
        .enumerate()
        .map(|(public_step, event)| {
            let public_step =
                u64::try_from(public_step).map_err(|_| AplotCompileError::StepRange)?;
            if public_step > i64::MAX as u64 {
                return Err(AplotCompileError::StepRange);
            }
            Ok(AplotEventPlacement {
                public_step,
                scheduled_tick: event.scheduled_tick,
                qsm_alias: event.qsm_alias,
                frame_ordinal: event.frame_ordinal,
                public_bucket: event.public_bucket,
                sequence: event.sequence,
                kind: event.kind,
                fragment_ordinal: event.fragment_ordinal,
                fragment_index: event.fragment_index,
                delivered: event.delivered,
                declared_fault_code: event.declared_fault_code,
            })
        })
        .collect()
}

fn build_compiler_manifest(
    source: &AplotPublicSourceArtifact,
    k7: &AplotK7Binding,
    event_count: usize,
    module_digest: Digest,
    target_ir_digest: Digest,
) -> Result<CompilerManifest, AplotCompileError> {
    let entries = vec![
        entry(
            "aplot.active_frame_capacity",
            source.active_frame_capacity().to_string(),
        ),
        entry(
            "aplot.application_retry_count",
            source.application_retry_count().to_string(),
        ),
        entry("aplot.epoch", source.epoch().0.to_string()),
        entry("aplot.event_count", event_count.to_string()),
        entry("aplot.fragment_bytes", FRAGMENT_SIZE.to_string()),
        entry("aplot.policy_hash", bytes_hex(&source.policy_hash().0)),
        entry(
            "aplot.schedule_digest",
            digest_hex(source.schedule_digest()),
        ),
        entry("aplot.service_alias", bytes_hex(&source.service_alias().0)),
        entry("aplot.source_digest", digest_hex(source.digest())),
        entry("aplot.ttl_ticks", source.ttl_ticks().to_string()),
        entry("compiler.id", COMPILER_ID.to_string()),
        entry("hardware.status", "NOT_VERIFIED".to_string()),
        entry("k7.certificate_digest", digest_hex(k7.certificate_digest())),
        entry(
            "k7.generated_runtime_digest",
            digest_hex(k7.generated_runtime_digest()),
        ),
        entry("module.digest", digest_hex(module_digest)),
        entry("p1.status", "NOT_VERIFIED".to_string()),
        entry("relation.status", "PENDING_K8_13D4".to_string()),
        entry("target_ir.digest", digest_hex(target_ir_digest)),
    ];
    CompilerManifest::new(entries)
        .map_err(|error| AplotCompileError::CompilerManifest(format!("{error:?}")))
}

fn build_relation_certificate(
    k7: &AplotK7Binding,
    target_ir_digest: Digest,
) -> RelationCertificate {
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

fn render_wat(events: &[AplotEventPlacement], qsm_alias: u32) -> String {
    let mut kind_checks = String::new();
    let mut fault_checks = String::new();
    for event in events {
        if event.kind != AplotPublicEventKind::FragmentAttempt {
            kind_checks.push_str(&format!(
                "    (if (i64.eq (local.get $step) (i64.const {})) (then (local.set $kind (i32.const {}))))\n",
                event.public_step,
                event.kind.code()
            ));
        }
        if event.declared_fault_code != 0 {
            fault_checks.push_str(&format!(
                "    (if (i64.eq (local.get $step) (i64.const {})) (then (local.set $declared_fault (i32.const {}))))\n",
                event.public_step, event.declared_fault_code
            ));
        }
    }
    let event_count = events.len();
    format!(
        r#"(module
  (import "qseal" "emit_frame" (func $emit_frame (param i32 i64) (result i32)))
  (import "qseal" "emit_action" (func $emit_action (param i32 i32) (result i32)))
  (import "qseal" "public_failure" (func $public_failure (param i32) (result i32)))
  (memory 1 1)
  (global $cursor (mut i64) (i64.const -1))
  (func $event_kind (param $step i64) (result i32)
    (local $kind i32)
    (local.set $kind (i32.const {APLOT_FRAGMENT_ATTEMPT_KIND}))
{kind_checks}    (local.get $kind))
  (func $declared_fault (param $step i64) (result i32)
    (local $declared_fault i32)
{fault_checks}    (local.get $declared_fault))
  (func (export "qseal.public.tick") (param $service i32) (param $step i64) (param $fault i32) (result i32)
    (local $result i32)
    (local $kind i32)
    (local $declared_fault i32)
    (if (i32.or
          (i32.ne (local.get $service) (i32.const {qsm_alias}))
          (i32.or
            (i64.lt_s (local.get $step) (i64.const 0))
            (i64.ge_u (local.get $step) (i64.const {event_count}))))
      (then (return (call $public_failure (i32.const {UNKNOWN_PUBLIC_EVENT})))))
    (if (i64.ne (local.get $step) (i64.add (global.get $cursor) (i64.const 1)))
      (then (return (call $public_failure (i32.const {OUT_OF_ORDER_EVENT})))))
    (global.set $cursor (local.get $step))
    (local.set $kind (call $event_kind (local.get $step)))
    (if (i32.eq (local.get $kind) (i32.const {APLOT_FRAGMENT_ATTEMPT_KIND}))
      (then
        (local.set $result (call $emit_frame (local.get $service) (local.get $step)))
        (if (i32.ne (local.get $result) (i32.const 0))
          (then (return (local.get $result))))))
    (local.set $declared_fault (call $declared_fault (local.get $step)))
    (if (i32.ne (local.get $declared_fault) (i32.const 0))
      (then
        (local.set $result (call $public_failure (local.get $declared_fault)))
        (if (i32.ne (local.get $result) (i32.const 0))
          (then (return (local.get $result))))))
    (if (i32.ne (local.get $fault) (i32.const 0))
      (then (return (call $public_failure (local.get $fault)))))
    (i32.const 0))
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
