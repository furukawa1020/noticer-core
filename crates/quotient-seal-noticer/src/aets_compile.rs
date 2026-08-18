use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use noticer_aetp::ServiceBinding;
use quotient_forge_caqt::{artifact_digest, Digest, InductiveCertificate};
use quotient_seal_abi::{
    validate_wasm_abi, AbiManifest, AbiVerdict, DeploymentProfile, WasmSurfaceLimits,
};
use quotient_seal_capsule::{
    build_qsm, CompilerManifest, CompilerManifestEntry, QsmBuildInput, QsmCapsule,
    QsmContainerLimits, QsmResourceBounds, QsmSectionTag, OBSERVER_REGISTRY_V1,
};
use quotient_seal_relation::RelationCertificate;
use quotient_seal_target_ir::{parse_and_lower, target_ir_hash, ParserLimits};
use thiserror::Error;

use crate::{
    aets_observer_registry_digest, aets_qsm_capsule_digest, AetsK7Binding, AetsPublicSourceArtifact,
};

pub const AETS_QSM_COMPILER_VERSION: &str = "noticer-aets-qsm-compiler/v1";
const INDUCTIVE_DIGEST_DOMAIN: &[u8] = b"noticer-core/qseal/inductive-certificate/v1";
const PENDING_ROBUST_CERTIFICATE: &[u8] = b"NOT_VERIFIED:AETS-ROBUST-CERTIFICATE-PENDING-V1";
const PENDING_RESOURCE_CERTIFICATE: &[u8] = b"NOT_VERIFIED:AETS-RESOURCE-CERTIFICATE-PENDING-V1";
const UNKNOWN_SERVICE_FAILURE: i32 = 0x0a001;
const OUTSIDE_SCHEDULE_FAILURE: i32 = 0x0a002;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AetsServiceCode {
    pub service: ServiceBinding,
    pub qsm_alias: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AetsCompileLimits {
    pub max_services: usize,
    pub max_actions: usize,
    pub max_wasm_bytes: usize,
    pub capsule_limits: QsmContainerLimits,
}

impl Default for AetsCompileLimits {
    fn default() -> Self {
        Self {
            max_services: 64,
            max_actions: 1_024,
            max_wasm_bytes: 1_048_576,
            capsule_limits: QsmContainerLimits::default(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AetsCompiledQsm {
    wasm_module: Box<[u8]>,
    capsule: Box<[u8]>,
    module_digest: Digest,
    capsule_digest: Digest,
    registry_capsule_digest: Digest,
    observer_registry_digest: Digest,
    source_digest: Digest,
}

impl AetsCompiledQsm {
    #[must_use]
    pub fn wasm_module(&self) -> &[u8] {
        &self.wasm_module
    }

    #[must_use]
    pub fn capsule(&self) -> &[u8] {
        &self.capsule
    }

    #[must_use]
    pub const fn module_digest(&self) -> Digest {
        self.module_digest
    }

    #[must_use]
    pub const fn capsule_digest(&self) -> Digest {
        self.capsule_digest
    }

    #[must_use]
    pub const fn registry_capsule_digest(&self) -> Digest {
        self.registry_capsule_digest
    }

    #[must_use]
    pub const fn observer_registry_digest(&self) -> Digest {
        self.observer_registry_digest
    }

    #[must_use]
    pub const fn source_digest(&self) -> Digest {
        self.source_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Placement {
    qsm_alias: u32,
    slot: u64,
    action: u16,
}

pub fn compile_aets_p0(
    source: &AetsPublicSourceArtifact,
    k7: &AetsK7Binding,
    service_codes: &[AetsServiceCode],
    limits: AetsCompileLimits,
) -> Result<AetsCompiledQsm, AetsCompileError> {
    if source.digest() != k7.source_digest() {
        return Err(AetsCompileError::K7SourceMismatch);
    }
    let (canonical_codes, placements, schedule_start, schedule_end) =
        compile_plan(source, service_codes, limits)?;
    let wat = emit_wat(&canonical_codes, &placements, schedule_start, schedule_end)?;
    let wasm = wat::parse_str(&wat).map_err(|error| AetsCompileError::Wat(error.to_string()))?;
    if wasm.len() > limits.max_wasm_bytes {
        return Err(AetsCompileError::WasmSize {
            actual: wasm.len(),
            limit: limits.max_wasm_bytes,
        });
    }
    let abi_manifest = AbiManifest::canonical(DeploymentProfile::P0PublicQuotientOnly);
    match validate_wasm_abi(&wasm, abi_manifest, WasmSurfaceLimits::default()) {
        AbiVerdict::Valid(_) => {}
        verdict => return Err(AetsCompileError::Abi(format!("{verdict:?}"))),
    }
    let target = parse_and_lower(&wasm, ParserLimits::default())
        .map_err(|error| AetsCompileError::Target(format!("{error:?}")))?;
    let target_digest = target_ir_hash(&target);
    let source_certificate = inductive_source_certificate(k7);
    let inductive_digest = artifact_digest(INDUCTIVE_DIGEST_DOMAIN, &source_certificate);
    let (quotient_inputs, public_inputs, fault_inputs) = k7.input_axes();
    let action_deadline_steps = u32::try_from(schedule_end.saturating_sub(schedule_start))
        .map_err(|_| AetsCompileError::Arithmetic)?;
    let relation_certificate = RelationCertificate {
        version: 1,
        inductive_digest,
        target_ir_digest: target_digest,
        k7_manifest_digest: k7.generated_runtime_digest(),
        quotient_inputs,
        public_inputs,
        fault_inputs,
        action_deadline_steps,
        records: Vec::new(),
    }
    .encode();
    let compiler_manifest = compiler_manifest(source, k7)?;
    let capsule = build_qsm(
        QsmBuildInput {
            resource_bounds: QsmResourceBounds::default(),
            source_certificate,
            wasm_module: wasm.clone(),
            abi_manifest,
            relation_certificate,
            robust_certificate: PENDING_ROBUST_CERTIFICATE.to_vec(),
            resource_certificate: PENDING_RESOURCE_CERTIFICATE.to_vec(),
            compiler_manifest,
        },
        limits.capsule_limits,
    )
    .map_err(|error| AetsCompileError::CapsuleBuild(format!("{error:?}")))?;
    let decoded = QsmCapsule::decode(&capsule, limits.capsule_limits)
        .map_err(|error| AetsCompileError::CapsuleDecode(format!("{error:?}")))?;
    let wasm_section = decoded.section(QsmSectionTag::WasmModule);
    if wasm_section.payload() != wasm {
        return Err(AetsCompileError::CapsuleBinding);
    }
    Ok(AetsCompiledQsm {
        wasm_module: wasm.into_boxed_slice(),
        capsule: capsule.clone().into_boxed_slice(),
        module_digest: wasm_section.digest,
        capsule_digest: decoded.digest(),
        registry_capsule_digest: aets_qsm_capsule_digest(&capsule),
        observer_registry_digest: aets_observer_registry_digest(OBSERVER_REGISTRY_V1),
        source_digest: source.digest(),
    })
}

fn compile_plan(
    source: &AetsPublicSourceArtifact,
    service_codes: &[AetsServiceCode],
    limits: AetsCompileLimits,
) -> Result<(Vec<AetsServiceCode>, Vec<Placement>, u64, u64), AetsCompileError> {
    let context = source.public_context();
    if context.network.services.len() > limits.max_services {
        return Err(AetsCompileError::ServiceLimit);
    }
    if source.action_semantics().obligations.len() > limits.max_actions {
        return Err(AetsCompileError::ActionLimit);
    }
    let expected: BTreeSet<_> = context.network.services.iter().copied().collect();
    let mut by_service = BTreeMap::new();
    let mut aliases = BTreeSet::new();
    for mapping in service_codes {
        if mapping.qsm_alias == 0
            || by_service
                .insert(mapping.service, mapping.qsm_alias)
                .is_some()
            || !aliases.insert(mapping.qsm_alias)
        {
            return Err(AetsCompileError::InvalidServiceMapping);
        }
    }
    if by_service.keys().copied().collect::<BTreeSet<_>>() != expected {
        return Err(AetsCompileError::InvalidServiceMapping);
    }
    let canonical_codes = by_service
        .iter()
        .map(|(service, qsm_alias)| AetsServiceCode {
            service: *service,
            qsm_alias: *qsm_alias,
        })
        .collect::<Vec<_>>();
    let slot_count = u64::from(context.schedule.buckets)
        .checked_mul(u64::from(context.schedule.slots_per_bucket))
        .ok_or(AetsCompileError::Arithmetic)?;
    let schedule_start = context.network.start_slot.0;
    let schedule_end = schedule_start
        .checked_add(
            slot_count
                .checked_sub(1)
                .ok_or(AetsCompileError::Arithmetic)?,
        )
        .ok_or(AetsCompileError::Arithmetic)?;
    if i64::try_from(schedule_end).is_err() {
        return Err(AetsCompileError::SlotRange);
    }
    let slots_per_bucket = u64::from(context.schedule.slots_per_bucket);
    let mut placements = Vec::new();
    for obligation in &source.action_semantics().obligations {
        let bucket_start = schedule_start
            .checked_add(
                obligation
                    .public_bucket
                    .0
                    .checked_mul(slots_per_bucket)
                    .ok_or(AetsCompileError::Arithmetic)?,
            )
            .ok_or(AetsCompileError::Arithmetic)?;
        let bucket_end = bucket_start
            .checked_add(slots_per_bucket - 1)
            .ok_or(AetsCompileError::Arithmetic)?;
        let start = obligation.release_window_start.0.max(bucket_start);
        let end = obligation.release_deadline.0.min(bucket_end);
        if start > end || end > schedule_end {
            return Err(AetsCompileError::ActionWindow);
        }
        let mut domain = Vec::with_capacity(24);
        domain.extend_from_slice(&obligation.service.0);
        domain.extend_from_slice(&obligation.public_bucket.0.to_le_bytes());
        let width = end - start + 1;
        let slot = start + source.schedule_tape().sample_u64(&domain, 0) % width;
        placements.push(Placement {
            qsm_alias: by_service[&obligation.service],
            slot,
            action: obligation.action as u16,
        });
    }
    placements.sort_by_key(|placement| (placement.slot, placement.qsm_alias, placement.action));
    Ok((canonical_codes, placements, schedule_start, schedule_end))
}

fn emit_wat(
    service_codes: &[AetsServiceCode],
    placements: &[Placement],
    schedule_start: u64,
    schedule_end: u64,
) -> Result<String, AetsCompileError> {
    let mut wat = String::new();
    writeln!(wat, "(module").map_err(|_| AetsCompileError::Formatting)?;
    writeln!(
        wat,
        "  (import \"qseal\" \"emit_frame\" (func $emit_frame (param i32 i64) (result i32)))"
    )
    .map_err(|_| AetsCompileError::Formatting)?;
    writeln!(
        wat,
        "  (import \"qseal\" \"emit_action\" (func $emit_action (param i32 i32) (result i32)))"
    )
    .map_err(|_| AetsCompileError::Formatting)?;
    writeln!(
        wat,
        "  (import \"qseal\" \"public_failure\" (func $public_failure (param i32) (result i32)))"
    )
    .map_err(|_| AetsCompileError::Formatting)?;
    writeln!(wat, "  (memory 1 1)").map_err(|_| AetsCompileError::Formatting)?;
    writeln!(wat, "  (global $state (mut i32) (i32.const 0))")
        .map_err(|_| AetsCompileError::Formatting)?;
    writeln!(wat, "  (func (export \"qseal.public.tick\") (param $service i32) (param $slot i64) (param $fault i32) (result i32) (local $known i32)").map_err(|_| AetsCompileError::Formatting)?;
    for mapping in service_codes {
        writeln!(wat, "    local.get $service\n    i32.const {}\n    i32.eq\n    if\n      i32.const 1\n      local.set $known\n    end", mapping.qsm_alias as i32).map_err(|_| AetsCompileError::Formatting)?;
    }
    writeln!(wat, "    local.get $known\n    i32.eqz\n    if\n      i32.const {UNKNOWN_SERVICE_FAILURE}\n      call $public_failure\n      drop\n      i32.const 1\n      return\n    end").map_err(|_| AetsCompileError::Formatting)?;
    writeln!(wat, "    local.get $slot\n    i64.const {}\n    i64.lt_u\n    local.get $slot\n    i64.const {}\n    i64.gt_u\n    i32.or\n    if\n      i32.const {OUTSIDE_SCHEDULE_FAILURE}\n      call $public_failure\n      drop\n      i32.const 2\n      return\n    end", schedule_start as i64, schedule_end as i64).map_err(|_| AetsCompileError::Formatting)?;
    writeln!(wat, "    local.get $service\n    local.get $slot\n    call $emit_frame\n    drop\n    global.get $state\n    i32.const 1\n    i32.add\n    global.set $state").map_err(|_| AetsCompileError::Formatting)?;
    writeln!(wat, "    local.get $fault\n    i32.eqz\n    if\n    else\n      local.get $fault\n      call $public_failure\n      drop\n      i32.const 3\n      return\n    end").map_err(|_| AetsCompileError::Formatting)?;
    for placement in placements {
        writeln!(wat, "    local.get $service\n    i32.const {}\n    i32.eq\n    local.get $slot\n    i64.const {}\n    i64.eq\n    i32.and\n    if\n      i32.const {}\n      local.get $slot\n      i32.wrap_i64\n      call $emit_action\n      drop\n    end", placement.qsm_alias as i32, placement.slot as i64, placement.action).map_err(|_| AetsCompileError::Formatting)?;
    }
    writeln!(wat, "    i32.const 0)").map_err(|_| AetsCompileError::Formatting)?;
    writeln!(wat, "  (func (export \"qseal.public.reset\") (result i32) i32.const 0 global.set $state i32.const 0)").map_err(|_| AetsCompileError::Formatting)?;
    writeln!(wat, "  (func (export \"qseal.public.handoff\") (result i64) global.get $state i64.extend_i32_u)").map_err(|_| AetsCompileError::Formatting)?;
    writeln!(
        wat,
        "  (func (export \"qseal.public.status\") (result i32) global.get $state)"
    )
    .map_err(|_| AetsCompileError::Formatting)?;
    writeln!(wat, ")").map_err(|_| AetsCompileError::Formatting)?;
    Ok(wat)
}

fn inductive_source_certificate(k7: &AetsK7Binding) -> Vec<u8> {
    let certificate = k7.certificate();
    InductiveCertificate {
        version: 1,
        bound_hashes: certificate.hashes,
        base_digest: k7.certificate_digest(),
        base_certificate: k7.source_certificate().to_vec(),
        initial_pairs: certificate.relation.clone(),
        invariant: certificate.relation.clone(),
        closure: Vec::new(),
    }
    .encode()
}

fn compiler_manifest(
    source: &AetsPublicSourceArtifact,
    k7: &AetsK7Binding,
) -> Result<CompilerManifest, AetsCompileError> {
    CompilerManifest::new(vec![
        CompilerManifestEntry {
            key: "aets.epoch".to_owned(),
            value: source.epoch().0.to_string(),
        },
        CompilerManifestEntry {
            key: "aets.policy_hash".to_owned(),
            value: hex(&source.policy_hash().0),
        },
        CompilerManifestEntry {
            key: "aets.service_alias".to_owned(),
            value: hex(&source.service_alias().0),
        },
        CompilerManifestEntry {
            key: "aets.source_digest".to_owned(),
            value: hex(source.digest().as_bytes()),
        },
        CompilerManifestEntry {
            key: "compiler.id".to_owned(),
            value: AETS_QSM_COMPILER_VERSION.to_owned(),
        },
        CompilerManifestEntry {
            key: "hardware.status".to_owned(),
            value: "NOT_VERIFIED".to_owned(),
        },
        CompilerManifestEntry {
            key: "k7.runtime_manifest".to_owned(),
            value: hex(k7.generated_runtime_digest().as_bytes()),
        },
    ])
    .map_err(|error| AetsCompileError::CompilerManifest(format!("{error:?}")))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Debug, Error)]
pub enum AetsCompileError {
    #[error("AETS K7 binding belongs to a different public source")]
    K7SourceMismatch,
    #[error("AETS service mapping is missing, duplicated, zero, or contains an extra service")]
    InvalidServiceMapping,
    #[error("AETS source exceeds the compiler service limit")]
    ServiceLimit,
    #[error("AETS source exceeds the compiler action limit")]
    ActionLimit,
    #[error("AETS schedule arithmetic overflow")]
    Arithmetic,
    #[error("AETS public slot exceeds the frozen signed Wasm literal range")]
    SlotRange,
    #[error("AETS action window does not fit the public schedule")]
    ActionWindow,
    #[error("AETS WAT formatting failed")]
    Formatting,
    #[error("AETS WAT compilation failed: {0}")]
    Wat(String),
    #[error("compiled AETS Wasm exceeds the limit: {actual} > {limit}")]
    WasmSize { actual: usize, limit: usize },
    #[error("compiled AETS Wasm violates the P0 ABI: {0}")]
    Abi(String),
    #[error("compiled AETS Wasm cannot be lowered to canonical target IR: {0}")]
    Target(String),
    #[error("AETS compiler manifest is invalid: {0}")]
    CompilerManifest(String),
    #[error("AETS QSM capsule build failed: {0}")]
    CapsuleBuild(String),
    #[error("AETS QSM capsule decode failed: {0}")]
    CapsuleDecode(String),
    #[error("AETS QSM capsule does not contain the generated module")]
    CapsuleBinding,
}
