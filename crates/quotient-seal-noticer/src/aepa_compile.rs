use std::collections::BTreeSet;

use noticer_protocol::WireServiceAlias;
use noticer_provenance_lease::{NPL1_PROFILE_ID, NPL1_VERSION};
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

use crate::{
    bind_aepa_k7_manifest, AepaK7Binding, AepaPublicInput, AepaPublicOutput,
    AepaPublicSourceArtifact, AepaPublicState, Digest, NoticerModuleId, NoticerQsmManifest,
};

pub const AEPA_QSM_COMPILER_VERSION: u16 = 1;
pub const AEPA_PUBLIC_REJECT: i32 = 0x4504;
pub const AEPA_PUBLIC_FAULT: i32 = 0x4505;

const COMPILER_ID: &str = "noticer.aepa-p0-compiler.v1";
const MODULE_DIGEST_DOMAIN: &[u8] = b"noticer-core/aepa/p0-module/v1";
const TRANSITION_DIGEST_DOMAIN: &[u8] = b"noticer-core/aepa/p0-transitions/v1";
const MANIFEST_DIGEST_DOMAIN: &[u8] = b"noticer-core/aepa/p0-compiler-manifest/v1";
const OBSERVER_DIGEST_DOMAIN: &[u8] = b"noticer-core/aepa/p0-observer-registry/v1";
const ROBUST_PENDING: &[u8] = b"AEPA_ROBUST_CERTIFICATE_PENDING_K8_13E5_NOT_VERIFIED_V1";
const RESOURCE_PENDING: &[u8] = b"AEPA_RESOURCE_CERTIFICATE_PENDING_K8_13E4_NOT_VERIFIED_V1";
pub const AEPA_UNKNOWN_PUBLIC_SERVICE: i32 = 0x4501;
pub const AEPA_UNKNOWN_PUBLIC_INPUT: i32 = 0x4502;
pub const AEPA_OUT_OF_ORDER_PUBLIC_STEP: i32 = 0x4503;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AepaServiceCode {
    pub service_alias: WireServiceAlias,
    pub qsm_alias: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AepaCompileLimits {
    pub max_states: usize,
    pub max_public_inputs: usize,
    pub max_transitions: usize,
    pub max_wasm_bytes: usize,
    pub max_capsule_bytes: usize,
}

impl Default for AepaCompileLimits {
    fn default() -> Self {
        Self {
            max_states: 4,
            max_public_inputs: 9,
            max_transitions: 36,
            max_wasm_bytes: 1_048_576,
            max_capsule_bytes: 2_097_152,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AepaLoweredTransition {
    pub source_state: AepaPublicState,
    pub public_input: AepaPublicInput,
    pub target_state: AepaPublicState,
    pub public_output: AepaPublicOutput,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AepaP0Binding {
    pub source_digest: Digest,
    pub transition_digest: Digest,
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
pub struct AepaCompiledQsm {
    wasm: Vec<u8>,
    capsule: Vec<u8>,
    compiler_manifest: Vec<u8>,
    service_code: AepaServiceCode,
    admission_action: u32,
    transitions: Vec<AepaLoweredTransition>,
    binding: AepaP0Binding,
}

impl AepaCompiledQsm {
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
    pub const fn service_code(&self) -> AepaServiceCode {
        self.service_code
    }

    #[must_use]
    pub const fn admission_action(&self) -> u32 {
        self.admission_action
    }

    #[must_use]
    pub fn transitions(&self) -> &[AepaLoweredTransition] {
        &self.transitions
    }

    #[must_use]
    pub const fn binding(&self) -> AepaP0Binding {
        self.binding
    }

    #[must_use]
    pub fn refines(&self, source: &AepaPublicSourceArtifact) -> bool {
        self.binding.source_digest == source.digest()
            && source.transitions().len() == self.transitions.len()
            && source.transitions().iter().all(|source_transition| {
                self.transitions.iter().any(|target_transition| {
                    target_transition.source_state == source_transition.from()
                        && target_transition.public_input == source_transition.input()
                        && target_transition.target_state == source_transition.to()
                        && target_transition.public_output == source_transition.output()
                })
            })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AepaCompiledManifestBinding {
    pub source_digest: Digest,
    pub transition_digest: Digest,
    pub module_digest: Digest,
    pub target_ir_digest: Digest,
    pub abi_digest: Digest,
    pub capsule_digest: Digest,
    pub observer_registry_digest: Digest,
    seal: AepaCompiledManifestSeal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AepaCompiledManifestSeal;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AepaCompileError {
    #[error("K7 binding does not match the AEPA source")]
    K7SourceMismatch,
    #[error("state count {actual} exceeds limit {limit}")]
    StateLimit { actual: usize, limit: usize },
    #[error("public input count {actual} exceeds limit {limit}")]
    PublicInputLimit { actual: usize, limit: usize },
    #[error("transition count {actual} exceeds limit {limit}")]
    TransitionLimit { actual: usize, limit: usize },
    #[error("AEPA source transition coverage is not canonical and total")]
    TransitionCoverage,
    #[error("AEPA source contains a duplicate state/input transition")]
    DuplicateTransition,
    #[error("AEPA admission action semantics are unsupported")]
    UnsupportedActionSemantics,
    #[error("service mapping must contain exactly the AEPA public service")]
    ServiceMappingCoverage,
    #[error("service mapping contains QSM alias zero")]
    ZeroQsmAlias,
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
    #[error("compiled target IR cannot be recomputed: {0}")]
    CompiledTargetIr(String),
    #[error("compiled capsule cannot be recomputed: {0}")]
    CompiledCapsule(String),
    #[error("AEPA registry K7 binding failed: {0}")]
    RegistryK7Binding(String),
    #[error("compiled artifact digest mismatch for {field}")]
    ArtifactDigestMismatch { field: &'static str },
}

pub fn compile_aepa_p0(
    source: &AepaPublicSourceArtifact,
    k7: &AepaK7Binding,
    service_codes: &[AepaServiceCode],
    limits: AepaCompileLimits,
) -> Result<AepaCompiledQsm, AepaCompileError> {
    if k7.source_digest() != source.digest() {
        return Err(AepaCompileError::K7SourceMismatch);
    }
    if AepaPublicState::ALL.len() > limits.max_states {
        return Err(AepaCompileError::StateLimit {
            actual: AepaPublicState::ALL.len(),
            limit: limits.max_states,
        });
    }
    if AepaPublicInput::ALL.len() > limits.max_public_inputs {
        return Err(AepaCompileError::PublicInputLimit {
            actual: AepaPublicInput::ALL.len(),
            limit: limits.max_public_inputs,
        });
    }
    if source.transitions().len() > limits.max_transitions {
        return Err(AepaCompileError::TransitionLimit {
            actual: source.transitions().len(),
            limit: limits.max_transitions,
        });
    }

    let transitions = canonicalize_transitions(source)?;
    let transition_digest = aepa_transition_digest(&transitions);
    let service_code = canonicalize_service_code(source, service_codes)?;
    let admission_action = canonical_admission_action(k7)?;
    let wat = render_wat(&transitions, service_code.qsm_alias, admission_action)?;
    let wasm = wat::parse_str(&wat).map_err(|error| AepaCompileError::Wat(error.to_string()))?;
    if wasm.len() > limits.max_wasm_bytes {
        return Err(AepaCompileError::WasmLimit {
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
        other => return Err(AepaCompileError::Abi(format!("{other:?}"))),
    }

    let target_ir = parse_and_lower(
        &wasm,
        ParserLimits {
            max_module_bytes: limits.max_wasm_bytes,
            ..ParserLimits::default()
        },
    )
    .map_err(|error| AepaCompileError::TargetIr(format!("{error:?}")))?;
    let target_ir_digest = target_ir_hash(&target_ir);
    let module_digest = artifact_digest(MODULE_DIGEST_DOMAIN, &wasm);
    let compiler_manifest = build_compiler_manifest(
        source,
        k7,
        service_code,
        admission_action,
        transition_digest,
        module_digest,
        target_ir_digest,
    )?;
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
    .map_err(|error| AepaCompileError::CapsuleBuild(format!("{error:?}")))?;
    let decoded = QsmCapsule::decode(&capsule, container_limits)
        .map_err(|error| AepaCompileError::CapsuleDecode(format!("{error:?}")))?;
    let capsule_digest = decoded.digest();
    let rebound = QsmCapsule::decode(&capsule, container_limits)
        .map_err(|error| AepaCompileError::CapsuleDecode(format!("{error:?}")))?;
    if rebound.digest() != capsule_digest {
        return Err(AepaCompileError::CapsuleBinding);
    }

    let binding = AepaP0Binding {
        source_digest: source.digest(),
        transition_digest,
        certificate_digest: k7.certificate_digest(),
        generated_runtime_digest: k7.generated_runtime_digest(),
        module_digest,
        target_ir_digest,
        abi_digest: quotient_seal_abi_v1_hash(),
        compiler_manifest_digest: artifact_digest(MANIFEST_DIGEST_DOMAIN, &compiler_manifest_bytes),
        capsule_digest,
        observer_registry_digest: artifact_digest(OBSERVER_DIGEST_DOMAIN, OBSERVER_REGISTRY_V1),
    };
    let compiled = AepaCompiledQsm {
        wasm,
        capsule,
        compiler_manifest: compiler_manifest_bytes,
        service_code,
        admission_action,
        transitions,
        binding,
    };
    if !compiled.refines(source) {
        return Err(AepaCompileError::TransitionCoverage);
    }
    Ok(compiled)
}

pub fn bind_aepa_compiled_manifest(
    manifest: &NoticerQsmManifest,
    source: &AepaPublicSourceArtifact,
    k7: &AepaK7Binding,
    compiled: &AepaCompiledQsm,
) -> Result<AepaCompiledManifestBinding, AepaCompileError> {
    bind_aepa_k7_manifest(manifest, source, k7)
        .map_err(|error| AepaCompileError::RegistryK7Binding(error.to_string()))?;
    let binding = compiled.binding();
    ensure_digest("source", binding.source_digest, source.digest())?;
    ensure_digest(
        "transition",
        binding.transition_digest,
        aepa_transition_digest(compiled.transitions()),
    )?;
    ensure_digest(
        "certificate",
        binding.certificate_digest,
        k7.certificate_digest(),
    )?;
    ensure_digest(
        "generated_runtime",
        binding.generated_runtime_digest,
        k7.generated_runtime_digest(),
    )?;
    ensure_digest(
        "module",
        binding.module_digest,
        artifact_digest(MODULE_DIGEST_DOMAIN, compiled.wasm()),
    )?;
    ensure_digest("abi", binding.abi_digest, quotient_seal_abi_v1_hash())?;
    ensure_digest(
        "compiler_manifest",
        binding.compiler_manifest_digest,
        artifact_digest(MANIFEST_DIGEST_DOMAIN, compiled.compiler_manifest()),
    )?;

    let target_ir = parse_and_lower(
        compiled.wasm(),
        ParserLimits {
            max_module_bytes: compiled.wasm().len(),
            ..ParserLimits::default()
        },
    )
    .map_err(|error| AepaCompileError::CompiledTargetIr(format!("{error:?}")))?;
    ensure_digest(
        "target_ir",
        binding.target_ir_digest,
        target_ir_hash(&target_ir),
    )?;
    let decoded = QsmCapsule::decode(
        compiled.capsule(),
        QsmContainerLimits {
            max_capsule_bytes: compiled.capsule().len(),
            ..QsmContainerLimits::default()
        },
    )
    .map_err(|error| AepaCompileError::CompiledCapsule(format!("{error:?}")))?;
    ensure_digest("capsule", binding.capsule_digest, decoded.digest())?;

    let registry = manifest.binding(NoticerModuleId::Aepa);
    ensure_digest(
        "registry_capsule",
        registry.qsm_capsule_digest,
        binding.capsule_digest,
    )?;
    ensure_digest(
        "registry_observer",
        registry.observer_registry_digest,
        binding.observer_registry_digest,
    )?;
    Ok(AepaCompiledManifestBinding {
        source_digest: binding.source_digest,
        transition_digest: binding.transition_digest,
        module_digest: binding.module_digest,
        target_ir_digest: binding.target_ir_digest,
        abi_digest: binding.abi_digest,
        capsule_digest: binding.capsule_digest,
        observer_registry_digest: binding.observer_registry_digest,
        seal: AepaCompiledManifestSeal,
    })
}

fn canonicalize_transitions(
    source: &AepaPublicSourceArtifact,
) -> Result<Vec<AepaLoweredTransition>, AepaCompileError> {
    let expected_count = AepaPublicState::ALL.len() * AepaPublicInput::ALL.len();
    if source.transitions().len() != expected_count {
        return Err(AepaCompileError::TransitionCoverage);
    }
    let mut seen = BTreeSet::new();
    let mut transitions = Vec::with_capacity(expected_count);
    for transition in source.transitions() {
        if !seen.insert((transition.from(), transition.input())) {
            return Err(AepaCompileError::DuplicateTransition);
        }
        transitions.push(AepaLoweredTransition {
            source_state: transition.from(),
            public_input: transition.input(),
            target_state: transition.to(),
            public_output: transition.output(),
        });
    }
    for state in AepaPublicState::ALL {
        for input in AepaPublicInput::ALL {
            if !seen.contains(&(state, input)) {
                return Err(AepaCompileError::TransitionCoverage);
            }
        }
    }
    transitions.sort_by_key(|transition| (transition.source_state, transition.public_input));
    if transitions
        .iter()
        .filter(|transition| transition.public_output == AepaPublicOutput::AdmitOnce)
        .count()
        != 1
    {
        return Err(AepaCompileError::TransitionCoverage);
    }
    Ok(transitions)
}

fn canonicalize_service_code(
    source: &AepaPublicSourceArtifact,
    service_codes: &[AepaServiceCode],
) -> Result<AepaServiceCode, AepaCompileError> {
    if service_codes.len() != 1
        || service_codes[0].service_alias != source.binding().wire_service_alias()
    {
        return Err(AepaCompileError::ServiceMappingCoverage);
    }
    if service_codes[0].qsm_alias == 0 {
        return Err(AepaCompileError::ZeroQsmAlias);
    }
    Ok(service_codes[0])
}

fn canonical_admission_action(k7: &AepaK7Binding) -> Result<u32, AepaCompileError> {
    let actions = k7
        .certificate()
        .transitions
        .iter()
        .filter_map(|transition| transition.required_action)
        .collect::<BTreeSet<_>>();
    if actions.len() != 1 {
        return Err(AepaCompileError::UnsupportedActionSemantics);
    }
    let action = *actions
        .first()
        .ok_or(AepaCompileError::UnsupportedActionSemantics)?;
    i32::try_from(action).map_err(|_| AepaCompileError::UnsupportedActionSemantics)?;
    Ok(action)
}

#[must_use]
pub fn aepa_transition_digest(transitions: &[AepaLoweredTransition]) -> Digest {
    let mut bytes = Vec::with_capacity(2 + transitions.len() * 4);
    bytes.extend_from_slice(&(transitions.len() as u16).to_le_bytes());
    for transition in transitions {
        bytes.extend_from_slice(&[
            transition.source_state as u8,
            transition.public_input as u8,
            transition.target_state as u8,
            transition.public_output as u8,
        ]);
    }
    artifact_digest(TRANSITION_DIGEST_DOMAIN, &bytes)
}

#[allow(clippy::too_many_arguments)]
fn build_compiler_manifest(
    source: &AepaPublicSourceArtifact,
    k7: &AepaK7Binding,
    service_code: AepaServiceCode,
    admission_action: u32,
    transition_digest: Digest,
    module_digest: Digest,
    target_ir_digest: Digest,
) -> Result<CompilerManifest, AepaCompileError> {
    let binding = source.binding();
    let (window_start, window_end) = binding.admission_window();
    let entries = vec![
        entry("aepa.action_code", admission_action.to_string()),
        entry("aepa.admission_window_end", window_end.to_string()),
        entry("aepa.admission_window_start", window_start.to_string()),
        entry(
            "aepa.assurance_profile_digest",
            bytes_hex(&binding.assurance_profile_digest().0),
        ),
        entry(
            "aepa.atv2_issuer_key_id",
            bytes_hex(&binding.atv2_issuer_key_id()),
        ),
        entry("aepa.epoch", binding.epoch().0.to_string()),
        entry("aepa.lease_profile_id", bytes_hex(&NPL1_PROFILE_ID)),
        entry("aepa.lease_profile_version", NPL1_VERSION.to_string()),
        entry(
            "aepa.lease_verifier_key_id",
            bytes_hex(&binding.lease_verifier_key_id().0),
        ),
        entry(
            "aepa.pairwise_service_alias",
            bytes_hex(&binding.pairwise_service_alias().0),
        ),
        entry(
            "aepa.pipeline_measurement_hash",
            bytes_hex(&binding.pipeline_measurement_hash().0),
        ),
        entry("aepa.policy_hash", bytes_hex(&binding.policy_hash().0)),
        entry("aepa.qsm_alias", service_code.qsm_alias.to_string()),
        entry("aepa.source_digest", digest_hex(source.digest())),
        entry(
            "aepa.transition_count",
            source.transitions().len().to_string(),
        ),
        entry("aepa.transition_digest", digest_hex(transition_digest)),
        entry(
            "aepa.wire_service_alias",
            bytes_hex(&binding.wire_service_alias().0),
        ),
        entry("compiler.id", COMPILER_ID.to_string()),
        entry("hardware.status", "NOT_VERIFIED".to_string()),
        entry("k7.certificate_digest", digest_hex(k7.certificate_digest())),
        entry(
            "k7.generated_runtime_digest",
            digest_hex(k7.generated_runtime_digest()),
        ),
        entry("module.digest", digest_hex(module_digest)),
        entry("p1.status", "NOT_VERIFIED_K8_13E4".to_string()),
        entry(
            "relation.status",
            "CHECKED_ALL_36_SOURCE_TRANSITIONS".to_string(),
        ),
        entry("target_ir.digest", digest_hex(target_ir_digest)),
    ];
    CompilerManifest::new(entries)
        .map_err(|error| AepaCompileError::CompilerManifest(format!("{error:?}")))
}

fn build_relation_certificate(k7: &AepaK7Binding, target_ir_digest: Digest) -> RelationCertificate {
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
    let (quotient_inputs, public_inputs, fault_inputs) = k7.input_axes();
    RelationCertificate {
        version: RELATION_FORMAT_VERSION,
        inductive_digest: k7.certificate_digest(),
        target_ir_digest,
        k7_manifest_digest: k7.generated_runtime_digest(),
        quotient_inputs,
        public_inputs,
        fault_inputs,
        action_deadline_steps: 0,
        records,
    }
}

fn render_wat(
    transitions: &[AepaLoweredTransition],
    qsm_alias: u32,
    admission_action: u32,
) -> Result<String, AepaCompileError> {
    let action = i32::try_from(admission_action)
        .map_err(|_| AepaCompileError::UnsupportedActionSemantics)?;
    let mut transition_checks = String::new();
    for transition in transitions {
        transition_checks.push_str(&format!(
            "    (if (i32.and (i32.eq (global.get $state) (i32.const {})) (i32.eq (local.get $input) (i32.const {}))) (then (local.set $next_state (i32.const {})) (local.set $output (i32.const {}))))\n",
            transition.source_state as u8,
            transition.public_input as u8,
            transition.target_state as u8,
            transition.public_output as u8,
        ));
    }
    Ok(format!(
        r#"(module
  (import "qseal" "emit_frame" (func $emit_frame (param i32 i64) (result i32)))
  (import "qseal" "emit_action" (func $emit_action (param i32 i32) (result i32)))
  (import "qseal" "public_failure" (func $public_failure (param i32) (result i32)))
  (memory 1 1)
  (global $state (mut i32) (i32.const 0))
  (global $cursor (mut i64) (i64.const -1))
  (func (export "qseal.public.tick") (param $service i32) (param $step i64) (param $input i32) (result i32)
    (local $next_state i32)
    (local $output i32)
    (local $result i32)
    (local.set $next_state (i32.const -1))
    (local.set $output (i32.const -1))
    (if (i32.ne (local.get $service) (i32.const {qsm_alias}))
      (then (return (call $public_failure (i32.const {AEPA_UNKNOWN_PUBLIC_SERVICE})))))
    (if (i64.ne (local.get $step) (i64.add (global.get $cursor) (i64.const 1)))
      (then (return (call $public_failure (i32.const {AEPA_OUT_OF_ORDER_PUBLIC_STEP})))))
{transition_checks}    (if (i32.eq (local.get $output) (i32.const -1))
      (then (return (call $public_failure (i32.const {AEPA_UNKNOWN_PUBLIC_INPUT})))))
    (local.set $result (call $emit_frame (local.get $service) (local.get $step)))
    (if (i32.ne (local.get $result) (i32.const 0))
      (then (return (local.get $result))))
    (global.set $state (local.get $next_state))
    (global.set $cursor (local.get $step))
    (if (i32.eq (local.get $output) (i32.const 1))
      (then (return (call $emit_action (i32.const {action}) (i32.wrap_i64 (local.get $step))))))
    (if (i32.eq (local.get $output) (i32.const 2))
      (then (return (call $public_failure (i32.const {AEPA_PUBLIC_REJECT})))))
    (if (i32.eq (local.get $output) (i32.const 3))
      (then (return (call $public_failure (i32.const {AEPA_PUBLIC_FAULT})))))
    (i32.const 0))
  (func (export "qseal.public.reset") (result i32)
    (global.set $state (i32.const 0))
    (global.set $cursor (i64.const -1))
    (i32.const 0))
  (func (export "qseal.public.handoff") (result i64)
    (local $snapshot i64)
    (local.set $snapshot (global.get $cursor))
    (global.set $state (i32.const 0))
    (local.get $snapshot))
  (func (export "qseal.public.status") (result i32)
    (global.get $state)))
"#
    ))
}

fn ensure_digest(
    field: &'static str,
    expected: Digest,
    actual: Digest,
) -> Result<(), AepaCompileError> {
    if expected != actual {
        return Err(AepaCompileError::ArtifactDigestMismatch { field });
    }
    Ok(())
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
