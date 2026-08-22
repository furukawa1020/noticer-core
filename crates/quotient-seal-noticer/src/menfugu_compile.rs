use std::collections::BTreeSet;

use noticer_protocol::WireServiceAlias;
use quotient_forge_caqt::{artifact_digest, Digest};
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
    bind_menfugu_k7_manifest, MenfuguK7Binding, MenfuguPublicInput, MenfuguPublicOutput,
    MenfuguPublicPolicyBinding, MenfuguPublicSourceArtifact, MenfuguPublicState,
    NoticerModuleBinding,
};

pub const MENFUGU_QSM_COMPILER_VERSION: u16 = 1;
pub const MENFUGU_UNKNOWN_PUBLIC_SERVICE: i32 = 0x4d01;
pub const MENFUGU_UNKNOWN_PUBLIC_INPUT: i32 = 0x4d02;
pub const MENFUGU_OUT_OF_ORDER_PUBLIC_STEP: i32 = 0x4d03;
pub const MENFUGU_PUBLIC_REJECT: i32 = 0x4d04;
pub const MENFUGU_PUBLIC_FAULT: i32 = 0x4d05;

const COMPILER_ID: &str = "noticer.menfugu-p0-compiler.v1";
const CERTIFICATE_DIGEST_DOMAIN: &[u8] = b"noticer-core/menfugu/k7-certificate/v1";
const RUNTIME_DIGEST_DOMAIN: &[u8] = b"noticer-core/menfugu/k7-runtime/v1";
const MODULE_DIGEST_DOMAIN: &[u8] = b"noticer-core/menfugu/p0-module/v1";
const TRANSITION_DIGEST_DOMAIN: &[u8] = b"noticer-core/menfugu/p0-transitions/v1";
const MANIFEST_DIGEST_DOMAIN: &[u8] = b"noticer-core/menfugu/p0-compiler-manifest/v1";
const OBSERVER_DIGEST_DOMAIN: &[u8] = b"noticer-core/menfugu/p0-observer-registry/v1";
const ROBUST_PENDING: &[u8] = b"MENFUGU_ROBUST_CERTIFICATE_PENDING_K8_13F4_NOT_VERIFIED_V1";
const RESOURCE_PENDING: &[u8] = b"MENFUGU_RESOURCE_CERTIFICATE_P0_NOT_APPLICABLE_V1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MenfuguServiceCode {
    pub service_alias: WireServiceAlias,
    pub qsm_alias: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MenfuguCompileLimits {
    pub max_states: usize,
    pub max_public_inputs: usize,
    pub max_transitions: usize,
    pub max_certificate_bytes: usize,
    pub max_generated_runtime_bytes: usize,
    pub max_wasm_bytes: usize,
    pub max_capsule_bytes: usize,
}

impl Default for MenfuguCompileLimits {
    fn default() -> Self {
        Self {
            max_states: 4,
            max_public_inputs: 14,
            max_transitions: 56,
            max_certificate_bytes: 1_048_576,
            max_generated_runtime_bytes: 1_048_576,
            max_wasm_bytes: 1_048_576,
            max_capsule_bytes: 2_097_152,
        }
    }
}

/// Opaque K7 output bytes. The compiler never parses private evidence from them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MenfuguK7Artifacts {
    source_certificate: Vec<u8>,
    generated_runtime: Vec<u8>,
}

impl MenfuguK7Artifacts {
    #[must_use]
    pub fn new(source_certificate: Vec<u8>, generated_runtime: Vec<u8>) -> Self {
        Self {
            source_certificate,
            generated_runtime,
        }
    }

    #[must_use]
    pub fn source_certificate(&self) -> &[u8] {
        &self.source_certificate
    }

    #[must_use]
    pub fn generated_runtime(&self) -> &[u8] {
        &self.generated_runtime
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MenfuguLoweredTransition {
    pub source_state: MenfuguPublicState,
    pub public_input: MenfuguPublicInput,
    pub target_state: MenfuguPublicState,
    pub public_output: MenfuguPublicOutput,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MenfuguP0Binding {
    pub public_policy_digest: Digest,
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
pub struct MenfuguCompiledQsm {
    wasm: Vec<u8>,
    capsule: Vec<u8>,
    compiler_manifest: Vec<u8>,
    service_code: MenfuguServiceCode,
    action_code: u32,
    transitions: Vec<MenfuguLoweredTransition>,
    binding: MenfuguP0Binding,
}

impl MenfuguCompiledQsm {
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
    pub const fn service_code(&self) -> MenfuguServiceCode {
        self.service_code
    }

    #[must_use]
    pub const fn action_code(&self) -> u32 {
        self.action_code
    }

    #[must_use]
    pub fn transitions(&self) -> &[MenfuguLoweredTransition] {
        &self.transitions
    }

    #[must_use]
    pub const fn binding(&self) -> MenfuguP0Binding {
        self.binding
    }

    #[must_use]
    pub fn refines(&self, source: &MenfuguPublicSourceArtifact) -> bool {
        self.binding.source_digest == source.digest
            && source.transitions.len() == self.transitions.len()
            && source.transitions.iter().all(|source_transition| {
                self.transitions.iter().any(|target_transition| {
                    target_transition.source_state == source_transition.state
                        && target_transition.public_input == source_transition.input
                        && target_transition.target_state == source_transition.next_state
                        && target_transition.public_output == source_transition.output
                })
            })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MenfuguCompiledManifestBinding {
    pub source_digest: Digest,
    pub transition_digest: Digest,
    pub module_digest: Digest,
    pub target_ir_digest: Digest,
    pub abi_digest: Digest,
    pub capsule_digest: Digest,
    pub observer_registry_digest: Digest,
    seal: MenfuguCompiledManifestSeal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MenfuguCompiledManifestSeal;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MenfuguCompileError {
    #[error("Menfugu source is invalid: {0}")]
    Source(String),
    #[error("Menfugu public policy is invalid: {0}")]
    Policy(String),
    #[error("K7 binding does not match the Menfugu source")]
    K7SourceMismatch,
    #[error("K7 binding does not match the Menfugu public policy")]
    K7PolicyMismatch,
    #[error("K7 source certificate digest mismatch")]
    CertificateDigestMismatch,
    #[error("K7 generated runtime digest mismatch")]
    GeneratedRuntimeDigestMismatch,
    #[error("state count {actual} exceeds limit {limit}")]
    StateLimit { actual: usize, limit: usize },
    #[error("public input count {actual} exceeds limit {limit}")]
    PublicInputLimit { actual: usize, limit: usize },
    #[error("transition count {actual} exceeds limit {limit}")]
    TransitionLimit { actual: usize, limit: usize },
    #[error("certificate size {actual} exceeds limit {limit}")]
    CertificateLimit { actual: usize, limit: usize },
    #[error("generated runtime size {actual} exceeds limit {limit}")]
    GeneratedRuntimeLimit { actual: usize, limit: usize },
    #[error("Menfugu source transition coverage is not canonical and total")]
    TransitionCoverage,
    #[error("Menfugu source contains a duplicate state/input transition")]
    DuplicateTransition,
    #[error("Menfugu exactly-once action semantics are unsupported")]
    UnsupportedActionSemantics,
    #[error("service mapping must contain exactly the Menfugu public service")]
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
    #[error("Menfugu registry K7 binding failed: {0}")]
    RegistryK7Binding(String),
    #[error("compiled artifact digest mismatch for {field}")]
    ArtifactDigestMismatch { field: &'static str },
}

#[allow(clippy::too_many_arguments)]
pub fn compile_menfugu_p0(
    source: &MenfuguPublicSourceArtifact,
    policy: MenfuguPublicPolicyBinding,
    k7: &MenfuguK7Binding,
    artifacts: &MenfuguK7Artifacts,
    service_codes: &[MenfuguServiceCode],
    limits: MenfuguCompileLimits,
) -> Result<MenfuguCompiledQsm, MenfuguCompileError> {
    source
        .verify()
        .map_err(|error| MenfuguCompileError::Source(error.to_string()))?;
    let policy = policy
        .validate()
        .map_err(|error| MenfuguCompileError::Policy(error.to_string()))?;
    if k7.source_digest != source.digest {
        return Err(MenfuguCompileError::K7SourceMismatch);
    }
    if k7.public_policy_digest
        != policy
            .digest()
            .map_err(|error| MenfuguCompileError::Policy(error.to_string()))?
    {
        return Err(MenfuguCompileError::K7PolicyMismatch);
    }
    check_k7_artifacts(k7, artifacts, limits)?;
    check_shape_limits(source, limits)?;

    let transitions = canonicalize_transitions(source)?;
    let transition_digest = menfugu_transition_digest(&transitions);
    let service_code = canonicalize_service_code(policy, service_codes)?;
    let action_code = policy.allowed_action as u32;
    let wat = render_wat(&transitions, service_code.qsm_alias, action_code)?;
    let wasm = wat::parse_str(&wat).map_err(|error| MenfuguCompileError::Wat(error.to_string()))?;
    if wasm.len() > limits.max_wasm_bytes {
        return Err(MenfuguCompileError::WasmLimit {
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
        other => return Err(MenfuguCompileError::Abi(format!("{other:?}"))),
    }

    let target_ir = parse_and_lower(
        &wasm,
        ParserLimits {
            max_module_bytes: limits.max_wasm_bytes,
            ..ParserLimits::default()
        },
    )
    .map_err(|error| MenfuguCompileError::TargetIr(format!("{error:?}")))?;
    let target_ir_digest = target_ir_hash(&target_ir);
    let module_digest = artifact_digest(MODULE_DIGEST_DOMAIN, &wasm);
    let compiler_manifest = build_compiler_manifest(
        source,
        policy,
        k7,
        service_code,
        transition_digest,
        module_digest,
        target_ir_digest,
    )?;
    let compiler_manifest_bytes = compiler_manifest.encode();
    let relation_certificate = build_relation_certificate(policy, k7, target_ir_digest);
    let container_limits = QsmContainerLimits {
        max_capsule_bytes: limits.max_capsule_bytes,
        ..QsmContainerLimits::default()
    };
    let capsule = build_qsm(
        QsmBuildInput {
            resource_bounds: QsmResourceBounds::default(),
            source_certificate: artifacts.source_certificate.clone(),
            wasm_module: wasm.clone(),
            abi_manifest,
            relation_certificate: relation_certificate.encode(),
            robust_certificate: ROBUST_PENDING.to_vec(),
            resource_certificate: RESOURCE_PENDING.to_vec(),
            compiler_manifest,
        },
        container_limits,
    )
    .map_err(|error| MenfuguCompileError::CapsuleBuild(format!("{error:?}")))?;
    let decoded = QsmCapsule::decode(&capsule, container_limits)
        .map_err(|error| MenfuguCompileError::CapsuleDecode(format!("{error:?}")))?;
    let capsule_digest = decoded.digest();
    let rebound = QsmCapsule::decode(&capsule, container_limits)
        .map_err(|error| MenfuguCompileError::CapsuleDecode(format!("{error:?}")))?;
    if rebound.digest() != capsule_digest {
        return Err(MenfuguCompileError::CapsuleBinding);
    }

    let binding = MenfuguP0Binding {
        public_policy_digest: k7.public_policy_digest,
        source_digest: source.digest,
        transition_digest,
        certificate_digest: k7.source_certificate_digest,
        generated_runtime_digest: k7.generated_runtime_digest,
        module_digest,
        target_ir_digest,
        abi_digest: quotient_seal_abi_v1_hash(),
        compiler_manifest_digest: artifact_digest(MANIFEST_DIGEST_DOMAIN, &compiler_manifest_bytes),
        capsule_digest,
        observer_registry_digest: menfugu_observer_registry_digest(),
    };
    let compiled = MenfuguCompiledQsm {
        wasm,
        capsule,
        compiler_manifest: compiler_manifest_bytes,
        service_code,
        action_code,
        transitions,
        binding,
    };
    if !compiled.refines(source) {
        return Err(MenfuguCompileError::TransitionCoverage);
    }
    Ok(compiled)
}

#[allow(clippy::too_many_arguments)]
pub fn bind_menfugu_compiled_manifest(
    module: NoticerModuleBinding,
    source: &MenfuguPublicSourceArtifact,
    policy: MenfuguPublicPolicyBinding,
    k7: MenfuguK7Binding,
    artifacts: &MenfuguK7Artifacts,
    compiled: &MenfuguCompiledQsm,
) -> Result<MenfuguCompiledManifestBinding, MenfuguCompileError> {
    bind_menfugu_k7_manifest(source, policy, k7, module)
        .map_err(|error| MenfuguCompileError::RegistryK7Binding(error.to_string()))?;
    check_k7_artifacts(&k7, artifacts, MenfuguCompileLimits::default())?;
    let binding = compiled.binding();
    ensure_digest("source", binding.source_digest, source.digest)?;
    ensure_digest(
        "public_policy",
        binding.public_policy_digest,
        policy
            .digest()
            .map_err(|error| MenfuguCompileError::Policy(error.to_string()))?,
    )?;
    ensure_digest(
        "transition",
        binding.transition_digest,
        menfugu_transition_digest(compiled.transitions()),
    )?;
    ensure_digest(
        "certificate",
        binding.certificate_digest,
        menfugu_source_certificate_digest(artifacts.source_certificate()),
    )?;
    ensure_digest(
        "generated_runtime",
        binding.generated_runtime_digest,
        menfugu_generated_runtime_digest(artifacts.generated_runtime()),
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
    .map_err(|error| MenfuguCompileError::CompiledTargetIr(format!("{error:?}")))?;
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
    .map_err(|error| MenfuguCompileError::CompiledCapsule(format!("{error:?}")))?;
    ensure_digest("capsule", binding.capsule_digest, decoded.digest())?;
    ensure_digest(
        "observer_registry",
        binding.observer_registry_digest,
        menfugu_observer_registry_digest(),
    )?;
    ensure_digest(
        "registry_capsule",
        module.qsm_capsule_digest,
        binding.capsule_digest,
    )?;
    ensure_digest(
        "registry_observer",
        module.observer_registry_digest,
        binding.observer_registry_digest,
    )?;
    if !compiled.refines(source) {
        return Err(MenfuguCompileError::TransitionCoverage);
    }
    Ok(MenfuguCompiledManifestBinding {
        source_digest: binding.source_digest,
        transition_digest: binding.transition_digest,
        module_digest: binding.module_digest,
        target_ir_digest: binding.target_ir_digest,
        abi_digest: binding.abi_digest,
        capsule_digest: binding.capsule_digest,
        observer_registry_digest: binding.observer_registry_digest,
        seal: MenfuguCompiledManifestSeal,
    })
}

#[must_use]
pub fn menfugu_source_certificate_digest(bytes: &[u8]) -> Digest {
    artifact_digest(CERTIFICATE_DIGEST_DOMAIN, bytes)
}

#[must_use]
pub fn menfugu_generated_runtime_digest(bytes: &[u8]) -> Digest {
    artifact_digest(RUNTIME_DIGEST_DOMAIN, bytes)
}

#[must_use]
pub fn menfugu_observer_registry_digest() -> Digest {
    artifact_digest(OBSERVER_DIGEST_DOMAIN, OBSERVER_REGISTRY_V1)
}

#[must_use]
pub fn menfugu_transition_digest(transitions: &[MenfuguLoweredTransition]) -> Digest {
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

fn check_shape_limits(
    source: &MenfuguPublicSourceArtifact,
    limits: MenfuguCompileLimits,
) -> Result<(), MenfuguCompileError> {
    if MenfuguPublicState::ALL.len() > limits.max_states {
        return Err(MenfuguCompileError::StateLimit {
            actual: MenfuguPublicState::ALL.len(),
            limit: limits.max_states,
        });
    }
    if MenfuguPublicInput::ALL.len() > limits.max_public_inputs {
        return Err(MenfuguCompileError::PublicInputLimit {
            actual: MenfuguPublicInput::ALL.len(),
            limit: limits.max_public_inputs,
        });
    }
    if source.transitions.len() > limits.max_transitions {
        return Err(MenfuguCompileError::TransitionLimit {
            actual: source.transitions.len(),
            limit: limits.max_transitions,
        });
    }
    Ok(())
}

fn check_k7_artifacts(
    k7: &MenfuguK7Binding,
    artifacts: &MenfuguK7Artifacts,
    limits: MenfuguCompileLimits,
) -> Result<(), MenfuguCompileError> {
    if artifacts.source_certificate.len() > limits.max_certificate_bytes {
        return Err(MenfuguCompileError::CertificateLimit {
            actual: artifacts.source_certificate.len(),
            limit: limits.max_certificate_bytes,
        });
    }
    if artifacts.generated_runtime.len() > limits.max_generated_runtime_bytes {
        return Err(MenfuguCompileError::GeneratedRuntimeLimit {
            actual: artifacts.generated_runtime.len(),
            limit: limits.max_generated_runtime_bytes,
        });
    }
    if menfugu_source_certificate_digest(artifacts.source_certificate())
        != k7.source_certificate_digest
    {
        return Err(MenfuguCompileError::CertificateDigestMismatch);
    }
    if menfugu_generated_runtime_digest(artifacts.generated_runtime())
        != k7.generated_runtime_digest
    {
        return Err(MenfuguCompileError::GeneratedRuntimeDigestMismatch);
    }
    Ok(())
}

fn canonicalize_transitions(
    source: &MenfuguPublicSourceArtifact,
) -> Result<Vec<MenfuguLoweredTransition>, MenfuguCompileError> {
    let expected_count = MenfuguPublicState::ALL.len() * MenfuguPublicInput::ALL.len();
    if source.transitions.len() != expected_count {
        return Err(MenfuguCompileError::TransitionCoverage);
    }
    let mut seen = BTreeSet::new();
    let mut transitions = Vec::with_capacity(expected_count);
    for transition in &source.transitions {
        if !seen.insert((transition.state, transition.input)) {
            return Err(MenfuguCompileError::DuplicateTransition);
        }
        transitions.push(MenfuguLoweredTransition {
            source_state: transition.state,
            public_input: transition.input,
            target_state: transition.next_state,
            public_output: transition.output,
        });
    }
    for state in MenfuguPublicState::ALL {
        for input in MenfuguPublicInput::ALL {
            if !seen.contains(&(state, input)) {
                return Err(MenfuguCompileError::TransitionCoverage);
            }
        }
    }
    transitions.sort_by_key(|transition| (transition.source_state, transition.public_input));
    if transitions
        .iter()
        .filter(|transition| transition.public_output.executes_action())
        .count()
        != 1
    {
        return Err(MenfuguCompileError::UnsupportedActionSemantics);
    }
    Ok(transitions)
}

fn canonicalize_service_code(
    policy: MenfuguPublicPolicyBinding,
    service_codes: &[MenfuguServiceCode],
) -> Result<MenfuguServiceCode, MenfuguCompileError> {
    if service_codes.len() != 1 || service_codes[0].service_alias != policy.service_alias {
        return Err(MenfuguCompileError::ServiceMappingCoverage);
    }
    if service_codes[0].qsm_alias == 0 {
        return Err(MenfuguCompileError::ZeroQsmAlias);
    }
    Ok(service_codes[0])
}

#[allow(clippy::too_many_arguments)]
fn build_compiler_manifest(
    source: &MenfuguPublicSourceArtifact,
    policy: MenfuguPublicPolicyBinding,
    k7: &MenfuguK7Binding,
    service_code: MenfuguServiceCode,
    transition_digest: Digest,
    module_digest: Digest,
    target_ir_digest: Digest,
) -> Result<CompilerManifest, MenfuguCompileError> {
    let entries = vec![
        entry("compiler.id", COMPILER_ID.to_string()),
        entry("hardware.status", "NOT_VERIFIED".to_string()),
        entry(
            "k7.certificate_digest",
            digest_hex(k7.source_certificate_digest),
        ),
        entry(
            "k7.generated_runtime_digest",
            digest_hex(k7.generated_runtime_digest),
        ),
        entry(
            "menfugu.action_code",
            (policy.allowed_action as u8).to_string(),
        ),
        entry("menfugu.cooldown_slots", policy.cooldown_slots.to_string()),
        entry("menfugu.epoch", policy.epoch.0.to_string()),
        entry(
            "menfugu.execution_offset_slots",
            policy.execution_offset_slots.to_string(),
        ),
        entry(
            "menfugu.execution_period_slots",
            policy.execution_period_slots.to_string(),
        ),
        entry(
            "menfugu.maximum_pump_ticks",
            policy.maximum_pump_ticks.to_string(),
        ),
        entry("menfugu.policy_hash", bytes_hex(&policy.policy_hash.0)),
        entry(
            "menfugu.public_deadline_slots",
            policy.public_deadline_slots.to_string(),
        ),
        entry(
            "menfugu.public_policy_digest",
            digest_hex(k7.public_policy_digest),
        ),
        entry("menfugu.pump_ticks", policy.pump_ticks.to_string()),
        entry("menfugu.qsm_alias", service_code.qsm_alias.to_string()),
        entry("menfugu.source_digest", digest_hex(source.digest)),
        entry(
            "menfugu.transition_count",
            source.transitions.len().to_string(),
        ),
        entry("menfugu.transition_digest", digest_hex(transition_digest)),
        entry(
            "menfugu.verifier_key_id",
            bytes_hex(&policy.verifier_key_id.0),
        ),
        entry(
            "menfugu.wire_service_alias",
            bytes_hex(&policy.service_alias.0),
        ),
        entry("module.digest", digest_hex(module_digest)),
        entry("p1.status", "NOT_APPLICABLE_P0".to_string()),
        entry("privacy.private_ingress", "FORBIDDEN".to_string()),
        entry(
            "relation.status",
            "CHECKED_ALL_56_SOURCE_TRANSITIONS".to_string(),
        ),
        entry("target_ir.digest", digest_hex(target_ir_digest)),
    ];
    CompilerManifest::new(entries)
        .map_err(|error| MenfuguCompileError::CompilerManifest(format!("{error:?}")))
}

fn build_relation_certificate(
    policy: MenfuguPublicPolicyBinding,
    k7: &MenfuguK7Binding,
    target_ir_digest: Digest,
) -> RelationCertificate {
    let records = (0..MenfuguPublicState::ALL.len() as u32)
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
        inductive_digest: k7.source_certificate_digest,
        target_ir_digest,
        k7_manifest_digest: k7.generated_runtime_digest,
        quotient_inputs: 0,
        public_inputs: MenfuguPublicInput::ALL.len() as u16,
        fault_inputs: 1,
        action_deadline_steps: policy.public_deadline_slots,
        records,
    }
}

fn render_wat(
    transitions: &[MenfuguLoweredTransition],
    qsm_alias: u32,
    action_code: u32,
) -> Result<String, MenfuguCompileError> {
    let action =
        i32::try_from(action_code).map_err(|_| MenfuguCompileError::UnsupportedActionSemantics)?;
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
      (then (return (call $public_failure (i32.const {MENFUGU_UNKNOWN_PUBLIC_SERVICE})))))
    (if (i64.ne (local.get $step) (i64.add (global.get $cursor) (i64.const 1)))
      (then (return (call $public_failure (i32.const {MENFUGU_OUT_OF_ORDER_PUBLIC_STEP})))))
{transition_checks}    (if (i32.eq (local.get $output) (i32.const -1))
      (then (return (call $public_failure (i32.const {MENFUGU_UNKNOWN_PUBLIC_INPUT})))))
    (local.set $result (call $emit_frame (local.get $service) (local.get $step)))
    (if (i32.ne (local.get $result) (i32.const 0))
      (then (return (local.get $result))))
    (global.set $state (local.get $next_state))
    (global.set $cursor (local.get $step))
    (if (i32.eq (local.get $output) (i32.const 2))
      (then (return (call $emit_action (i32.const {action}) (i32.wrap_i64 (local.get $step))))))
    (if (i32.eq (local.get $output) (i32.const 3))
      (then (return (call $public_failure (i32.const {MENFUGU_PUBLIC_REJECT})))))
    (if (i32.eq (local.get $output) (i32.const 7))
      (then (return (call $public_failure (i32.const {MENFUGU_PUBLIC_FAULT})))))
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
) -> Result<(), MenfuguCompileError> {
    if expected != actual {
        return Err(MenfuguCompileError::ArtifactDigestMismatch { field });
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
