#![forbid(unsafe_code)]

//! Public-only bindings between Noticer modules and Quotient-Sealed Modules.
//!
//! This crate contains no acquisition, private evidence, baseline, or raw
//! feature dependency. Its fixed binary registry cannot encode arbitrary
//! private fields.

mod aets;
mod aets_compile;
mod aets_counterexample;
mod aets_differential;
mod aets_matrix;
mod aets_matrix_execution;
mod aets_reference;
mod atv2;
mod atv2_compile;
mod atv2_differential;
mod atv2_reference;
mod manifest;

pub use aets::{
    aets_observer_registry_digest, aets_qsm_capsule_digest, bind_aets_p0, codegen_manifest_digest,
    verify_aets_k7, AetsArtifactSet, AetsBindingError, AetsK7Binding, AetsP0Binding,
    AetsPublicSourceArtifact, AETS_PUBLIC_SOURCE_FORMAT_VERSION,
};
pub use aets_compile::{
    compile_aets_p0, AetsActionPlacement, AetsCompileError, AetsCompileLimits, AetsCompiledQsm,
    AetsServiceCode, AETS_QSM_COMPILER_VERSION,
};
pub use aets_counterexample::{
    build_aets_counterexample_bundle, shrink_aets_counterexample,
    verify_aets_counterexample_bundle, verify_aets_counterexample_bundle_with,
    AetsComparisonSignature, AetsCounterexampleBundle, AetsCounterexampleCaseArtifact,
    AetsCounterexampleError, AetsCounterexampleInput, AetsCounterexampleInputArtifact,
    AetsDifferenceOrigin, AetsDifferenceSignature, AetsShrinkAttempt, AetsShrinkOperation,
    AetsShrinkOutcome, CommandArtifact, LimitsArtifact, AETS_COUNTEREXAMPLE_BUNDLE_VERSION,
};
pub use aets_differential::{
    evaluate_aets_differential, evaluate_aets_differential_with_host_tape,
    AetsDifferentialArtifact, AetsDifferentialError, AetsDifferentialVerdict, AetsEngineDigests,
    AetsSourceRefinement, AETS_DIFFERENTIAL_VERSION,
};
pub use aets_matrix::{
    AetsAdversarialCase, AetsAdversarialCaseSpec, AetsAdversarialMatrix, AetsCaseId, AetsHostAxis,
    AetsMatrixDigest, AetsMatrixError, AetsMatrixLimits, AetsMatrixSeed, AetsResourceAxis,
    AetsScenarioAxis, AETS_ADVERSARIAL_MATRIX_VERSION,
};
pub use aets_matrix_execution::{
    evaluate_aets_adversarial_matrix, AetsHostInjection, AetsMatrixCaseArtifact,
    AetsMatrixExecutionArtifact, AetsMatrixExecutionError, AETS_MATRIX_EXECUTION_VERSION,
};
pub use aets_reference::{
    evaluate_aets_source_reference, AetsPublicSequence, AetsReferenceArtifact, AetsReferenceError,
    AetsReferenceUnresolved, AetsReferenceVerdict, AETS_SOURCE_REFERENCE_VERSION,
};
pub use atv2::{
    bind_atv2_k7_manifest, verify_atv2_k7, Atv2BindingError, Atv2K7Binding, Atv2K7ManifestBinding,
    Atv2PlannedFrame, Atv2PublicSourceArtifact, ATV2_K7_SPEC_FAMILY,
    ATV2_PUBLIC_SOURCE_FORMAT_VERSION,
};
pub use atv2_compile::{
    compile_atv2_p0, Atv2CompileError, Atv2CompileLimits, Atv2CompiledQsm, Atv2FramePlacement,
    Atv2P0Binding, Atv2ServiceCode, ATV2_FIXED_CIPHERTEXT_BYTES, ATV2_QSM_COMPILER_VERSION,
};
pub use atv2_differential::{
    evaluate_atv2_differential, evaluate_atv2_differential_with_host_tape,
    Atv2DifferentialArtifact, Atv2DifferentialError, Atv2DifferentialVerdict, Atv2EngineDigests,
    Atv2ExpectedFrame, Atv2ExpectedFrameKind, Atv2SourceRefinement, ATV2_DIFFERENTIAL_VERSION,
};
pub use atv2_reference::{
    evaluate_atv2_source_reference, Atv2PublicSequence, Atv2ReferenceArtifact, Atv2ReferenceError,
    Atv2ReferenceUnresolved, Atv2ReferenceVerdict, ATV2_SOURCE_REFERENCE_VERSION,
};

pub use manifest::{
    existing_binding_type_names, ManifestDecodeError, ManifestError, NoticerModuleBinding,
    NoticerModuleId, NoticerQsmManifest, P1ResourceEvidence, NOTICER_QSM_MANIFEST_BYTES,
    NOTICER_QSM_MANIFEST_MAGIC, NOTICER_QSM_MANIFEST_VERSION,
};

pub use noticer_protocol::WireServiceAlias;
pub use noticer_types::{Epoch, PolicyHash};
pub use quotient_forge_caqt::Digest;
pub use quotient_seal_abi::DeploymentProfile;
