#![forbid(unsafe_code)]

//! Public-only bindings between Noticer modules and Quotient-Sealed Modules.
//!
//! This crate contains no acquisition, private evidence, baseline, or raw
//! feature dependency. Its fixed binary registry cannot encode arbitrary
//! private fields.

mod aepa;
mod aepa_adversarial;
mod aepa_compile;
mod aepa_counterexample;
mod aepa_differential;
mod aepa_p1;
mod aets;
mod aets_compile;
mod aets_counterexample;
mod aets_differential;
mod aets_matrix;
mod aets_matrix_execution;
mod aets_reference;
mod aplot;
mod aplot_compile;
mod aplot_counterexample;
mod aplot_differential;
mod aplot_matrix;
mod aplot_matrix_execution;
mod aplot_reference;
mod atv2;
mod atv2_compile;
mod atv2_counterexample;
mod atv2_differential;
mod atv2_matrix;
mod atv2_matrix_execution;
mod atv2_reference;
mod manifest;
mod menfugu;
mod menfugu_compile;
mod menfugu_counterexample;
mod menfugu_differential;
mod menfugu_matrix;
mod release_stack;
mod release_stack_path;

pub use aepa::{
    bind_aepa_k7_manifest, verify_aepa_k7, AepaBindingError, AepaK7Binding, AepaK7ManifestBinding,
    AepaPublicInput, AepaPublicOutput, AepaPublicPolicyBinding, AepaPublicSourceArtifact,
    AepaPublicState, AepaPublicTransition, AEPA_K7_SPEC_FAMILY, AEPA_PUBLIC_SOURCE_FORMAT_VERSION,
};
pub use aepa_adversarial::{
    evaluate_aepa_adversarial_case_spec, evaluate_aepa_adversarial_matrix,
    verify_aepa_adversarial_execution, AepaAdversarialCase, AepaAdversarialCaseArtifact,
    AepaAdversarialCaseSpec, AepaAdversarialExecutionArtifact, AepaAdversarialMatrix,
    AepaAdversarialMatrixError, AepaAdversarialMatrixLimits, AepaAdversarialMatrixSeed,
    AepaCaseOutcome, AepaProfileAxis, AepaScenarioAxis, AEPA_ADVERSARIAL_MATRIX_VERSION,
};
pub use aepa_compile::{
    aepa_transition_digest, bind_aepa_compiled_manifest, compile_aepa_p0, AepaCompileError,
    AepaCompileLimits, AepaCompiledManifestBinding, AepaCompiledQsm, AepaLoweredTransition,
    AepaP0Binding, AepaServiceCode, AEPA_OUT_OF_ORDER_PUBLIC_STEP, AEPA_PUBLIC_FAULT,
    AEPA_PUBLIC_REJECT, AEPA_QSM_COMPILER_VERSION, AEPA_UNKNOWN_PUBLIC_INPUT,
    AEPA_UNKNOWN_PUBLIC_SERVICE,
};
pub use aepa_counterexample::{
    build_aepa_counterexample_bundle, shrink_aepa_counterexample,
    verify_aepa_counterexample_bundle, verify_aepa_counterexample_bundle_with, AepaCommandArtifact,
    AepaComparisonSignature, AepaCounterexampleBundle, AepaCounterexampleCaseArtifact,
    AepaCounterexampleError, AepaCounterexampleInput, AepaCounterexampleInputArtifact,
    AepaDifferenceOrigin, AepaDifferenceSignature, AepaLimitsArtifact, AepaShrinkAttempt,
    AepaShrinkOperation, AepaShrinkOutcome, AEPA_COUNTEREXAMPLE_BUNDLE_VERSION,
};
pub use aepa_differential::{
    build_aepa_injected_fixture_artifact, evaluate_aepa_differential,
    evaluate_aepa_differential_with_host_tape, AepaDifferentialArtifact, AepaDifferentialError,
    AepaDifferentialEvidenceOrigin, AepaDifferentialVerdict, AepaEngineDigests,
    AepaExpectedTransition, AepaPublicSequence, AepaSourceRefinement, AEPA_DIFFERENTIAL_VERSION,
};
pub use aepa_p1::{
    authorize_aepa_profile, issue_aepa_p1_resource_witness, prove_aepa_p1_resource_equality,
    revalidate_aepa_p1_resource_witness, AepaP1Error, AepaP1ResourceWitness, AepaP1Revalidation,
    AepaProfileAuthorization,
};
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
pub use aplot::{
    bind_aplot_k7_manifest, verify_aplot_k7, AplotBindingError, AplotFragmentSlot, AplotFrameInput,
    AplotK7Binding, AplotK7ManifestBinding, AplotPublicFramePlan, AplotPublicSourceArtifact,
    APLOT_APPLICATION_RETRY_COUNT, APLOT_MAX_FRAMES, APLOT_MAX_RECONNECT_TICKS,
    APLOT_PUBLIC_SOURCE_FORMAT_VERSION,
};
pub use aplot_compile::{
    compile_aplot_p0, AplotCompileError, AplotCompileLimits, AplotCompiledQsm, AplotEventPlacement,
    AplotP0Binding, AplotPublicEventKind, AplotServiceCode, APLOT_DEADLINE_KIND,
    APLOT_FRAGMENT_ATTEMPT_KIND, APLOT_PUBLIC_DEADLINE, APLOT_PUBLIC_LOSS, APLOT_PUBLIC_RECONNECT,
    APLOT_QSM_COMPILER_VERSION, APLOT_RECONNECT_KIND,
};
pub use aplot_counterexample::{
    build_aplot_counterexample_bundle, shrink_aplot_counterexample,
    verify_aplot_counterexample_bundle, verify_aplot_counterexample_bundle_with,
    AplotCommandArtifact, AplotComparisonSignature, AplotCounterexampleBundle,
    AplotCounterexampleCaseArtifact, AplotCounterexampleError, AplotCounterexampleInput,
    AplotCounterexampleInputArtifact, AplotDifferenceOrigin, AplotDifferenceSignature,
    AplotLimitsArtifact, AplotShrinkAttempt, AplotShrinkOperation, AplotShrinkOutcome,
    APLOT_COUNTEREXAMPLE_BUNDLE_VERSION,
};
pub use aplot_differential::{
    evaluate_aplot_differential, evaluate_aplot_differential_with_host_tape,
    AplotDifferentialArtifact, AplotDifferentialError, AplotDifferentialVerdict,
    AplotEngineDigests, AplotExpectedEvent, AplotExpectedEventKind, AplotSourceRefinement,
    APLOT_DIFFERENTIAL_VERSION,
};
pub use aplot_matrix::{
    AplotAdversarialCase, AplotAdversarialCaseSpec, AplotAdversarialMatrix, AplotCaseId,
    AplotHostAxis, AplotMatrixDigest, AplotMatrixError, AplotMatrixLimits, AplotMatrixSeed,
    AplotResourceAxis, AplotScenarioAxis, APLOT_ADVERSARIAL_MATRIX_VERSION,
};
pub use aplot_matrix_execution::{
    evaluate_aplot_adversarial_matrix, AplotHostInjection, AplotMatrixCaseArtifact,
    AplotMatrixExecutionArtifact, AplotMatrixExecutionError, APLOT_MATRIX_EXECUTION_VERSION,
};
pub use aplot_reference::{
    evaluate_aplot_source_reference, AplotPublicSequence, AplotReferenceArtifact,
    AplotReferenceError, AplotReferenceUnresolved, AplotReferenceVerdict,
    APLOT_SOURCE_REFERENCE_VERSION,
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
pub use atv2_counterexample::{
    build_atv2_counterexample_bundle, shrink_atv2_counterexample,
    verify_atv2_counterexample_bundle, verify_atv2_counterexample_bundle_with, Atv2CommandArtifact,
    Atv2ComparisonSignature, Atv2CounterexampleBundle, Atv2CounterexampleCaseArtifact,
    Atv2CounterexampleError, Atv2CounterexampleInput, Atv2CounterexampleInputArtifact,
    Atv2DifferenceOrigin, Atv2DifferenceSignature, Atv2LimitsArtifact, Atv2ShrinkAttempt,
    Atv2ShrinkOperation, Atv2ShrinkOutcome, ATV2_COUNTEREXAMPLE_BUNDLE_VERSION,
};
pub use atv2_differential::{
    evaluate_atv2_differential, evaluate_atv2_differential_with_host_tape,
    Atv2DifferentialArtifact, Atv2DifferentialError, Atv2DifferentialVerdict, Atv2EngineDigests,
    Atv2ExpectedFrame, Atv2ExpectedFrameKind, Atv2SourceRefinement, ATV2_DIFFERENTIAL_VERSION,
};
pub use atv2_matrix::{
    Atv2AdversarialCase, Atv2AdversarialCaseSpec, Atv2AdversarialMatrix, Atv2CaseId, Atv2HostAxis,
    Atv2MatrixDigest, Atv2MatrixError, Atv2MatrixLimits, Atv2MatrixSeed, Atv2ResourceAxis,
    Atv2ScenarioAxis, ATV2_ADVERSARIAL_MATRIX_VERSION,
};
pub use atv2_matrix_execution::{
    evaluate_atv2_adversarial_matrix, Atv2HostInjection, Atv2MatrixCaseArtifact,
    Atv2MatrixExecutionArtifact, Atv2MatrixExecutionError, ATV2_MATRIX_EXECUTION_VERSION,
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
pub use menfugu::{
    bind_menfugu_k7_manifest, MenfuguBindingError, MenfuguK7Binding, MenfuguK7ManifestBinding,
    MenfuguPublicInput, MenfuguPublicOutput, MenfuguPublicPolicyBinding,
    MenfuguPublicSourceArtifact, MenfuguPublicState, MenfuguPublicTransition,
    MENFUGU_K7_SPEC_FAMILY, MENFUGU_PUBLIC_SOURCE_FORMAT_VERSION,
};
pub use menfugu_compile::{
    bind_menfugu_compiled_manifest, compile_menfugu_p0, menfugu_generated_runtime_digest,
    menfugu_observer_registry_digest, menfugu_source_certificate_digest, menfugu_transition_digest,
    MenfuguCompileError, MenfuguCompileLimits, MenfuguCompiledManifestBinding, MenfuguCompiledQsm,
    MenfuguK7Artifacts, MenfuguLoweredTransition, MenfuguP0Binding, MenfuguServiceCode,
    MENFUGU_OUT_OF_ORDER_PUBLIC_STEP, MENFUGU_PUBLIC_FAULT, MENFUGU_PUBLIC_REJECT,
    MENFUGU_QSM_COMPILER_VERSION, MENFUGU_UNKNOWN_PUBLIC_INPUT, MENFUGU_UNKNOWN_PUBLIC_SERVICE,
};
pub use menfugu_counterexample::{
    build_menfugu_counterexample_bundle, verify_menfugu_counterexample_bundle,
    MenfuguCommandArtifact, MenfuguCounterexampleBundle, MenfuguCounterexampleCaseArtifact,
    MenfuguCounterexampleError, MenfuguCounterexampleInputArtifact, MenfuguDifferenceOrigin,
    MenfuguDifferenceSignature, MenfuguInjection, MenfuguLimitsArtifact, MenfuguShrinkAttempt,
    MenfuguShrinkOperation, MenfuguShrinkOutcome, MENFUGU_COUNTEREXAMPLE_BUNDLE_VERSION,
};
pub use menfugu_differential::{
    build_menfugu_injected_fixture_artifact, evaluate_menfugu_differential,
    evaluate_menfugu_differential_with_host_tape, MenfuguDifferentialArtifact,
    MenfuguDifferentialError, MenfuguDifferentialEvidenceOrigin, MenfuguDifferentialVerdict,
    MenfuguEngineDigests, MenfuguExpectedTransition, MenfuguPublicSequence,
    MenfuguSourceRefinement, MENFUGU_DIFFERENTIAL_VERSION,
};
pub use menfugu_matrix::{
    evaluate_menfugu_adversarial_matrix, verify_menfugu_adversarial_execution,
    MenfuguActionClassification, MenfuguAdversarialCase, MenfuguAdversarialCaseArtifact,
    MenfuguAdversarialExecutionArtifact, MenfuguAdversarialMatrix, MenfuguAdversarialMatrixError,
    MenfuguAdversarialMatrixLimits, MenfuguAdversarialMatrixSeed, MenfuguCaseOutcome,
    MenfuguProfileAxis, MenfuguScenarioAxis, MENFUGU_ADVERSARIAL_MATRIX_VERSION,
};
pub use release_stack::{
    ReleaseStackCompositionContract, ReleaseStackCompositionError, RELEASE_STACK_COMPOSITION_BYTES,
    RELEASE_STACK_COMPOSITION_MAGIC, RELEASE_STACK_COMPOSITION_VERSION,
    RELEASE_STACK_FORBIDDEN_FIELDS, RELEASE_STACK_HANDOFFS, RELEASE_STACK_HANDOFF_COUNT,
    RELEASE_STACK_HARDWARE_STATUS, RELEASE_STACK_STAGE_COUNT,
};
pub use release_stack_path::{
    execute_canonical_release_path, verify_canonical_release_path, ReleasePathKind,
    ReleaseStackPathArtifact, ReleaseStackPathError, ReleaseStackPublicInput, ReleaseStageReceipt,
    RELEASE_STACK_CANONICAL_SEED, RELEASE_STACK_PATH_VERSION,
};

pub use noticer_protocol::WireServiceAlias;
pub use noticer_types::{Epoch, PolicyHash};
pub use quotient_forge_caqt::Digest;
pub use quotient_seal_abi::DeploymentProfile;
