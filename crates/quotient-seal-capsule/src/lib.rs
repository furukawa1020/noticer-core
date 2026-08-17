#![forbid(unsafe_code)]

//! Canonical Quotient-Sealed Module (`.qseal`) capsules and independent checks.

mod checker;
mod format;
mod manifest;

pub use checker::{
    check_qsm, BackendFailure, QsmCounterexample, QsmCounterexampleStage, QsmInconclusive,
    QsmInvalid, QsmReport, QsmResourceMode, QsmVerdict, RecomputedSemantics,
    SemanticRecomputeInput, SemanticRecomputer, HARDWARE_STATUS,
};
pub use format::{
    build_qsm, QsmBoundsError, QsmBuildError, QsmBuildInput, QsmCapsule, QsmContainerLimits,
    QsmDecodeError, QsmHardBounds, QsmResourceBounds, QsmSection, QsmSectionTag,
    QSM_FORMAT_VERSION, QSM_MAGIC, QSM_SECTION_COUNT,
};
pub use manifest::{
    CompilerManifest, CompilerManifestEntry, CompilerManifestError, OBSERVER_REGISTRY_V1,
};

pub const QUOTIENT_SEAL_CAPSULE_V1: &str = "QUOTIENT_SEAL_CAPSULE_V1";
