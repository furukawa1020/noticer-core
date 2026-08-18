#![forbid(unsafe_code)]

//! Public-only bindings between Noticer modules and Quotient-Sealed Modules.
//!
//! This crate contains no acquisition, private evidence, baseline, or raw
//! feature dependency. Its fixed binary registry cannot encode arbitrary
//! private fields.

mod aets;
mod aets_compile;
mod manifest;

pub use aets::{
    aets_observer_registry_digest, aets_qsm_capsule_digest, bind_aets_p0, codegen_manifest_digest,
    verify_aets_k7, AetsArtifactSet, AetsBindingError, AetsK7Binding, AetsP0Binding,
    AetsPublicSourceArtifact, AETS_PUBLIC_SOURCE_FORMAT_VERSION,
};
pub use aets_compile::{
    compile_aets_p0, AetsCompileError, AetsCompileLimits, AetsCompiledQsm, AetsServiceCode,
    AETS_QSM_COMPILER_VERSION,
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
