#![forbid(unsafe_code)]

mod certificate;
mod validator;

pub use certificate::{
    GlobalPredicate, MemoryPredicate, MemoryRange, RelationCertificate, RelationDecodeError,
    RelationLimits, RelationRecord, RELATION_FORMAT_VERSION,
};
pub use validator::{
    validate_relation, DivergenceKind, RelationCounterexample, RelationIncompatible,
    RelationResourceBound, RelationUnresolved, RelationValidationInput, RelationValidationLimits,
    RelationValidationReport, RelationVerdict,
};

pub const QUOTIENT_SEAL_RELATION_V1: &str = "QUOTIENT_SEAL_RELATION_V1";
