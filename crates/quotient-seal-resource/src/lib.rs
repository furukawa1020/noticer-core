#![forbid(unsafe_code)]

//! Strict resource-trace equivalence and bounded QuotientPad normalization.

mod checker;
mod model;

pub use checker::{check_resource_strict, check_resource_with_normalization};
pub use model::{
    project_resource_trace, NormalizationKind, NormalizationOverhead, PadSide,
    QuotientPadCandidate, QuotientPadOperation, QuotientPadRevalidator, ResourceAxis, ResourceCase,
    ResourceCounterexample, ResourceDivergence, ResourceEvent, ResourceInconclusive,
    ResourceLimits, ResourceReport, ResourceTrace, ResourceVerdict, RevalidationEvidence,
    QUOTIENT_PAD_FORMAT_VERSION, QUOTIENT_SEAL_RESOURCE_V1,
};
