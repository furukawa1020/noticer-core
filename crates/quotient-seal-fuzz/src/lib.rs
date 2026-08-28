#![forbid(unsafe_code)]

//! Bounded adaptive malicious-host fuzzing for QuotientSeal public contexts.

mod action_state;
mod coverage;

pub use action_state::{
    apply_public_feedback, AdaptiveContextBounds, AdaptiveContextState, AdaptiveHostAction,
    AdaptiveHostProgram, AdaptiveProgramError, AdaptivePublicObservation, AdaptiveStateTransition,
    ADAPTIVE_CONTEXT_SCHEMA, ADAPTIVE_HOST_MAGIC,
};
pub use coverage::{
    CorpusBounds, CorpusEntry, CorpusInsertDisposition, CorpusInsertResult, CoverageError,
    CoverageFeedback, CoverageKind, CoveragePoint, CoverageRecord, DeterministicCorpus,
    PublicCoverageSnapshot, PublicObserverDivergence, PublicUtilityViolation,
    COVERAGE_CORPUS_SCHEMA, COVERAGE_FEEDBACK_SCHEMA,
};
