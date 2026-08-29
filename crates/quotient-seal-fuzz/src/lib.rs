#![forbid(unsafe_code)]

//! Bounded adaptive malicious-host fuzzing for QuotientSeal public contexts.

mod action_state;
mod bundle;
mod coverage;
mod fuzzer;
mod shrinker;

pub use action_state::{
    apply_public_feedback, AdaptiveContextBounds, AdaptiveContextState, AdaptiveHostAction,
    AdaptiveHostProgram, AdaptiveProgramError, AdaptivePublicObservation, AdaptiveStateTransition,
    ADAPTIVE_CONTEXT_SCHEMA, ADAPTIVE_HOST_MAGIC,
};
pub use bundle::{
    AdaptiveFuzzReproductionBundle, BundleArtifactRef, BundleArtifactRole, BundleError,
    BundleInconclusiveReason, BundleVerdict, ADAPTIVE_FUZZ_BUNDLE_SCHEMA,
};
pub use coverage::{
    CorpusBounds, CorpusEntry, CorpusInsertDisposition, CorpusInsertResult, CoverageError,
    CoverageFeedback, CoverageKind, CoveragePoint, CoverageRecord, DeterministicCorpus,
    PublicCoverageSnapshot, PublicObserverDivergence, PublicUtilityViolation,
    COVERAGE_CORPUS_SCHEMA, COVERAGE_FEEDBACK_SCHEMA,
};
pub use fuzzer::{
    run_adaptive_fuzz, AdaptiveActionClass, AdaptiveFuzzBudget, AdaptiveFuzzConfig,
    AdaptiveFuzzReport, FuzzCounterexample, FuzzError, FuzzInconclusiveReason, FuzzStep,
    FuzzVerdict, FuzzViolationKind, PublicFuzzInput, PublicFuzzTarget, PublicTargetStatus,
    PublicTargetStep, ADAPTIVE_FUZZ_REPORT_SCHEMA,
};
pub use shrinker::{
    shrink_counterexample, CheckerRole, IndependentReplayChecker, ReplayResult, ShrinkAttempt,
    ShrinkAttemptDecision, ShrinkBounds, ShrinkError, ShrinkInconclusiveReason, ShrinkPhase,
    ShrinkReport, ShrinkVerdict, SHRINK_REPORT_SCHEMA,
};
