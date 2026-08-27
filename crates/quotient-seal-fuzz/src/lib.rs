#![forbid(unsafe_code)]

//! Bounded adaptive malicious-host fuzzing for QuotientSeal public contexts.

mod action_state;

pub use action_state::{
    apply_public_feedback, AdaptiveContextBounds, AdaptiveContextState, AdaptiveHostAction,
    AdaptiveHostProgram, AdaptiveProgramError, AdaptivePublicObservation, AdaptiveStateTransition,
    ADAPTIVE_CONTEXT_SCHEMA, ADAPTIVE_HOST_MAGIC,
};
