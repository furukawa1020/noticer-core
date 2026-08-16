#![forbid(unsafe_code)]

//! Typed repair synthesis for finite AQRS release machines.
//!
//! Repairs operate only on the explicit release model and machine table. This
//! crate deliberately has no Rust parser, source rewriter, or fixed AETS
//! template.

mod engine;
mod operator;

pub use engine::{
    repair, InconclusiveReason, ParetoFrontier, RepairDistance, RepairError, RepairLimits,
    RepairOutcome, RepairPoint, RepairProvenance, RepairStats, SourceFingerprint,
};
pub use operator::RepairOperator;
