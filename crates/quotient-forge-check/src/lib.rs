#![forbid(unsafe_code)]

//! Solver-independent bounded product checking for Action-Quotient Release
//! Synthesis (AQRS).
//!
//! The checker consumes a finite, explicit product-check normal form. It never
//! interprets solver output as a proof and never reports resource exhaustion as
//! a successful verification result.

mod checker;
mod counterexample;
mod model;

use std::marker::PhantomData;

pub use checker::{
    check, CheckLimits, CheckOutcome, InconclusiveReason, InconclusiveReport, VerifiedReport,
};
pub use counterexample::{
    CausalField, Counterexample, CounterexampleKind, Observation, RepairCandidate, Side, TraceStep,
};
pub use model::{
    ActionEmission, ActionId, ActionObligation, CheckerModel, EnvironmentInput, FaultInput,
    FaultInputId, FieldId, InitialPair, InputId, ModelError, ObligationId, ObligationRef, Observer,
    ObserverId, PrivateHistoryId, RecoveryRequirement, Release, SemanticContract, SemanticId,
    State, StateId, Transition,
};

/// Compile-time marker for the canonical K6-03 IR accepted by a future lowering
/// adapter. The solver-independent checker intentionally does not reach into
/// private acquisition types or mutate the source IR.
#[derive(Clone, Copy, Debug, Default)]
pub struct IrCompatibility(PhantomData<fn() -> quotient_forge_ir::CompiledModel>);

impl IrCompatibility {
    #[must_use]
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

/// Returns the concrete K6-03 source type linked into this checker build.
#[must_use]
pub fn ir_input_type_name() -> &'static str {
    std::any::type_name::<quotient_forge_ir::CompiledModel>()
}
