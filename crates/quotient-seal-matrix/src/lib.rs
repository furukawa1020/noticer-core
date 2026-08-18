//! Reproducible compiler-matrix orchestration for QuotientSeal artifacts.
//!
//! Compilers and optimizers are subjects of this evaluation, not members of
//! the trusted computing base. Only an independent checker may issue an
//! `ACCEPT` verdict.

pub mod config;
pub mod manifest;
pub mod planner;
pub mod runner;

pub use config::{
    CodegenUnits, CompilationConfig, CompilationMatrix, LtoMode, MatrixError, OptLevel,
    ToolchainRole, ToolchainSpec, WasmOptLevel,
};
pub use manifest::{
    ArtifactDigest, CheckerRecord, MatrixVerdict, ReproducibilityRecord, ReproducibilityStatus,
    RunManifest, ToolEvidence,
};
pub use planner::{plan_configuration, CommandSpec, CompilationPlan, PlanError, PlanInput};
pub use runner::{run_plan, CommandExecutor, CommandOutput, ProcessExecutor};
