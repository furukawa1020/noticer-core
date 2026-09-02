#![forbid(unsafe_code)]

//! Canonical SMT-LIB 2.6 generation and explicit solver orchestration.
//!
//! External solvers propose candidate transducers. The independent product
//! checker remains the security oracle and every counterexample becomes a hard
//! CEGIS blocking constraint.

mod backend;
mod matrix;
mod parser;
mod process;
mod smtlib;

pub use backend::{
    solve, BackendConfig, BackendError, BackendResult, BackendStatus, DetectionRecord,
    OutputStream, PhaseArtifact, RuntimeError, RuntimeOutput, SolverArtifact, SolverKind,
    SolverRuntime, SolverSelection, StandardRuntime,
};
pub use matrix::{
    SolverAsset, SolverCommands, SolverId, SolverMatrix, SolverMatrixError, SolverPin,
    SolverPlatform, MAX_SOLVER_MATRIX_BYTES, SOLVER_MATRIX_SCHEMA_V1,
};
pub use parser::{parse_solver_output, ParseModelError, ParsedSolverOutput};
pub use process::{
    run_bounded_process, BoundedProcessOutput, BoundedSolverRuntime, ProcessError, ProcessLimits,
    SolverBinding,
};
pub use smtlib::{
    encode_smtlib, expected_variable_names, ConstraintKind, HardBlocker, ObjectiveCost,
    SmtEncoding, SmtEncodingError, SmtPhase,
};
