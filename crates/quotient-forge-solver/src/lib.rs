#![forbid(unsafe_code)]

//! Canonical SMT-LIB 2.6 generation and explicit solver orchestration.
//!
//! External solvers propose candidate transducers. The independent product
//! checker remains the security oracle and every counterexample becomes a hard
//! CEGIS blocking constraint.

mod artifact;
mod backend;
mod matrix;
mod parser;
mod probe;
mod process;
mod qdimacs;
mod smtlib;

pub use artifact::{
    classify_runtime_output, IndependentCheckerResult, SolverArtifactError, SolverResultArtifact,
    SolverResultKind, SolverRunMetadata, SOLVER_RESULT_SCHEMA_V1,
};
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
pub use probe::{
    run_capability_probe, CapabilityProbeArtifact, CapabilityProbeArtifactError,
    CapabilityProbeCheck, CapabilityProbeStatus, SolverCapability, SOLVER_PROBE_SCHEMA_V1,
};
pub use process::{
    run_bounded_process, BoundedProcessOutput, BoundedSolverRuntime, ProcessError, ProcessLimits,
    SolverBinding,
};
pub use qdimacs::{
    encode_qdimacs, validate_qdimacs, QdimacsArtifact, QdimacsBounds, QdimacsError,
    QdimacsMetadata, QdimacsSpec, QdimacsValidation, QuantifierBlock, QuantifierKind,
    SymbolicClause, SymbolicLiteral, VariableKey, VariableRecord, VariableRole,
    MAX_QDIMACS_CLAUSES, MAX_QDIMACS_VARIABLES, MAX_VARIABLE_COORDINATE, MAX_VARIABLE_COORDINATES,
    QDIMACS_SCHEMA_V1,
};
pub use smtlib::{
    encode_smtlib, expected_variable_names, ConstraintKind, HardBlocker, ObjectiveCost,
    SmtEncoding, SmtEncodingError, SmtPhase,
};
