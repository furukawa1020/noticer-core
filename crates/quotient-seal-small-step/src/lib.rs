#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod machine;

pub use machine::{
    CallFrame, ControlEvent, ControlKind, ExecutionEvent, ExecutionReport, FuelClass,
    HostDirective, HostOutcome, InstantiationError, InterpreterLimits, MachineStatus,
    MemoryAccessKind, ProgramCounter, PublicHostFault, PublicHostTape, ResourceExhaustion,
    TrapCode, Value, WasmMachine, WasmState,
};
#[cfg(feature = "checker-internals")]
pub use machine::{CheckerMemoryPatch, CheckerSeed, CheckerSeedError};

pub const QUOTIENT_SEAL_SMALL_STEP_V1: &str = "QUOTIENT_SEAL_SMALL_STEP_V1";
pub const INSTRUCTION_FUEL_COST: u64 = 1;
pub const EMIT_FRAME_FUEL_COST: u64 = 8;
pub const EMIT_ACTION_FUEL_COST: u64 = 8;
pub const PUBLIC_FAILURE_FUEL_COST: u64 = 4;
