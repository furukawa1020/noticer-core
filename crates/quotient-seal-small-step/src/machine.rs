use alloc::{
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::mem;

use quotient_seal_target_ir::{
    BlockType, CanonicalTargetIr, Function, FunctionType, Instruction, InstructionImmediate,
    ValueType,
};

use crate::{
    EMIT_ACTION_FUEL_COST, EMIT_FRAME_FUEL_COST, INSTRUCTION_FUEL_COST, PUBLIC_FAILURE_FUEL_COST,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Value {
    I32(u32),
    I64(u64),
}

impl Value {
    const fn zero(value_type: ValueType) -> Self {
        match value_type {
            ValueType::I32 => Self::I32(0),
            ValueType::I64 => Self::I64(0),
        }
    }

    const fn matches(self, value_type: ValueType) -> bool {
        matches!(
            (self, value_type),
            (Self::I32(_), ValueType::I32) | (Self::I64(_), ValueType::I64)
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProgramCounter {
    pub function_index: u32,
    pub instruction_index: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlKind {
    Function,
    Block,
    Loop,
    If,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlEvent {
    Enter,
    Else,
    End,
    Branch { depth: u32 },
    Return,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryAccessKind {
    Load,
    Store,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FuelClass {
    Instruction,
    HostImport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicHostFault {
    Timeout,
    Reconnect,
    Loss,
    Denied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostOutcome {
    Continue,
    Terminate,
    Fault(PublicHostFault),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostDirective {
    import: String,
    outcome: HostOutcome,
}

impl HostDirective {
    #[must_use]
    pub fn new(import: impl Into<String>, outcome: HostOutcome) -> Self {
        Self {
            import: import.into(),
            outcome,
        }
    }

    #[must_use]
    pub fn import(&self) -> &str {
        &self.import
    }

    #[must_use]
    pub const fn outcome(&self) -> HostOutcome {
        self.outcome
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PublicHostTape {
    directives: Vec<HostDirective>,
    cursor: usize,
}

#[cfg(feature = "checker-internals")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckerMemoryPatch {
    pub offset: u32,
    pub bytes: Vec<u8>,
}

#[cfg(feature = "checker-internals")]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CheckerSeed {
    pub globals: Vec<(u32, Value)>,
    pub memory: Vec<CheckerMemoryPatch>,
}

#[cfg(feature = "checker-internals")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckerSeedError {
    GlobalIndex,
    GlobalType,
    MemoryBounds,
}

impl PublicHostTape {
    #[must_use]
    pub fn new(directives: Vec<HostDirective>) -> Self {
        Self {
            directives,
            cursor: 0,
        }
    }

    #[must_use]
    pub const fn cursor(&self) -> usize {
        self.cursor
    }

    #[must_use]
    pub fn directives(&self) -> &[HostDirective] {
        &self.directives
    }

    fn take(&mut self, expected: &str) -> Result<HostOutcome, TrapCode> {
        let directive = self
            .directives
            .get(self.cursor)
            .ok_or(TrapCode::HostTapeExhausted)?;
        if directive.import != expected {
            return Err(TrapCode::HostTapeMismatch);
        }
        self.cursor += 1;
        Ok(directive.outcome)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrapCode {
    Unreachable,
    IntegerDivideByZero,
    IntegerOverflow,
    MemoryOutOfBounds,
    StackUnderflow,
    TypeMismatch,
    InvalidConversion,
    InvalidControl,
    InvalidLocal,
    InvalidGlobal,
    InvalidFunction,
    HostTapeExhausted,
    HostTapeMismatch,
    HostFault(PublicHostFault),
    UnsupportedInstruction(u8),
    UndeclaredHostImport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceExhaustion {
    Fuel { needed: u64, remaining: u64 },
    EventLog { limit: usize },
    OperandStack { limit: usize },
    CallDepth { limit: usize },
    Memory { limit: usize, requested: usize },
    HostCalls { limit: usize },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MachineStatus {
    Running,
    Returned(Vec<Value>),
    Terminated,
    Trapped(TrapCode),
    ResourceBound(ResourceExhaustion),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionEvent {
    ApiInvoke {
        export: String,
        arguments: Vec<Value>,
        initial_fuel: u64,
    },
    FuelCharged {
        class: FuelClass,
        amount: u64,
        remaining: u64,
    },
    Instruction {
        pc: ProgramCounter,
        opcode: u8,
    },
    Control {
        pc: ProgramCounter,
        kind: ControlKind,
        event: ControlEvent,
    },
    FunctionEnter {
        function_index: u32,
    },
    FunctionReturn {
        function_index: u32,
        results: Vec<Value>,
    },
    Memory {
        pc: ProgramCounter,
        kind: MemoryAccessKind,
        address: u64,
        width: u8,
    },
    HostCall {
        import: String,
        arguments: Vec<Value>,
        ordinal: u64,
        public_cost: u64,
        outcome: HostOutcome,
    },
    Trap {
        pc: ProgramCounter,
        code: TrapCode,
    },
    Termination {
        pc: ProgramCounter,
    },
    ResourceBound {
        pc: ProgramCounter,
        resource: ResourceExhaustion,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ControlLabel {
    kind: ControlKind,
    start_pc: usize,
    end_pc: usize,
    result: Option<ValueType>,
    stack_height: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallFrame {
    pc: ProgramCounter,
    locals: Vec<Value>,
    control_stack: Vec<ControlLabel>,
}

impl CallFrame {
    #[must_use]
    pub const fn resume_pc(&self) -> ProgramCounter {
        self.pc
    }

    #[must_use]
    pub fn locals(&self) -> &[Value] {
        &self.locals
    }

    #[must_use]
    pub fn control_depth(&self) -> usize {
        self.control_stack.len()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WasmState {
    pc: ProgramCounter,
    stack: Vec<Value>,
    locals: Vec<Value>,
    globals: Vec<Value>,
    memory: Vec<u8>,
    control_stack: Vec<ControlLabel>,
    call_stack: Vec<CallFrame>,
    events: Vec<ExecutionEvent>,
    fuel: u64,
    status: MachineStatus,
}

impl WasmState {
    #[must_use]
    pub const fn pc(&self) -> ProgramCounter {
        self.pc
    }

    #[must_use]
    pub fn stack(&self) -> &[Value] {
        &self.stack
    }

    #[must_use]
    pub fn locals(&self) -> &[Value] {
        &self.locals
    }

    #[must_use]
    pub fn globals(&self) -> &[Value] {
        &self.globals
    }

    #[must_use]
    pub fn memory(&self) -> &[u8] {
        &self.memory
    }

    #[must_use]
    pub fn call_stack(&self) -> &[CallFrame] {
        &self.call_stack
    }

    #[must_use]
    pub fn control_depth(&self) -> usize {
        self.control_stack.len()
    }

    #[must_use]
    pub fn events(&self) -> &[ExecutionEvent] {
        &self.events
    }

    #[must_use]
    pub const fn fuel(&self) -> u64 {
        self.fuel
    }

    #[must_use]
    pub fn status(&self) -> &MachineStatus {
        &self.status
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterpreterLimits {
    pub max_initial_fuel: u64,
    pub max_events: usize,
    pub max_operand_stack: usize,
    pub max_call_depth: usize,
    pub max_memory_bytes: usize,
    pub max_host_calls: usize,
}

impl InterpreterLimits {
    #[must_use]
    pub const fn frozen_v1() -> Self {
        Self {
            max_initial_fuel: 1_000_000,
            max_events: 2_000_000,
            max_operand_stack: 4_096,
            max_call_depth: 256,
            max_memory_bytes: 1_048_576,
            max_host_calls: 65_536,
        }
    }
}

impl Default for InterpreterLimits {
    fn default() -> Self {
        Self::frozen_v1()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstantiationError {
    ExportNotFound,
    ExportIsImport,
    InvalidFunction,
    InvalidType,
    ArgumentCount,
    ArgumentType,
    ImportHasResult,
    UndeclaredHostImport,
    MissingFunctionEnd,
    InitialFuelLimit,
    EventLimit,
    MemoryLimit,
    DataOutsideMemory,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionReport {
    state: WasmState,
    consumed_host_directives: usize,
}

impl ExecutionReport {
    #[must_use]
    pub fn state(&self) -> &WasmState {
        &self.state
    }

    #[must_use]
    pub const fn consumed_host_directives(&self) -> usize {
        self.consumed_host_directives
    }

    #[must_use]
    pub fn into_state(self) -> WasmState {
        self.state
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WasmMachine {
    module: CanonicalTargetIr,
    state: WasmState,
    host_tape: PublicHostTape,
    limits: InterpreterLimits,
    host_calls: usize,
}

impl WasmMachine {
    pub fn instantiate(
        module: &CanonicalTargetIr,
        export: &str,
        arguments: Vec<Value>,
        initial_fuel: u64,
        host_tape: PublicHostTape,
        limits: InterpreterLimits,
    ) -> Result<Self, InstantiationError> {
        if initial_fuel > limits.max_initial_fuel {
            return Err(InstantiationError::InitialFuelLimit);
        }
        if limits.max_events == 0 {
            return Err(InstantiationError::EventLimit);
        }
        validate_imports(module)?;

        let memory_len = usize::try_from(module.memory().bytes())
            .map_err(|_| InstantiationError::MemoryLimit)?;
        if memory_len > limits.max_memory_bytes {
            return Err(InstantiationError::MemoryLimit);
        }
        let mut memory = vec![0_u8; memory_len];
        for segment in module.data_segments() {
            let start = usize::try_from(segment.offset())
                .map_err(|_| InstantiationError::DataOutsideMemory)?;
            let end = start
                .checked_add(segment.bytes().len())
                .ok_or(InstantiationError::DataOutsideMemory)?;
            let target = memory
                .get_mut(start..end)
                .ok_or(InstantiationError::DataOutsideMemory)?;
            target.copy_from_slice(segment.bytes());
        }

        let exported_index = module
            .exports()
            .iter()
            .find(|candidate| candidate.name() == export)
            .map(quotient_seal_target_ir::FunctionExport::function_index)
            .ok_or(InstantiationError::ExportNotFound)?;
        if usize::try_from(exported_index).map_or(true, |index| index < module.imports().len()) {
            return Err(InstantiationError::ExportIsImport);
        }
        let (locals, result) = make_locals(module, exported_index, arguments.as_slice())?;
        let function =
            defined_function(module, exported_index).ok_or(InstantiationError::InvalidFunction)?;
        let end_pc = function
            .instructions()
            .len()
            .checked_sub(1)
            .filter(|index| function.instructions()[*index].opcode() == 0x0b)
            .ok_or(InstantiationError::MissingFunctionEnd)?;

        let globals = module
            .globals()
            .iter()
            .map(|global| match global.initial() {
                quotient_seal_target_ir::ConstValue::I32(value) => Value::I32(value as u32),
                quotient_seal_target_ir::ConstValue::I64(value) => Value::I64(value as u64),
            })
            .collect();
        let pc = ProgramCounter {
            function_index: exported_index,
            instruction_index: 0,
        };
        let events = vec![
            ExecutionEvent::ApiInvoke {
                export: export.to_string(),
                arguments,
                initial_fuel,
            },
            ExecutionEvent::FunctionEnter {
                function_index: exported_index,
            },
        ];
        if events.len() > limits.max_events {
            return Err(InstantiationError::EventLimit);
        }
        let state = WasmState {
            pc,
            stack: Vec::new(),
            locals,
            globals,
            memory,
            control_stack: vec![ControlLabel {
                kind: ControlKind::Function,
                start_pc: 0,
                end_pc,
                result,
                stack_height: 0,
            }],
            call_stack: Vec::new(),
            events,
            fuel: initial_fuel,
            status: MachineStatus::Running,
        };
        Ok(Self {
            module: module.clone(),
            state,
            host_tape,
            limits,
            host_calls: 0,
        })
    }

    #[cfg(feature = "checker-internals")]
    pub fn instantiate_for_checker(
        module: &CanonicalTargetIr,
        export: &str,
        arguments: Vec<Value>,
        initial_fuel: u64,
        host_tape: PublicHostTape,
        limits: InterpreterLimits,
        seed: &CheckerSeed,
    ) -> Result<Self, CheckerSeedError> {
        let mut machine =
            Self::instantiate(module, export, arguments, initial_fuel, host_tape, limits)
                .map_err(|_| CheckerSeedError::GlobalIndex)?;
        for (index, value) in &seed.globals {
            let index = usize::try_from(*index).map_err(|_| CheckerSeedError::GlobalIndex)?;
            let target = machine
                .state
                .globals
                .get_mut(index)
                .ok_or(CheckerSeedError::GlobalIndex)?;
            if core::mem::discriminant(target) != core::mem::discriminant(value) {
                return Err(CheckerSeedError::GlobalType);
            }
            *target = *value;
        }
        for patch in &seed.memory {
            let start =
                usize::try_from(patch.offset).map_err(|_| CheckerSeedError::MemoryBounds)?;
            let end = start
                .checked_add(patch.bytes.len())
                .ok_or(CheckerSeedError::MemoryBounds)?;
            let target = machine
                .state
                .memory
                .get_mut(start..end)
                .ok_or(CheckerSeedError::MemoryBounds)?;
            target.copy_from_slice(&patch.bytes);
        }
        Ok(machine)
    }

    #[must_use]
    pub fn state(&self) -> &WasmState {
        &self.state
    }

    #[must_use]
    pub fn host_tape(&self) -> &PublicHostTape {
        &self.host_tape
    }

    pub fn step(&mut self) {
        if self.state.status != MachineStatus::Running {
            return;
        }
        let pc = self.state.pc;
        let Some(instruction) = self.current_instruction() else {
            self.set_trap(TrapCode::InvalidControl);
            return;
        };
        if !self.charge(FuelClass::Instruction, INSTRUCTION_FUEL_COST) {
            return;
        }
        if !self.record(ExecutionEvent::Instruction {
            pc,
            opcode: instruction.opcode(),
        }) {
            return;
        }
        self.execute(instruction);
    }

    #[must_use]
    pub fn run(mut self) -> ExecutionReport {
        while self.state.status == MachineStatus::Running {
            self.step();
        }
        ExecutionReport {
            consumed_host_directives: self.host_tape.cursor,
            state: self.state,
        }
    }

    fn current_instruction(&self) -> Option<Instruction> {
        defined_function(&self.module, self.state.pc.function_index)?
            .instructions()
            .get(self.state.pc.instruction_index)
            .copied()
    }

    fn execute(&mut self, instruction: Instruction) {
        match instruction.opcode() {
            0x00 => self.set_trap(TrapCode::Unreachable),
            0x01 => self.advance(),
            0x02..=0x04 => self.enter_control(instruction),
            0x05 => self.execute_else(),
            0x0b => self.execute_end(),
            0x0c => self.execute_branch(instruction, false),
            0x0d => self.execute_branch(instruction, true),
            0x0f => self.finish_current_function(),
            0x10 => self.execute_call(instruction),
            0x1a => {
                if self.pop_value().is_ok() {
                    self.advance();
                }
            }
            0x1b => self.execute_select(),
            0x20..=0x22 => self.execute_local(instruction),
            0x23..=0x24 => self.execute_global(instruction),
            0x28..=0x3e => self.execute_memory(instruction),
            0x41 | 0x42 => self.execute_const(instruction),
            0x45..=0x5a | 0x67..=0x8a | 0xa7 | 0xac | 0xad | 0xc0..=0xc4 => {
                self.execute_numeric(instruction.opcode());
            }
            opcode => self.set_trap(TrapCode::UnsupportedInstruction(opcode)),
        }
    }

    fn enter_control(&mut self, instruction: Instruction) {
        let pc = self.state.pc;
        let Some((else_pc, end_pc)) = find_control_bounds(
            defined_function(&self.module, pc.function_index)
                .map(Function::instructions)
                .unwrap_or_default(),
            pc.instruction_index,
        ) else {
            self.set_trap(TrapCode::InvalidControl);
            return;
        };
        let InstructionImmediate::Block(block_type) = instruction.immediate() else {
            self.set_trap(TrapCode::InvalidControl);
            return;
        };
        let result = block_result(block_type);
        let kind = match instruction.opcode() {
            0x02 => ControlKind::Block,
            0x03 => ControlKind::Loop,
            0x04 => ControlKind::If,
            _ => {
                self.set_trap(TrapCode::InvalidControl);
                return;
            }
        };
        let condition = if kind == ControlKind::If {
            match self.pop_i32(TrapCode::TypeMismatch) {
                Ok(value) => Some(value),
                Err(code) => {
                    self.set_trap(code);
                    return;
                }
            }
        } else {
            None
        };
        self.state.control_stack.push(ControlLabel {
            kind,
            start_pc: pc.instruction_index + 1,
            end_pc,
            result,
            stack_height: self.state.stack.len(),
        });
        if !self.record(ExecutionEvent::Control {
            pc,
            kind,
            event: ControlEvent::Enter,
        }) {
            return;
        }
        if let Some(condition) = condition {
            if condition == 0 {
                self.state.pc.instruction_index = else_pc.map_or(end_pc, |index| index + 1);
            } else {
                self.advance();
            }
        } else {
            self.advance();
        }
    }

    fn execute_else(&mut self) {
        let pc = self.state.pc;
        let Some(label) = self.state.control_stack.last().cloned() else {
            self.set_trap(TrapCode::InvalidControl);
            return;
        };
        if label.kind != ControlKind::If {
            self.set_trap(TrapCode::InvalidControl);
            return;
        }
        if let Err(code) = self.normalize_stack(&label) {
            self.set_trap(code);
            return;
        }
        self.state.control_stack.pop();
        if !self.record(ExecutionEvent::Control {
            pc,
            kind: ControlKind::If,
            event: ControlEvent::Else,
        }) {
            return;
        }
        self.state.pc.instruction_index = label.end_pc + 1;
    }

    fn execute_end(&mut self) {
        let pc = self.state.pc;
        let Some(label) = self.state.control_stack.last().cloned() else {
            self.set_trap(TrapCode::InvalidControl);
            return;
        };
        if label.end_pc != pc.instruction_index {
            self.set_trap(TrapCode::InvalidControl);
            return;
        }
        if label.kind == ControlKind::Function {
            self.finish_current_function();
            return;
        }
        if let Err(code) = self.normalize_stack(&label) {
            self.set_trap(code);
            return;
        }
        self.state.control_stack.pop();
        if !self.record(ExecutionEvent::Control {
            pc,
            kind: label.kind,
            event: ControlEvent::End,
        }) {
            return;
        }
        self.advance();
    }

    fn execute_branch(&mut self, instruction: Instruction, conditional: bool) {
        let InstructionImmediate::Index(depth) = instruction.immediate() else {
            self.set_trap(TrapCode::InvalidControl);
            return;
        };
        if conditional {
            match self.pop_i32(TrapCode::TypeMismatch) {
                Ok(0) => {
                    self.advance();
                    return;
                }
                Ok(_) => {}
                Err(code) => {
                    self.set_trap(code);
                    return;
                }
            }
        }
        let Ok(depth_usize) = usize::try_from(depth) else {
            self.set_trap(TrapCode::InvalidControl);
            return;
        };
        let Some(target_index) = self.state.control_stack.len().checked_sub(depth_usize + 1) else {
            self.set_trap(TrapCode::InvalidControl);
            return;
        };
        let target = self.state.control_stack[target_index].clone();
        if !self.record(ExecutionEvent::Control {
            pc: self.state.pc,
            kind: target.kind,
            event: ControlEvent::Branch { depth },
        }) {
            return;
        }
        match target.kind {
            ControlKind::Loop => {
                self.state.stack.truncate(target.stack_height);
                self.state.control_stack.truncate(target_index + 1);
                self.state.pc.instruction_index = target.start_pc;
            }
            ControlKind::Function => self.finish_current_function(),
            ControlKind::Block | ControlKind::If => {
                if let Err(code) = self.normalize_stack(&target) {
                    self.set_trap(code);
                    return;
                }
                self.state.control_stack.truncate(target_index);
                self.state.pc.instruction_index = target.end_pc + 1;
            }
        }
    }

    fn execute_select(&mut self) {
        let condition = match self.pop_i32(TrapCode::TypeMismatch) {
            Ok(value) => value,
            Err(code) => {
                self.set_trap(code);
                return;
            }
        };
        let second = match self.pop_value() {
            Ok(value) => value,
            Err(code) => {
                self.set_trap(code);
                return;
            }
        };
        let first = match self.pop_value() {
            Ok(value) => value,
            Err(code) => {
                self.set_trap(code);
                return;
            }
        };
        if core::mem::discriminant(&first) != core::mem::discriminant(&second) {
            self.set_trap(TrapCode::TypeMismatch);
            return;
        }
        if self.push(if condition == 0 { second } else { first }) {
            self.advance();
        }
    }

    fn execute_local(&mut self, instruction: Instruction) {
        let InstructionImmediate::Index(index) = instruction.immediate() else {
            self.set_trap(TrapCode::InvalidLocal);
            return;
        };
        let Ok(index) = usize::try_from(index) else {
            self.set_trap(TrapCode::InvalidLocal);
            return;
        };
        match instruction.opcode() {
            0x20 => {
                let Some(value) = self.state.locals.get(index).copied() else {
                    self.set_trap(TrapCode::InvalidLocal);
                    return;
                };
                if self.push(value) {
                    self.advance();
                }
            }
            0x21 | 0x22 => {
                let value = match self.pop_value() {
                    Ok(value) => value,
                    Err(code) => {
                        self.set_trap(code);
                        return;
                    }
                };
                let Some(local) = self.state.locals.get_mut(index) else {
                    self.set_trap(TrapCode::InvalidLocal);
                    return;
                };
                if core::mem::discriminant(local) != core::mem::discriminant(&value) {
                    self.set_trap(TrapCode::TypeMismatch);
                    return;
                }
                *local = value;
                if instruction.opcode() != 0x22 || self.push(value) {
                    self.advance();
                }
            }
            _ => self.set_trap(TrapCode::UnsupportedInstruction(instruction.opcode())),
        }
    }

    fn execute_global(&mut self, instruction: Instruction) {
        let InstructionImmediate::Index(index) = instruction.immediate() else {
            self.set_trap(TrapCode::InvalidGlobal);
            return;
        };
        let Ok(index) = usize::try_from(index) else {
            self.set_trap(TrapCode::InvalidGlobal);
            return;
        };
        match instruction.opcode() {
            0x23 => {
                let Some(value) = self.state.globals.get(index).copied() else {
                    self.set_trap(TrapCode::InvalidGlobal);
                    return;
                };
                if self.push(value) {
                    self.advance();
                }
            }
            0x24 => {
                if !self
                    .module
                    .globals()
                    .get(index)
                    .is_some_and(|global| global.is_mutable())
                {
                    self.set_trap(TrapCode::InvalidGlobal);
                    return;
                }
                let value = match self.pop_value() {
                    Ok(value) => value,
                    Err(code) => {
                        self.set_trap(code);
                        return;
                    }
                };
                let Some(global) = self.state.globals.get_mut(index) else {
                    self.set_trap(TrapCode::InvalidGlobal);
                    return;
                };
                if core::mem::discriminant(global) != core::mem::discriminant(&value) {
                    self.set_trap(TrapCode::TypeMismatch);
                    return;
                }
                *global = value;
                self.advance();
            }
            _ => self.set_trap(TrapCode::UnsupportedInstruction(instruction.opcode())),
        }
    }

    fn execute_const(&mut self, instruction: Instruction) {
        let value = match instruction.immediate() {
            InstructionImmediate::I32(value) => Value::I32(value as u32),
            InstructionImmediate::I64(value) => Value::I64(value as u64),
            _ => {
                self.set_trap(TrapCode::InvalidConversion);
                return;
            }
        };
        if self.push(value) {
            self.advance();
        }
    }

    fn execute_call(&mut self, instruction: Instruction) {
        let InstructionImmediate::Index(function_index) = instruction.immediate() else {
            self.set_trap(TrapCode::InvalidFunction);
            return;
        };
        let Some(function_type) = function_type(&self.module, function_index).cloned() else {
            self.set_trap(TrapCode::InvalidFunction);
            return;
        };
        if usize::try_from(function_index)
            .ok()
            .is_some_and(|index| index < self.module.imports().len())
        {
            self.execute_host_call(function_index, &function_type);
        } else {
            self.execute_direct_call(function_index, &function_type);
        }
    }

    fn execute_host_call(&mut self, function_index: u32, function_type: &FunctionType) {
        let Some(import) = usize::try_from(function_index)
            .ok()
            .and_then(|index| self.module.imports().get(index))
        else {
            self.set_trap(TrapCode::InvalidFunction);
            return;
        };
        let import_name = import.name().to_string();
        let Some(public_cost) = host_cost(&import_name) else {
            self.set_trap(TrapCode::UndeclaredHostImport);
            return;
        };
        if !self.charge(FuelClass::HostImport, public_cost) {
            return;
        }
        if self.host_calls >= self.limits.max_host_calls {
            self.set_resource(ResourceExhaustion::HostCalls {
                limit: self.limits.max_host_calls,
            });
            return;
        }
        let arguments = match self.pop_arguments(function_type.params()) {
            Ok(values) => values,
            Err(code) => {
                self.set_trap(code);
                return;
            }
        };
        let outcome = match self.host_tape.take(&import_name) {
            Ok(outcome) => outcome,
            Err(code) => {
                self.set_trap(code);
                return;
            }
        };
        let ordinal = self.host_calls as u64;
        self.host_calls += 1;
        if !self.record(ExecutionEvent::HostCall {
            import: import_name,
            arguments,
            ordinal,
            public_cost,
            outcome,
        }) {
            return;
        }
        self.advance();
        match outcome {
            HostOutcome::Continue => {}
            HostOutcome::Terminate => {
                let pc = self.state.pc;
                if self.record(ExecutionEvent::Termination { pc }) {
                    self.state.status = MachineStatus::Terminated;
                }
            }
            HostOutcome::Fault(fault) => self.set_trap(TrapCode::HostFault(fault)),
        }
    }

    fn execute_direct_call(&mut self, function_index: u32, function_type: &FunctionType) {
        if self.state.call_stack.len() >= self.limits.max_call_depth {
            self.set_resource(ResourceExhaustion::CallDepth {
                limit: self.limits.max_call_depth,
            });
            return;
        }
        let arguments = match self.pop_arguments(function_type.params()) {
            Ok(values) => values,
            Err(code) => {
                self.set_trap(code);
                return;
            }
        };
        let (locals, result) = match make_locals(&self.module, function_index, &arguments) {
            Ok(value) => value,
            Err(_) => {
                self.set_trap(TrapCode::InvalidFunction);
                return;
            }
        };
        let Some(function) = defined_function(&self.module, function_index) else {
            self.set_trap(TrapCode::InvalidFunction);
            return;
        };
        let Some(end_pc) = function.instructions().len().checked_sub(1) else {
            self.set_trap(TrapCode::InvalidControl);
            return;
        };
        let frame = CallFrame {
            pc: ProgramCounter {
                function_index: self.state.pc.function_index,
                instruction_index: self.state.pc.instruction_index + 1,
            },
            locals: mem::take(&mut self.state.locals),
            control_stack: mem::take(&mut self.state.control_stack),
        };
        self.state.call_stack.push(frame);
        self.state.pc = ProgramCounter {
            function_index,
            instruction_index: 0,
        };
        self.state.locals = locals;
        self.state.control_stack.push(ControlLabel {
            kind: ControlKind::Function,
            start_pc: 0,
            end_pc,
            result,
            stack_height: self.state.stack.len(),
        });
        self.record(ExecutionEvent::FunctionEnter { function_index });
    }

    fn finish_current_function(&mut self) {
        let function_index = self.state.pc.function_index;
        let Some(function_type) = function_type(&self.module, function_index).cloned() else {
            self.set_trap(TrapCode::InvalidFunction);
            return;
        };
        let results = match self.pop_results(function_type.results()) {
            Ok(values) => values,
            Err(code) => {
                self.set_trap(code);
                return;
            }
        };
        let Some(base) = self
            .state
            .control_stack
            .first()
            .map(|label| label.stack_height)
        else {
            self.set_trap(TrapCode::InvalidControl);
            return;
        };
        self.state.stack.truncate(base);
        if !self.record(ExecutionEvent::Control {
            pc: self.state.pc,
            kind: ControlKind::Function,
            event: ControlEvent::Return,
        }) || !self.record(ExecutionEvent::FunctionReturn {
            function_index,
            results: results.clone(),
        }) {
            return;
        }
        if let Some(frame) = self.state.call_stack.pop() {
            self.state.pc = frame.pc;
            self.state.locals = frame.locals;
            self.state.control_stack = frame.control_stack;
            for result in results {
                if !self.push(result) {
                    return;
                }
            }
        } else {
            self.state.status = MachineStatus::Returned(results);
        }
    }

    fn execute_memory(&mut self, instruction: Instruction) {
        let InstructionImmediate::Memory { offset, .. } = instruction.immediate() else {
            self.set_trap(TrapCode::MemoryOutOfBounds);
            return;
        };
        let opcode = instruction.opcode();
        if opcode <= 0x35 {
            let address = match self.pop_i32(TrapCode::TypeMismatch) {
                Ok(value) => value,
                Err(code) => {
                    self.set_trap(code);
                    return;
                }
            };
            let Some((width, signed, result_type)) = load_shape(opcode) else {
                self.set_trap(TrapCode::UnsupportedInstruction(opcode));
                return;
            };
            let effective = match self.effective_address(address, offset, width) {
                Ok(value) => value,
                Err(code) => {
                    self.set_trap(code);
                    return;
                }
            };
            let raw = read_little_endian(&self.state.memory[effective..effective + width]);
            let value = match result_type {
                ValueType::I32 => {
                    let value = if signed {
                        sign_extend(raw, width * 8, 32)
                    } else {
                        raw
                    };
                    Value::I32(value as u32)
                }
                ValueType::I64 => {
                    let value = if signed {
                        sign_extend(raw, width * 8, 64)
                    } else {
                        raw
                    };
                    Value::I64(value)
                }
            };
            if !self.record_memory(MemoryAccessKind::Load, effective, width) {
                return;
            }
            if self.push(value) {
                self.advance();
            }
        } else {
            let Some((width, value_type)) = store_shape(opcode) else {
                self.set_trap(TrapCode::UnsupportedInstruction(opcode));
                return;
            };
            let value = match self.pop_value() {
                Ok(value) if value.matches(value_type) => value,
                Ok(_) => {
                    self.set_trap(TrapCode::TypeMismatch);
                    return;
                }
                Err(code) => {
                    self.set_trap(code);
                    return;
                }
            };
            let address = match self.pop_i32(TrapCode::TypeMismatch) {
                Ok(value) => value,
                Err(code) => {
                    self.set_trap(code);
                    return;
                }
            };
            let effective = match self.effective_address(address, offset, width) {
                Ok(value) => value,
                Err(code) => {
                    self.set_trap(code);
                    return;
                }
            };
            let raw = match value {
                Value::I32(value) => u64::from(value),
                Value::I64(value) => value,
            };
            write_little_endian(&mut self.state.memory[effective..effective + width], raw);
            if self.record_memory(MemoryAccessKind::Store, effective, width) {
                self.advance();
            }
        }
    }

    fn execute_numeric(&mut self, opcode: u8) {
        let result = match opcode {
            0x45 => self.unary_i32(|value| u32::from(value == 0)),
            0x46..=0x4f => self.compare_i32(opcode),
            0x50 => self.unary_i64_to_i32(|value| u32::from(value == 0)),
            0x51..=0x5a => self.compare_i64(opcode),
            0x67 => self.unary_i32(u32::leading_zeros),
            0x68 => self.unary_i32(u32::trailing_zeros),
            0x69 => self.unary_i32(u32::count_ones),
            0x6a => self.binary_i32(u32::wrapping_add),
            0x6b => self.binary_i32(u32::wrapping_sub),
            0x6c => self.binary_i32(u32::wrapping_mul),
            0x6d => self.div_i32_signed(),
            0x6e => self.div_i32_unsigned(),
            0x6f => self.rem_i32_signed(),
            0x70 => self.rem_i32_unsigned(),
            0x71 => self.binary_i32(|left, right| left & right),
            0x72 => self.binary_i32(|left, right| left | right),
            0x73 => self.binary_i32(|left, right| left ^ right),
            0x74 => self.binary_i32(|left, right| left.wrapping_shl(right & 31)),
            0x75 => self.binary_i32(|left, right| ((left as i32) >> (right & 31)) as u32),
            0x76 => self.binary_i32(|left, right| left >> (right & 31)),
            0x77 => self.binary_i32(|left, right| left.rotate_left(right & 31)),
            0x78 => self.binary_i32(|left, right| left.rotate_right(right & 31)),
            0x79 => self.unary_i64(u64::leading_zeros, true),
            0x7a => self.unary_i64(u64::trailing_zeros, true),
            0x7b => self.unary_i64(u64::count_ones, true),
            0x7c => self.binary_i64(u64::wrapping_add),
            0x7d => self.binary_i64(u64::wrapping_sub),
            0x7e => self.binary_i64(u64::wrapping_mul),
            0x7f => self.div_i64_signed(),
            0x80 => self.div_i64_unsigned(),
            0x81 => self.rem_i64_signed(),
            0x82 => self.rem_i64_unsigned(),
            0x83 => self.binary_i64(|left, right| left & right),
            0x84 => self.binary_i64(|left, right| left | right),
            0x85 => self.binary_i64(|left, right| left ^ right),
            0x86 => self.binary_i64(|left, right| left.wrapping_shl((right & 63) as u32)),
            0x87 => self.binary_i64(|left, right| ((left as i64) >> (right & 63)) as u64),
            0x88 => self.binary_i64(|left, right| left >> (right & 63)),
            0x89 => self.binary_i64(|left, right| left.rotate_left((right & 63) as u32)),
            0x8a => self.binary_i64(|left, right| left.rotate_right((right & 63) as u32)),
            0xa7 => match self.pop_i64(TrapCode::InvalidConversion) {
                Ok(value) => self.push_result(Value::I32(value as u32)),
                Err(code) => Err(code),
            },
            0xac => match self.pop_i32(TrapCode::InvalidConversion) {
                Ok(value) => self.push_result(Value::I64((value as i32 as i64) as u64)),
                Err(code) => Err(code),
            },
            0xad => match self.pop_i32(TrapCode::InvalidConversion) {
                Ok(value) => self.push_result(Value::I64(u64::from(value))),
                Err(code) => Err(code),
            },
            0xc0 => self.unary_i32(|value| (value as u8 as i8 as i32) as u32),
            0xc1 => self.unary_i32(|value| (value as u16 as i16 as i32) as u32),
            0xc2 => self.unary_i64_same(|value| (value as u8 as i8 as i64) as u64),
            0xc3 => self.unary_i64_same(|value| (value as u16 as i16 as i64) as u64),
            0xc4 => self.unary_i64_same(|value| (value as u32 as i32 as i64) as u64),
            _ => Err(TrapCode::UnsupportedInstruction(opcode)),
        };
        match result {
            Ok(()) => self.advance(),
            Err(code) => self.set_trap(code),
        }
    }

    fn compare_i32(&mut self, opcode: u8) -> Result<(), TrapCode> {
        let (left, right) = self.pop_pair_i32()?;
        let value = match opcode {
            0x46 => left == right,
            0x47 => left != right,
            0x48 => (left as i32) < (right as i32),
            0x49 => left < right,
            0x4a => (left as i32) > (right as i32),
            0x4b => left > right,
            0x4c => (left as i32) <= (right as i32),
            0x4d => left <= right,
            0x4e => (left as i32) >= (right as i32),
            0x4f => left >= right,
            _ => return Err(TrapCode::UnsupportedInstruction(opcode)),
        };
        self.push_result(Value::I32(u32::from(value)))
    }

    fn compare_i64(&mut self, opcode: u8) -> Result<(), TrapCode> {
        let (left, right) = self.pop_pair_i64()?;
        let value = match opcode {
            0x51 => left == right,
            0x52 => left != right,
            0x53 => (left as i64) < (right as i64),
            0x54 => left < right,
            0x55 => (left as i64) > (right as i64),
            0x56 => left > right,
            0x57 => (left as i64) <= (right as i64),
            0x58 => left <= right,
            0x59 => (left as i64) >= (right as i64),
            0x5a => left >= right,
            _ => return Err(TrapCode::UnsupportedInstruction(opcode)),
        };
        self.push_result(Value::I32(u32::from(value)))
    }

    fn unary_i32(&mut self, operation: impl FnOnce(u32) -> u32) -> Result<(), TrapCode> {
        let value = self.pop_i32(TrapCode::TypeMismatch)?;
        self.push_result(Value::I32(operation(value)))
    }

    fn unary_i64(
        &mut self,
        operation: impl FnOnce(u64) -> u32,
        widen: bool,
    ) -> Result<(), TrapCode> {
        let value = self.pop_i64(TrapCode::TypeMismatch)?;
        let result = operation(value);
        self.push_result(if widen {
            Value::I64(u64::from(result))
        } else {
            Value::I32(result)
        })
    }

    fn unary_i64_to_i32(&mut self, operation: impl FnOnce(u64) -> u32) -> Result<(), TrapCode> {
        let value = self.pop_i64(TrapCode::TypeMismatch)?;
        self.push_result(Value::I32(operation(value)))
    }

    fn unary_i64_same(&mut self, operation: impl FnOnce(u64) -> u64) -> Result<(), TrapCode> {
        let value = self.pop_i64(TrapCode::TypeMismatch)?;
        self.push_result(Value::I64(operation(value)))
    }

    fn binary_i32(&mut self, operation: impl FnOnce(u32, u32) -> u32) -> Result<(), TrapCode> {
        let (left, right) = self.pop_pair_i32()?;
        self.push_result(Value::I32(operation(left, right)))
    }

    fn binary_i64(&mut self, operation: impl FnOnce(u64, u64) -> u64) -> Result<(), TrapCode> {
        let (left, right) = self.pop_pair_i64()?;
        self.push_result(Value::I64(operation(left, right)))
    }

    fn div_i32_signed(&mut self) -> Result<(), TrapCode> {
        let (left, right) = self.pop_pair_i32()?;
        let (left, right) = (left as i32, right as i32);
        if right == 0 {
            return Err(TrapCode::IntegerDivideByZero);
        }
        if left == i32::MIN && right == -1 {
            return Err(TrapCode::IntegerOverflow);
        }
        self.push_result(Value::I32((left / right) as u32))
    }

    fn div_i32_unsigned(&mut self) -> Result<(), TrapCode> {
        let (left, right) = self.pop_pair_i32()?;
        if right == 0 {
            return Err(TrapCode::IntegerDivideByZero);
        }
        self.push_result(Value::I32(left / right))
    }

    fn rem_i32_signed(&mut self) -> Result<(), TrapCode> {
        let (left, right) = self.pop_pair_i32()?;
        let (left, right) = (left as i32, right as i32);
        if right == 0 {
            return Err(TrapCode::IntegerDivideByZero);
        }
        let value = if left == i32::MIN && right == -1 {
            0
        } else {
            left % right
        };
        self.push_result(Value::I32(value as u32))
    }

    fn rem_i32_unsigned(&mut self) -> Result<(), TrapCode> {
        let (left, right) = self.pop_pair_i32()?;
        if right == 0 {
            return Err(TrapCode::IntegerDivideByZero);
        }
        self.push_result(Value::I32(left % right))
    }

    fn div_i64_signed(&mut self) -> Result<(), TrapCode> {
        let (left, right) = self.pop_pair_i64()?;
        let (left, right) = (left as i64, right as i64);
        if right == 0 {
            return Err(TrapCode::IntegerDivideByZero);
        }
        if left == i64::MIN && right == -1 {
            return Err(TrapCode::IntegerOverflow);
        }
        self.push_result(Value::I64((left / right) as u64))
    }

    fn div_i64_unsigned(&mut self) -> Result<(), TrapCode> {
        let (left, right) = self.pop_pair_i64()?;
        if right == 0 {
            return Err(TrapCode::IntegerDivideByZero);
        }
        self.push_result(Value::I64(left / right))
    }

    fn rem_i64_signed(&mut self) -> Result<(), TrapCode> {
        let (left, right) = self.pop_pair_i64()?;
        let (left, right) = (left as i64, right as i64);
        if right == 0 {
            return Err(TrapCode::IntegerDivideByZero);
        }
        let value = if left == i64::MIN && right == -1 {
            0
        } else {
            left % right
        };
        self.push_result(Value::I64(value as u64))
    }

    fn rem_i64_unsigned(&mut self) -> Result<(), TrapCode> {
        let (left, right) = self.pop_pair_i64()?;
        if right == 0 {
            return Err(TrapCode::IntegerDivideByZero);
        }
        self.push_result(Value::I64(left % right))
    }

    fn pop_pair_i32(&mut self) -> Result<(u32, u32), TrapCode> {
        let right = self.pop_i32(TrapCode::TypeMismatch)?;
        let left = self.pop_i32(TrapCode::TypeMismatch)?;
        Ok((left, right))
    }

    fn pop_pair_i64(&mut self) -> Result<(u64, u64), TrapCode> {
        let right = self.pop_i64(TrapCode::TypeMismatch)?;
        let left = self.pop_i64(TrapCode::TypeMismatch)?;
        Ok((left, right))
    }

    fn normalize_stack(&mut self, label: &ControlLabel) -> Result<(), TrapCode> {
        let result = match label.result {
            Some(value_type) => {
                let value = self.pop_value()?;
                if !value.matches(value_type) {
                    return Err(TrapCode::TypeMismatch);
                }
                Some(value)
            }
            None => None,
        };
        if self.state.stack.len() < label.stack_height {
            return Err(TrapCode::StackUnderflow);
        }
        self.state.stack.truncate(label.stack_height);
        if let Some(value) = result {
            self.push_result(value)?;
        }
        Ok(())
    }

    fn pop_arguments(&mut self, types: &[ValueType]) -> Result<Vec<Value>, TrapCode> {
        let mut values = Vec::with_capacity(types.len());
        for value_type in types.iter().rev() {
            let value = self.pop_value()?;
            if !value.matches(*value_type) {
                return Err(TrapCode::TypeMismatch);
            }
            values.push(value);
        }
        values.reverse();
        Ok(values)
    }

    fn pop_results(&mut self, types: &[ValueType]) -> Result<Vec<Value>, TrapCode> {
        self.pop_arguments(types)
    }

    fn pop_value(&mut self) -> Result<Value, TrapCode> {
        self.state.stack.pop().ok_or(TrapCode::StackUnderflow)
    }

    fn pop_i32(&mut self, mismatch: TrapCode) -> Result<u32, TrapCode> {
        match self.pop_value()? {
            Value::I32(value) => Ok(value),
            Value::I64(_) => Err(mismatch),
        }
    }

    fn pop_i64(&mut self, mismatch: TrapCode) -> Result<u64, TrapCode> {
        match self.pop_value()? {
            Value::I64(value) => Ok(value),
            Value::I32(_) => Err(mismatch),
        }
    }

    fn push_result(&mut self, value: Value) -> Result<(), TrapCode> {
        if self.push(value) {
            Ok(())
        } else {
            Err(TrapCode::StackUnderflow)
        }
    }

    fn push(&mut self, value: Value) -> bool {
        if self.state.stack.len() >= self.limits.max_operand_stack {
            self.set_resource(ResourceExhaustion::OperandStack {
                limit: self.limits.max_operand_stack,
            });
            false
        } else {
            self.state.stack.push(value);
            true
        }
    }

    fn effective_address(
        &self,
        address: u32,
        offset: u32,
        width: usize,
    ) -> Result<usize, TrapCode> {
        let effective = u64::from(address)
            .checked_add(u64::from(offset))
            .ok_or(TrapCode::MemoryOutOfBounds)?;
        let start = usize::try_from(effective).map_err(|_| TrapCode::MemoryOutOfBounds)?;
        let end = start
            .checked_add(width)
            .ok_or(TrapCode::MemoryOutOfBounds)?;
        if end > self.state.memory.len() {
            Err(TrapCode::MemoryOutOfBounds)
        } else {
            Ok(start)
        }
    }

    fn record_memory(&mut self, kind: MemoryAccessKind, address: usize, width: usize) -> bool {
        self.record(ExecutionEvent::Memory {
            pc: self.state.pc,
            kind,
            address: address as u64,
            width: width as u8,
        })
    }

    fn advance(&mut self) {
        self.state.pc.instruction_index += 1;
    }

    fn charge(&mut self, class: FuelClass, amount: u64) -> bool {
        if self.state.fuel < amount {
            self.set_resource(ResourceExhaustion::Fuel {
                needed: amount,
                remaining: self.state.fuel,
            });
            return false;
        }
        self.state.fuel -= amount;
        self.record(ExecutionEvent::FuelCharged {
            class,
            amount,
            remaining: self.state.fuel,
        })
    }

    fn record(&mut self, event: ExecutionEvent) -> bool {
        if self.state.events.len() >= self.limits.max_events {
            self.state.status = MachineStatus::ResourceBound(ResourceExhaustion::EventLog {
                limit: self.limits.max_events,
            });
            false
        } else {
            self.state.events.push(event);
            true
        }
    }

    fn set_trap(&mut self, code: TrapCode) {
        let event = ExecutionEvent::Trap {
            pc: self.state.pc,
            code,
        };
        if self.record(event) {
            self.state.status = MachineStatus::Trapped(code);
        }
    }

    fn set_resource(&mut self, resource: ResourceExhaustion) {
        if self.state.events.len() < self.limits.max_events {
            self.state.events.push(ExecutionEvent::ResourceBound {
                pc: self.state.pc,
                resource,
            });
        }
        self.state.status = MachineStatus::ResourceBound(resource);
    }
}

fn validate_imports(module: &CanonicalTargetIr) -> Result<(), InstantiationError> {
    for import in module.imports() {
        if host_cost(import.name()).is_none() || import.module() != "qseal" {
            return Err(InstantiationError::UndeclaredHostImport);
        }
        let function_type = module
            .types()
            .get(import.type_index() as usize)
            .ok_or(InstantiationError::InvalidType)?;
        if !function_type.results().is_empty() {
            return Err(InstantiationError::ImportHasResult);
        }
    }
    Ok(())
}

fn make_locals(
    module: &CanonicalTargetIr,
    function_index: u32,
    arguments: &[Value],
) -> Result<(Vec<Value>, Option<ValueType>), InstantiationError> {
    let function =
        defined_function(module, function_index).ok_or(InstantiationError::InvalidFunction)?;
    let function_type = module
        .types()
        .get(function.type_index() as usize)
        .ok_or(InstantiationError::InvalidType)?;
    if function_type.params().len() != arguments.len() {
        return Err(InstantiationError::ArgumentCount);
    }
    if arguments
        .iter()
        .zip(function_type.params())
        .any(|(value, value_type)| !value.matches(*value_type))
    {
        return Err(InstantiationError::ArgumentType);
    }
    let mut locals = arguments.to_vec();
    for declaration in function.locals() {
        for _ in 0..declaration.count() {
            locals.push(Value::zero(declaration.value_type()));
        }
    }
    Ok((locals, function_type.results().first().copied()))
}

fn defined_function(module: &CanonicalTargetIr, function_index: u32) -> Option<&Function> {
    let index = usize::try_from(function_index)
        .ok()?
        .checked_sub(module.imports().len())?;
    module.functions().get(index)
}

fn function_type(module: &CanonicalTargetIr, function_index: u32) -> Option<&FunctionType> {
    let index = usize::try_from(function_index).ok()?;
    let type_index = if index < module.imports().len() {
        module.imports().get(index)?.type_index()
    } else {
        defined_function(module, function_index)?.type_index()
    };
    module.types().get(type_index as usize)
}

fn find_control_bounds(
    instructions: &[Instruction],
    start: usize,
) -> Option<(Option<usize>, usize)> {
    let mut depth = 1_u32;
    let mut else_pc = None;
    for (index, instruction) in instructions.iter().enumerate().skip(start + 1) {
        match instruction.opcode() {
            0x02..=0x04 => depth = depth.checked_add(1)?,
            0x05 if depth == 1 => else_pc = Some(index),
            0x0b => {
                depth -= 1;
                if depth == 0 {
                    return Some((else_pc, index));
                }
            }
            _ => {}
        }
    }
    None
}

const fn block_result(block_type: BlockType) -> Option<ValueType> {
    match block_type {
        BlockType::Empty => None,
        BlockType::Value(value_type) => Some(value_type),
    }
}

const fn host_cost(name: &str) -> Option<u64> {
    match name.as_bytes() {
        b"emit_frame" => Some(EMIT_FRAME_FUEL_COST),
        b"emit_action" => Some(EMIT_ACTION_FUEL_COST),
        b"public_failure" => Some(PUBLIC_FAILURE_FUEL_COST),
        _ => None,
    }
}

const fn load_shape(opcode: u8) -> Option<(usize, bool, ValueType)> {
    match opcode {
        0x28 => Some((4, false, ValueType::I32)),
        0x29 => Some((8, false, ValueType::I64)),
        0x2c => Some((1, true, ValueType::I32)),
        0x2d => Some((1, false, ValueType::I32)),
        0x2e => Some((2, true, ValueType::I32)),
        0x2f => Some((2, false, ValueType::I32)),
        0x30 => Some((1, true, ValueType::I64)),
        0x31 => Some((1, false, ValueType::I64)),
        0x32 => Some((2, true, ValueType::I64)),
        0x33 => Some((2, false, ValueType::I64)),
        0x34 => Some((4, true, ValueType::I64)),
        0x35 => Some((4, false, ValueType::I64)),
        _ => None,
    }
}

const fn store_shape(opcode: u8) -> Option<(usize, ValueType)> {
    match opcode {
        0x36 => Some((4, ValueType::I32)),
        0x37 => Some((8, ValueType::I64)),
        0x3a => Some((1, ValueType::I32)),
        0x3b => Some((2, ValueType::I32)),
        0x3c => Some((1, ValueType::I64)),
        0x3d => Some((2, ValueType::I64)),
        0x3e => Some((4, ValueType::I64)),
        _ => None,
    }
}

fn read_little_endian(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .enumerate()
        .fold(0_u64, |value, (shift, byte)| {
            value | (u64::from(*byte) << (shift * 8))
        })
}

fn write_little_endian(bytes: &mut [u8], value: u64) {
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = (value >> (index * 8)) as u8;
    }
}

fn sign_extend(value: u64, source_bits: usize, target_bits: usize) -> u64 {
    let shift = target_bits - source_bits;
    if target_bits == 32 {
        (((value as u32) << shift) as i32 >> shift) as u32 as u64
    } else {
        ((value << shift) as i64 >> shift) as u64
    }
}
