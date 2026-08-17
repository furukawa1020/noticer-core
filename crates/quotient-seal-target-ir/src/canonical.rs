use alloc::{string::String, vec::Vec};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ValueType {
    I32,
    I64,
}

impl ValueType {
    const fn code(self) -> u8 {
        match self {
            Self::I32 => 0x7f,
            Self::I64 => 0x7e,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FunctionType {
    params: Vec<ValueType>,
    results: Vec<ValueType>,
}

impl FunctionType {
    pub(crate) fn new(params: Vec<ValueType>, results: Vec<ValueType>) -> Self {
        Self { params, results }
    }

    #[must_use]
    pub fn params(&self) -> &[ValueType] {
        &self.params
    }

    #[must_use]
    pub fn results(&self) -> &[ValueType] {
        &self.results
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FunctionImport {
    module: String,
    name: String,
    type_index: u32,
}

impl FunctionImport {
    pub(crate) fn new(module: String, name: String, type_index: u32) -> Self {
        Self {
            module,
            name,
            type_index,
        }
    }

    #[must_use]
    pub fn module(&self) -> &str {
        &self.module
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn type_index(&self) -> u32 {
        self.type_index
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedMemory {
    pages: u32,
}

impl FixedMemory {
    pub(crate) const fn new(pages: u32) -> Self {
        Self { pages }
    }

    #[must_use]
    pub const fn pages(self) -> u32 {
        self.pages
    }

    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.pages as u64 * 65_536
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConstValue {
    I32(i32),
    I64(i64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Global {
    value_type: ValueType,
    mutable: bool,
    initial: ConstValue,
}

impl Global {
    pub(crate) const fn new(value_type: ValueType, mutable: bool, initial: ConstValue) -> Self {
        Self {
            value_type,
            mutable,
            initial,
        }
    }

    #[must_use]
    pub const fn value_type(self) -> ValueType {
        self.value_type
    }

    #[must_use]
    pub const fn is_mutable(self) -> bool {
        self.mutable
    }

    #[must_use]
    pub const fn initial(self) -> ConstValue {
        self.initial
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalDecl {
    count: u32,
    value_type: ValueType,
}

impl LocalDecl {
    pub(crate) const fn new(count: u32, value_type: ValueType) -> Self {
        Self { count, value_type }
    }

    #[must_use]
    pub const fn count(self) -> u32 {
        self.count
    }

    #[must_use]
    pub const fn value_type(self) -> ValueType {
        self.value_type
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockType {
    Empty,
    Value(ValueType),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstructionImmediate {
    None,
    Index(u32),
    I32(i32),
    I64(i64),
    Block(BlockType),
    Memory { alignment: u32, offset: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Instruction {
    opcode: u8,
    immediate: InstructionImmediate,
}

impl Instruction {
    pub(crate) const fn new(opcode: u8, immediate: InstructionImmediate) -> Self {
        Self { opcode, immediate }
    }

    #[must_use]
    pub const fn opcode(self) -> u8 {
        self.opcode
    }

    #[must_use]
    pub const fn immediate(self) -> InstructionImmediate {
        self.immediate
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Function {
    type_index: u32,
    locals: Vec<LocalDecl>,
    instructions: Vec<Instruction>,
}

impl Function {
    pub(crate) fn new(
        type_index: u32,
        locals: Vec<LocalDecl>,
        instructions: Vec<Instruction>,
    ) -> Self {
        Self {
            type_index,
            locals,
            instructions,
        }
    }

    #[must_use]
    pub const fn type_index(&self) -> u32 {
        self.type_index
    }

    #[must_use]
    pub fn locals(&self) -> &[LocalDecl] {
        &self.locals
    }

    #[must_use]
    pub fn instructions(&self) -> &[Instruction] {
        &self.instructions
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FunctionExport {
    name: String,
    function_index: u32,
}

impl FunctionExport {
    pub(crate) fn new(name: String, function_index: u32) -> Self {
        Self {
            name,
            function_index,
        }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn function_index(&self) -> u32 {
        self.function_index
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DataSegment {
    offset: u32,
    bytes: Vec<u8>,
}

impl DataSegment {
    pub(crate) fn new(offset: u32, bytes: Vec<u8>) -> Self {
        Self { offset, bytes }
    }

    #[must_use]
    pub const fn offset(&self) -> u32 {
        self.offset
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalTargetIr {
    types: Vec<FunctionType>,
    imports: Vec<FunctionImport>,
    memory: FixedMemory,
    globals: Vec<Global>,
    functions: Vec<Function>,
    exports: Vec<FunctionExport>,
    data_segments: Vec<DataSegment>,
}

impl CanonicalTargetIr {
    pub(crate) fn new(
        types: Vec<FunctionType>,
        imports: Vec<FunctionImport>,
        memory: FixedMemory,
        globals: Vec<Global>,
        functions: Vec<Function>,
        exports: Vec<FunctionExport>,
        data_segments: Vec<DataSegment>,
    ) -> Self {
        Self {
            types,
            imports,
            memory,
            globals,
            functions,
            exports,
            data_segments,
        }
    }

    #[must_use]
    pub fn types(&self) -> &[FunctionType] {
        &self.types
    }

    #[must_use]
    pub fn imports(&self) -> &[FunctionImport] {
        &self.imports
    }

    #[must_use]
    pub const fn memory(&self) -> FixedMemory {
        self.memory
    }

    #[must_use]
    pub fn globals(&self) -> &[Global] {
        &self.globals
    }

    #[must_use]
    pub fn functions(&self) -> &[Function] {
        &self.functions
    }

    #[must_use]
    pub fn exports(&self) -> &[FunctionExport] {
        &self.exports
    }

    #[must_use]
    pub fn data_segments(&self) -> &[DataSegment] {
        &self.data_segments
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"QSTI");
        put_u32(&mut out, 1);
        put_u32(&mut out, self.memory.pages());

        put_len(&mut out, self.types.len());
        for function_type in &self.types {
            put_len(&mut out, function_type.params.len());
            for value_type in &function_type.params {
                out.push(value_type.code());
            }
            put_len(&mut out, function_type.results.len());
            for value_type in &function_type.results {
                out.push(value_type.code());
            }
        }

        put_len(&mut out, self.imports.len());
        for import in &self.imports {
            put_string(&mut out, &import.module);
            put_string(&mut out, &import.name);
            put_u32(&mut out, import.type_index);
        }

        put_len(&mut out, self.globals.len());
        for global in &self.globals {
            out.push(global.value_type.code());
            out.push(u8::from(global.mutable));
            match global.initial {
                ConstValue::I32(value) => {
                    out.push(0);
                    out.extend_from_slice(&value.to_le_bytes());
                }
                ConstValue::I64(value) => {
                    out.push(1);
                    out.extend_from_slice(&value.to_le_bytes());
                }
            }
        }

        put_len(&mut out, self.functions.len());
        for function in &self.functions {
            put_u32(&mut out, function.type_index);
            put_len(&mut out, function.locals.len());
            for local in &function.locals {
                put_u32(&mut out, local.count);
                out.push(local.value_type.code());
            }
            put_len(&mut out, function.instructions.len());
            for instruction in &function.instructions {
                encode_instruction(&mut out, *instruction);
            }
        }

        put_len(&mut out, self.exports.len());
        for export in &self.exports {
            put_string(&mut out, &export.name);
            put_u32(&mut out, export.function_index);
        }

        put_len(&mut out, self.data_segments.len());
        for segment in &self.data_segments {
            put_u32(&mut out, segment.offset);
            put_len(&mut out, segment.bytes.len());
            out.extend_from_slice(&segment.bytes);
        }
        out
    }
}

fn encode_instruction(out: &mut Vec<u8>, instruction: Instruction) {
    out.push(instruction.opcode);
    match instruction.immediate {
        InstructionImmediate::None => out.push(0),
        InstructionImmediate::Index(value) => {
            out.push(1);
            put_u32(out, value);
        }
        InstructionImmediate::I32(value) => {
            out.push(2);
            out.extend_from_slice(&value.to_le_bytes());
        }
        InstructionImmediate::I64(value) => {
            out.push(3);
            out.extend_from_slice(&value.to_le_bytes());
        }
        InstructionImmediate::Block(block_type) => {
            out.push(4);
            out.push(match block_type {
                BlockType::Empty => 0x40,
                BlockType::Value(value_type) => value_type.code(),
            });
        }
        InstructionImmediate::Memory { alignment, offset } => {
            out.push(5);
            put_u32(out, alignment);
            put_u32(out, offset);
        }
    }
}

fn put_string(out: &mut Vec<u8>, value: &str) {
    put_len(out, value.len());
    out.extend_from_slice(value.as_bytes());
}

fn put_len(out: &mut Vec<u8>, value: usize) {
    put_u32(out, u32::try_from(value).unwrap_or(u32::MAX));
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}
