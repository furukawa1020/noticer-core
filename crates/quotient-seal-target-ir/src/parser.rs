use alloc::{string::String, vec::Vec};
use core::str;
use quotient_forge_caqt::Digest;

use crate::canonical::{
    BlockType, CanonicalTargetIr, ConstValue, DataSegment, FixedMemory, Function, FunctionExport,
    FunctionImport, FunctionType, Global, Instruction, InstructionImmediate, LocalDecl, ValueType,
};
use crate::target_ir_hash;

const ALLOWED_IMPORTS: &[&str] = &["emit_action", "emit_frame", "public_failure"];
const ALLOWED_EXPORTS: &[&str] = &["handoff", "reset", "status", "tick"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParserLimits {
    pub max_module_bytes: usize,
    pub max_sections: u32,
    pub max_types: u32,
    pub max_imports: u32,
    pub max_functions: u32,
    pub max_globals: u32,
    pub max_exports: u32,
    pub max_name_bytes: u32,
    pub max_memory_pages: u32,
    pub max_local_groups: u32,
    pub max_locals_per_function: u32,
    pub max_function_body_bytes: u32,
    pub max_instructions_per_function: u32,
    pub max_control_depth: u32,
    pub max_data_segments: u32,
    pub max_data_bytes: u32,
}

impl ParserLimits {
    #[must_use]
    pub const fn frozen_v1() -> Self {
        Self {
            max_module_bytes: 1_048_576,
            max_sections: 32,
            max_types: 256,
            max_imports: 16,
            max_functions: 512,
            max_globals: 128,
            max_exports: 32,
            max_name_bytes: 128,
            max_memory_pages: 16,
            max_local_groups: 64,
            max_locals_per_function: 1_024,
            max_function_body_bytes: 65_536,
            max_instructions_per_function: 16_384,
            max_control_depth: 128,
            max_data_segments: 256,
            max_data_bytes: 262_144,
        }
    }
}

impl Default for ParserLimits {
    fn default() -> Self {
        Self::frozen_v1()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceKind {
    ModuleBytes,
    Sections,
    Types,
    Imports,
    Functions,
    Globals,
    Exports,
    NameBytes,
    MemoryPages,
    LocalGroups,
    Locals,
    FunctionBodyBytes,
    Instructions,
    ControlDepth,
    DataSegments,
    DataBytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceBound {
    pub resource: ResourceKind,
    pub limit: u64,
    pub observed: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidReason {
    BadMagic,
    UnsupportedVersion,
    UnexpectedEof,
    NonCanonicalLeb128,
    IntegerOverflow,
    UnknownSection(u8),
    DuplicateSection(u8),
    SectionOrder { previous: u8, current: u8 },
    TrailingSectionBytes(u8),
    TrailingFunctionBytes,
    InvalidUtf8,
    DuplicateName,
    InvalidTypeForm,
    InvalidMutability,
    InvalidLimits,
    InvalidMemoryAlignment,
    InvalidConstExpression,
    InvalidElse,
    InvalidBranchDepth,
    InvalidIndex,
    FunctionCodeCountMismatch,
    MissingFunctionEnd,
    OverlappingDataSegments,
    DataOutsideMemory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnsupportedFeature {
    Float,
    Simd,
    Threads,
    Atomics,
    BulkMemory,
    MemoryGrow,
    MemorySize,
    CallIndirect,
    Table,
    StartFunction,
    ElementSegment,
    DataCount,
    Wasi,
    ImportedMemory,
    ExportedMemory,
    NonFunctionImport,
    NonFunctionExport,
    HostImport,
    PublicExport,
    SharedMemory,
    Memory64,
    NonFixedMemory,
    MultipleMemories,
    MissingFixedMemory,
    PassiveData,
    ReferenceType,
    MultiValue,
    BlockSignature,
    Instruction(u8),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetIrError {
    Invalid(InvalidReason),
    Incompatible(UnsupportedFeature),
    ResourceBound(ResourceBound),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalParserDecision {
    Accepted(Digest),
    Rejected,
    ResourceBound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalParserDecision {
    Accepted,
    Rejected,
    ResourceBound,
    NotRun,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsensusVerdict {
    Valid(Digest),
    Invalid,
    ResourceBound,
    Unresolved,
}

#[must_use]
pub fn local_parser_decision(
    result: &Result<CanonicalTargetIr, TargetIrError>,
) -> LocalParserDecision {
    match result {
        Ok(ir) => LocalParserDecision::Accepted(target_ir_hash(ir)),
        Err(TargetIrError::ResourceBound(_)) => LocalParserDecision::ResourceBound,
        Err(TargetIrError::Invalid(_) | TargetIrError::Incompatible(_)) => {
            LocalParserDecision::Rejected
        }
    }
}

#[must_use]
pub const fn reconcile_parser_decisions(
    local: LocalParserDecision,
    wasmparser: ExternalParserDecision,
    wasm_tools: ExternalParserDecision,
) -> ConsensusVerdict {
    match (local, wasmparser, wasm_tools) {
        (
            LocalParserDecision::Accepted(hash),
            ExternalParserDecision::Accepted,
            ExternalParserDecision::Accepted,
        ) => ConsensusVerdict::Valid(hash),
        (
            LocalParserDecision::Rejected,
            ExternalParserDecision::Rejected,
            ExternalParserDecision::Rejected,
        ) => ConsensusVerdict::Invalid,
        (
            LocalParserDecision::ResourceBound,
            ExternalParserDecision::ResourceBound,
            ExternalParserDecision::ResourceBound,
        ) => ConsensusVerdict::ResourceBound,
        _ => ConsensusVerdict::Unresolved,
    }
}

pub fn parse_and_lower(
    bytes: &[u8],
    limits: ParserLimits,
) -> Result<CanonicalTargetIr, TargetIrError> {
    if bytes.len() > limits.max_module_bytes {
        return Err(resource(
            ResourceKind::ModuleBytes,
            limits.max_module_bytes,
            bytes.len(),
        ));
    }
    if bytes.len() < 8 {
        return Err(invalid(InvalidReason::UnexpectedEof));
    }
    if &bytes[..4] != b"\0asm" {
        return Err(invalid(InvalidReason::BadMagic));
    }
    if &bytes[4..8] != b"\x01\0\0\0" {
        return Err(invalid(InvalidReason::UnsupportedVersion));
    }

    let mut reader = Reader::new(&bytes[8..]);
    let mut seen = [false; 13];
    let mut last_section = 0_u8;
    let mut section_count = 0_u32;
    let mut custom_names = Vec::<String>::new();
    let mut types = Vec::new();
    let mut imports = Vec::new();
    let mut function_types = Vec::new();
    let mut memory = None;
    let mut globals = Vec::new();
    let mut exports = Vec::new();
    let mut functions = Vec::new();
    let mut data_segments = Vec::new();

    while !reader.is_empty() {
        section_count = section_count
            .checked_add(1)
            .ok_or_else(|| invalid(InvalidReason::IntegerOverflow))?;
        ensure_u32(ResourceKind::Sections, section_count, limits.max_sections)?;

        let section_id = reader.read_u8()?;
        if section_id > 12 {
            return Err(invalid(InvalidReason::UnknownSection(section_id)));
        }
        let section_len = reader.read_u32()? as usize;
        let section_bytes = reader.read_bytes(section_len)?;
        let mut section = Reader::new(section_bytes);

        if section_id == 0 {
            let name = section.read_name(limits.max_name_bytes)?;
            if custom_names.iter().any(|existing| existing == &name) {
                return Err(invalid(InvalidReason::DuplicateName));
            }
            custom_names.push(name);
            section.consume_remaining();
            continue;
        }

        if seen[usize::from(section_id)] {
            return Err(invalid(InvalidReason::DuplicateSection(section_id)));
        }
        if section_id <= last_section {
            return Err(invalid(InvalidReason::SectionOrder {
                previous: last_section,
                current: section_id,
            }));
        }
        seen[usize::from(section_id)] = true;
        last_section = section_id;

        match section_id {
            1 => types = parse_types(&mut section, &limits)?,
            2 => imports = parse_imports(&mut section, &types, &limits)?,
            3 => function_types = parse_function_section(&mut section, &types, &limits)?,
            4 => return Err(incompatible(UnsupportedFeature::Table)),
            5 => memory = Some(parse_memory(&mut section, &limits)?),
            6 => globals = parse_globals(&mut section, &limits)?,
            7 => {
                exports =
                    parse_exports(&mut section, imports.len(), function_types.len(), &limits)?;
            }
            8 => return Err(incompatible(UnsupportedFeature::StartFunction)),
            9 => return Err(incompatible(UnsupportedFeature::ElementSegment)),
            10 => {
                functions = parse_code(
                    &mut section,
                    &types,
                    &function_types,
                    imports.len(),
                    &globals,
                    memory,
                    &limits,
                )?;
            }
            11 => {
                let fixed =
                    memory.ok_or_else(|| incompatible(UnsupportedFeature::MissingFixedMemory))?;
                data_segments = parse_data(&mut section, fixed, &limits)?;
            }
            12 => return Err(incompatible(UnsupportedFeature::DataCount)),
            _ => return Err(invalid(InvalidReason::UnknownSection(section_id))),
        }

        if !section.is_empty() {
            return Err(invalid(InvalidReason::TrailingSectionBytes(section_id)));
        }
    }

    if functions.len() != function_types.len() {
        return Err(invalid(InvalidReason::FunctionCodeCountMismatch));
    }
    let fixed_memory =
        memory.ok_or_else(|| incompatible(UnsupportedFeature::MissingFixedMemory))?;
    exports.sort();
    data_segments.sort();
    reject_overlapping_data(&data_segments)?;

    Ok(CanonicalTargetIr::new(
        types,
        imports,
        fixed_memory,
        globals,
        functions,
        exports,
        data_segments,
    ))
}

fn parse_types(
    reader: &mut Reader<'_>,
    limits: &ParserLimits,
) -> Result<Vec<FunctionType>, TargetIrError> {
    let count = reader.read_u32()?;
    ensure_u32(ResourceKind::Types, count, limits.max_types)?;
    let mut types = Vec::with_capacity(count as usize);
    for _ in 0..count {
        if reader.read_u8()? != 0x60 {
            return Err(invalid(InvalidReason::InvalidTypeForm));
        }
        let param_count = reader.read_u32()?;
        ensure_u32(
            ResourceKind::Locals,
            param_count,
            limits.max_locals_per_function,
        )?;
        let mut params = Vec::with_capacity(param_count as usize);
        for _ in 0..param_count {
            params.push(read_value_type(reader)?);
        }
        let result_count = reader.read_u32()?;
        if result_count > 1 {
            return Err(incompatible(UnsupportedFeature::MultiValue));
        }
        let mut results = Vec::with_capacity(result_count as usize);
        for _ in 0..result_count {
            results.push(read_value_type(reader)?);
        }
        types.push(FunctionType::new(params, results));
    }
    Ok(types)
}

fn parse_imports(
    reader: &mut Reader<'_>,
    types: &[FunctionType],
    limits: &ParserLimits,
) -> Result<Vec<FunctionImport>, TargetIrError> {
    let count = reader.read_u32()?;
    ensure_u32(ResourceKind::Imports, count, limits.max_imports)?;
    let mut imports = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let module = reader.read_name(limits.max_name_bytes)?;
        let name = reader.read_name(limits.max_name_bytes)?;
        if module.starts_with("wasi") {
            return Err(incompatible(UnsupportedFeature::Wasi));
        }
        let kind = reader.read_u8()?;
        if kind != 0 {
            return Err(incompatible(if kind == 2 {
                UnsupportedFeature::ImportedMemory
            } else {
                UnsupportedFeature::NonFunctionImport
            }));
        }
        if module != "qseal" || !ALLOWED_IMPORTS.contains(&name.as_str()) {
            return Err(incompatible(UnsupportedFeature::HostImport));
        }
        if imports
            .iter()
            .any(|existing: &FunctionImport| existing.name() == name)
        {
            return Err(invalid(InvalidReason::DuplicateName));
        }
        let type_index = reader.read_u32()?;
        if usize::try_from(type_index)
            .ok()
            .and_then(|index| types.get(index))
            .is_none()
        {
            return Err(invalid(InvalidReason::InvalidIndex));
        }
        imports.push(FunctionImport::new(module, name, type_index));
    }
    Ok(imports)
}

fn parse_function_section(
    reader: &mut Reader<'_>,
    types: &[FunctionType],
    limits: &ParserLimits,
) -> Result<Vec<u32>, TargetIrError> {
    let count = reader.read_u32()?;
    ensure_u32(ResourceKind::Functions, count, limits.max_functions)?;
    let mut function_types = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let type_index = reader.read_u32()?;
        if usize::try_from(type_index)
            .ok()
            .and_then(|index| types.get(index))
            .is_none()
        {
            return Err(invalid(InvalidReason::InvalidIndex));
        }
        function_types.push(type_index);
    }
    Ok(function_types)
}

fn parse_memory(
    reader: &mut Reader<'_>,
    limits: &ParserLimits,
) -> Result<FixedMemory, TargetIrError> {
    let count = reader.read_u32()?;
    if count != 1 {
        return Err(incompatible(if count > 1 {
            UnsupportedFeature::MultipleMemories
        } else {
            UnsupportedFeature::MissingFixedMemory
        }));
    }
    let flags = reader.read_u32()?;
    if flags & 0x04 != 0 {
        return Err(incompatible(UnsupportedFeature::Memory64));
    }
    if flags & 0x02 != 0 {
        return Err(incompatible(UnsupportedFeature::SharedMemory));
    }
    if flags != 0x01 {
        return Err(incompatible(UnsupportedFeature::NonFixedMemory));
    }
    let minimum = reader.read_u32()?;
    let maximum = reader.read_u32()?;
    if minimum != maximum {
        return Err(incompatible(UnsupportedFeature::NonFixedMemory));
    }
    if minimum == 0 {
        return Err(invalid(InvalidReason::InvalidLimits));
    }
    ensure_u32(ResourceKind::MemoryPages, minimum, limits.max_memory_pages)?;
    Ok(FixedMemory::new(minimum))
}

fn parse_globals(
    reader: &mut Reader<'_>,
    limits: &ParserLimits,
) -> Result<Vec<Global>, TargetIrError> {
    let count = reader.read_u32()?;
    ensure_u32(ResourceKind::Globals, count, limits.max_globals)?;
    let mut globals = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let value_type = read_value_type(reader)?;
        let mutable = match reader.read_u8()? {
            0 => false,
            1 => true,
            _ => return Err(invalid(InvalidReason::InvalidMutability)),
        };
        let initial = match (value_type, reader.read_u8()?) {
            (ValueType::I32, 0x41) => ConstValue::I32(reader.read_i32()?),
            (ValueType::I64, 0x42) => ConstValue::I64(reader.read_i64()?),
            (_, 0x43 | 0x44) => return Err(incompatible(UnsupportedFeature::Float)),
            _ => return Err(invalid(InvalidReason::InvalidConstExpression)),
        };
        if reader.read_u8()? != 0x0b {
            return Err(invalid(InvalidReason::InvalidConstExpression));
        }
        globals.push(Global::new(value_type, mutable, initial));
    }
    Ok(globals)
}

fn parse_exports(
    reader: &mut Reader<'_>,
    imported_functions: usize,
    defined_functions: usize,
    limits: &ParserLimits,
) -> Result<Vec<FunctionExport>, TargetIrError> {
    let count = reader.read_u32()?;
    ensure_u32(ResourceKind::Exports, count, limits.max_exports)?;
    let total_functions = imported_functions
        .checked_add(defined_functions)
        .ok_or_else(|| invalid(InvalidReason::IntegerOverflow))?;
    let mut exports = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let name = reader.read_name(limits.max_name_bytes)?;
        let kind = reader.read_u8()?;
        if kind != 0 {
            return Err(incompatible(if kind == 2 {
                UnsupportedFeature::ExportedMemory
            } else {
                UnsupportedFeature::NonFunctionExport
            }));
        }
        if !ALLOWED_EXPORTS.contains(&name.as_str()) {
            return Err(incompatible(UnsupportedFeature::PublicExport));
        }
        if exports
            .iter()
            .any(|existing: &FunctionExport| existing.name() == name)
        {
            return Err(invalid(InvalidReason::DuplicateName));
        }
        let function_index = reader.read_u32()?;
        if usize::try_from(function_index).map_or(true, |index| index >= total_functions) {
            return Err(invalid(InvalidReason::InvalidIndex));
        }
        exports.push(FunctionExport::new(name, function_index));
    }
    Ok(exports)
}

#[allow(clippy::too_many_arguments)]
fn parse_code(
    reader: &mut Reader<'_>,
    types: &[FunctionType],
    function_types: &[u32],
    imported_functions: usize,
    globals: &[Global],
    memory: Option<FixedMemory>,
    limits: &ParserLimits,
) -> Result<Vec<Function>, TargetIrError> {
    let count = reader.read_u32()?;
    if usize::try_from(count).ok() != Some(function_types.len()) {
        return Err(invalid(InvalidReason::FunctionCodeCountMismatch));
    }
    let total_functions = imported_functions
        .checked_add(function_types.len())
        .ok_or_else(|| invalid(InvalidReason::IntegerOverflow))?;
    let mut functions = Vec::with_capacity(count as usize);

    for type_index in function_types {
        let body_len = reader.read_u32()?;
        ensure_u32(
            ResourceKind::FunctionBodyBytes,
            body_len,
            limits.max_function_body_bytes,
        )?;
        let mut body = Reader::new(reader.read_bytes(body_len as usize)?);
        let local_group_count = body.read_u32()?;
        ensure_u32(
            ResourceKind::LocalGroups,
            local_group_count,
            limits.max_local_groups,
        )?;
        let mut locals = Vec::with_capacity(local_group_count as usize);
        let mut local_count = 0_u32;
        for _ in 0..local_group_count {
            let count = body.read_u32()?;
            local_count = local_count
                .checked_add(count)
                .ok_or_else(|| invalid(InvalidReason::IntegerOverflow))?;
            ensure_u32(
                ResourceKind::Locals,
                local_count,
                limits.max_locals_per_function,
            )?;
            locals.push(LocalDecl::new(count, read_value_type(&mut body)?));
        }
        let function_type = types
            .get(*type_index as usize)
            .ok_or_else(|| invalid(InvalidReason::InvalidIndex))?;
        let parameter_count = u32::try_from(function_type.params().len())
            .map_err(|_| invalid(InvalidReason::IntegerOverflow))?;
        let total_locals = parameter_count
            .checked_add(local_count)
            .ok_or_else(|| invalid(InvalidReason::IntegerOverflow))?;
        let instructions = parse_instructions(
            &mut body,
            total_locals,
            total_functions,
            globals,
            memory,
            limits,
        )?;
        if !body.is_empty() {
            return Err(invalid(InvalidReason::TrailingFunctionBytes));
        }
        functions.push(Function::new(*type_index, locals, instructions));
    }
    Ok(functions)
}

#[derive(Clone, Copy)]
enum ControlFrame {
    Function,
    Block,
    Loop,
    If { saw_else: bool },
}

fn parse_instructions(
    reader: &mut Reader<'_>,
    total_locals: u32,
    total_functions: usize,
    globals: &[Global],
    memory: Option<FixedMemory>,
    limits: &ParserLimits,
) -> Result<Vec<Instruction>, TargetIrError> {
    let mut instructions = Vec::new();
    let mut control = Vec::new();
    control.push(ControlFrame::Function);

    loop {
        if reader.is_empty() {
            return Err(invalid(InvalidReason::MissingFunctionEnd));
        }
        let opcode = reader.read_u8()?;
        let immediate = match opcode {
            0x00
            | 0x01
            | 0x0f
            | 0x1a
            | 0x1b
            | 0x45..=0x5a
            | 0x67..=0x8a
            | 0xa7
            | 0xac
            | 0xad
            | 0xc0..=0xc4 => InstructionImmediate::None,
            0x02..=0x04 => {
                let block_type = read_block_type(reader)?;
                control.push(match opcode {
                    0x02 => ControlFrame::Block,
                    0x03 => ControlFrame::Loop,
                    _ => ControlFrame::If { saw_else: false },
                });
                ensure_usize(
                    ResourceKind::ControlDepth,
                    control.len(),
                    limits.max_control_depth as usize,
                )?;
                InstructionImmediate::Block(block_type)
            }
            0x05 => {
                let Some(ControlFrame::If { saw_else }) = control.last_mut() else {
                    return Err(invalid(InvalidReason::InvalidElse));
                };
                if *saw_else {
                    return Err(invalid(InvalidReason::InvalidElse));
                }
                *saw_else = true;
                InstructionImmediate::None
            }
            0x0b => {
                control.pop();
                InstructionImmediate::None
            }
            0x0c | 0x0d => {
                let depth = reader.read_u32()?;
                if usize::try_from(depth).map_or(true, |value| value >= control.len()) {
                    return Err(invalid(InvalidReason::InvalidBranchDepth));
                }
                InstructionImmediate::Index(depth)
            }
            0x10 => {
                let index = reader.read_u32()?;
                if usize::try_from(index).map_or(true, |value| value >= total_functions) {
                    return Err(invalid(InvalidReason::InvalidIndex));
                }
                InstructionImmediate::Index(index)
            }
            0x11 => return Err(incompatible(UnsupportedFeature::CallIndirect)),
            0x20..=0x22 => {
                let index = reader.read_u32()?;
                if index >= total_locals {
                    return Err(invalid(InvalidReason::InvalidIndex));
                }
                InstructionImmediate::Index(index)
            }
            0x23 | 0x24 => {
                let index = reader.read_u32()?;
                let global = usize::try_from(index)
                    .ok()
                    .and_then(|value| globals.get(value))
                    .ok_or_else(|| invalid(InvalidReason::InvalidIndex))?;
                if opcode == 0x24 && !global.is_mutable() {
                    return Err(invalid(InvalidReason::InvalidIndex));
                }
                InstructionImmediate::Index(index)
            }
            0x25 | 0x26 => return Err(incompatible(UnsupportedFeature::Table)),
            0x28..=0x3e => {
                if matches!(opcode, 0x2a | 0x2b | 0x38 | 0x39) {
                    return Err(incompatible(UnsupportedFeature::Float));
                }
                let fixed =
                    memory.ok_or_else(|| incompatible(UnsupportedFeature::MissingFixedMemory))?;
                let (max_alignment, width) = memory_shape(opcode)
                    .ok_or_else(|| incompatible(UnsupportedFeature::Instruction(opcode)))?;
                let alignment = reader.read_u32()?;
                let offset = reader.read_u32()?;
                if alignment > max_alignment {
                    return Err(invalid(InvalidReason::InvalidMemoryAlignment));
                }
                if u64::from(offset)
                    .checked_add(u64::from(width))
                    .is_none_or(|end| end > fixed.bytes())
                {
                    return Err(invalid(InvalidReason::DataOutsideMemory));
                }
                InstructionImmediate::Memory { alignment, offset }
            }
            0x3f => return Err(incompatible(UnsupportedFeature::MemorySize)),
            0x40 => return Err(incompatible(UnsupportedFeature::MemoryGrow)),
            0x41 => InstructionImmediate::I32(reader.read_i32()?),
            0x42 => InstructionImmediate::I64(reader.read_i64()?),
            0x43..=0x44 | 0x5b..=0x66 | 0x8b..=0xa6 | 0xa8..=0xab | 0xae..=0xbf => {
                return Err(incompatible(UnsupportedFeature::Float));
            }
            0xfc => return Err(incompatible(UnsupportedFeature::BulkMemory)),
            0xfd => return Err(incompatible(UnsupportedFeature::Simd)),
            0xfe => return Err(incompatible(UnsupportedFeature::Threads)),
            0xd0..=0xd2 => return Err(incompatible(UnsupportedFeature::ReferenceType)),
            _ => return Err(incompatible(UnsupportedFeature::Instruction(opcode))),
        };

        instructions.push(Instruction::new(opcode, immediate));
        ensure_usize(
            ResourceKind::Instructions,
            instructions.len(),
            limits.max_instructions_per_function as usize,
        )?;
        if control.is_empty() {
            break;
        }
    }
    Ok(instructions)
}

fn memory_shape(opcode: u8) -> Option<(u32, u32)> {
    match opcode {
        0x28 | 0x36 => Some((2, 4)),
        0x29 | 0x37 => Some((3, 8)),
        0x2c | 0x2d | 0x30 | 0x31 | 0x3a | 0x3c => Some((0, 1)),
        0x2e | 0x2f | 0x32 | 0x33 | 0x3b | 0x3d => Some((1, 2)),
        0x34 | 0x35 | 0x3e => Some((2, 4)),
        _ => None,
    }
}

fn parse_data(
    reader: &mut Reader<'_>,
    memory: FixedMemory,
    limits: &ParserLimits,
) -> Result<Vec<DataSegment>, TargetIrError> {
    let count = reader.read_u32()?;
    ensure_u32(ResourceKind::DataSegments, count, limits.max_data_segments)?;
    let mut total_bytes = 0_u32;
    let mut segments = Vec::with_capacity(count as usize);
    for _ in 0..count {
        if reader.read_u32()? != 0 {
            return Err(incompatible(UnsupportedFeature::PassiveData));
        }
        if reader.read_u8()? != 0x41 {
            return Err(invalid(InvalidReason::InvalidConstExpression));
        }
        let signed_offset = reader.read_i32()?;
        if signed_offset < 0 || reader.read_u8()? != 0x0b {
            return Err(invalid(InvalidReason::InvalidConstExpression));
        }
        let offset = signed_offset as u32;
        let len = reader.read_u32()?;
        total_bytes = total_bytes
            .checked_add(len)
            .ok_or_else(|| invalid(InvalidReason::IntegerOverflow))?;
        ensure_u32(ResourceKind::DataBytes, total_bytes, limits.max_data_bytes)?;
        let data = reader.read_bytes(len as usize)?.to_vec();
        if u64::from(offset)
            .checked_add(u64::from(len))
            .is_none_or(|end| end > memory.bytes())
        {
            return Err(invalid(InvalidReason::DataOutsideMemory));
        }
        segments.push(DataSegment::new(offset, data));
    }
    Ok(segments)
}

fn reject_overlapping_data(segments: &[DataSegment]) -> Result<(), TargetIrError> {
    for pair in segments.windows(2) {
        let left_end = u64::from(pair[0].offset())
            + u64::try_from(pair[0].bytes().len())
                .map_err(|_| invalid(InvalidReason::IntegerOverflow))?;
        if left_end > u64::from(pair[1].offset()) {
            return Err(invalid(InvalidReason::OverlappingDataSegments));
        }
    }
    Ok(())
}

fn read_value_type(reader: &mut Reader<'_>) -> Result<ValueType, TargetIrError> {
    match reader.read_u8()? {
        0x7f => Ok(ValueType::I32),
        0x7e => Ok(ValueType::I64),
        0x7d | 0x7c => Err(incompatible(UnsupportedFeature::Float)),
        0x7b => Err(incompatible(UnsupportedFeature::Simd)),
        0x70 | 0x6f => Err(incompatible(UnsupportedFeature::ReferenceType)),
        _ => Err(invalid(InvalidReason::InvalidTypeForm)),
    }
}

fn read_block_type(reader: &mut Reader<'_>) -> Result<BlockType, TargetIrError> {
    match reader.read_u8()? {
        0x40 => Ok(BlockType::Empty),
        0x7f => Ok(BlockType::Value(ValueType::I32)),
        0x7e => Ok(BlockType::Value(ValueType::I64)),
        0x7d | 0x7c => Err(incompatible(UnsupportedFeature::Float)),
        _ => Err(incompatible(UnsupportedFeature::BlockSignature)),
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn consume_remaining(&mut self) {
        self.position = self.bytes.len();
    }

    fn read_u8(&mut self) -> Result<u8, TargetIrError> {
        let byte = self
            .bytes
            .get(self.position)
            .copied()
            .ok_or_else(|| invalid(InvalidReason::UnexpectedEof))?;
        self.position += 1;
        Ok(byte)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], TargetIrError> {
        let end = self
            .position
            .checked_add(len)
            .ok_or_else(|| invalid(InvalidReason::IntegerOverflow))?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| invalid(InvalidReason::UnexpectedEof))?;
        self.position = end;
        Ok(bytes)
    }

    fn read_name(&mut self, max_name_bytes: u32) -> Result<String, TargetIrError> {
        let len = self.read_u32()?;
        ensure_u32(ResourceKind::NameBytes, len, max_name_bytes)?;
        let bytes = self.read_bytes(len as usize)?;
        let value = str::from_utf8(bytes).map_err(|_| invalid(InvalidReason::InvalidUtf8))?;
        Ok(String::from(value))
    }

    fn read_u32(&mut self) -> Result<u32, TargetIrError> {
        let start = self.position;
        let mut value = 0_u64;
        for shift in (0..35).step_by(7) {
            let byte = self.read_u8()?;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                let value =
                    u32::try_from(value).map_err(|_| invalid(InvalidReason::IntegerOverflow))?;
                if self.position - start != unsigned_leb_len(value) {
                    return Err(invalid(InvalidReason::NonCanonicalLeb128));
                }
                return Ok(value);
            }
        }
        Err(invalid(InvalidReason::IntegerOverflow))
    }

    fn read_i32(&mut self) -> Result<i32, TargetIrError> {
        let value = self.read_signed(32, 5)?;
        i32::try_from(value).map_err(|_| invalid(InvalidReason::IntegerOverflow))
    }

    fn read_i64(&mut self) -> Result<i64, TargetIrError> {
        self.read_signed(64, 10)
    }

    fn read_signed(&mut self, bits: u32, max_bytes: usize) -> Result<i64, TargetIrError> {
        let start = self.position;
        let mut value = 0_i128;
        let mut shift = 0_u32;
        let terminal = loop {
            if self.position - start >= max_bytes {
                return Err(invalid(InvalidReason::IntegerOverflow));
            }
            let byte = self.read_u8()?;
            value |= i128::from(byte & 0x7f) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                break byte;
            }
        };
        if terminal & 0x40 != 0 {
            value |= (!0_i128) << shift;
        }
        let minimum = -(1_i128 << (bits - 1));
        let maximum = (1_i128 << (bits - 1)) - 1;
        if value < minimum || value > maximum {
            return Err(invalid(InvalidReason::IntegerOverflow));
        }
        let value = value as i64;
        if self.position - start != signed_leb_len(value) {
            return Err(invalid(InvalidReason::NonCanonicalLeb128));
        }
        Ok(value)
    }
}

fn unsigned_leb_len(mut value: u32) -> usize {
    let mut len = 1;
    while value >= 0x80 {
        value >>= 7;
        len += 1;
    }
    len
}

fn signed_leb_len(mut value: i64) -> usize {
    let mut len = 0;
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        len += 1;
        let done = (value == 0 && byte & 0x40 == 0) || (value == -1 && byte & 0x40 != 0);
        if done {
            return len;
        }
    }
}

fn ensure_u32(resource_kind: ResourceKind, observed: u32, limit: u32) -> Result<(), TargetIrError> {
    if observed > limit {
        Err(TargetIrError::ResourceBound(ResourceBound {
            resource: resource_kind,
            limit: u64::from(limit),
            observed: u64::from(observed),
        }))
    } else {
        Ok(())
    }
}

fn ensure_usize(
    resource_kind: ResourceKind,
    observed: usize,
    limit: usize,
) -> Result<(), TargetIrError> {
    if observed > limit {
        Err(resource(resource_kind, limit, observed))
    } else {
        Ok(())
    }
}

fn resource(resource_kind: ResourceKind, limit: usize, observed: usize) -> TargetIrError {
    TargetIrError::ResourceBound(ResourceBound {
        resource: resource_kind,
        limit: u64::try_from(limit).unwrap_or(u64::MAX),
        observed: u64::try_from(observed).unwrap_or(u64::MAX),
    })
}

const fn invalid(reason: InvalidReason) -> TargetIrError {
    TargetIrError::Invalid(reason)
}

const fn incompatible(feature: UnsupportedFeature) -> TargetIrError {
    TargetIrError::Incompatible(feature)
}
