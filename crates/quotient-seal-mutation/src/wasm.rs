use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{MutationOperator, MutationRecipe};

const WASM_HEADER: &[u8; 8] = b"\0asm\x01\0\0\0";
const CODE_SECTION: u8 = 10;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MutationEdit {
    pub section_id: u8,
    pub offset: usize,
    pub before_hex: String,
    pub after_hex: String,
    pub locus: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationArtifact {
    pub operator: MutationOperator,
    pub seed_sha256: String,
    pub mutant_sha256: String,
    pub bytes: Vec<u8>,
    pub edits: Vec<MutationEdit>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawSection {
    id: u8,
    payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawModule {
    sections: Vec<RawSection>,
}

pub fn validate_wasm_container(bytes: &[u8]) -> Result<(), MutationError> {
    RawModule::decode(bytes).map(|_| ())
}

pub fn mutate_wasm(
    seed: &[u8],
    operator: MutationOperator,
) -> Result<MutationArtifact, MutationError> {
    let mut module = RawModule::decode(seed)?;
    let marker = operator.ordinal();
    let primary = match operator.recipe() {
        MutationRecipe::IncrementI32Constant => module.increment_i32_constant(operator, marker)?,
        MutationRecipe::InjectConstDrop => {
            module.inject_code(operator, &[0x41, marker, 0x1a], "const-drop probe")?
        }
        MutationRecipe::FlipCodeOpcode => module.flip_code_opcode(operator, marker)?,
        MutationRecipe::DuplicateCall => module.duplicate_call(operator)?,
        MutationRecipe::DropCall => module.drop_call(operator)?,
        MutationRecipe::IncrementCallIndex => module.increment_call_index(operator, marker)?,
        MutationRecipe::InsertCall => {
            module.inject_code(operator, &[0x10, 0x00], "extra call")?
        }
        MutationRecipe::ReorderCalls => module.reorder_calls(operator)?,
        MutationRecipe::AppendFunctionExport => module.append_export(operator, 0, 0)?,
        MutationRecipe::AppendFunctionImport => module.append_import(operator)?,
        MutationRecipe::InsertUnreachable => {
            module.inject_code(operator, &[0x00], "unreachable")?
        }
        MutationRecipe::InsertDivisionByZero => module.inject_code(
            operator,
            &[0x41, 0x01, 0x41, 0x00, 0x6e, 0x1a],
            "unsigned division by zero",
        )?,
        MutationRecipe::InsertSignedOverflow => module.inject_code(
            operator,
            &[
                0x41, 0x80, 0x80, 0x80, 0x80, 0x78, 0x41, 0x7f, 0x6d, 0x1a,
            ],
            "signed division overflow",
        )?,
        MutationRecipe::AppendMemoryExport => module.append_export(operator, 2, 0)?,
        MutationRecipe::InsertMemoryGrow => module.inject_code(
            operator,
            &[0x41, 0x01, 0x40, 0x00, 0x1a],
            "memory.grow",
        )?,
        MutationRecipe::IncrementMemoryOffset => module.increment_memory_offset(operator, marker)?,
        MutationRecipe::AppendMutableGlobal => module.append_mutable_global(operator, marker)?,
        MutationRecipe::ShiftDataOffset => module.shift_data_offset(operator, marker)?,
        MutationRecipe::InsertPrivateBranch => module.inject_code(
            operator,
            &[0x41, marker, 0x04, 0x40, 0x01, 0x0b],
            "private branch probe",
        )?,
        MutationRecipe::InflateOpcodeCost => {
            let nops = vec![0x01; usize::from(marker % 5 + 2)];
            module.inject_code(operator, &nops, "opcode cost inflation")?
        }
        MutationRecipe::InsertLoopBackedge => module.inject_code(
            operator,
            &[0x03, 0x40, 0x0c, 0x00, 0x0b],
            "loop backedge",
        )?,
        MutationRecipe::AppendBindingSection => module.append_binding(operator)?,
    };
    let witness = module.append_witness(operator);
    let bytes = module.encode()?;
    Ok(MutationArtifact {
        operator,
        seed_sha256: sha256(seed),
        mutant_sha256: sha256(&bytes),
        bytes,
        edits: vec![primary, witness],
    })
}

impl RawModule {
    fn decode(bytes: &[u8]) -> Result<Self, MutationError> {
        if bytes.len() < WASM_HEADER.len() {
            return Err(MutationError::UnexpectedEof);
        }
        if &bytes[..4] != b"\0asm" {
            return Err(MutationError::BadMagic);
        }
        if &bytes[4..8] != b"\x01\0\0\0" {
            return Err(MutationError::UnsupportedVersion);
        }
        let mut position = WASM_HEADER.len();
        let mut sections = Vec::new();
        let mut seen = HashSet::new();
        let mut previous = 0_u8;
        while position < bytes.len() {
            let id = *bytes.get(position).ok_or(MutationError::UnexpectedEof)?;
            position += 1;
            if id > 12 {
                return Err(MutationError::UnknownSection(id));
            }
            let size = usize::try_from(read_u32(bytes, &mut position)?)
                .map_err(|_| MutationError::IntegerOverflow)?;
            let end = position
                .checked_add(size)
                .ok_or(MutationError::IntegerOverflow)?;
            let payload = bytes
                .get(position..end)
                .ok_or(MutationError::UnexpectedEof)?
                .to_vec();
            position = end;
            if id != 0 {
                if !seen.insert(id) {
                    return Err(MutationError::DuplicateSection(id));
                }
                if id <= previous {
                    return Err(MutationError::SectionOrder {
                        previous,
                        current: id,
                    });
                }
                previous = id;
            }
            sections.push(RawSection { id, payload });
        }
        Ok(Self { sections })
    }

    fn encode(&self) -> Result<Vec<u8>, MutationError> {
        let mut bytes = WASM_HEADER.to_vec();
        for section in &self.sections {
            bytes.push(section.id);
            bytes.extend(encode_u32(
                u32::try_from(section.payload.len()).map_err(|_| MutationError::IntegerOverflow)?,
            ));
            bytes.extend_from_slice(&section.payload);
        }
        Ok(bytes)
    }

    fn section_mut(&mut self, id: u8) -> Option<&mut RawSection> {
        self.sections.iter_mut().find(|section| section.id == id)
    }

    fn insert_section(&mut self, section: RawSection) {
        let position = self
            .sections
            .iter()
            .position(|current| current.id != 0 && current.id > section.id)
            .unwrap_or(self.sections.len());
        self.sections.insert(position, section);
    }

    fn edit_first_body<F>(
        &mut self,
        operator: MutationOperator,
        edit: F,
    ) -> Result<MutationEdit, MutationError>
    where
        F: FnOnce(&mut Vec<u8>, usize) -> Result<MutationEdit, MutationError>,
    {
        let section = self
            .section_mut(CODE_SECTION)
            .ok_or_else(|| not_applicable(operator, "code section"))?;
        let mut position = 0;
        let count = read_u32(&section.payload, &mut position)?;
        if count == 0 {
            return Err(not_applicable(operator, "non-empty code section"));
        }
        let size_start = position;
        let body_size = usize::try_from(read_u32(&section.payload, &mut position)?)
            .map_err(|_| MutationError::IntegerOverflow)?;
        let body_start = position;
        let body_end = body_start
            .checked_add(body_size)
            .ok_or(MutationError::IntegerOverflow)?;
        let mut body = section
            .payload
            .get(body_start..body_end)
            .ok_or(MutationError::UnexpectedEof)?
            .to_vec();
        let result = edit(&mut body, body_start)?;
        let mut payload = section.payload[..size_start].to_vec();
        payload.extend(encode_u32(
            u32::try_from(body.len()).map_err(|_| MutationError::IntegerOverflow)?,
        ));
        payload.extend_from_slice(&body);
        payload.extend_from_slice(
            section
                .payload
                .get(body_end..)
                .ok_or(MutationError::UnexpectedEof)?,
        );
        section.payload = payload;
        Ok(result)
    }

    fn inject_code(
        &mut self,
        operator: MutationOperator,
        instruction: &[u8],
        locus: &str,
    ) -> Result<MutationEdit, MutationError> {
        self.edit_first_body(operator, |body, base| {
            if body.last() != Some(&0x0b) {
                return Err(not_applicable(operator, "terminated function body"));
            }
            let offset = body.len() - 1;
            body.splice(offset..offset, instruction.iter().copied());
            Ok(edit_record(
                CODE_SECTION,
                base + offset,
                &[],
                instruction,
                locus,
            ))
        })
    }

    fn increment_i32_constant(
        &mut self,
        operator: MutationOperator,
        marker: u8,
    ) -> Result<MutationEdit, MutationError> {
        self.edit_first_body(operator, |body, base| {
            let start = instruction_start(body)?;
            for index in start..body.len().saturating_sub(1) {
                if body[index] == 0x41 && body[index + 1] & 0x80 == 0 {
                    let before = body[index + 1];
                    let after = before.wrapping_add(marker).min(0x3f);
                    body[index + 1] = if after == before { before ^ 1 } else { after };
                    return Ok(edit_record(
                        CODE_SECTION,
                        base + index + 1,
                        &[before],
                        &[body[index + 1]],
                        "i32.const immediate",
                    ));
                }
            }
            Err(not_applicable(operator, "single-byte i32.const"))
        })
    }

    fn flip_code_opcode(
        &mut self,
        operator: MutationOperator,
        marker: u8,
    ) -> Result<MutationEdit, MutationError> {
        self.edit_first_body(operator, |body, base| {
            let index = instruction_start(body)?;
            let before = *body
                .get(index)
                .ok_or_else(|| not_applicable(operator, "function instruction"))?;
            let after = before ^ (marker | 1);
            body[index] = after;
            Ok(edit_record(
                CODE_SECTION,
                base + index,
                &[before],
                &[after],
                "first opcode",
            ))
        })
    }

    fn duplicate_call(
        &mut self,
        operator: MutationOperator,
    ) -> Result<MutationEdit, MutationError> {
        self.edit_first_body(operator, |body, base| {
            let calls = call_spans(body)?;
            let (start, end) = calls
                .first()
                .copied()
                .ok_or_else(|| not_applicable(operator, "call instruction"))?;
            let call = body[start..end].to_vec();
            body.splice(end..end, call.iter().copied());
            Ok(edit_record(
                CODE_SECTION,
                base + end,
                &[],
                &call,
                "duplicate call",
            ))
        })
    }

    fn drop_call(&mut self, operator: MutationOperator) -> Result<MutationEdit, MutationError> {
        self.edit_first_body(operator, |body, base| {
            let calls = call_spans(body)?;
            let (start, end) = calls
                .first()
                .copied()
                .ok_or_else(|| not_applicable(operator, "call instruction"))?;
            let before = body[start..end].to_vec();
            body.drain(start..end);
            Ok(edit_record(
                CODE_SECTION,
                base + start,
                &before,
                &[],
                "drop call",
            ))
        })
    }

    fn increment_call_index(
        &mut self,
        operator: MutationOperator,
        marker: u8,
    ) -> Result<MutationEdit, MutationError> {
        self.edit_first_body(operator, |body, base| {
            let calls = call_spans(body)?;
            let (start, end) = calls
                .first()
                .copied()
                .ok_or_else(|| not_applicable(operator, "call instruction"))?;
            let mut position = start + 1;
            let value = read_u32(body, &mut position)?;
            let before = body[start + 1..end].to_vec();
            let after = encode_u32(value.wrapping_add(u32::from(marker)));
            body.splice(start + 1..end, after.iter().copied());
            Ok(edit_record(
                CODE_SECTION,
                base + start + 1,
                &before,
                &after,
                "call function index",
            ))
        })
    }

    fn reorder_calls(&mut self, operator: MutationOperator) -> Result<MutationEdit, MutationError> {
        self.edit_first_body(operator, |body, base| {
            let calls = call_spans(body)?;
            if calls.len() < 2 {
                return Err(not_applicable(operator, "two call instructions"));
            }
            let (first_start, first_end) = calls[0];
            let (second_start, second_end) = calls[1];
            let before = body[first_start..second_end].to_vec();
            let first = body[first_start..first_end].to_vec();
            let middle = body[first_end..second_start].to_vec();
            let second = body[second_start..second_end].to_vec();
            let mut after = second;
            after.extend(middle);
            after.extend(first);
            body.splice(first_start..second_end, after.iter().copied());
            Ok(edit_record(
                CODE_SECTION,
                base + first_start,
                &before,
                &after,
                "reorder calls",
            ))
        })
    }

    fn append_import(
        &mut self,
        operator: MutationOperator,
    ) -> Result<MutationEdit, MutationError> {
        if self.sections.iter().all(|section| section.id != 1) {
            return Err(not_applicable(operator, "type section with type index zero"));
        }
        let mut entry = encode_name("env");
        entry.extend(encode_name(operator.id()));
        entry.extend([0x00, 0x00]);
        self.append_vector_entry(operator, 2, entry, "function import")
    }

    fn append_export(
        &mut self,
        operator: MutationOperator,
        kind: u8,
        index: u32,
    ) -> Result<MutationEdit, MutationError> {
        let mut entry = encode_name(operator.id());
        entry.push(kind);
        entry.extend(encode_u32(index));
        self.append_vector_entry(operator, 7, entry, "export")
    }

    fn append_mutable_global(
        &mut self,
        operator: MutationOperator,
        marker: u8,
    ) -> Result<MutationEdit, MutationError> {
        let entry = vec![0x7f, 0x01, 0x41, marker, 0x0b];
        self.append_vector_entry(operator, 6, entry, "mutable i32 global")
    }

    fn append_vector_entry(
        &mut self,
        operator: MutationOperator,
        section_id: u8,
        entry: Vec<u8>,
        locus: &str,
    ) -> Result<MutationEdit, MutationError> {
        if let Some(section) = self.section_mut(section_id) {
            let mut position = 0;
            let count = read_u32(&section.payload, &mut position)?;
            let offset = section.payload.len();
            let mut payload = encode_u32(count.checked_add(1).ok_or(MutationError::IntegerOverflow)?);
            payload.extend_from_slice(&section.payload[position..]);
            payload.extend_from_slice(&entry);
            section.payload = payload;
            return Ok(edit_record(section_id, offset, &[], &entry, locus));
        }
        let mut payload = encode_u32(1);
        payload.extend_from_slice(&entry);
        self.insert_section(RawSection {
            id: section_id,
            payload,
        });
        Ok(edit_record(section_id, 0, &[], &entry, locus))
    }

    fn increment_memory_offset(
        &mut self,
        operator: MutationOperator,
        marker: u8,
    ) -> Result<MutationEdit, MutationError> {
        self.edit_first_body(operator, |body, base| {
            let start = instruction_start(body)?;
            for opcode_at in start..body.len() {
                if (0x28..=0x3e).contains(&body[opcode_at]) {
                    let mut position = opcode_at + 1;
                    let _alignment = read_u32(body, &mut position)?;
                    let offset_start = position;
                    let offset = read_u32(body, &mut position)?;
                    let before = body[offset_start..position].to_vec();
                    let after = encode_u32(offset.wrapping_add(u32::from(marker)));
                    body.splice(offset_start..position, after.iter().copied());
                    return Ok(edit_record(
                        CODE_SECTION,
                        base + offset_start,
                        &before,
                        &after,
                        "memory address offset",
                    ));
                }
            }
            Err(not_applicable(operator, "load or store instruction"))
        })
    }

    fn shift_data_offset(
        &mut self,
        operator: MutationOperator,
        marker: u8,
    ) -> Result<MutationEdit, MutationError> {
        let section = self
            .section_mut(11)
            .ok_or_else(|| not_applicable(operator, "active data segment"))?;
        let mut position = 0;
        if read_u32(&section.payload, &mut position)? == 0
            || read_u32(&section.payload, &mut position)? != 0
            || section.payload.get(position) != Some(&0x41)
        {
            return Err(not_applicable(operator, "active i32 data offset"));
        }
        position += 1;
        let before_start = position;
        let value = read_u32(&section.payload, &mut position)?;
        let before = section.payload[before_start..position].to_vec();
        let after = encode_u32(value.wrapping_add(u32::from(marker)));
        section
            .payload
            .splice(before_start..position, after.iter().copied());
        Ok(edit_record(
            11,
            before_start,
            &before,
            &after,
            "active data offset",
        ))
    }

    fn append_binding(
        &mut self,
        operator: MutationOperator,
    ) -> Result<MutationEdit, MutationError> {
        let name = format!("quotient.seal.binding/{}", operator.id());
        let payload = custom_payload(&name, &[operator.ordinal()]);
        self.sections.push(RawSection {
            id: 0,
            payload: payload.clone(),
        });
        Ok(edit_record(0, 0, &[], &payload, "binding custom section"))
    }

    fn append_witness(&mut self, operator: MutationOperator) -> MutationEdit {
        let mut evidence = operator.id().as_bytes().to_vec();
        evidence.push(0);
        evidence.push(operator.ordinal());
        let payload = custom_payload("quotient.seal.mutation", &evidence);
        self.sections.push(RawSection {
            id: 0,
            payload: payload.clone(),
        });
        edit_record(0, 0, &[], &payload, "mutation witness")
    }
}

fn instruction_start(body: &[u8]) -> Result<usize, MutationError> {
    let mut position = 0;
    let groups = read_u32(body, &mut position)?;
    for _ in 0..groups {
        let _count = read_u32(body, &mut position)?;
        position = position
            .checked_add(1)
            .ok_or(MutationError::IntegerOverflow)?;
        if position > body.len() {
            return Err(MutationError::UnexpectedEof);
        }
    }
    Ok(position)
}

fn call_spans(body: &[u8]) -> Result<Vec<(usize, usize)>, MutationError> {
    let start = instruction_start(body)?;
    let mut calls = Vec::new();
    let mut position = start;
    while position + 1 < body.len() {
        if body[position] == 0x10 {
            let call_start = position;
            position += 1;
            let _index = read_u32(body, &mut position)?;
            calls.push((call_start, position));
        } else {
            position += 1;
        }
    }
    Ok(calls)
}

fn encode_name(name: &str) -> Vec<u8> {
    let mut encoded = encode_u32(u32::try_from(name.len()).unwrap_or(u32::MAX));
    encoded.extend_from_slice(name.as_bytes());
    encoded
}

fn custom_payload(name: &str, evidence: &[u8]) -> Vec<u8> {
    let mut payload = encode_name(name);
    payload.extend_from_slice(evidence);
    payload
}

fn read_u32(bytes: &[u8], position: &mut usize) -> Result<u32, MutationError> {
    let start = *position;
    let mut value = 0_u64;
    for shift in (0..35).step_by(7) {
        let byte = *bytes.get(*position).ok_or(MutationError::UnexpectedEof)?;
        *position += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            let value = u32::try_from(value).map_err(|_| MutationError::IntegerOverflow)?;
            if encode_u32(value).len() != *position - start {
                return Err(MutationError::NonCanonicalLeb128);
            }
            return Ok(value);
        }
    }
    Err(MutationError::IntegerOverflow)
}

fn encode_u32(mut value: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        bytes.push(byte);
        if value == 0 {
            return bytes;
        }
    }
}

fn edit_record(
    section_id: u8,
    offset: usize,
    before: &[u8],
    after: &[u8],
    locus: &str,
) -> MutationEdit {
    MutationEdit {
        section_id,
        offset,
        before_hex: hex(before),
        after_hex: hex(after),
        locus: locus.to_owned(),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn not_applicable(operator: MutationOperator, requirement: &str) -> MutationError {
    MutationError::NotApplicable {
        operator,
        requirement: requirement.to_owned(),
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MutationError {
    #[error("unexpected end of WASM input")]
    UnexpectedEof,
    #[error("bad WASM magic")]
    BadMagic,
    #[error("unsupported WASM version")]
    UnsupportedVersion,
    #[error("non-canonical LEB128")]
    NonCanonicalLeb128,
    #[error("integer overflow")]
    IntegerOverflow,
    #[error("unknown core section {0}")]
    UnknownSection(u8),
    #[error("duplicate core section {0}")]
    DuplicateSection(u8),
    #[error("section order moved backward from {previous} to {current}")]
    SectionOrder { previous: u8, current: u8 },
    #[error("operator {operator:?} is not applicable: missing {requirement}")]
    NotApplicable {
        operator: MutationOperator,
        requirement: String,
    },
}

