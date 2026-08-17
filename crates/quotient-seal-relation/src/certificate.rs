use quotient_forge_caqt::Digest;
use quotient_seal_small_step::Value;

pub const RELATION_FORMAT_VERSION: u16 = 1;
const MAGIC: [u8; 4] = *b"QSRL";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GlobalPredicate {
    pub index: u32,
    pub value: Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryPredicate {
    pub offset: u32,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryRange {
    pub offset: u32,
    pub length: u32,
}

impl MemoryRange {
    #[must_use]
    pub fn contains(self, address: u64, width: u8) -> bool {
        let start = u64::from(self.offset);
        let Some(end) = start.checked_add(u64::from(self.length)) else {
            return false;
        };
        let Some(access_end) = address.checked_add(u64::from(width)) else {
            return false;
        };
        address >= start && access_end <= end
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationRecord {
    pub source_state: u32,
    pub entry_pcs: Vec<u32>,
    pub exit_pcs: Vec<u32>,
    pub globals: Vec<GlobalPredicate>,
    pub memory: Vec<MemoryPredicate>,
    pub allowed_writes: Vec<MemoryRange>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationCertificate {
    pub version: u16,
    pub inductive_digest: Digest,
    pub target_ir_digest: Digest,
    pub k7_manifest_digest: Digest,
    pub quotient_inputs: u16,
    pub public_inputs: u16,
    pub fault_inputs: u16,
    pub action_deadline_steps: u32,
    pub records: Vec<RelationRecord>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelationLimits {
    pub max_bytes: usize,
    pub max_records: usize,
    pub max_pcs_per_record: usize,
    pub max_globals_per_record: usize,
    pub max_memory_predicates_per_record: usize,
    pub max_write_ranges_per_record: usize,
    pub max_predicate_bytes: usize,
}

impl Default for RelationLimits {
    fn default() -> Self {
        Self {
            max_bytes: 8 * 1024 * 1024,
            max_records: 1_000_000,
            max_pcs_per_record: 4_096,
            max_globals_per_record: 4_096,
            max_memory_predicates_per_record: 4_096,
            max_write_ranges_per_record: 4_096,
            max_predicate_bytes: 4 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelationDecodeError {
    SizeLimit {
        actual: usize,
        limit: usize,
    },
    RecordLimit {
        actual: usize,
        limit: usize,
    },
    PcLimit {
        actual: usize,
        limit: usize,
    },
    GlobalLimit {
        actual: usize,
        limit: usize,
    },
    MemoryPredicateLimit {
        actual: usize,
        limit: usize,
    },
    WriteRangeLimit {
        actual: usize,
        limit: usize,
    },
    PredicateBytesLimit {
        actual: usize,
        limit: usize,
    },
    BadMagic,
    UnsupportedVersion {
        actual: u16,
    },
    UnexpectedEof {
        offset: usize,
    },
    InvalidValueTag {
        offset: usize,
        tag: u8,
    },
    TrailingData {
        offset: usize,
        remaining: usize,
    },
    EmptyAxis,
    NonZeroDeadline,
    RecordOrder {
        index: usize,
    },
    EmptyPcSet {
        record: usize,
        entry: bool,
    },
    PcOrder {
        record: usize,
        entry: bool,
        index: usize,
    },
    GlobalOrder {
        record: usize,
        index: usize,
    },
    EmptyMemoryPredicate {
        record: usize,
        index: usize,
    },
    MemoryOrder {
        record: usize,
        index: usize,
    },
    EmptyWriteRange {
        record: usize,
        index: usize,
    },
    WriteRangeOrder {
        record: usize,
        index: usize,
    },
    ArithmeticOverflow,
}

impl RelationCertificate {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::default();
        writer.bytes(&MAGIC);
        writer.u16(self.version);
        writer.bytes(self.inductive_digest.as_bytes());
        writer.bytes(self.target_ir_digest.as_bytes());
        writer.bytes(self.k7_manifest_digest.as_bytes());
        writer.u16(self.quotient_inputs);
        writer.u16(self.public_inputs);
        writer.u16(self.fault_inputs);
        writer.u32(self.action_deadline_steps);
        writer.length(self.records.len());
        for record in &self.records {
            writer.u32(record.source_state);
            writer.length(record.entry_pcs.len());
            writer.length(record.exit_pcs.len());
            writer.length(record.globals.len());
            writer.length(record.memory.len());
            writer.length(record.allowed_writes.len());
            for pc in &record.entry_pcs {
                writer.u32(*pc);
            }
            for pc in &record.exit_pcs {
                writer.u32(*pc);
            }
            for predicate in &record.globals {
                writer.u32(predicate.index);
                match predicate.value {
                    Value::I32(value) => {
                        writer.u8(0);
                        writer.u32(value);
                    }
                    Value::I64(value) => {
                        writer.u8(1);
                        writer.u64(value);
                    }
                }
            }
            for predicate in &record.memory {
                writer.u32(predicate.offset);
                writer.length(predicate.bytes.len());
                writer.bytes(&predicate.bytes);
            }
            for range in &record.allowed_writes {
                writer.u32(range.offset);
                writer.u32(range.length);
            }
        }
        writer.finish()
    }

    pub fn decode(bytes: &[u8], limits: RelationLimits) -> Result<Self, RelationDecodeError> {
        if bytes.len() > limits.max_bytes {
            return Err(RelationDecodeError::SizeLimit {
                actual: bytes.len(),
                limit: limits.max_bytes,
            });
        }
        let mut reader = Reader::new(bytes);
        if reader.array::<4>()? != MAGIC {
            return Err(RelationDecodeError::BadMagic);
        }
        let version = reader.u16()?;
        if version != RELATION_FORMAT_VERSION {
            return Err(RelationDecodeError::UnsupportedVersion { actual: version });
        }
        let inductive_digest = Digest::new(reader.array::<32>()?);
        let target_ir_digest = Digest::new(reader.array::<32>()?);
        let k7_manifest_digest = Digest::new(reader.array::<32>()?);
        let quotient_inputs = reader.u16()?;
        let public_inputs = reader.u16()?;
        let fault_inputs = reader.u16()?;
        let action_deadline_steps = reader.u32()?;
        let record_count = reader.length(limits.max_records, |actual, limit| {
            RelationDecodeError::RecordLimit { actual, limit }
        })?;
        let mut records = Vec::with_capacity(record_count);
        let mut predicate_bytes = 0_usize;
        for _ in 0..record_count {
            let source_state = reader.u32()?;
            let entry_count = reader.length(limits.max_pcs_per_record, |actual, limit| {
                RelationDecodeError::PcLimit { actual, limit }
            })?;
            let exit_count = reader.length(limits.max_pcs_per_record, |actual, limit| {
                RelationDecodeError::PcLimit { actual, limit }
            })?;
            let global_count = reader.length(limits.max_globals_per_record, |actual, limit| {
                RelationDecodeError::GlobalLimit { actual, limit }
            })?;
            let memory_count = reader
                .length(limits.max_memory_predicates_per_record, |actual, limit| {
                    RelationDecodeError::MemoryPredicateLimit { actual, limit }
                })?;
            let write_count = reader
                .length(limits.max_write_ranges_per_record, |actual, limit| {
                    RelationDecodeError::WriteRangeLimit { actual, limit }
                })?;

            let mut entry_pcs = Vec::with_capacity(entry_count);
            for _ in 0..entry_count {
                entry_pcs.push(reader.u32()?);
            }
            let mut exit_pcs = Vec::with_capacity(exit_count);
            for _ in 0..exit_count {
                exit_pcs.push(reader.u32()?);
            }
            let mut globals = Vec::with_capacity(global_count);
            for _ in 0..global_count {
                let index = reader.u32()?;
                let tag_offset = reader.position;
                let tag = reader.u8()?;
                let value = match tag {
                    0 => Value::I32(reader.u32()?),
                    1 => Value::I64(reader.u64()?),
                    _ => {
                        return Err(RelationDecodeError::InvalidValueTag {
                            offset: tag_offset,
                            tag,
                        });
                    }
                };
                globals.push(GlobalPredicate { index, value });
            }
            let mut memory = Vec::with_capacity(memory_count);
            for _ in 0..memory_count {
                let offset = reader.u32()?;
                let len = reader.u32()? as usize;
                predicate_bytes = predicate_bytes
                    .checked_add(len)
                    .ok_or(RelationDecodeError::ArithmeticOverflow)?;
                if predicate_bytes > limits.max_predicate_bytes {
                    return Err(RelationDecodeError::PredicateBytesLimit {
                        actual: predicate_bytes,
                        limit: limits.max_predicate_bytes,
                    });
                }
                memory.push(MemoryPredicate {
                    offset,
                    bytes: reader.bytes(len)?.to_vec(),
                });
            }
            let mut allowed_writes = Vec::with_capacity(write_count);
            for _ in 0..write_count {
                allowed_writes.push(MemoryRange {
                    offset: reader.u32()?,
                    length: reader.u32()?,
                });
            }
            records.push(RelationRecord {
                source_state,
                entry_pcs,
                exit_pcs,
                globals,
                memory,
                allowed_writes,
            });
        }
        if !reader.is_empty() {
            return Err(RelationDecodeError::TrailingData {
                offset: reader.position,
                remaining: reader.remaining(),
            });
        }
        let certificate = Self {
            version,
            inductive_digest,
            target_ir_digest,
            k7_manifest_digest,
            quotient_inputs,
            public_inputs,
            fault_inputs,
            action_deadline_steps,
            records,
        };
        certificate.validate_canonical()?;
        Ok(certificate)
    }

    #[must_use]
    pub fn record(&self, source_state: u32) -> Option<&RelationRecord> {
        self.records
            .binary_search_by_key(&source_state, |record| record.source_state)
            .ok()
            .and_then(|index| self.records.get(index))
    }

    fn validate_canonical(&self) -> Result<(), RelationDecodeError> {
        if self.quotient_inputs == 0 || self.public_inputs == 0 || self.fault_inputs == 0 {
            return Err(RelationDecodeError::EmptyAxis);
        }
        if self.action_deadline_steps != 0 {
            return Err(RelationDecodeError::NonZeroDeadline);
        }
        for (record_index, record) in self.records.iter().enumerate() {
            if record_index > 0
                && self.records[record_index - 1].source_state >= record.source_state
            {
                return Err(RelationDecodeError::RecordOrder {
                    index: record_index,
                });
            }
            validate_pc_set(&record.entry_pcs, record_index, true)?;
            validate_pc_set(&record.exit_pcs, record_index, false)?;
            for index in 1..record.globals.len() {
                if record.globals[index - 1].index >= record.globals[index].index {
                    return Err(RelationDecodeError::GlobalOrder {
                        record: record_index,
                        index,
                    });
                }
            }
            validate_memory(&record.memory, record_index)?;
            validate_ranges(&record.allowed_writes, record_index)?;
        }
        Ok(())
    }
}

fn validate_pc_set(pcs: &[u32], record: usize, entry: bool) -> Result<(), RelationDecodeError> {
    if pcs.is_empty() {
        return Err(RelationDecodeError::EmptyPcSet { record, entry });
    }
    for index in 1..pcs.len() {
        if pcs[index - 1] >= pcs[index] {
            return Err(RelationDecodeError::PcOrder {
                record,
                entry,
                index,
            });
        }
    }
    Ok(())
}

fn validate_memory(
    predicates: &[MemoryPredicate],
    record: usize,
) -> Result<(), RelationDecodeError> {
    let mut previous_end = 0_u64;
    for (index, predicate) in predicates.iter().enumerate() {
        if predicate.bytes.is_empty() {
            return Err(RelationDecodeError::EmptyMemoryPredicate { record, index });
        }
        let start = u64::from(predicate.offset);
        let end = start
            .checked_add(predicate.bytes.len() as u64)
            .ok_or(RelationDecodeError::ArithmeticOverflow)?;
        if index > 0 && start < previous_end {
            return Err(RelationDecodeError::MemoryOrder { record, index });
        }
        previous_end = end;
    }
    Ok(())
}

fn validate_ranges(ranges: &[MemoryRange], record: usize) -> Result<(), RelationDecodeError> {
    let mut previous_end = 0_u64;
    for (index, range) in ranges.iter().enumerate() {
        if range.length == 0 {
            return Err(RelationDecodeError::EmptyWriteRange { record, index });
        }
        let start = u64::from(range.offset);
        let end = start
            .checked_add(u64::from(range.length))
            .ok_or(RelationDecodeError::ArithmeticOverflow)?;
        if index > 0 && start < previous_end {
            return Err(RelationDecodeError::WriteRangeOrder { record, index });
        }
        previous_end = end;
    }
    Ok(())
}

#[derive(Default)]
struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn length(&mut self, value: usize) {
        self.u32(u32::try_from(value).unwrap_or(u32::MAX));
    }

    fn bytes(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
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

    fn u8(&mut self) -> Result<u8, RelationDecodeError> {
        let value =
            self.bytes
                .get(self.position)
                .copied()
                .ok_or(RelationDecodeError::UnexpectedEof {
                    offset: self.position,
                })?;
        self.position += 1;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, RelationDecodeError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, RelationDecodeError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, RelationDecodeError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], RelationDecodeError> {
        let end = self
            .position
            .checked_add(N)
            .ok_or(RelationDecodeError::ArithmeticOverflow)?;
        let source =
            self.bytes
                .get(self.position..end)
                .ok_or(RelationDecodeError::UnexpectedEof {
                    offset: self.position,
                })?;
        let mut value = [0_u8; N];
        value.copy_from_slice(source);
        self.position = end;
        Ok(value)
    }

    fn bytes(&mut self, len: usize) -> Result<&'a [u8], RelationDecodeError> {
        let end = self
            .position
            .checked_add(len)
            .ok_or(RelationDecodeError::ArithmeticOverflow)?;
        let value =
            self.bytes
                .get(self.position..end)
                .ok_or(RelationDecodeError::UnexpectedEof {
                    offset: self.position,
                })?;
        self.position = end;
        Ok(value)
    }

    fn length(
        &mut self,
        limit: usize,
        error: impl FnOnce(usize, usize) -> RelationDecodeError,
    ) -> Result<usize, RelationDecodeError> {
        let value = self.u32()? as usize;
        if value > limit {
            Err(error(value, limit))
        } else {
            Ok(value)
        }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }

    fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }
}
