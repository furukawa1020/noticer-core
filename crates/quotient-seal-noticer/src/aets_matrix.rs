use std::collections::BTreeSet;

use quotient_seal_abi::quotient_seal_abi_v1_hash;
use quotient_seal_context::{CommandKind, ContextCommand, ContextFamily};
use quotient_seal_engine::ExecutionLimits;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{AetsCompiledQsm, AetsPublicSequence};

pub const AETS_ADVERSARIAL_MATRIX_VERSION: &str = "noticer-aets-adversarial-matrix/v1";
const FORMAT_VERSION: u16 = 1;
const MAGIC: &[u8; 8] = b"AETSMTX1";
const CASE_ID_DOMAIN: &[u8] = b"noticer-aets-adversarial-case-id/v1";
const MATRIX_DIGEST_DOMAIN: &[u8] = b"noticer-aets-adversarial-matrix-digest/v1";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AetsMatrixSeed([u8; 32]);

impl AetsMatrixSeed {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AetsCaseId([u8; 32]);

impl AetsCaseId {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn to_hex(self) -> String {
        hex(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AetsMatrixDigest([u8; 32]);

impl AetsMatrixDigest {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn to_hex(self) -> String {
        hex(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum AetsScenarioAxis {
    Normal = 0,
    PublicFaultTimeout = 1,
    PublicFaultReconnect = 2,
    PublicFaultLoss = 3,
    Reset = 4,
    Handoff = 5,
    DeadlineBefore = 6,
    DeadlineAt = 7,
    DeadlineAfter = 8,
    UnknownService = 9,
}

impl AetsScenarioAxis {
    fn from_code(code: u8) -> Result<Self, AetsMatrixError> {
        match code {
            0 => Ok(Self::Normal),
            1 => Ok(Self::PublicFaultTimeout),
            2 => Ok(Self::PublicFaultReconnect),
            3 => Ok(Self::PublicFaultLoss),
            4 => Ok(Self::Reset),
            5 => Ok(Self::Handoff),
            6 => Ok(Self::DeadlineBefore),
            7 => Ok(Self::DeadlineAt),
            8 => Ok(Self::DeadlineAfter),
            9 => Ok(Self::UnknownService),
            _ => Err(AetsMatrixError::UnknownAxis {
                axis: "scenario",
                code,
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum AetsHostAxis {
    Continue = 0,
    Terminate = 1,
    Timeout = 2,
    Reconnect = 3,
    Loss = 4,
}

impl AetsHostAxis {
    fn from_code(code: u8) -> Result<Self, AetsMatrixError> {
        match code {
            0 => Ok(Self::Continue),
            1 => Ok(Self::Terminate),
            2 => Ok(Self::Timeout),
            3 => Ok(Self::Reconnect),
            4 => Ok(Self::Loss),
            _ => Err(AetsMatrixError::UnknownAxis { axis: "host", code }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum AetsResourceAxis {
    Nominal = 0,
    FuelBoundary = 1,
    MemoryBoundary = 2,
    HostCallBoundary = 3,
}

impl AetsResourceAxis {
    fn from_code(code: u8) -> Result<Self, AetsMatrixError> {
        match code {
            0 => Ok(Self::Nominal),
            1 => Ok(Self::FuelBoundary),
            2 => Ok(Self::MemoryBoundary),
            3 => Ok(Self::HostCallBoundary),
            _ => Err(AetsMatrixError::UnknownAxis {
                axis: "resource",
                code,
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AetsMatrixLimits {
    pub max_artifact_bytes: usize,
    pub max_cases: usize,
    pub max_commands_per_case: usize,
}

impl AetsMatrixLimits {
    #[must_use]
    pub const fn frozen_v1() -> Self {
        Self {
            max_artifact_bytes: 16 * 1024 * 1024,
            max_cases: 4_096,
            max_commands_per_case: 256,
        }
    }

    fn validate(self) -> Result<(), AetsMatrixError> {
        if self.max_artifact_bytes == 0 || self.max_cases == 0 || self.max_commands_per_case == 0 {
            Err(AetsMatrixError::InvalidDecodeLimits)
        } else {
            Ok(())
        }
    }
}

impl Default for AetsMatrixLimits {
    fn default() -> Self {
        Self::frozen_v1()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AetsAdversarialCaseSpec {
    scenario: AetsScenarioAxis,
    host: AetsHostAxis,
    resource: AetsResourceAxis,
    commands: Vec<ContextCommand>,
    limits: ExecutionLimits,
}

impl AetsAdversarialCaseSpec {
    #[must_use]
    pub fn new(
        scenario: AetsScenarioAxis,
        host: AetsHostAxis,
        resource: AetsResourceAxis,
        commands: Vec<ContextCommand>,
        limits: ExecutionLimits,
    ) -> Self {
        Self {
            scenario,
            host,
            resource,
            commands,
            limits,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AetsAdversarialCase {
    scenario: AetsScenarioAxis,
    host: AetsHostAxis,
    resource: AetsResourceAxis,
    commands: Box<[ContextCommand]>,
    limits: ExecutionLimits,
    sequence_digest: [u8; 32],
    case_id: AetsCaseId,
}

impl AetsAdversarialCase {
    #[must_use]
    pub const fn scenario(&self) -> AetsScenarioAxis {
        self.scenario
    }

    #[must_use]
    pub const fn host(&self) -> AetsHostAxis {
        self.host
    }

    #[must_use]
    pub const fn resource(&self) -> AetsResourceAxis {
        self.resource
    }

    #[must_use]
    pub fn commands(&self) -> &[ContextCommand] {
        &self.commands
    }

    #[must_use]
    pub const fn limits(&self) -> ExecutionLimits {
        self.limits
    }

    #[must_use]
    pub const fn sequence_digest(&self) -> &[u8; 32] {
        &self.sequence_digest
    }

    #[must_use]
    pub const fn case_id(&self) -> AetsCaseId {
        self.case_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AetsAdversarialMatrix {
    seed: AetsMatrixSeed,
    source_digest: [u8; 32],
    module_digest: [u8; 32],
    capsule_digest: [u8; 32],
    abi_digest: [u8; 32],
    cases: Box<[AetsAdversarialCase]>,
    matrix_digest: AetsMatrixDigest,
}

impl AetsAdversarialMatrix {
    pub fn new(
        compiled: &AetsCompiledQsm,
        seed: AetsMatrixSeed,
        specs: Vec<AetsAdversarialCaseSpec>,
        limits: AetsMatrixLimits,
    ) -> Result<Self, AetsMatrixError> {
        limits.validate()?;
        if specs.is_empty() || specs.len() > limits.max_cases {
            return Err(AetsMatrixError::CaseCount);
        }
        let source_digest = *compiled.source_digest().as_bytes();
        let module_digest = *compiled.module_digest().as_bytes();
        let capsule_digest = *compiled.capsule_digest().as_bytes();
        let abi_digest = *quotient_seal_abi_v1_hash().as_bytes();
        let mut cases = Vec::with_capacity(specs.len());
        for (index, spec) in specs.into_iter().enumerate() {
            validate_commands(&spec.commands, spec.limits, limits.max_commands_per_case)?;
            let sequence = AetsPublicSequence::new(
                compiled,
                spec.commands.clone(),
                spec.limits,
                limits.max_commands_per_case,
            )
            .map_err(|error| AetsMatrixError::PublicSequence {
                case_index: index,
                detail: error.to_string(),
            })?;
            let mut case = AetsAdversarialCase {
                scenario: spec.scenario,
                host: spec.host,
                resource: spec.resource,
                commands: spec.commands.into_boxed_slice(),
                limits: spec.limits,
                sequence_digest: *sequence.digest().as_bytes(),
                case_id: AetsCaseId([0; 32]),
            };
            case.case_id = compute_case_id(
                seed,
                &source_digest,
                &module_digest,
                &capsule_digest,
                &abi_digest,
                &case,
            )?;
            cases.push(case);
        }
        cases.sort_by_key(AetsAdversarialCase::case_id);
        validate_case_set(&cases)?;
        let mut matrix = Self {
            seed,
            source_digest,
            module_digest,
            capsule_digest,
            abi_digest,
            cases: cases.into_boxed_slice(),
            matrix_digest: AetsMatrixDigest([0; 32]),
        };
        matrix.matrix_digest = matrix.compute_matrix_digest()?;
        if matrix.canonical_bytes()?.len() > limits.max_artifact_bytes {
            return Err(AetsMatrixError::ArtifactSize);
        }
        Ok(matrix)
    }

    pub fn from_bytes(bytes: &[u8], limits: AetsMatrixLimits) -> Result<Self, AetsMatrixError> {
        limits.validate()?;
        if bytes.len() > limits.max_artifact_bytes {
            return Err(AetsMatrixError::ArtifactSize);
        }
        let mut reader = Reader::new(bytes);
        if reader.read_array::<8>()? != *MAGIC {
            return Err(AetsMatrixError::Magic);
        }
        let version = reader.read_u16()?;
        if version != FORMAT_VERSION {
            return Err(AetsMatrixError::Version(version));
        }
        let seed = AetsMatrixSeed(reader.read_array()?);
        let source_digest = reader.read_array()?;
        let module_digest = reader.read_array()?;
        let capsule_digest = reader.read_array()?;
        let abi_digest = reader.read_array()?;
        let case_count = reader.read_u32()? as usize;
        if case_count == 0 || case_count > limits.max_cases {
            return Err(AetsMatrixError::CaseCount);
        }
        let mut cases = Vec::with_capacity(case_count);
        for _ in 0..case_count {
            let scenario = AetsScenarioAxis::from_code(reader.read_u8()?)?;
            let host = AetsHostAxis::from_code(reader.read_u8()?)?;
            let resource = AetsResourceAxis::from_code(reader.read_u8()?)?;
            let execution_limits = ExecutionLimits {
                fuel: reader.read_u64()?,
                max_memory_pages: reader.read_u32()?,
                max_host_calls: reader.read_u64()?,
                timeout_ms: reader.read_u64()?,
            };
            let sequence_digest = reader.read_array()?;
            let command_count = reader.read_u32()? as usize;
            if command_count == 0 || command_count > limits.max_commands_per_case {
                return Err(AetsMatrixError::CommandCount);
            }
            let mut commands = Vec::with_capacity(command_count);
            for _ in 0..command_count {
                commands.push(read_command(&mut reader)?);
            }
            validate_commands(&commands, execution_limits, limits.max_commands_per_case)?;
            let case_id = AetsCaseId(reader.read_array()?);
            let case = AetsAdversarialCase {
                scenario,
                host,
                resource,
                commands: commands.into_boxed_slice(),
                limits: execution_limits,
                sequence_digest,
                case_id,
            };
            let expected = compute_case_id(
                seed,
                &source_digest,
                &module_digest,
                &capsule_digest,
                &abi_digest,
                &case,
            )?;
            if expected != case.case_id {
                return Err(AetsMatrixError::CaseIdMismatch);
            }
            cases.push(case);
        }
        validate_case_set(&cases)?;
        let matrix_digest = AetsMatrixDigest(reader.read_array()?);
        reader.finish()?;
        let matrix = Self {
            seed,
            source_digest,
            module_digest,
            capsule_digest,
            abi_digest,
            cases: cases.into_boxed_slice(),
            matrix_digest,
        };
        if matrix.compute_matrix_digest()? != matrix.matrix_digest {
            return Err(AetsMatrixError::MatrixDigestMismatch);
        }
        Ok(matrix)
    }

    pub fn validate_against(
        &self,
        compiled: &AetsCompiledQsm,
        limits: AetsMatrixLimits,
    ) -> Result<(), AetsMatrixError> {
        limits.validate()?;
        if self.source_digest != *compiled.source_digest().as_bytes()
            || self.module_digest != *compiled.module_digest().as_bytes()
            || self.capsule_digest != *compiled.capsule_digest().as_bytes()
            || self.abi_digest != *quotient_seal_abi_v1_hash().as_bytes()
        {
            return Err(AetsMatrixError::CompiledBindingMismatch);
        }
        let canonical = self.canonical_bytes()?;
        if canonical.len() > limits.max_artifact_bytes
            || Self::from_bytes(&canonical, limits)? != *self
        {
            return Err(AetsMatrixError::ArtifactContract);
        }
        for (index, case) in self.cases.iter().enumerate() {
            let sequence = AetsPublicSequence::new(
                compiled,
                case.commands.to_vec(),
                case.limits,
                limits.max_commands_per_case,
            )
            .map_err(|error| AetsMatrixError::PublicSequence {
                case_index: index,
                detail: error.to_string(),
            })?;
            if sequence.digest().as_bytes() != &case.sequence_digest {
                return Err(AetsMatrixError::SequenceDigestMismatch { case_index: index });
            }
        }
        Ok(())
    }

    #[must_use]
    pub const fn seed(&self) -> AetsMatrixSeed {
        self.seed
    }

    #[must_use]
    pub fn cases(&self) -> &[AetsAdversarialCase] {
        &self.cases
    }

    #[must_use]
    pub const fn matrix_digest(&self) -> AetsMatrixDigest {
        self.matrix_digest
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AetsMatrixError> {
        let mut bytes = self.encode_without_matrix_digest()?;
        bytes.extend_from_slice(self.matrix_digest.as_bytes());
        Ok(bytes)
    }

    fn compute_matrix_digest(&self) -> Result<AetsMatrixDigest, AetsMatrixError> {
        Ok(AetsMatrixDigest(domain_hash(
            MATRIX_DIGEST_DOMAIN,
            &self.encode_without_matrix_digest()?,
        )))
    }

    fn encode_without_matrix_digest(&self) -> Result<Vec<u8>, AetsMatrixError> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes.extend_from_slice(self.seed.as_bytes());
        bytes.extend_from_slice(&self.source_digest);
        bytes.extend_from_slice(&self.module_digest);
        bytes.extend_from_slice(&self.capsule_digest);
        bytes.extend_from_slice(&self.abi_digest);
        put_len(&mut bytes, self.cases.len())?;
        for case in &self.cases {
            put_case(&mut bytes, case)?;
            bytes.extend_from_slice(case.case_id.as_bytes());
        }
        Ok(bytes)
    }
}

fn compute_case_id(
    seed: AetsMatrixSeed,
    source_digest: &[u8; 32],
    module_digest: &[u8; 32],
    capsule_digest: &[u8; 32],
    abi_digest: &[u8; 32],
    case: &AetsAdversarialCase,
) -> Result<AetsCaseId, AetsMatrixError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(seed.as_bytes());
    bytes.extend_from_slice(source_digest);
    bytes.extend_from_slice(module_digest);
    bytes.extend_from_slice(capsule_digest);
    bytes.extend_from_slice(abi_digest);
    put_case(&mut bytes, case)?;
    Ok(AetsCaseId(domain_hash(CASE_ID_DOMAIN, &bytes)))
}

fn put_case(bytes: &mut Vec<u8>, case: &AetsAdversarialCase) -> Result<(), AetsMatrixError> {
    bytes.push(case.scenario as u8);
    bytes.push(case.host as u8);
    bytes.push(case.resource as u8);
    bytes.extend_from_slice(&case.limits.fuel.to_le_bytes());
    bytes.extend_from_slice(&case.limits.max_memory_pages.to_le_bytes());
    bytes.extend_from_slice(&case.limits.max_host_calls.to_le_bytes());
    bytes.extend_from_slice(&case.limits.timeout_ms.to_le_bytes());
    bytes.extend_from_slice(&case.sequence_digest);
    put_len(bytes, case.commands.len())?;
    for command in &case.commands {
        bytes.push(command.family as u8);
        bytes.push(command.kind as u8);
        bytes.extend_from_slice(&command.service_alias.to_le_bytes());
        bytes.extend_from_slice(&command.public_slot.to_le_bytes());
        bytes.push(command.fault);
        bytes.extend_from_slice(&command.payload_tag.to_le_bytes());
    }
    Ok(())
}

fn validate_case_set(cases: &[AetsAdversarialCase]) -> Result<(), AetsMatrixError> {
    let mut tuples = BTreeSet::new();
    let mut previous = None;
    for case in cases {
        if let Some(previous) = previous {
            if case.case_id == previous {
                return Err(AetsMatrixError::DuplicateCaseId);
            }
            if case.case_id < previous {
                return Err(AetsMatrixError::NonCanonicalOrder);
            }
        }
        previous = Some(case.case_id);
        if !tuples.insert((case.scenario, case.host, case.resource)) {
            return Err(AetsMatrixError::DuplicateAxisTuple);
        }
    }
    Ok(())
}

fn validate_commands(
    commands: &[ContextCommand],
    limits: ExecutionLimits,
    max_commands: usize,
) -> Result<(), AetsMatrixError> {
    if commands.is_empty() || commands.len() > max_commands {
        return Err(AetsMatrixError::CommandCount);
    }
    if limits.fuel == 0
        || limits.max_memory_pages == 0
        || limits.max_host_calls == 0
        || limits.timeout_ms == 0
    {
        return Err(AetsMatrixError::ExecutionLimits);
    }
    let mut stopped = false;
    for command in commands {
        if stopped || command.kind != command.family.command_kind() || command.payload_tag != 0 {
            return Err(AetsMatrixError::CommandContract);
        }
        match command.family {
            ContextFamily::Tick | ContextFamily::Retry | ContextFamily::Deadline => {
                if command.fault != 0 || command.service_alias == 0 {
                    return Err(AetsMatrixError::CommandContract);
                }
            }
            ContextFamily::FaultTimeout => validate_fault(command, 1)?,
            ContextFamily::FaultReconnect => validate_fault(command, 2)?,
            ContextFamily::FaultLoss => validate_fault(command, 3)?,
            ContextFamily::Reset | ContextFamily::Handoff | ContextFamily::Stop => {
                if command.service_alias != 0 || command.public_slot != 0 || command.fault != 0 {
                    return Err(AetsMatrixError::CommandContract);
                }
            }
            ContextFamily::ServiceCollusion | ContextFamily::CrossServiceReplay => {
                if command.fault != 0 || command.service_alias == 0 {
                    return Err(AetsMatrixError::CommandContract);
                }
            }
            ContextFamily::Malformed => return Err(AetsMatrixError::CommandContract),
        }
        stopped = command.kind == CommandKind::Stop;
    }
    Ok(())
}

fn validate_fault(command: &ContextCommand, expected: u8) -> Result<(), AetsMatrixError> {
    if command.kind == CommandKind::PublicFault
        && command.fault == expected
        && command.service_alias != 0
    {
        Ok(())
    } else {
        Err(AetsMatrixError::CommandContract)
    }
}

fn read_command(reader: &mut Reader<'_>) -> Result<ContextCommand, AetsMatrixError> {
    let family_code = reader.read_u8()?;
    let family = match family_code {
        0 => ContextFamily::Tick,
        1 => ContextFamily::Reset,
        2 => ContextFamily::Handoff,
        3 => ContextFamily::Malformed,
        4 => ContextFamily::Retry,
        5 => ContextFamily::Deadline,
        6 => ContextFamily::FaultTimeout,
        7 => ContextFamily::FaultReconnect,
        8 => ContextFamily::FaultLoss,
        9 => ContextFamily::ServiceCollusion,
        10 => ContextFamily::CrossServiceReplay,
        11 => ContextFamily::Stop,
        code => return Err(AetsMatrixError::UnknownContextFamily(code)),
    };
    let kind_code = reader.read_u8()?;
    let kind = match kind_code {
        0 => CommandKind::PublicCall,
        1 => CommandKind::PublicFault,
        2 => CommandKind::PublicReset,
        3 => CommandKind::PublicHandoff,
        4 => CommandKind::Stop,
        code => return Err(AetsMatrixError::UnknownCommandKind(code)),
    };
    Ok(ContextCommand {
        family,
        kind,
        service_alias: reader.read_u32()?,
        public_slot: reader.read_u64()?,
        fault: reader.read_u8()?,
        payload_tag: reader.read_u32()?,
    })
}

fn put_len(bytes: &mut Vec<u8>, len: usize) -> Result<(), AetsMatrixError> {
    let len = u32::try_from(len).map_err(|_| AetsMatrixError::Arithmetic)?;
    bytes.extend_from_slice(&len.to_le_bytes());
    Ok(())
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_le_bytes());
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], AetsMatrixError> {
        let slice = self.read_exact(N)?;
        slice.try_into().map_err(|_| AetsMatrixError::Truncated)
    }

    fn read_u8(&mut self) -> Result<u8, AetsMatrixError> {
        Ok(self.read_array::<1>()?[0])
    }

    fn read_u16(&mut self) -> Result<u16, AetsMatrixError> {
        Ok(u16::from_le_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> Result<u32, AetsMatrixError> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    fn read_u64(&mut self) -> Result<u64, AetsMatrixError> {
        Ok(u64::from_le_bytes(self.read_array()?))
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], AetsMatrixError> {
        let end = self
            .cursor
            .checked_add(len)
            .ok_or(AetsMatrixError::Arithmetic)?;
        let slice = self
            .bytes
            .get(self.cursor..end)
            .ok_or(AetsMatrixError::Truncated)?;
        self.cursor = end;
        Ok(slice)
    }

    fn finish(self) -> Result<(), AetsMatrixError> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(AetsMatrixError::TrailingBytes)
        }
    }
}

#[derive(Debug, Error)]
pub enum AetsMatrixError {
    #[error("AETS matrix decode limits must be nonzero")]
    InvalidDecodeLimits,
    #[error("AETS matrix case count is empty or exceeds the bound")]
    CaseCount,
    #[error("AETS matrix command count is empty or exceeds the bound")]
    CommandCount,
    #[error("AETS matrix execution limits must be nonzero")]
    ExecutionLimits,
    #[error("AETS matrix command violates the public command contract")]
    CommandContract,
    #[error("AETS matrix public sequence failed for case {case_index}: {detail}")]
    PublicSequence { case_index: usize, detail: String },
    #[error("AETS matrix artifact exceeds the byte bound")]
    ArtifactSize,
    #[error("AETS matrix arithmetic overflow")]
    Arithmetic,
    #[error("AETS matrix magic is invalid")]
    Magic,
    #[error("unsupported AETS matrix format version {0}")]
    Version(u16),
    #[error("AETS matrix input is truncated")]
    Truncated,
    #[error("unknown AETS matrix {axis} axis code {code}")]
    UnknownAxis { axis: &'static str, code: u8 },
    #[error("unknown context family code {0}")]
    UnknownContextFamily(u8),
    #[error("unknown command kind code {0}")]
    UnknownCommandKind(u8),
    #[error("AETS matrix case ID does not match its payload")]
    CaseIdMismatch,
    #[error("AETS matrix case IDs are not in canonical order")]
    NonCanonicalOrder,
    #[error("AETS matrix contains a duplicate case ID")]
    DuplicateCaseId,
    #[error("AETS matrix contains a duplicate axis tuple")]
    DuplicateAxisTuple,
    #[error("AETS matrix digest does not match its canonical payload")]
    MatrixDigestMismatch,
    #[error("AETS matrix contains trailing bytes")]
    TrailingBytes,
    #[error("AETS matrix compiled artifact bindings do not match")]
    CompiledBindingMismatch,
    #[error("AETS matrix sequence digest differs for case {case_index}")]
    SequenceDigestMismatch { case_index: usize },
    #[error("AETS matrix object violated its canonical artifact contract")]
    ArtifactContract,
}
