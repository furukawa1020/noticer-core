use std::collections::BTreeSet;

use quotient_seal_abi::quotient_seal_abi_v1_hash;
use quotient_seal_context::{CommandKind, ContextCommand, ContextFamily};
use quotient_seal_engine::ExecutionLimits;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{AplotCompiledQsm, AplotPublicSequence};

pub const APLOT_ADVERSARIAL_MATRIX_VERSION: &str = "noticer-aplot-adversarial-matrix/v1";
const FORMAT_VERSION: u16 = 1;
const MAGIC: &[u8; 8] = b"APMTX001";
const CASE_ID_DOMAIN: &[u8] = b"noticer-aplot-adversarial-case-id/v1";
const MATRIX_DIGEST_DOMAIN: &[u8] = b"noticer-aplot-adversarial-matrix-digest/v1";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AplotMatrixSeed([u8; 32]);

impl AplotMatrixSeed {
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
pub struct AplotCaseId([u8; 32]);

impl AplotCaseId {
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
pub struct AplotMatrixDigest([u8; 32]);

impl AplotMatrixDigest {
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
pub enum AplotScenarioAxis {
    Normal = 0,
    DeclaredLoss = 1,
    DeclaredReconnect = 2,
    PublicFaultTimeout = 3,
    PublicFaultReconnect = 4,
    PublicFaultLoss = 5,
    DuplicateStep = 6,
    CapacityBoundary = 7,
    SecretRetryAttempt = 8,
    Reset = 9,
    Handoff = 10,
    DeadlineBefore = 11,
    DeadlineAt = 12,
    DeadlineAfter = 13,
    UnknownService = 14,
}

impl AplotScenarioAxis {
    fn from_code(code: u8) -> Result<Self, AplotMatrixError> {
        match code {
            0 => Ok(Self::Normal),
            1 => Ok(Self::DeclaredLoss),
            2 => Ok(Self::DeclaredReconnect),
            3 => Ok(Self::PublicFaultTimeout),
            4 => Ok(Self::PublicFaultReconnect),
            5 => Ok(Self::PublicFaultLoss),
            6 => Ok(Self::DuplicateStep),
            7 => Ok(Self::CapacityBoundary),
            8 => Ok(Self::SecretRetryAttempt),
            9 => Ok(Self::Reset),
            10 => Ok(Self::Handoff),
            11 => Ok(Self::DeadlineBefore),
            12 => Ok(Self::DeadlineAt),
            13 => Ok(Self::DeadlineAfter),
            14 => Ok(Self::UnknownService),
            _ => Err(AplotMatrixError::UnknownAxis {
                axis: "scenario",
                code,
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum AplotHostAxis {
    Continue = 0,
    Terminate = 1,
    Timeout = 2,
    Reconnect = 3,
    Loss = 4,
}

impl AplotHostAxis {
    fn from_code(code: u8) -> Result<Self, AplotMatrixError> {
        match code {
            0 => Ok(Self::Continue),
            1 => Ok(Self::Terminate),
            2 => Ok(Self::Timeout),
            3 => Ok(Self::Reconnect),
            4 => Ok(Self::Loss),
            _ => Err(AplotMatrixError::UnknownAxis { axis: "host", code }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum AplotResourceAxis {
    Nominal = 0,
    FuelBoundary = 1,
    MemoryBoundary = 2,
    HostCallBoundary = 3,
}

impl AplotResourceAxis {
    fn from_code(code: u8) -> Result<Self, AplotMatrixError> {
        match code {
            0 => Ok(Self::Nominal),
            1 => Ok(Self::FuelBoundary),
            2 => Ok(Self::MemoryBoundary),
            3 => Ok(Self::HostCallBoundary),
            _ => Err(AplotMatrixError::UnknownAxis {
                axis: "resource",
                code,
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AplotMatrixLimits {
    pub max_artifact_bytes: usize,
    pub max_cases: usize,
    pub max_commands_per_case: usize,
}

impl AplotMatrixLimits {
    #[must_use]
    pub const fn frozen_v1() -> Self {
        Self {
            max_artifact_bytes: 16 * 1024 * 1024,
            max_cases: 4_096,
            max_commands_per_case: 256,
        }
    }

    fn validate(self) -> Result<(), AplotMatrixError> {
        if self.max_artifact_bytes == 0 || self.max_cases == 0 || self.max_commands_per_case == 0 {
            Err(AplotMatrixError::InvalidDecodeLimits)
        } else {
            Ok(())
        }
    }
}

impl Default for AplotMatrixLimits {
    fn default() -> Self {
        Self::frozen_v1()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AplotAdversarialCaseSpec {
    scenario: AplotScenarioAxis,
    host: AplotHostAxis,
    resource: AplotResourceAxis,
    commands: Vec<ContextCommand>,
    limits: ExecutionLimits,
}

impl AplotAdversarialCaseSpec {
    #[must_use]
    pub fn new(
        scenario: AplotScenarioAxis,
        host: AplotHostAxis,
        resource: AplotResourceAxis,
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
pub struct AplotAdversarialCase {
    scenario: AplotScenarioAxis,
    host: AplotHostAxis,
    resource: AplotResourceAxis,
    commands: Box<[ContextCommand]>,
    limits: ExecutionLimits,
    sequence_digest: [u8; 32],
    case_id: AplotCaseId,
}

impl AplotAdversarialCase {
    #[must_use]
    pub const fn scenario(&self) -> AplotScenarioAxis {
        self.scenario
    }

    #[must_use]
    pub const fn host(&self) -> AplotHostAxis {
        self.host
    }

    #[must_use]
    pub const fn resource(&self) -> AplotResourceAxis {
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
    pub const fn case_id(&self) -> AplotCaseId {
        self.case_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AplotAdversarialMatrix {
    seed: AplotMatrixSeed,
    source_digest: [u8; 32],
    module_digest: [u8; 32],
    capsule_digest: [u8; 32],
    abi_digest: [u8; 32],
    cases: Box<[AplotAdversarialCase]>,
    matrix_digest: AplotMatrixDigest,
}

impl AplotAdversarialMatrix {
    pub fn new(
        compiled: &AplotCompiledQsm,
        seed: AplotMatrixSeed,
        specs: Vec<AplotAdversarialCaseSpec>,
        limits: AplotMatrixLimits,
    ) -> Result<Self, AplotMatrixError> {
        limits.validate()?;
        if specs.is_empty() || specs.len() > limits.max_cases {
            return Err(AplotMatrixError::CaseCount);
        }
        let source_digest = *compiled.binding().source_digest.as_bytes();
        let module_digest = *compiled.binding().module_digest.as_bytes();
        let capsule_digest = *compiled.binding().capsule_digest.as_bytes();
        let abi_digest = *quotient_seal_abi_v1_hash().as_bytes();
        let mut cases = Vec::with_capacity(specs.len());
        for (index, spec) in specs.into_iter().enumerate() {
            validate_commands(&spec.commands, spec.limits, limits.max_commands_per_case)?;
            let sequence = AplotPublicSequence::new(
                compiled,
                spec.commands.clone(),
                spec.limits,
                limits.max_commands_per_case,
            )
            .map_err(|error| AplotMatrixError::PublicSequence {
                case_index: index,
                detail: error.to_string(),
            })?;
            let mut case = AplotAdversarialCase {
                scenario: spec.scenario,
                host: spec.host,
                resource: spec.resource,
                commands: spec.commands.into_boxed_slice(),
                limits: spec.limits,
                sequence_digest: *sequence.digest().as_bytes(),
                case_id: AplotCaseId([0; 32]),
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
        cases.sort_by_key(AplotAdversarialCase::case_id);
        validate_case_set(&cases)?;
        let mut matrix = Self {
            seed,
            source_digest,
            module_digest,
            capsule_digest,
            abi_digest,
            cases: cases.into_boxed_slice(),
            matrix_digest: AplotMatrixDigest([0; 32]),
        };
        matrix.matrix_digest = matrix.compute_matrix_digest()?;
        if matrix.canonical_bytes()?.len() > limits.max_artifact_bytes {
            return Err(AplotMatrixError::ArtifactSize);
        }
        Ok(matrix)
    }

    pub fn from_bytes(bytes: &[u8], limits: AplotMatrixLimits) -> Result<Self, AplotMatrixError> {
        limits.validate()?;
        if bytes.len() > limits.max_artifact_bytes {
            return Err(AplotMatrixError::ArtifactSize);
        }
        let mut reader = Reader::new(bytes);
        if reader.read_array::<8>()? != *MAGIC {
            return Err(AplotMatrixError::Magic);
        }
        let version = reader.read_u16()?;
        if version != FORMAT_VERSION {
            return Err(AplotMatrixError::Version(version));
        }
        let seed = AplotMatrixSeed(reader.read_array()?);
        let source_digest = reader.read_array()?;
        let module_digest = reader.read_array()?;
        let capsule_digest = reader.read_array()?;
        let abi_digest = reader.read_array()?;
        let case_count = reader.read_u32()? as usize;
        if case_count == 0 || case_count > limits.max_cases {
            return Err(AplotMatrixError::CaseCount);
        }
        let mut cases = Vec::with_capacity(case_count);
        for _ in 0..case_count {
            let scenario = AplotScenarioAxis::from_code(reader.read_u8()?)?;
            let host = AplotHostAxis::from_code(reader.read_u8()?)?;
            let resource = AplotResourceAxis::from_code(reader.read_u8()?)?;
            let execution_limits = ExecutionLimits {
                fuel: reader.read_u64()?,
                max_memory_pages: reader.read_u32()?,
                max_host_calls: reader.read_u64()?,
                timeout_ms: reader.read_u64()?,
            };
            let sequence_digest = reader.read_array()?;
            let command_count = reader.read_u32()? as usize;
            if command_count == 0 || command_count > limits.max_commands_per_case {
                return Err(AplotMatrixError::CommandCount);
            }
            let mut commands = Vec::with_capacity(command_count);
            for _ in 0..command_count {
                commands.push(read_command(&mut reader)?);
            }
            validate_commands(&commands, execution_limits, limits.max_commands_per_case)?;
            let case_id = AplotCaseId(reader.read_array()?);
            let case = AplotAdversarialCase {
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
                return Err(AplotMatrixError::CaseIdMismatch);
            }
            cases.push(case);
        }
        validate_case_set(&cases)?;
        let matrix_digest = AplotMatrixDigest(reader.read_array()?);
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
            return Err(AplotMatrixError::MatrixDigestMismatch);
        }
        Ok(matrix)
    }

    pub fn validate_against(
        &self,
        compiled: &AplotCompiledQsm,
        limits: AplotMatrixLimits,
    ) -> Result<(), AplotMatrixError> {
        limits.validate()?;
        if self.source_digest != *compiled.binding().source_digest.as_bytes()
            || self.module_digest != *compiled.binding().module_digest.as_bytes()
            || self.capsule_digest != *compiled.binding().capsule_digest.as_bytes()
            || self.abi_digest != *quotient_seal_abi_v1_hash().as_bytes()
        {
            return Err(AplotMatrixError::CompiledBindingMismatch);
        }
        let canonical = self.canonical_bytes()?;
        if canonical.len() > limits.max_artifact_bytes
            || Self::from_bytes(&canonical, limits)? != *self
        {
            return Err(AplotMatrixError::ArtifactContract);
        }
        for (index, case) in self.cases.iter().enumerate() {
            let sequence = AplotPublicSequence::new(
                compiled,
                case.commands.to_vec(),
                case.limits,
                limits.max_commands_per_case,
            )
            .map_err(|error| AplotMatrixError::PublicSequence {
                case_index: index,
                detail: error.to_string(),
            })?;
            if sequence.digest().as_bytes() != &case.sequence_digest {
                return Err(AplotMatrixError::SequenceDigestMismatch { case_index: index });
            }
        }
        Ok(())
    }

    #[must_use]
    pub const fn seed(&self) -> AplotMatrixSeed {
        self.seed
    }

    #[must_use]
    pub fn cases(&self) -> &[AplotAdversarialCase] {
        &self.cases
    }

    #[must_use]
    pub const fn matrix_digest(&self) -> AplotMatrixDigest {
        self.matrix_digest
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AplotMatrixError> {
        let mut bytes = self.encode_without_matrix_digest()?;
        bytes.extend_from_slice(self.matrix_digest.as_bytes());
        Ok(bytes)
    }

    fn compute_matrix_digest(&self) -> Result<AplotMatrixDigest, AplotMatrixError> {
        Ok(AplotMatrixDigest(domain_hash(
            MATRIX_DIGEST_DOMAIN,
            &self.encode_without_matrix_digest()?,
        )))
    }

    fn encode_without_matrix_digest(&self) -> Result<Vec<u8>, AplotMatrixError> {
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
    seed: AplotMatrixSeed,
    source_digest: &[u8; 32],
    module_digest: &[u8; 32],
    capsule_digest: &[u8; 32],
    abi_digest: &[u8; 32],
    case: &AplotAdversarialCase,
) -> Result<AplotCaseId, AplotMatrixError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(seed.as_bytes());
    bytes.extend_from_slice(source_digest);
    bytes.extend_from_slice(module_digest);
    bytes.extend_from_slice(capsule_digest);
    bytes.extend_from_slice(abi_digest);
    put_case(&mut bytes, case)?;
    Ok(AplotCaseId(domain_hash(CASE_ID_DOMAIN, &bytes)))
}

fn put_case(bytes: &mut Vec<u8>, case: &AplotAdversarialCase) -> Result<(), AplotMatrixError> {
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

fn validate_case_set(cases: &[AplotAdversarialCase]) -> Result<(), AplotMatrixError> {
    let mut tuples = BTreeSet::new();
    let mut previous = None;
    for case in cases {
        if let Some(previous) = previous {
            if case.case_id == previous {
                return Err(AplotMatrixError::DuplicateCaseId);
            }
            if case.case_id < previous {
                return Err(AplotMatrixError::NonCanonicalOrder);
            }
        }
        previous = Some(case.case_id);
        if !tuples.insert((case.scenario, case.host, case.resource)) {
            return Err(AplotMatrixError::DuplicateAxisTuple);
        }
    }
    Ok(())
}

fn validate_commands(
    commands: &[ContextCommand],
    limits: ExecutionLimits,
    max_commands: usize,
) -> Result<(), AplotMatrixError> {
    if commands.is_empty() || commands.len() > max_commands {
        return Err(AplotMatrixError::CommandCount);
    }
    if limits.fuel == 0
        || limits.max_memory_pages == 0
        || limits.max_host_calls == 0
        || limits.timeout_ms == 0
    {
        return Err(AplotMatrixError::ExecutionLimits);
    }
    let mut stopped = false;
    for command in commands {
        if stopped || command.kind != command.family.command_kind() || command.payload_tag != 0 {
            return Err(AplotMatrixError::CommandContract);
        }
        match command.family {
            ContextFamily::Tick | ContextFamily::Deadline => {
                if command.fault != 0 || command.service_alias == 0 {
                    return Err(AplotMatrixError::CommandContract);
                }
            }
            ContextFamily::FaultTimeout => validate_fault(command, 1)?,
            ContextFamily::FaultReconnect => validate_fault(command, 2)?,
            ContextFamily::FaultLoss => validate_fault(command, 3)?,
            ContextFamily::Reset | ContextFamily::Handoff | ContextFamily::Stop => {
                if command.service_alias != 0 || command.public_slot != 0 || command.fault != 0 {
                    return Err(AplotMatrixError::CommandContract);
                }
            }
            ContextFamily::ServiceCollusion | ContextFamily::CrossServiceReplay => {
                if command.fault != 0 || command.service_alias == 0 {
                    return Err(AplotMatrixError::CommandContract);
                }
            }
            ContextFamily::Retry | ContextFamily::Malformed => {
                return Err(AplotMatrixError::CommandContract)
            }
        }
        stopped = command.kind == CommandKind::Stop;
    }
    Ok(())
}

fn validate_fault(command: &ContextCommand, expected: u8) -> Result<(), AplotMatrixError> {
    if command.kind == CommandKind::PublicFault
        && command.fault == expected
        && command.service_alias != 0
    {
        Ok(())
    } else {
        Err(AplotMatrixError::CommandContract)
    }
}

fn read_command(reader: &mut Reader<'_>) -> Result<ContextCommand, AplotMatrixError> {
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
        code => return Err(AplotMatrixError::UnknownContextFamily(code)),
    };
    let kind_code = reader.read_u8()?;
    let kind = match kind_code {
        0 => CommandKind::PublicCall,
        1 => CommandKind::PublicFault,
        2 => CommandKind::PublicReset,
        3 => CommandKind::PublicHandoff,
        4 => CommandKind::Stop,
        code => return Err(AplotMatrixError::UnknownCommandKind(code)),
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

fn put_len(bytes: &mut Vec<u8>, len: usize) -> Result<(), AplotMatrixError> {
    let len = u32::try_from(len).map_err(|_| AplotMatrixError::Arithmetic)?;
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

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], AplotMatrixError> {
        let slice = self.read_exact(N)?;
        slice.try_into().map_err(|_| AplotMatrixError::Truncated)
    }

    fn read_u8(&mut self) -> Result<u8, AplotMatrixError> {
        Ok(self.read_array::<1>()?[0])
    }

    fn read_u16(&mut self) -> Result<u16, AplotMatrixError> {
        Ok(u16::from_le_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> Result<u32, AplotMatrixError> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    fn read_u64(&mut self) -> Result<u64, AplotMatrixError> {
        Ok(u64::from_le_bytes(self.read_array()?))
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], AplotMatrixError> {
        let end = self
            .cursor
            .checked_add(len)
            .ok_or(AplotMatrixError::Arithmetic)?;
        let slice = self
            .bytes
            .get(self.cursor..end)
            .ok_or(AplotMatrixError::Truncated)?;
        self.cursor = end;
        Ok(slice)
    }

    fn finish(self) -> Result<(), AplotMatrixError> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(AplotMatrixError::TrailingBytes)
        }
    }
}

#[derive(Debug, Error)]
pub enum AplotMatrixError {
    #[error("APLOT matrix decode limits must be nonzero")]
    InvalidDecodeLimits,
    #[error("APLOT matrix case count is empty or exceeds the bound")]
    CaseCount,
    #[error("APLOT matrix command count is empty or exceeds the bound")]
    CommandCount,
    #[error("APLOT matrix execution limits must be nonzero")]
    ExecutionLimits,
    #[error("APLOT matrix command violates the public command contract")]
    CommandContract,
    #[error("APLOT matrix public sequence failed for case {case_index}: {detail}")]
    PublicSequence { case_index: usize, detail: String },
    #[error("APLOT matrix artifact exceeds the byte bound")]
    ArtifactSize,
    #[error("APLOT matrix arithmetic overflow")]
    Arithmetic,
    #[error("APLOT matrix magic is invalid")]
    Magic,
    #[error("unsupported APLOT matrix format version {0}")]
    Version(u16),
    #[error("APLOT matrix input is truncated")]
    Truncated,
    #[error("unknown APLOT matrix {axis} axis code {code}")]
    UnknownAxis { axis: &'static str, code: u8 },
    #[error("unknown context family code {0}")]
    UnknownContextFamily(u8),
    #[error("unknown command kind code {0}")]
    UnknownCommandKind(u8),
    #[error("APLOT matrix case ID does not match its payload")]
    CaseIdMismatch,
    #[error("APLOT matrix case IDs are not in canonical order")]
    NonCanonicalOrder,
    #[error("APLOT matrix contains a duplicate case ID")]
    DuplicateCaseId,
    #[error("APLOT matrix contains a duplicate axis tuple")]
    DuplicateAxisTuple,
    #[error("APLOT matrix digest does not match its canonical payload")]
    MatrixDigestMismatch,
    #[error("APLOT matrix contains trailing bytes")]
    TrailingBytes,
    #[error("APLOT matrix compiled artifact bindings do not match")]
    CompiledBindingMismatch,
    #[error("APLOT matrix sequence digest differs for case {case_index}")]
    SequenceDigestMismatch { case_index: usize },
    #[error("APLOT matrix object violated its canonical artifact contract")]
    ArtifactContract,
}
