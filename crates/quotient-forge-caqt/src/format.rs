use alloc::vec::Vec;

pub const FORMAT_VERSION: u16 = 1;
const MAGIC: [u8; 4] = *b"CAQT";
const NO_ACTION: u32 = u32::MAX;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Digest([u8; 32]);

impl Digest {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn zero() -> Self {
        Self([0; 32])
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum HashDomain {
    Spec,
    Plant,
    Quotient,
    Observer,
    Utility,
    Fault,
    Transducer,
    CheckerContract,
}

impl HashDomain {
    pub(crate) const ALL: [Self; 8] = [
        Self::Spec,
        Self::Plant,
        Self::Quotient,
        Self::Observer,
        Self::Utility,
        Self::Fault,
        Self::Transducer,
        Self::CheckerContract,
    ];
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DomainHashes {
    pub spec: Digest,
    pub plant: Digest,
    pub quotient: Digest,
    pub observer: Digest,
    pub utility: Digest,
    pub fault: Digest,
    pub transducer: Digest,
    pub checker_contract: Digest,
}

impl DomainHashes {
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            spec: Digest::zero(),
            plant: Digest::zero(),
            quotient: Digest::zero(),
            observer: Digest::zero(),
            utility: Digest::zero(),
            fault: Digest::zero(),
            transducer: Digest::zero(),
            checker_contract: Digest::zero(),
        }
    }

    #[must_use]
    pub const fn get(&self, domain: HashDomain) -> Digest {
        match domain {
            HashDomain::Spec => self.spec,
            HashDomain::Plant => self.plant,
            HashDomain::Quotient => self.quotient,
            HashDomain::Observer => self.observer,
            HashDomain::Utility => self.utility,
            HashDomain::Fault => self.fault,
            HashDomain::Transducer => self.transducer,
            HashDomain::CheckerContract => self.checker_contract,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CostVector {
    pub states: u64,
    pub emitting_transitions: u64,
    pub payload_bytes: u64,
    pub action_emissions: u64,
}

impl CostVector {
    #[must_use]
    pub const fn componentwise_within(self, budget: Self) -> bool {
        self.states <= budget.states
            && self.emitting_transitions <= budget.emitting_transitions
            && self.payload_bytes <= budget.payload_bytes
            && self.action_emissions <= budget.action_emissions
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ObserverRecord {
    pub id: u32,
    pub sees_presence: bool,
    pub sees_payload: bool,
    pub sees_actions: bool,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct OutputRecord {
    pub id: u32,
    pub emitted: bool,
    pub payload: Vec<u8>,
    pub actions: Vec<u32>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TransitionRecord {
    pub from: u32,
    pub input: u32,
    pub to: u32,
    pub output: u32,
    pub authorized_actions: Vec<u32>,
    pub required_action: Option<u32>,
    pub recoverable_fault_action: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RelationPair {
    pub left: u32,
    pub right: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Certificate {
    pub version: u16,
    pub hashes: DomainHashes,
    pub state_count: u32,
    pub input_count: u32,
    pub observer_count: u32,
    pub state_bound: u32,
    pub claimed_cost: CostVector,
    pub observers: Vec<ObserverRecord>,
    pub outputs: Vec<OutputRecord>,
    pub transitions: Vec<TransitionRecord>,
    pub relation: Vec<RelationPair>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertificateLimits {
    pub max_bytes: usize,
    pub max_records: usize,
    pub max_payload_bytes: usize,
    pub max_actions_per_record: usize,
}

impl Default for CertificateLimits {
    fn default() -> Self {
        Self {
            max_bytes: 8 * 1024 * 1024,
            max_records: 1_000_000,
            max_payload_bytes: 64 * 1024,
            max_actions_per_record: 4_096,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseError {
    SizeLimit { actual: usize, limit: usize },
    UnexpectedEof { offset: usize },
    BadMagic,
    InvalidBoolean { offset: usize, value: u8 },
    InvalidObserverFlags { offset: usize, value: u8 },
    RecordLimit { actual: usize, limit: usize },
    PayloadLimit { actual: usize, limit: usize },
    ActionLimit { actual: usize, limit: usize },
    TrailingData { offset: usize, remaining: usize },
}

impl Certificate {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::default();
        writer.bytes(&MAGIC);
        writer.u16(self.version);
        for domain in HashDomain::ALL {
            writer.bytes(self.hashes.get(domain).as_bytes());
        }
        writer.u32(self.state_count);
        writer.u32(self.input_count);
        writer.u32(self.observer_count);
        writer.u32(self.state_bound);
        writer.cost(self.claimed_cost);
        writer.u32(length_u32(self.observers.len()));
        writer.u32(length_u32(self.outputs.len()));
        writer.u32(length_u32(self.transitions.len()));
        writer.u32(length_u32(self.relation.len()));

        for observer in &self.observers {
            writer.u32(observer.id);
            let flags = u8::from(observer.sees_presence)
                | (u8::from(observer.sees_payload) << 1)
                | (u8::from(observer.sees_actions) << 2);
            writer.u8(flags);
        }
        for output in &self.outputs {
            writer.u32(output.id);
            writer.bool(output.emitted);
            writer.length_prefixed(&output.payload);
            writer.u32(length_u32(output.actions.len()));
            for action in &output.actions {
                writer.u32(*action);
            }
        }
        for transition in &self.transitions {
            writer.u32(transition.from);
            writer.u32(transition.input);
            writer.u32(transition.to);
            writer.u32(transition.output);
            writer.u32(length_u32(transition.authorized_actions.len()));
            for action in &transition.authorized_actions {
                writer.u32(*action);
            }
            writer.optional_u32(transition.required_action);
            writer.optional_u32(transition.recoverable_fault_action);
        }
        for pair in &self.relation {
            writer.u32(pair.left);
            writer.u32(pair.right);
        }
        writer.finish()
    }

    pub fn decode(bytes: &[u8], limits: CertificateLimits) -> Result<Self, ParseError> {
        if bytes.len() > limits.max_bytes {
            return Err(ParseError::SizeLimit {
                actual: bytes.len(),
                limit: limits.max_bytes,
            });
        }
        let mut reader = Reader::new(bytes);
        if reader.array::<4>()? != MAGIC {
            return Err(ParseError::BadMagic);
        }
        let version = reader.u16()?;
        let hashes = DomainHashes {
            spec: reader.digest()?,
            plant: reader.digest()?,
            quotient: reader.digest()?,
            observer: reader.digest()?,
            utility: reader.digest()?,
            fault: reader.digest()?,
            transducer: reader.digest()?,
            checker_contract: reader.digest()?,
        };
        let state_count = reader.u32()?;
        let input_count = reader.u32()?;
        let observer_count = reader.u32()?;
        let state_bound = reader.u32()?;
        let claimed_cost = reader.cost()?;
        let observer_records = reader.count(limits.max_records)?;
        let output_records = reader.count(limits.max_records)?;
        let transition_records = reader.count(limits.max_records)?;
        let relation_records = reader.count(limits.max_records)?;

        let mut observers = Vec::with_capacity(observer_records);
        for _ in 0..observer_records {
            let id = reader.u32()?;
            let offset = reader.position();
            let flags = reader.u8()?;
            if flags & !0b111 != 0 {
                return Err(ParseError::InvalidObserverFlags {
                    offset,
                    value: flags,
                });
            }
            observers.push(ObserverRecord {
                id,
                sees_presence: flags & 1 != 0,
                sees_payload: flags & 2 != 0,
                sees_actions: flags & 4 != 0,
            });
        }

        let mut outputs = Vec::with_capacity(output_records);
        for _ in 0..output_records {
            let id = reader.u32()?;
            let emitted = reader.bool()?;
            let payload = reader.length_prefixed(limits.max_payload_bytes)?;
            let action_count = reader.action_count(limits.max_actions_per_record)?;
            let mut actions = Vec::with_capacity(action_count);
            for _ in 0..action_count {
                actions.push(reader.u32()?);
            }
            outputs.push(OutputRecord {
                id,
                emitted,
                payload,
                actions,
            });
        }

        let mut transitions = Vec::with_capacity(transition_records);
        for _ in 0..transition_records {
            let from = reader.u32()?;
            let input = reader.u32()?;
            let to = reader.u32()?;
            let output = reader.u32()?;
            let authorized_count = reader.action_count(limits.max_actions_per_record)?;
            let mut authorized_actions = Vec::with_capacity(authorized_count);
            for _ in 0..authorized_count {
                authorized_actions.push(reader.u32()?);
            }
            transitions.push(TransitionRecord {
                from,
                input,
                to,
                output,
                authorized_actions,
                required_action: reader.optional_u32()?,
                recoverable_fault_action: reader.optional_u32()?,
            });
        }

        let mut relation = Vec::with_capacity(relation_records);
        for _ in 0..relation_records {
            relation.push(RelationPair {
                left: reader.u32()?,
                right: reader.u32()?,
            });
        }
        reader.finish()?;
        Ok(Self {
            version,
            hashes,
            state_count,
            input_count,
            observer_count,
            state_bound,
            claimed_cost,
            observers,
            outputs,
            transitions,
            relation,
        })
    }
}

fn length_u32(length: usize) -> u32 {
    u32::try_from(length).unwrap_or(u32::MAX)
}

#[derive(Default)]
pub(crate) struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    pub(crate) fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub(crate) fn bool(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    pub(crate) fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub(crate) fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub(crate) fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub(crate) fn bytes(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    pub(crate) fn length_prefixed(&mut self, value: &[u8]) {
        self.u32(length_u32(value.len()));
        self.bytes(value);
    }

    pub(crate) fn optional_u32(&mut self, value: Option<u32>) {
        self.u32(value.unwrap_or(NO_ACTION));
    }

    pub(crate) fn cost(&mut self, cost: CostVector) {
        self.u64(cost.states);
        self.u64(cost.emitting_transitions);
        self.u64(cost.payload_bytes);
        self.u64(cost.action_emissions);
    }

    pub(crate) fn finish(self) -> Vec<u8> {
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

    const fn position(&self) -> usize {
        self.position
    }

    fn array<const LENGTH: usize>(&mut self) -> Result<[u8; LENGTH], ParseError> {
        let end = self
            .position
            .checked_add(LENGTH)
            .ok_or(ParseError::UnexpectedEof {
                offset: self.position,
            })?;
        let slice = self
            .bytes
            .get(self.position..end)
            .ok_or(ParseError::UnexpectedEof {
                offset: self.position,
            })?;
        let mut result = [0; LENGTH];
        result.copy_from_slice(slice);
        self.position = end;
        Ok(result)
    }

    fn u8(&mut self) -> Result<u8, ParseError> {
        Ok(self.array::<1>()?[0])
    }

    fn bool(&mut self) -> Result<bool, ParseError> {
        let offset = self.position;
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(ParseError::InvalidBoolean { offset, value }),
        }
    }

    fn u16(&mut self) -> Result<u16, ParseError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, ParseError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, ParseError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn digest(&mut self) -> Result<Digest, ParseError> {
        Ok(Digest::new(self.array()?))
    }

    fn cost(&mut self) -> Result<CostVector, ParseError> {
        Ok(CostVector {
            states: self.u64()?,
            emitting_transitions: self.u64()?,
            payload_bytes: self.u64()?,
            action_emissions: self.u64()?,
        })
    }

    fn count(&mut self, limit: usize) -> Result<usize, ParseError> {
        let count = usize::try_from(self.u32()?).unwrap_or(usize::MAX);
        if count > limit {
            Err(ParseError::RecordLimit {
                actual: count,
                limit,
            })
        } else {
            Ok(count)
        }
    }

    fn action_count(&mut self, limit: usize) -> Result<usize, ParseError> {
        let count = usize::try_from(self.u32()?).unwrap_or(usize::MAX);
        if count > limit {
            Err(ParseError::ActionLimit {
                actual: count,
                limit,
            })
        } else {
            Ok(count)
        }
    }

    fn length_prefixed(&mut self, limit: usize) -> Result<Vec<u8>, ParseError> {
        let length = usize::try_from(self.u32()?).unwrap_or(usize::MAX);
        if length > limit {
            return Err(ParseError::PayloadLimit {
                actual: length,
                limit,
            });
        }
        Ok(self.array_slice(length)?.to_vec())
    }

    fn array_slice(&mut self, length: usize) -> Result<&'a [u8], ParseError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(ParseError::UnexpectedEof {
                offset: self.position,
            })?;
        let result = self
            .bytes
            .get(self.position..end)
            .ok_or(ParseError::UnexpectedEof {
                offset: self.position,
            })?;
        self.position = end;
        Ok(result)
    }

    fn optional_u32(&mut self) -> Result<Option<u32>, ParseError> {
        let value = self.u32()?;
        Ok((value != NO_ACTION).then_some(value))
    }

    fn finish(self) -> Result<(), ParseError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(ParseError::TrailingData {
                offset: self.position,
                remaining: self.bytes.len() - self.position,
            })
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {}

impl core::fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "CAQT parse error: {self:?}")
    }
}
