use quotient_forge_caqt::{artifact_digest, Digest, RelationPair};
use quotient_seal_context::{EventKind, Observation, ProductVerdict, RelationBinding, TargetEvent};
use quotient_seal_relation::RelationVerdict;

pub const QUOTIENT_PAD_FORMAT_VERSION: u16 = 1;
pub const QUOTIENT_SEAL_RESOURCE_V1: &str = "QUOTIENT_SEAL_RESOURCE_V1";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ResourceAxis {
    Opcode = 0,
    Branch = 1,
    MemoryAddress = 2,
    Import = 3,
    Fuel = 4,
    MemoryPages = 5,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ResourceEvent {
    pub axis: ResourceAxis,
    pub label: u32,
    pub slot: u64,
    pub value: u64,
}

#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ResourceTrace {
    events: Vec<ResourceEvent>,
}

impl ResourceTrace {
    #[must_use]
    pub fn new(events: Vec<ResourceEvent>) -> Self {
        Self { events }
    }

    #[must_use]
    pub fn events(&self) -> &[ResourceEvent] {
        &self.events
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

#[must_use]
pub fn project_resource_trace(trace: &[TargetEvent]) -> ResourceTrace {
    let events = trace
        .iter()
        .filter_map(|event| {
            let axis = match event.kind {
                EventKind::Instruction => ResourceAxis::Opcode,
                EventKind::Control => ResourceAxis::Branch,
                EventKind::MemoryAccess => ResourceAxis::MemoryAddress,
                EventKind::HostCall => ResourceAxis::Import,
                EventKind::Resource => ResourceAxis::Fuel,
                EventKind::MemoryGrow => ResourceAxis::MemoryPages,
                EventKind::ApiCall
                | EventKind::ApiReturn
                | EventKind::Action
                | EventKind::Trap
                | EventKind::Termination
                | EventKind::UnknownFailure
                | EventKind::ContextCommand => return None,
            };
            Some(ResourceEvent {
                axis,
                label: event.label,
                slot: event.slot,
                value: event.value,
            })
        })
        .collect();
    ResourceTrace::new(events)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceCase {
    pub pair: RelationPair,
    pub left_trace: Vec<TargetEvent>,
    pub right_trace: Vec<TargetEvent>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum NormalizationKind {
    PublicNoOp = 0,
    BoundedLoop = 1,
    BranchFuel = 2,
    FixedScratch = 3,
    FailureReturnPath = 4,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum PadSide {
    Left = 0,
    Right = 1,
    Both = 2,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct QuotientPadOperation {
    pub pair: RelationPair,
    pub event_index: u32,
    pub axis: ResourceAxis,
    pub kind: NormalizationKind,
    pub side: PadSide,
    pub amount: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NormalizationOverhead {
    pub operation_count: usize,
    pub added_instructions: u64,
    pub added_fuel: u64,
    pub bounded_loop_iterations: u64,
    pub fixed_scratch_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotientPadCandidate {
    pub version: u16,
    pub operations: Vec<QuotientPadOperation>,
    pub overhead: NormalizationOverhead,
}

impl QuotientPadCandidate {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64 + self.operations.len().saturating_mul(38));
        bytes.extend_from_slice(b"QPAD");
        bytes.extend_from_slice(&self.version.to_le_bytes());
        push_usize(&mut bytes, self.operations.len());
        for operation in &self.operations {
            bytes.extend_from_slice(&operation.pair.left.to_le_bytes());
            bytes.extend_from_slice(&operation.pair.right.to_le_bytes());
            bytes.extend_from_slice(&operation.event_index.to_le_bytes());
            bytes.push(operation.axis as u8);
            bytes.push(operation.kind as u8);
            bytes.push(operation.side as u8);
            bytes.extend_from_slice(&operation.amount.to_le_bytes());
        }
        encode_overhead(&mut bytes, self.overhead);
        bytes
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        artifact_digest(
            b"quotient-seal/resource/quotient-pad/v1",
            &self.canonical_bytes(),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceLimits {
    pub max_cases: usize,
    pub max_events_per_trace: usize,
    pub max_operations: usize,
    pub max_added_instructions: u64,
    pub max_added_fuel: u64,
    pub max_loop_iterations: u64,
    pub max_scratch_bytes: u64,
}

impl ResourceLimits {
    pub(crate) const fn is_valid(self) -> bool {
        self.max_cases > 0
            && self.max_events_per_trace > 0
            && self.max_operations > 0
            && self.max_added_instructions > 0
            && self.max_added_fuel > 0
            && self.max_loop_iterations > 0
            && self.max_scratch_bytes > 0
    }
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_cases: 4_096,
            max_events_per_trace: 1_000_000,
            max_operations: 65_536,
            max_added_instructions: 1_000_000,
            max_added_fuel: 1_000_000,
            max_loop_iterations: 100_000,
            max_scratch_bytes: 1_048_576,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevalidationEvidence {
    pub relation: RelationVerdict,
    pub context: ProductVerdict,
    pub normalized_cases: Vec<ResourceCase>,
    pub utility_preserved: bool,
    pub deadlines_preserved: bool,
}

pub trait QuotientPadRevalidator {
    fn revalidate(&self, candidate: &QuotientPadCandidate) -> RevalidationEvidence;
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ResourceDivergence {
    UpstreamRelation = 0,
    UpstreamContext = 1,
    PublicSurface = 2,
    ResourceOnly = 3,
    NormalizationChangedPublic = 4,
    NormalizationChangedUtility = 5,
    NormalizationChangedDeadline = 6,
    NormalizationFailed = 7,
    PostRelation = 8,
    PostContext = 9,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceCounterexample {
    pub version: u16,
    pub divergence: ResourceDivergence,
    pub pair: RelationPair,
    pub event_index: u32,
    pub left_public: Observation,
    pub right_public: Observation,
    pub left_resource: Option<ResourceEvent>,
    pub right_resource: Option<ResourceEvent>,
    pub candidate_digest: Option<Digest>,
}

impl ResourceCounterexample {
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(192);
        bytes.extend_from_slice(b"QRCE");
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.push(self.divergence as u8);
        bytes.extend_from_slice(&self.pair.left.to_le_bytes());
        bytes.extend_from_slice(&self.pair.right.to_le_bytes());
        bytes.extend_from_slice(&self.event_index.to_le_bytes());
        encode_observation(&mut bytes, &self.left_public);
        encode_observation(&mut bytes, &self.right_public);
        encode_optional_resource(&mut bytes, self.left_resource.as_ref());
        encode_optional_resource(&mut bytes, self.right_resource.as_ref());
        match self.candidate_digest {
            Some(digest) => {
                bytes.push(1);
                bytes.extend_from_slice(digest.as_bytes());
            }
            None => bytes.push(0),
        }
        bytes
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        artifact_digest(
            b"quotient-seal/resource/counterexample/v1",
            &self.canonical_bytes(),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResourceInconclusive {
    EmptyCases,
    NonCanonicalCases,
    InvalidLimits,
    CaseBound { actual: usize, limit: usize },
    TraceBound { actual: usize, limit: usize },
    UpstreamRelation,
    UpstreamContext,
    CandidateBound,
    RevalidationRelation,
    RevalidationContext,
    RevalidationCaseMismatch,
    ArithmeticOverflow,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceReport {
    pub pre_binding: RelationBinding,
    pub post_binding: RelationBinding,
    pub checked_cases: usize,
    pub checked_resource_events: usize,
    pub candidate_digest: Option<Digest>,
    pub overhead: NormalizationOverhead,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResourceVerdict {
    Strict(Box<ResourceReport>),
    Normalized(Box<ResourceReport>),
    Counterexample(Box<ResourceCounterexample>),
    Inconclusive(ResourceInconclusive),
}

fn encode_overhead(bytes: &mut Vec<u8>, overhead: NormalizationOverhead) {
    push_usize(bytes, overhead.operation_count);
    bytes.extend_from_slice(&overhead.added_instructions.to_le_bytes());
    bytes.extend_from_slice(&overhead.added_fuel.to_le_bytes());
    bytes.extend_from_slice(&overhead.bounded_loop_iterations.to_le_bytes());
    bytes.extend_from_slice(&overhead.fixed_scratch_bytes.to_le_bytes());
}

fn encode_observation(bytes: &mut Vec<u8>, observation: &Observation) {
    push_usize(bytes, observation.events().len());
    for event in observation.events() {
        bytes.push(event.kind as u8);
        bytes.extend_from_slice(&event.label.to_le_bytes());
        bytes.extend_from_slice(&event.slot.to_le_bytes());
        bytes.extend_from_slice(&event.value.to_le_bytes());
    }
}

fn encode_optional_resource(bytes: &mut Vec<u8>, event: Option<&ResourceEvent>) {
    match event {
        Some(event) => {
            bytes.push(1);
            bytes.push(event.axis as u8);
            bytes.extend_from_slice(&event.label.to_le_bytes());
            bytes.extend_from_slice(&event.slot.to_le_bytes());
            bytes.extend_from_slice(&event.value.to_le_bytes());
        }
        None => bytes.push(0),
    }
}

fn push_usize(bytes: &mut Vec<u8>, value: usize) {
    bytes.extend_from_slice(&u64::try_from(value).unwrap_or(u64::MAX).to_le_bytes());
}
