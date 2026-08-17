use quotient_forge_caqt::{artifact_digest, Digest, RelationPair};
use quotient_seal_relation::RelationValidationReport;

pub const CONTEXT_PRODUCT_FORMAT_VERSION: u16 = 1;
pub const CONTEXT_FAMILY_COUNT: usize = 12;
pub const MAX_PREFIX_HARD_LIMIT: u16 = 256;
pub const QUOTIENT_SEAL_CONTEXT_PRODUCT_V1: &str = "QUOTIENT_SEAL_CONTEXT_PRODUCT_V1";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ContextFamily {
    Tick = 0,
    Reset = 1,
    Handoff = 2,
    Malformed = 3,
    Retry = 4,
    Deadline = 5,
    FaultTimeout = 6,
    FaultReconnect = 7,
    FaultLoss = 8,
    ServiceCollusion = 9,
    CrossServiceReplay = 10,
    Stop = 11,
}

impl ContextFamily {
    pub const ALL: [Self; CONTEXT_FAMILY_COUNT] = [
        Self::Tick,
        Self::Reset,
        Self::Handoff,
        Self::Malformed,
        Self::Retry,
        Self::Deadline,
        Self::FaultTimeout,
        Self::FaultReconnect,
        Self::FaultLoss,
        Self::ServiceCollusion,
        Self::CrossServiceReplay,
        Self::Stop,
    ];

    #[must_use]
    pub const fn command_kind(self) -> CommandKind {
        match self {
            Self::Reset => CommandKind::PublicReset,
            Self::Handoff => CommandKind::PublicHandoff,
            Self::FaultTimeout | Self::FaultReconnect | Self::FaultLoss => CommandKind::PublicFault,
            Self::Stop => CommandKind::Stop,
            Self::Tick
            | Self::Malformed
            | Self::Retry
            | Self::Deadline
            | Self::ServiceCollusion
            | Self::CrossServiceReplay => CommandKind::PublicCall,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CommandKind {
    PublicCall = 0,
    PublicFault = 1,
    PublicReset = 2,
    PublicHandoff = 3,
    Stop = 4,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContextCommand {
    pub family: ContextFamily,
    pub kind: CommandKind,
    pub service_alias: u32,
    pub public_slot: u64,
    pub fault: u8,
    pub payload_tag: u32,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ObserverProfile {
    O0Api = 0,
    O1Trap = 1,
    O2Control = 2,
    O3Instruction = 3,
    O4Memory = 4,
    O5CombinedService = 5,
    O6Collusion = 6,
}

impl ObserverProfile {
    pub const ALL: [Self; 7] = [
        Self::O0Api,
        Self::O1Trap,
        Self::O2Control,
        Self::O3Instruction,
        Self::O4Memory,
        Self::O5CombinedService,
        Self::O6Collusion,
    ];

    #[must_use]
    pub const fn sees(self, kind: EventKind) -> bool {
        match self {
            Self::O0Api => matches!(
                kind,
                EventKind::ApiCall | EventKind::ApiReturn | EventKind::Action
            ),
            Self::O1Trap => matches!(
                kind,
                EventKind::ApiCall
                    | EventKind::ApiReturn
                    | EventKind::Action
                    | EventKind::Trap
                    | EventKind::Termination
                    | EventKind::UnknownFailure
            ),
            Self::O2Control => matches!(
                kind,
                EventKind::ApiCall
                    | EventKind::ApiReturn
                    | EventKind::Action
                    | EventKind::Trap
                    | EventKind::Termination
                    | EventKind::UnknownFailure
                    | EventKind::Control
            ),
            Self::O3Instruction => matches!(
                kind,
                EventKind::ApiCall
                    | EventKind::ApiReturn
                    | EventKind::Action
                    | EventKind::Trap
                    | EventKind::Termination
                    | EventKind::UnknownFailure
                    | EventKind::Control
                    | EventKind::Instruction
            ),
            Self::O4Memory => matches!(
                kind,
                EventKind::ApiCall
                    | EventKind::ApiReturn
                    | EventKind::Action
                    | EventKind::Trap
                    | EventKind::Termination
                    | EventKind::UnknownFailure
                    | EventKind::Control
                    | EventKind::MemoryAccess
                    | EventKind::MemoryGrow
            ),
            Self::O5CombinedService => !matches!(kind, EventKind::ContextCommand),
            Self::O6Collusion => true,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum EventKind {
    ApiCall = 0,
    ApiReturn = 1,
    Action = 2,
    HostCall = 3,
    Trap = 4,
    Control = 5,
    Instruction = 6,
    MemoryAccess = 7,
    MemoryGrow = 8,
    Resource = 9,
    Termination = 10,
    UnknownFailure = 11,
    ContextCommand = 12,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TargetEvent {
    pub kind: EventKind,
    pub label: u32,
    pub slot: u64,
    pub value: u64,
}

#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Observation {
    events: Vec<TargetEvent>,
}

impl Observation {
    #[must_use]
    pub const fn empty() -> Self {
        Self { events: Vec::new() }
    }

    #[must_use]
    pub fn new(events: Vec<TargetEvent>) -> Self {
        Self { events }
    }

    #[must_use]
    pub fn events(&self) -> &[TargetEvent] {
        &self.events
    }
}

#[must_use]
pub fn project_trace(trace: &[TargetEvent], profile: ObserverProfile) -> Observation {
    Observation::new(
        trace
            .iter()
            .filter(|event| profile.sees(event.kind))
            .cloned()
            .collect(),
    )
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum SourceEventKind {
    PublicCall = 0,
    PublicReturn = 1,
    AuthorizedAction = 2,
    PublicFault = 3,
    Termination = 4,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SourceEvent {
    pub kind: SourceEventKind,
    pub label: u32,
    pub slot: u64,
    pub value: u64,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ExecutionBoundary {
    NormalReturn = 0,
    DeclaredTrap = 1,
    Termination = 2,
    BoundedNontermination = 3,
    FuelExhausted = 4,
    StateBoundExhausted = 5,
    UnsupportedInstruction = 6,
    UnknownImport = 7,
    ParserDisagreement = 8,
    UnknownFailure = 9,
}

impl ExecutionBoundary {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::DeclaredTrap | Self::Termination | Self::BoundedNontermination
        )
    }

    #[must_use]
    pub const fn is_inconclusive(self) -> bool {
        matches!(
            self,
            Self::FuelExhausted
                | Self::StateBoundExhausted
                | Self::UnsupportedInstruction
                | Self::UnknownImport
                | Self::ParserDisagreement
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunState {
    pub source_state: u32,
    pub target_state_digest: Digest,
    pub public_state_digest: Digest,
    pub target_pc: u32,
    pub memory_pages: u32,
    pub execution_status: u8,
    pub action_semantics_id: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitialRun {
    pub state: RunState,
    pub target_trace: Vec<TargetEvent>,
    pub relation_holds: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunStep {
    pub next: RunState,
    pub source_trace: Vec<SourceEvent>,
    pub target_trace: Vec<TargetEvent>,
    pub relation_holds: bool,
    pub utility_holds: bool,
    pub boundary: ExecutionBoundary,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum World {
    Left,
    Right,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleCounterexample {
    pub code: u32,
    pub detail_digest: Digest,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum OracleInconclusive {
    FuelExhausted,
    StateBoundExhausted,
    UnsupportedInstruction,
    UnknownImport,
    ParserDisagreement,
    UnknownTransition,
    ResourceBound,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OracleResult<T> {
    Valid(T),
    Counterexample(OracleCounterexample),
    Inconclusive(OracleInconclusive),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelationBinding {
    pub relation_digest: Digest,
    pub inductive_digest: Digest,
    pub target_ir_digest: Digest,
}

impl RelationBinding {
    #[must_use]
    pub const fn from_report(report: &RelationValidationReport) -> Self {
        Self {
            relation_digest: report.relation_digest,
            inductive_digest: report.inductive_digest,
            target_ir_digest: report.target_ir_digest,
        }
    }
}

pub trait ValidatedProductSystem {
    fn relation_binding(&self) -> RelationBinding;

    fn finite_state_bound(&self) -> usize;

    fn initial(&self, pair: RelationPair, world: World) -> OracleResult<InitialRun>;

    fn step(
        &self,
        world: World,
        state: &RunState,
        command: &ContextCommand,
    ) -> OracleResult<RunStep>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextTransition {
    pub from_state: u32,
    pub observation_index: u32,
    pub randomness: u32,
    pub to_state: u32,
    pub command: ContextCommand,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextAutomaton {
    pub family: ContextFamily,
    pub state_count: u32,
    pub randomness_count: u32,
    pub initial_state: u32,
    pub observations: Vec<Observation>,
    pub transitions: Vec<ContextTransition>,
}

impl ContextAutomaton {
    #[must_use]
    pub fn transition(
        &self,
        state: u32,
        observation_index: usize,
        randomness: u32,
    ) -> Option<&ContextTransition> {
        let observations = self.observations.len();
        let randomness_count = usize::try_from(self.randomness_count).ok()?;
        let state = usize::try_from(state).ok()?;
        let randomness = usize::try_from(randomness).ok()?;
        let index = state
            .checked_mul(observations)?
            .checked_add(observation_index)?
            .checked_mul(randomness_count)?
            .checked_add(randomness)?;
        self.transitions.get(index)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InductionObligations {
    pub base_case: bool,
    pub step_closure: bool,
    pub source_determinism: bool,
    pub target_determinism: bool,
    pub context_determinism: bool,
    pub finite_state_space: bool,
    pub resource_progress: bool,
}

impl InductionObligations {
    #[must_use]
    pub const fn closed(self) -> bool {
        self.base_case
            && self.step_closure
            && self.source_determinism
            && self.target_determinism
            && self.context_determinism
            && self.finite_state_space
            && self.resource_progress
    }
}

impl Default for InductionObligations {
    fn default() -> Self {
        Self {
            base_case: true,
            step_closure: true,
            source_determinism: true,
            target_determinism: true,
            context_determinism: true,
            finite_state_space: true,
            resource_progress: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductLimits {
    pub max_prefix: u16,
    pub max_product_states: usize,
    pub max_context_states: u32,
    pub max_observations: usize,
    pub max_randomness: u32,
    pub max_context_transitions: usize,
    pub max_system_states: usize,
}

impl Default for ProductLimits {
    fn default() -> Self {
        Self {
            max_prefix: MAX_PREFIX_HARD_LIMIT,
            max_product_states: 65_536,
            max_context_states: 1_024,
            max_observations: 1_024,
            max_randomness: 64,
            max_context_transitions: 1_048_576,
            max_system_states: 4_096,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallRecord {
    pub randomness: u32,
    pub command: ContextCommand,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum DivergenceKind {
    RelationGate = 1,
    Oracle = 2,
    SourceTrace = 3,
    ObserverTrace = 4,
    StateRelation = 5,
    Utility = 6,
    ExecutionBoundary = 7,
    UnknownFailure = 8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductCounterexample {
    pub observer: ObserverProfile,
    pub family: ContextFamily,
    pub private_pair: RelationPair,
    pub call_sequence: Vec<CallRecord>,
    pub shared_action: Option<ContextCommand>,
    pub shared_emitted_action: Option<u32>,
    pub divergence: DivergenceKind,
    pub detail_code: u32,
    pub left_observation: Observation,
    pub right_observation: Observation,
}

impl ProductCounterexample {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"QSCP");
        push_u16(&mut bytes, CONTEXT_PRODUCT_FORMAT_VERSION);
        bytes.push(self.observer as u8);
        bytes.push(self.family as u8);
        push_u32(&mut bytes, self.private_pair.left);
        push_u32(&mut bytes, self.private_pair.right);
        push_u32(
            &mut bytes,
            u32::try_from(self.call_sequence.len()).unwrap_or(u32::MAX),
        );
        for call in &self.call_sequence {
            push_u32(&mut bytes, call.randomness);
            encode_command(&mut bytes, &call.command);
        }
        encode_optional_command(&mut bytes, self.shared_action.as_ref());
        match self.shared_emitted_action {
            Some(action) => {
                bytes.push(1);
                push_u32(&mut bytes, action);
            }
            None => bytes.push(0),
        }
        push_u16(&mut bytes, self.divergence as u16);
        push_u32(&mut bytes, self.detail_code);
        encode_observation(&mut bytes, &self.left_observation);
        encode_observation(&mut bytes, &self.right_observation);
        bytes
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        artifact_digest(b"quotient-seal-context-counterexample-v1", &self.encode())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContextViolationKind {
    MissingFamily,
    DuplicateFamily,
    StateCount,
    RandomnessCount,
    InitialState,
    ObservationCount,
    ObservationOrder,
    TransitionCount,
    TransitionOrder,
    TransitionTarget,
    CommandFamily,
    CommandKind,
    CommandFields,
    PrivatePairOrder,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContextViolation {
    pub kind: ContextViolationKind,
    pub family: Option<ContextFamily>,
    pub index: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProductInconclusive {
    InvalidLimits,
    EmptyPrivatePairs,
    RelationGate,
    RelationBinding,
    InvalidContext(ContextViolation),
    Oracle {
        world: World,
        reason: OracleInconclusive,
    },
    ExecutionBoundary {
        world: World,
        boundary: ExecutionBoundary,
    },
    UnknownObservation {
        observer: ObserverProfile,
        family: ContextFamily,
        depth: u16,
    },
    PrefixBound {
        limit: u16,
    },
    ProductStateBound {
        limit: usize,
    },
    SystemStateBound {
        actual: usize,
        limit: usize,
    },
    NondeterministicOracle,
    ArithmeticOverflow,
    InductionNotClosed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductCheckReport {
    pub binding: RelationBinding,
    pub observer_profiles: usize,
    pub context_families: usize,
    pub private_pairs: usize,
    pub visited_product_states: usize,
    pub checked_edges: usize,
    pub maximum_shortest_prefix: u16,
    pub declared_product_bound: usize,
    pub induction_closed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProductVerdict {
    Accept(Box<ProductCheckReport>),
    Counterexample(Box<ProductCounterexample>),
    Inconclusive(ProductInconclusive),
}

fn encode_optional_command(bytes: &mut Vec<u8>, command: Option<&ContextCommand>) {
    match command {
        Some(command) => {
            bytes.push(1);
            encode_command(bytes, command);
        }
        None => bytes.push(0),
    }
}

fn encode_command(bytes: &mut Vec<u8>, command: &ContextCommand) {
    bytes.push(command.family as u8);
    bytes.push(command.kind as u8);
    push_u32(bytes, command.service_alias);
    push_u64(bytes, command.public_slot);
    bytes.push(command.fault);
    push_u32(bytes, command.payload_tag);
}

fn encode_observation(bytes: &mut Vec<u8>, observation: &Observation) {
    push_u32(
        bytes,
        u32::try_from(observation.events().len()).unwrap_or(u32::MAX),
    );
    for event in observation.events() {
        bytes.push(event.kind as u8);
        push_u32(bytes, event.label);
        push_u64(bytes, event.slot);
        push_u64(bytes, event.value);
    }
}

fn push_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}
