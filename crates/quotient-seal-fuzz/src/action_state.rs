use quotient_seal_context::{CommandKind, ContextCommand, ContextFamily};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

pub const ADAPTIVE_CONTEXT_SCHEMA: &str = "quotient-seal.adaptive-host-context.v1";
pub const ADAPTIVE_HOST_MAGIC: [u8; 8] = *b"QSFUZZC1";
const MAX_PROGRAM_BYTES: usize = 128 * 1024;
const PROGRAM_DOMAIN: &[u8] = b"QUOTIENT_SEAL_ADAPTIVE_HOST_CONTEXT_V1";
const STATE_DOMAIN: &[u8] = b"QUOTIENT_SEAL_ADAPTIVE_CONTEXT_STATE_V1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdaptiveHostAction {
    Tick { public_slot: u64 },
    Reset { epoch: u32 },
    Handoff { service_alias: u32 },
    Malformed { payload_tag: u32 },
    Repeat { count: u8 },
    StaleSlot { delta: u16 },
    FutureSlot { delta: u16 },
    Fault { code: u8 },
    Reconnect { service_alias: u32 },
    ServiceSwitch { from: u32, to: u32 },
}

impl AdaptiveHostAction {
    pub fn validate(self, bounds: AdaptiveContextBounds) -> Result<(), AdaptiveProgramError> {
        match self {
            Self::Repeat { count } if count == 0 || count > bounds.max_repeat => {
                Err(AdaptiveProgramError::ActionBound)
            }
            Self::StaleSlot { delta } | Self::FutureSlot { delta } if delta == 0 => {
                Err(AdaptiveProgramError::ActionBound)
            }
            Self::Fault { code: 0 } => Err(AdaptiveProgramError::ActionBound),
            Self::Handoff { service_alias } | Self::Reconnect { service_alias }
                if service_alias >= bounds.max_service_alias =>
            {
                Err(AdaptiveProgramError::ServiceBound)
            }
            Self::ServiceSwitch { from, to }
                if from >= bounds.max_service_alias
                    || to >= bounds.max_service_alias
                    || from == to =>
            {
                Err(AdaptiveProgramError::ServiceBound)
            }
            _ => Ok(()),
        }
    }

    pub fn to_context_command(
        self,
        state: AdaptiveContextState,
    ) -> Result<ContextCommand, AdaptiveProgramError> {
        self.validate(state.bounds)?;
        let (family, service_alias, public_slot, fault, payload_tag) = match self {
            Self::Tick { public_slot } => {
                (ContextFamily::Tick, state.service_alias, public_slot, 0, 0)
            }
            Self::Reset { epoch } => (
                ContextFamily::Reset,
                state.service_alias,
                state.last_public_slot,
                0,
                epoch,
            ),
            Self::Handoff { service_alias } => (
                ContextFamily::Handoff,
                service_alias,
                state.last_public_slot,
                0,
                0,
            ),
            Self::Malformed { payload_tag } => (
                ContextFamily::Malformed,
                state.service_alias,
                state.last_public_slot,
                0,
                payload_tag,
            ),
            Self::Repeat { count } => (
                ContextFamily::Retry,
                state.service_alias,
                state.last_public_slot,
                0,
                u32::from(count),
            ),
            Self::StaleSlot { delta } => (
                ContextFamily::Deadline,
                state.service_alias,
                state.last_public_slot.saturating_sub(u64::from(delta)),
                0,
                u32::from(delta),
            ),
            Self::FutureSlot { delta } => (
                ContextFamily::Deadline,
                state.service_alias,
                state.last_public_slot.saturating_add(u64::from(delta)),
                0,
                u32::from(delta),
            ),
            Self::Fault { code } => (
                fault_family(code),
                state.service_alias,
                state.last_public_slot,
                code,
                0,
            ),
            Self::Reconnect { service_alias } => (
                ContextFamily::FaultReconnect,
                service_alias,
                state.last_public_slot,
                1,
                0,
            ),
            Self::ServiceSwitch { from, to } => (
                ContextFamily::ServiceCollusion,
                to,
                state.last_public_slot,
                0,
                from,
            ),
        };
        Ok(ContextCommand {
            family,
            kind: family.command_kind(),
            service_alias,
            public_slot,
            fault,
            payload_tag,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptiveContextBounds {
    pub max_steps: u32,
    pub max_service_alias: u32,
    pub max_repeat: u8,
    pub max_faults: u16,
    pub max_public_events: u32,
}

impl AdaptiveContextBounds {
    pub fn validate(self) -> Result<(), AdaptiveProgramError> {
        if self.max_steps == 0
            || self.max_service_alias < 2
            || self.max_repeat == 0
            || self.max_faults == 0
            || self.max_public_events == 0
        {
            return Err(AdaptiveProgramError::Bounds);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptivePublicObservation {
    pub event_count: u32,
    pub action_count: u32,
    pub trap_count: u32,
    pub host_call_count: u32,
    pub resource_units: u32,
    pub public_trace_sha256: [u8; 32],
}

impl AdaptivePublicObservation {
    fn validate(self, bounds: AdaptiveContextBounds) -> Result<(), AdaptiveProgramError> {
        if self.event_count > bounds.max_public_events || self.public_trace_sha256 == [0; 32] {
            return Err(AdaptiveProgramError::ObservationBound);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptiveContextState {
    pub bounds: AdaptiveContextBounds,
    pub step: u32,
    pub last_public_slot: u64,
    pub service_alias: u32,
    pub connected: bool,
    pub repeat_used: u16,
    pub fault_count: u16,
    pub public_event_count: u32,
    pub public_observation_sha256: [u8; 32],
}

impl AdaptiveContextState {
    pub fn initial(bounds: AdaptiveContextBounds) -> Result<Self, AdaptiveProgramError> {
        bounds.validate()?;
        Ok(Self {
            bounds,
            step: 0,
            last_public_slot: 0,
            service_alias: 0,
            connected: true,
            repeat_used: 0,
            fault_count: 0,
            public_event_count: 0,
            public_observation_sha256: domain_hash(STATE_DOMAIN, b"INITIAL"),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptiveStateTransition {
    pub before_sha256: [u8; 32],
    pub action: AdaptiveHostAction,
    pub observation: AdaptivePublicObservation,
    pub after: AdaptiveContextState,
    pub after_sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptiveHostProgram {
    pub schema: String,
    pub seed: u64,
    pub bounds: AdaptiveContextBounds,
    pub actions: Vec<AdaptiveHostAction>,
    pub evidence_origin: String,
    pub hardware_status: String,
    pub artifact_sha256: [u8; 32],
}

impl AdaptiveHostProgram {
    pub fn build(
        seed: u64,
        bounds: AdaptiveContextBounds,
        actions: Vec<AdaptiveHostAction>,
    ) -> Result<Self, AdaptiveProgramError> {
        bounds.validate()?;
        if actions.is_empty() || actions.len() > bounds.max_steps as usize {
            return Err(AdaptiveProgramError::ProgramBound);
        }
        for action in &actions {
            action.validate(bounds)?;
        }
        let mut program = Self {
            schema: ADAPTIVE_CONTEXT_SCHEMA.to_owned(),
            seed,
            bounds,
            actions,
            evidence_origin: "INJECTED_TEST_FIXTURE".to_owned(),
            hardware_status: "NOT_VERIFIED".to_owned(),
            artifact_sha256: [0; 32],
        };
        program.artifact_sha256 = program.recomputed_sha256()?;
        Ok(program)
    }

    pub fn validate(&self) -> Result<(), AdaptiveProgramError> {
        let expected = Self::build(self.seed, self.bounds, self.actions.clone())?;
        if self != &expected {
            return Err(AdaptiveProgramError::ArtifactMismatch);
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, AdaptiveProgramError> {
        serde_json::to_vec(self).map_err(|_| AdaptiveProgramError::Json)
    }

    pub fn recomputed_sha256(&self) -> Result<[u8; 32], AdaptiveProgramError> {
        let mut value = self.clone();
        value.artifact_sha256 = [0; 32];
        let encoded = serde_json::to_vec(&value).map_err(|_| AdaptiveProgramError::Json)?;
        Ok(domain_hash(PROGRAM_DOMAIN, &encoded))
    }

    pub fn encode(&self) -> Result<Vec<u8>, AdaptiveProgramError> {
        self.validate()?;
        let json = self.canonical_json()?;
        let length = u32::try_from(json.len()).map_err(|_| AdaptiveProgramError::Length)?;
        let mut output = Vec::with_capacity(12 + json.len() + 32);
        output.extend_from_slice(&ADAPTIVE_HOST_MAGIC);
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(&json);
        output.extend_from_slice(&domain_hash(PROGRAM_DOMAIN, &json));
        Ok(output)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, AdaptiveProgramError> {
        if encoded.len() < 44 || encoded[..8] != ADAPTIVE_HOST_MAGIC {
            return Err(AdaptiveProgramError::Envelope);
        }
        let length = u32::from_be_bytes(
            encoded[8..12]
                .try_into()
                .map_err(|_| AdaptiveProgramError::Envelope)?,
        ) as usize;
        if length > MAX_PROGRAM_BYTES || encoded.len() != 12 + length + 32 {
            return Err(AdaptiveProgramError::Length);
        }
        let json = &encoded[12..12 + length];
        if encoded[12 + length..] != domain_hash(PROGRAM_DOMAIN, json) {
            return Err(AdaptiveProgramError::Digest);
        }
        let program: Self = serde_json::from_slice(json).map_err(|_| AdaptiveProgramError::Json)?;
        program.validate()?;
        if program.canonical_json()? != json {
            return Err(AdaptiveProgramError::NonCanonical);
        }
        Ok(program)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AdaptiveProgramError {
    #[error("adaptive context bounds are invalid")]
    Bounds,
    #[error("adaptive action exceeds its bound")]
    ActionBound,
    #[error("adaptive action service alias is invalid")]
    ServiceBound,
    #[error("public observation exceeds its bound")]
    ObservationBound,
    #[error("adaptive program exceeds its step bound")]
    ProgramBound,
    #[error("adaptive context state bound was reached")]
    StateBound,
    #[error("adaptive host envelope is malformed")]
    Envelope,
    #[error("adaptive host envelope length is invalid")]
    Length,
    #[error("adaptive host digest mismatch")]
    Digest,
    #[error("adaptive host JSON is invalid")]
    Json,
    #[error("adaptive host JSON is not canonical")]
    NonCanonical,
    #[error("adaptive host artifact failed recomputation")]
    ArtifactMismatch,
}

pub fn apply_public_feedback(
    state: AdaptiveContextState,
    action: AdaptiveHostAction,
    observation: AdaptivePublicObservation,
) -> Result<AdaptiveStateTransition, AdaptiveProgramError> {
    state.bounds.validate()?;
    action.validate(state.bounds)?;
    observation.validate(state.bounds)?;
    if state.step >= state.bounds.max_steps {
        return Err(AdaptiveProgramError::StateBound);
    }
    let before_sha256 = state_digest(&state)?;
    let command = action.to_context_command(state)?;
    let repeat_increment = match action {
        AdaptiveHostAction::Repeat { count } => u16::from(count),
        _ => 0,
    };
    let fault_increment = u16::from(command.kind == CommandKind::PublicFault);
    let repeat_used = state
        .repeat_used
        .checked_add(repeat_increment)
        .ok_or(AdaptiveProgramError::StateBound)?;
    let fault_count = state
        .fault_count
        .checked_add(fault_increment)
        .ok_or(AdaptiveProgramError::StateBound)?;
    let public_event_count = state
        .public_event_count
        .checked_add(observation.event_count)
        .ok_or(AdaptiveProgramError::StateBound)?;
    if repeat_used > u16::from(state.bounds.max_repeat) * state.bounds.max_steps as u16
        || fault_count > state.bounds.max_faults
        || public_event_count > state.bounds.max_public_events
    {
        return Err(AdaptiveProgramError::StateBound);
    }
    let service_alias = match action {
        AdaptiveHostAction::Handoff { service_alias }
        | AdaptiveHostAction::Reconnect { service_alias } => service_alias,
        AdaptiveHostAction::ServiceSwitch { to, .. } => to,
        _ => state.service_alias,
    };
    let connected = !matches!(action, AdaptiveHostAction::Fault { .. });
    let after = AdaptiveContextState {
        bounds: state.bounds,
        step: state.step + 1,
        last_public_slot: command.public_slot,
        service_alias,
        connected,
        repeat_used,
        fault_count,
        public_event_count,
        public_observation_sha256: observation.public_trace_sha256,
    };
    let after_sha256 = state_digest(&after)?;
    Ok(AdaptiveStateTransition {
        before_sha256,
        action,
        observation,
        after,
        after_sha256,
    })
}

const fn fault_family(code: u8) -> ContextFamily {
    match code % 3 {
        0 => ContextFamily::FaultTimeout,
        1 => ContextFamily::FaultReconnect,
        _ => ContextFamily::FaultLoss,
    }
}

fn state_digest(state: &AdaptiveContextState) -> Result<[u8; 32], AdaptiveProgramError> {
    let encoded = serde_json::to_vec(state).map_err(|_| AdaptiveProgramError::Json)?;
    Ok(domain_hash(STATE_DOMAIN, &encoded))
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}
