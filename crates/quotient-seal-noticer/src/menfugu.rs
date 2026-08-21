//! Public-only Menfugu execution semantics and K7 artifact binding.

use crate::{NoticerModuleBinding, NoticerModuleId};
use noticer_menfugu_core::ExecutionPolicy;
use noticer_protocol::{KeyId, WireServiceAlias};
use noticer_types::{ActionCode, Epoch, PolicyHash};
use quotient_forge_caqt::Digest;
use quotient_seal_abi::DeploymentProfile;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

pub const MENFUGU_PUBLIC_SOURCE_FORMAT_VERSION: u16 = 1;
pub const MENFUGU_K7_SPEC_FAMILY: &str = "noticer.menfugu.public-execution.v1";

const SOURCE_DIGEST_DOMAIN: &[u8] = b"noticer-core/qseal/menfugu-public-source/v1";
const POLICY_DIGEST_DOMAIN: &[u8] = b"noticer-core/qseal/menfugu-public-policy/v1";

/// Public planner states. No token identifier or replay-set state is represented.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum MenfuguPublicState {
    Ready = 0,
    Executing = 1,
    Cooldown = 2,
    FailClosed = 3,
}

impl MenfuguPublicState {
    pub const ALL: [Self; 4] = [
        Self::Ready,
        Self::Executing,
        Self::Cooldown,
        Self::FailClosed,
    ];
}

/// Public verifier/runtime outcomes consumed by the execution planner.
///
/// Rejection classes carry no token material, feature values, or replay-set
/// contents. They all refine to the same externally visible `Reject` output.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum MenfuguPublicInput {
    AuthorizedAction = 0,
    Cover = 1,
    ReplayRejected = 2,
    ExpiredRejected = 3,
    WrongServiceRejected = 4,
    WrongPolicyRejected = 5,
    WrongKeyRejected = 6,
    DuplicateTransport = 7,
    PumpStopped = 8,
    CooldownElapsed = 9,
    Reset = 10,
    Handoff = 11,
    Deadline = 12,
    Fault = 13,
}

impl MenfuguPublicInput {
    pub const ALL: [Self; 14] = [
        Self::AuthorizedAction,
        Self::Cover,
        Self::ReplayRejected,
        Self::ExpiredRejected,
        Self::WrongServiceRejected,
        Self::WrongPolicyRejected,
        Self::WrongKeyRejected,
        Self::DuplicateTransport,
        Self::PumpStopped,
        Self::CooldownElapsed,
        Self::Reset,
        Self::Handoff,
        Self::Deadline,
        Self::Fault,
    ];
}

/// Public effects. `ExecuteOnce` is the only action-bearing output.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum MenfuguPublicOutput {
    NoOp = 0,
    Cover = 1,
    ExecuteOnce = 2,
    Reject = 3,
    Stop = 4,
    StopAndReset = 5,
    StopAndHandoff = 6,
    FailClosed = 7,
}

impl MenfuguPublicOutput {
    #[must_use]
    pub const fn executes_action(self) -> bool {
        matches!(self, Self::ExecuteOnce)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MenfuguPublicTransition {
    pub state: MenfuguPublicState,
    pub input: MenfuguPublicInput,
    pub next_state: MenfuguPublicState,
    pub output: MenfuguPublicOutput,
}

/// Canonical, total public source machine consumed by the K8 compiler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MenfuguPublicSourceArtifact {
    pub format_version: u16,
    pub transitions: Vec<MenfuguPublicTransition>,
    pub digest: Digest,
}

impl MenfuguPublicSourceArtifact {
    #[must_use]
    pub fn canonical() -> Self {
        let transitions = MenfuguPublicState::ALL
            .into_iter()
            .flat_map(|state| {
                MenfuguPublicInput::ALL
                    .into_iter()
                    .map(move |input| canonical_transition(state, input))
            })
            .collect::<Vec<_>>();
        let digest = source_digest(MENFUGU_PUBLIC_SOURCE_FORMAT_VERSION, &transitions);
        Self {
            format_version: MENFUGU_PUBLIC_SOURCE_FORMAT_VERSION,
            transitions,
            digest,
        }
    }

    pub fn verify(&self) -> Result<(), MenfuguBindingError> {
        if self.format_version != MENFUGU_PUBLIC_SOURCE_FORMAT_VERSION {
            return Err(MenfuguBindingError::SourceFormatVersion);
        }
        let expected_len = MenfuguPublicState::ALL.len() * MenfuguPublicInput::ALL.len();
        if self.transitions.len() != expected_len {
            return Err(MenfuguBindingError::TransitionCount);
        }
        for (index, transition) in self.transitions.iter().enumerate() {
            let state = MenfuguPublicState::ALL[index / MenfuguPublicInput::ALL.len()];
            let input = MenfuguPublicInput::ALL[index % MenfuguPublicInput::ALL.len()];
            if *transition != canonical_transition(state, input) {
                return Err(MenfuguBindingError::NonCanonicalTransition { index });
            }
        }
        if self.digest != source_digest(self.format_version, &self.transitions) {
            return Err(MenfuguBindingError::SourceDigest);
        }
        Ok(())
    }

    pub fn step(
        &self,
        state: MenfuguPublicState,
        input: MenfuguPublicInput,
    ) -> Result<MenfuguPublicTransition, MenfuguBindingError> {
        self.verify()?;
        let index = state as usize * MenfuguPublicInput::ALL.len() + input as usize;
        Ok(self.transitions[index])
    }
}

/// Public deployment policy committed by the K7 package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MenfuguPublicPolicyBinding {
    pub service_alias: WireServiceAlias,
    pub epoch: Epoch,
    pub policy_hash: PolicyHash,
    pub verifier_key_id: KeyId,
    pub allowed_action: ActionCode,
    pub pump_ticks: u32,
    pub maximum_pump_ticks: u32,
    pub cooldown_slots: u32,
    pub execution_period_slots: u32,
    pub execution_offset_slots: u32,
    pub public_deadline_slots: u32,
}

impl MenfuguPublicPolicyBinding {
    pub fn validate(self) -> Result<Self, MenfuguBindingError> {
        if self.allowed_action != ActionCode::MenfuguInflateSoft || self.public_deadline_slots == 0
        {
            return Err(MenfuguBindingError::InvalidPolicy);
        }
        self.execution_policy()
            .map_err(|_| MenfuguBindingError::InvalidPolicy)?;
        Ok(self)
    }

    pub fn execution_policy(self) -> Result<ExecutionPolicy, MenfuguBindingError> {
        ExecutionPolicy {
            pump_ticks: self.pump_ticks,
            maximum_pump_ticks: self.maximum_pump_ticks,
            cooldown_slots: self.cooldown_slots,
            execution_period_slots: self.execution_period_slots,
            execution_offset_slots: self.execution_offset_slots,
        }
        .validate()
        .map_err(|_| MenfuguBindingError::InvalidPolicy)
    }

    pub fn digest(self) -> Result<Digest, MenfuguBindingError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(128);
        bytes.extend_from_slice(POLICY_DIGEST_DOMAIN);
        bytes.extend_from_slice(&self.service_alias.0);
        bytes.extend_from_slice(&self.epoch.0.to_le_bytes());
        bytes.extend_from_slice(&self.policy_hash.0);
        bytes.extend_from_slice(&self.verifier_key_id.0);
        bytes.push(self.allowed_action as u8);
        bytes.extend_from_slice(&self.pump_ticks.to_le_bytes());
        bytes.extend_from_slice(&self.maximum_pump_ticks.to_le_bytes());
        bytes.extend_from_slice(&self.cooldown_slots.to_le_bytes());
        bytes.extend_from_slice(&self.execution_period_slots.to_le_bytes());
        bytes.extend_from_slice(&self.execution_offset_slots.to_le_bytes());
        bytes.extend_from_slice(&self.public_deadline_slots.to_le_bytes());
        Ok(hash(&bytes))
    }
}

/// Digests exported by K7 and required by the Noticer integration manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MenfuguK7Binding {
    pub public_policy_digest: Digest,
    pub source_digest: Digest,
    pub source_certificate_digest: Digest,
    pub generated_runtime_digest: Digest,
    pub qsm_capsule_digest: Digest,
    pub observer_registry_digest: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MenfuguK7ManifestBinding {
    pub module: NoticerModuleBinding,
    pub policy: MenfuguPublicPolicyBinding,
    pub k7: MenfuguK7Binding,
}

/// Bind public Menfugu semantics to one P0 K7 package and manifest entry.
///
/// Every digest-bearing field is checked independently so a partially updated
/// package cannot be admitted. P1 admission is deliberately deferred.
pub fn bind_menfugu_k7_manifest(
    source: &MenfuguPublicSourceArtifact,
    policy: MenfuguPublicPolicyBinding,
    k7: MenfuguK7Binding,
    module: NoticerModuleBinding,
) -> Result<MenfuguK7ManifestBinding, MenfuguBindingError> {
    source.verify()?;
    let policy = policy.validate()?;
    if policy.digest()? != k7.public_policy_digest {
        return Err(MenfuguBindingError::K7Mismatch("public_policy_digest"));
    }
    if source.digest != k7.source_digest {
        return Err(MenfuguBindingError::K7Mismatch("source_digest"));
    }
    if module.module_id != NoticerModuleId::MenfuguExecutionPlanner {
        return Err(MenfuguBindingError::ManifestMismatch("module_id"));
    }
    if module.deployment_profile != DeploymentProfile::P0PublicQuotientOnly {
        return Err(MenfuguBindingError::ManifestMismatch("deployment_profile"));
    }
    if module.p1_resource_evidence.is_some() {
        return Err(MenfuguBindingError::ManifestMismatch(
            "p1_resource_evidence",
        ));
    }
    if module.service_alias != policy.service_alias {
        return Err(MenfuguBindingError::ManifestMismatch("service_alias"));
    }
    if module.epoch != policy.epoch {
        return Err(MenfuguBindingError::ManifestMismatch("epoch"));
    }
    if module.policy_hash != policy.policy_hash {
        return Err(MenfuguBindingError::ManifestMismatch("policy_hash"));
    }
    for (field, actual, expected) in [
        ("source_digest", module.source_digest, k7.source_digest),
        (
            "source_certificate_digest",
            module.source_certificate_digest,
            k7.source_certificate_digest,
        ),
        (
            "generated_runtime_digest",
            module.generated_runtime_digest,
            k7.generated_runtime_digest,
        ),
        (
            "qsm_capsule_digest",
            module.qsm_capsule_digest,
            k7.qsm_capsule_digest,
        ),
        (
            "observer_registry_digest",
            module.observer_registry_digest,
            k7.observer_registry_digest,
        ),
    ] {
        if actual != expected {
            return Err(MenfuguBindingError::ManifestMismatch(field));
        }
    }
    Ok(MenfuguK7ManifestBinding { module, policy, k7 })
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MenfuguBindingError {
    #[error("unsupported Menfugu public source format version")]
    SourceFormatVersion,
    #[error("Menfugu public source transition count is not total")]
    TransitionCount,
    #[error("Menfugu transition {index} is not canonical")]
    NonCanonicalTransition { index: usize },
    #[error("Menfugu public source digest mismatch")]
    SourceDigest,
    #[error("invalid Menfugu public execution policy")]
    InvalidPolicy,
    #[error("Menfugu K7 field mismatch: {0}")]
    K7Mismatch(&'static str),
    #[error("Menfugu manifest field mismatch: {0}")]
    ManifestMismatch(&'static str),
}

fn canonical_transition(
    state: MenfuguPublicState,
    input: MenfuguPublicInput,
) -> MenfuguPublicTransition {
    use MenfuguPublicInput as Input;
    use MenfuguPublicOutput as Output;
    use MenfuguPublicState as State;

    let (next_state, output) = match input {
        Input::AuthorizedAction => match state {
            State::Ready => (State::Executing, Output::ExecuteOnce),
            State::Executing | State::Cooldown => (state, Output::Reject),
            State::FailClosed => (State::FailClosed, Output::FailClosed),
        },
        Input::Cover => (state, Output::Cover),
        Input::ReplayRejected
        | Input::ExpiredRejected
        | Input::WrongServiceRejected
        | Input::WrongPolicyRejected
        | Input::WrongKeyRejected
        | Input::DuplicateTransport => (state, Output::Reject),
        Input::PumpStopped => match state {
            State::Executing => (State::Cooldown, Output::Stop),
            _ => (state, Output::NoOp),
        },
        Input::CooldownElapsed => match state {
            State::Cooldown => (State::Ready, Output::NoOp),
            _ => (state, Output::NoOp),
        },
        Input::Reset => (State::Ready, Output::StopAndReset),
        Input::Handoff => (State::Ready, Output::StopAndHandoff),
        Input::Deadline => match state {
            State::Executing => (State::Cooldown, Output::Stop),
            _ => (state, Output::NoOp),
        },
        Input::Fault => (State::FailClosed, Output::FailClosed),
    };
    MenfuguPublicTransition {
        state,
        input,
        next_state,
        output,
    }
}

fn source_digest(version: u16, transitions: &[MenfuguPublicTransition]) -> Digest {
    let mut bytes = Vec::with_capacity(16 + transitions.len() * 4);
    bytes.extend_from_slice(SOURCE_DIGEST_DOMAIN);
    bytes.extend_from_slice(&version.to_le_bytes());
    bytes.extend_from_slice(&(transitions.len() as u32).to_le_bytes());
    for transition in transitions {
        bytes.extend_from_slice(&[
            transition.state as u8,
            transition.input as u8,
            transition.next_state as u8,
            transition.output as u8,
        ]);
    }
    hash(&bytes)
}

fn hash(bytes: &[u8]) -> Digest {
    Digest::new(Sha256::digest(bytes).into())
}
