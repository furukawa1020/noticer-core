#![forbid(unsafe_code)]

//! Public action semantics used by Action-Equivalent Trace Privacy (AETP).
//!
//! This crate deliberately contains no biosignal samples, evidence scores,
//! evidence-ready timestamps, cryptographic keys, or wire-format code.

use noticer_types::{ActionCode, LogicalSlot, PolicyHash};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ServiceBinding(pub [u8; 16]);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PairwiseServiceAlias(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BucketId(pub u64);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum SemanticLevel {
    None = 0,
    ChangeCue = 1,
    StateLabel = 2,
    Diagnosis = 3,
}

impl SemanticLevel {
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::None),
            1 => Some(Self::ChangeCue),
            2 => Some(Self::StateLabel),
            3 => Some(Self::Diagnosis),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum AudienceLevel {
    InternalOnly = 0,
    UserOnly = 1,
    PairedActuator = 2,
    Application = 3,
    Public = 4,
}

impl AudienceLevel {
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::InternalOnly),
            1 => Some(Self::UserOnly),
            2 => Some(Self::PairedActuator),
            3 => Some(Self::Application),
            4 => Some(Self::Public),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ImpactLevel {
    NoAction = 0,
    AmbientCue = 1,
    DirectPrompt = 2,
    HighImpact = 3,
}

impl ImpactLevel {
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::NoAction),
            1 => Some(Self::AmbientCue),
            2 => Some(Self::DirectPrompt),
            3 => Some(Self::HighImpact),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ClaimBound {
    pub semantic: SemanticLevel,
    pub audience: AudienceLevel,
    pub impact: ImpactLevel,
}

impl ClaimBound {
    pub const NONE: Self = Self {
        semantic: SemanticLevel::None,
        audience: AudienceLevel::InternalOnly,
        impact: ImpactLevel::NoAction,
    };

    pub const fn permits(self, required: Self) -> bool {
        (self.semantic as u8) >= (required.semantic as u8)
            && (self.audience as u8) >= (required.audience as u8)
            && (self.impact as u8) >= (required.impact as u8)
    }
}

pub const fn required_claim(action: ActionCode) -> ClaimBound {
    match action {
        ActionCode::NoAction => ClaimBound::NONE,
        ActionCode::RenderAmbientPulse => ClaimBound {
            semantic: SemanticLevel::ChangeCue,
            audience: AudienceLevel::UserOnly,
            impact: ImpactLevel::AmbientCue,
        },
        ActionCode::MenfuguInflateSoft => ClaimBound {
            semantic: SemanticLevel::ChangeCue,
            audience: AudienceLevel::PairedActuator,
            impact: ImpactLevel::DirectPrompt,
        },
        ActionCode::RenderReviewPrompt => ClaimBound {
            semantic: SemanticLevel::ChangeCue,
            audience: AudienceLevel::UserOnly,
            impact: ImpactLevel::DirectPrompt,
        },
        ActionCode::RenderStressLabel => ClaimBound {
            semantic: SemanticLevel::StateLabel,
            audience: AudienceLevel::UserOnly,
            impact: ImpactLevel::DirectPrompt,
        },
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ActionObligation {
    pub service: ServiceBinding,
    pub action: ActionCode,
    pub public_bucket: BucketId,
    pub admission_cutoff: LogicalSlot,
    pub release_window_start: LogicalSlot,
    pub release_deadline: LogicalSlot,
    pub max_uses: u16,
    pub policy_hash: PolicyHash,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionSemantics {
    pub obligations: Vec<ActionObligation>,
}

impl ActionSemantics {
    pub fn new(mut obligations: Vec<ActionObligation>) -> Result<Self, AetpError> {
        obligations.sort_by_key(|item| {
            (
                item.public_bucket,
                item.service,
                item.action as u16,
                item.release_window_start,
            )
        });
        for item in &obligations {
            validate_obligation(item)?;
        }
        for pair in obligations.windows(2) {
            if pair[0].service == pair[1].service
                && pair[0].public_bucket == pair[1].public_bucket
            {
                return Err(AetpError::AmbiguousActionSlot);
            }
        }
        Ok(Self { obligations })
    }

    pub fn canonical_hash(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"NOTICER_AETP_ACTION_SEMANTICS_V1");
        for item in &self.obligations {
            digest.update(item.service.0);
            digest.update((item.action as u16).to_le_bytes());
            digest.update(item.public_bucket.0.to_le_bytes());
            digest.update(item.admission_cutoff.0.to_le_bytes());
            digest.update(item.release_window_start.0.to_le_bytes());
            digest.update(item.release_deadline.0.to_le_bytes());
            digest.update(item.max_uses.to_le_bytes());
            digest.update(item.policy_hash.0);
        }
        digest.finalize().into()
    }
}

pub fn validate_obligation(item: &ActionObligation) -> Result<(), AetpError> {
    if item.action == ActionCode::NoAction
        || item.max_uses != 1
        || item.release_window_start < item.admission_cutoff
        || item.release_deadline < item.release_window_start
    {
        return Err(AetpError::InvalidObligation);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChannelSchedule {
    pub buckets: u16,
    pub slots_per_bucket: u16,
    pub frame_interval_ms: u32,
    pub fixed_plaintext_size: u16,
    pub fixed_ciphertext_size: u16,
}

impl ChannelSchedule {
    pub fn frame_count(self, service_count: usize) -> Result<usize, AetpError> {
        if self.buckets == 0
            || self.slots_per_bucket == 0
            || self.frame_interval_ms == 0
            || self.fixed_ciphertext_size == 0
        {
            return Err(AetpError::InvalidSchedule);
        }
        usize::from(self.buckets)
            .checked_mul(usize::from(self.slots_per_bucket))
            .and_then(|value| value.checked_mul(service_count))
            .ok_or(AetpError::InvalidSchedule)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicNetworkTape {
    pub services: Vec<ServiceBinding>,
    pub public_epoch: u32,
    pub start_slot: LogicalSlot,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicContext {
    pub schedule: ChannelSchedule,
    pub network: PublicNetworkTape,
}

impl PublicContext {
    pub fn validate(&self) -> Result<(), AetpError> {
        self.schedule.frame_count(self.network.services.len())?;
        if self.network.services.is_empty() {
            return Err(AetpError::InvalidSchedule);
        }
        let mut services = self.network.services.clone();
        services.sort_unstable();
        services.dedup();
        if services.len() != self.network.services.len() {
            return Err(AetpError::DuplicateService);
        }
        Ok(())
    }
}

/// Randomness used only for public schedule placement. It is never key material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScheduleRandomTape(pub [u8; 32]);

impl ScheduleRandomTape {
    pub fn sample_u64(self, domain: &[u8], ordinal: u64) -> u64 {
        let mut digest = Sha256::new();
        digest.update(b"NOTICER_AETP_SCHEDULE_TAPE_V1");
        digest.update(self.0);
        digest.update(domain);
        digest.update(ordinal.to_le_bytes());
        let output: [u8; 32] = digest.finalize().into();
        u64::from_le_bytes(output[..8].try_into().expect("fixed digest prefix"))
    }
}

pub fn action_equivalent(left: &ActionSemantics, right: &ActionSemantics) -> bool {
    left == right
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AetpError {
    #[error("invalid public channel schedule")]
    InvalidSchedule,
    #[error("duplicate public service binding")]
    DuplicateService,
    #[error("invalid action obligation")]
    InvalidObligation,
    #[error("multiple actions occupy one public service bucket")]
    AmbiguousActionSlot,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_order_is_componentwise() {
        let required = required_claim(ActionCode::RenderAmbientPulse);
        assert!(required.permits(required));
        assert!(!ClaimBound::NONE.permits(required));
    }

    #[test]
    fn schedule_tape_is_deterministic() {
        let tape = ScheduleRandomTape([7; 32]);
        assert_eq!(tape.sample_u64(b"slot", 4), tape.sample_u64(b"slot", 4));
        assert_ne!(tape.sample_u64(b"slot", 4), tape.sample_u64(b"slot", 5));
    }
}
