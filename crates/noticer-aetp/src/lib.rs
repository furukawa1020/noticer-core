#![forbid(unsafe_code)]

use noticer_types::{ActionCode, LogicalSlot, PolicyHash};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ServiceBinding(pub [u8; 16]);

impl ServiceBinding {
    pub const fn from_u64(value: u64) -> Self {
        let mut bytes = [0; 16];
        let encoded = value.to_be_bytes();
        let mut index = 0;
        while index < 8 {
            bytes[index + 8] = encoded[index];
            index += 1;
        }
        Self(bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PairwiseServiceAlias(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BucketId(pub u64);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ActionObligation {
    pub service: ServiceBinding,
    pub action: ActionCode,
    pub public_bucket: BucketId,
    pub admission_cutoff: LogicalSlot,
    pub release_window_start: LogicalSlot,
    pub release_deadline: LogicalSlot,
    pub max_uses: u8,
    pub policy_hash: PolicyHash,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ActionSemantics {
    pub obligations: Vec<ActionObligation>,
}

impl ActionSemantics {
    pub fn validate(&self, schedule: ChannelSchedule) -> Result<(), SemanticsError> {
        if self.obligations.is_empty() {
            return Err(SemanticsError::Empty);
        }
        for obligation in &self.obligations {
            let bucket_start = obligation
                .public_bucket
                .0
                .checked_mul(u64::from(schedule.slots_per_bucket))
                .ok_or(SemanticsError::InvalidWindow)?;
            let bucket_end = bucket_start
                .checked_add(u64::from(schedule.slots_per_bucket) - 1)
                .ok_or(SemanticsError::InvalidWindow)?;
            if obligation.action == ActionCode::NoAction
                || obligation.max_uses != 1
                || obligation.release_window_start.0 > obligation.release_deadline.0
                || obligation.release_window_start.0 < bucket_start
                || obligation.release_deadline.0 > bucket_end
                || obligation.admission_cutoff.0 >= obligation.release_window_start.0
            {
                return Err(SemanticsError::InvalidWindow);
            }
        }
        Ok(())
    }

    pub fn canonical_hash(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"NOTICER_AETP_SEMANTICS_V1");
        for obligation in &self.obligations {
            hash.update(obligation.service.0);
            hash.update([obligation.action as u8]);
            hash.update(obligation.public_bucket.0.to_be_bytes());
            hash.update(obligation.admission_cutoff.0.to_be_bytes());
            hash.update(obligation.release_window_start.0.to_be_bytes());
            hash.update(obligation.release_deadline.0.to_be_bytes());
            hash.update([obligation.max_uses]);
            hash.update(obligation.policy_hash.0);
        }
        hash.finalize().into()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ChannelSchedule {
    pub buckets: u16,
    pub slots_per_bucket: u16,
    pub frame_interval_ms: u32,
    pub fixed_plaintext_size: u16,
    pub fixed_ciphertext_size: u16,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TransportStatus {
    Delivered,
    PublicDrop,
    PublicEndpointUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicNetworkTape {
    pub statuses: Vec<TransportStatus>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicContext {
    pub protocol_version: u16,
    pub public_epoch: u64,
    pub channel_schedule: ChannelSchedule,
    pub public_network_tape: PublicNetworkTape,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RandomTape(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ApproximateAetpBudget {
    pub epsilon: f64,
    pub delta: f64,
}

pub fn compose_basic(budgets: &[ApproximateAetpBudget]) -> ApproximateAetpBudget {
    ApproximateAetpBudget {
        epsilon: budgets.iter().map(|budget| budget.epsilon).sum(),
        delta: budgets.iter().map(|budget| budget.delta).sum(),
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum SemanticsError {
    #[error("action semantics must contain an obligation")]
    Empty,
    #[error("action semantics contain an invalid or infeasible release window")]
    InvalidWindow,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_composition_adds_declared_budgets_only() {
        let total = compose_basic(&[
            ApproximateAetpBudget {
                epsilon: 0.1,
                delta: 1e-6,
            },
            ApproximateAetpBudget {
                epsilon: 0.2,
                delta: 2e-6,
            },
        ]);
        assert!((total.epsilon - 0.3).abs() < 1e-12);
        assert!((total.delta - 3e-6).abs() < 1e-12);
    }
}
