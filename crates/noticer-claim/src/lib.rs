#![forbid(unsafe_code)]

use noticer_evidence::{EvidencePermit, GuaranteeMarker};
use noticer_types::{ActionCode, LogicalSlot, PolicyHash};
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct ClaimPolicy {
    pub policy_hash: PolicyHash,
    pub allowed_actions: Vec<ActionCode>,
    pub maximum_ttl_slots: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionClaim {
    action: ActionCode,
    policy_hash: PolicyHash,
    issued_slot: LogicalSlot,
    expires_slot: LogicalSlot,
}

impl ActionClaim {
    pub const fn action(&self) -> ActionCode {
        self.action
    }

    pub const fn policy_hash(&self) -> PolicyHash {
        self.policy_hash
    }

    pub const fn issued_slot(&self) -> LogicalSlot {
        self.issued_slot
    }

    pub const fn expires_slot(&self) -> LogicalSlot {
        self.expires_slot
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ClaimViolation {
    #[error("permit policy does not match the claim policy")]
    PolicyMismatch,
    #[error("permit action is not authorized by the claim policy")]
    ActionNotAllowed,
    #[error("permit lifetime is invalid or exceeds the claim policy")]
    InvalidLifetime,
}

pub struct ClaimQuotient {
    policy: ClaimPolicy,
}

impl ClaimQuotient {
    pub fn new(policy: ClaimPolicy) -> Result<Self, ClaimViolation> {
        if policy.maximum_ttl_slots == 0
            || policy.allowed_actions.is_empty()
            || policy.allowed_actions.contains(&ActionCode::NoAction)
        {
            return Err(ClaimViolation::ActionNotAllowed);
        }
        Ok(Self { policy })
    }

    pub fn declassify<G: GuaranteeMarker>(
        &self,
        permit: EvidencePermit<G>,
    ) -> Result<ActionClaim, ClaimViolation> {
        let (action, policy_hash, issued_slot, expires_slot, _, _) =
            permit.consume().into_claim_parts();
        if policy_hash != self.policy.policy_hash {
            return Err(ClaimViolation::PolicyMismatch);
        }
        if !self.policy.allowed_actions.contains(&action) {
            return Err(ClaimViolation::ActionNotAllowed);
        }
        let ttl = expires_slot
            .0
            .checked_sub(issued_slot.0)
            .filter(|ttl| *ttl > 0)
            .ok_or(ClaimViolation::InvalidLifetime)?;
        if ttl > self.policy.maximum_ttl_slots {
            return Err(ClaimViolation::InvalidLifetime);
        }
        Ok(ActionClaim {
            action,
            policy_hash,
            issued_slot,
            expires_slot,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_policy_is_rejected() {
        let result = ClaimQuotient::new(ClaimPolicy {
            policy_hash: PolicyHash([0; 32]),
            allowed_actions: vec![ActionCode::NoAction],
            maximum_ttl_slots: 10,
        });
        assert!(matches!(result, Err(ClaimViolation::ActionNotAllowed)));
    }
}
