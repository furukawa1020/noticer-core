//! Fail-closed admission control for bounded recovery backlogs.

use crate::receipt::hmac_sha256;

const POLICY_DOMAIN: &[u8] = b"noticer.quotient-commit.recovery-admission-policy.v1\0";
const SNAPSHOT_DOMAIN: &[u8] = b"noticer.quotient-commit.recovery-admission-snapshot.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionPolicy {
    pub epoch: u64,
    pub pending_weight: u64,
    pub delivered_weight: u64,
    pub halt_above: u64,
    pub resume_at_or_below: u64,
    pub authenticator: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AdmissionState {
    Accepting = 1,
    Halted = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionSnapshot {
    pub policy_epoch: u64,
    pub state: AdmissionState,
    pub weighted_backlog: u64,
    pub policy_authenticator: [u8; 32],
    pub authenticator: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionError {
    InvalidKey,
    InvalidPolicy,
    PolicyAuthenticationFailed,
    SnapshotAuthenticationFailed,
    PolicyMismatch,
    AdmissionHalted,
}

#[derive(Debug)]
pub struct RecoveryAdmissionController {
    policy: AdmissionPolicy,
    key: [u8; 32],
    state: AdmissionState,
    weighted_backlog: u64,
}

impl RecoveryAdmissionController {
    pub fn new(policy: AdmissionPolicy, key: [u8; 32]) -> Result<Self, AdmissionError> {
        validate_policy(policy, key)?;
        Ok(Self {
            policy,
            key,
            state: AdmissionState::Accepting,
            weighted_backlog: 0,
        })
    }

    pub fn restore(
        policy: AdmissionPolicy,
        snapshot: AdmissionSnapshot,
        key: [u8; 32],
    ) -> Result<Self, AdmissionError> {
        validate_policy(policy, key)?;
        if snapshot.policy_epoch != policy.epoch
            || snapshot.policy_authenticator != policy.authenticator
        {
            return Err(AdmissionError::PolicyMismatch);
        }
        if snapshot.authenticator != authenticate_snapshot(snapshot, key) {
            return Err(AdmissionError::SnapshotAuthenticationFailed);
        }
        Ok(Self {
            policy,
            key,
            state: snapshot.state,
            weighted_backlog: snapshot.weighted_backlog,
        })
    }

    pub fn observe(&mut self, pending: u64, delivered: u64) -> AdmissionState {
        self.weighted_backlog = pending
            .saturating_mul(self.policy.pending_weight)
            .saturating_add(delivered.saturating_mul(self.policy.delivered_weight));
        self.state = match self.state {
            AdmissionState::Accepting if self.weighted_backlog > self.policy.halt_above => {
                AdmissionState::Halted
            }
            AdmissionState::Halted if self.weighted_backlog <= self.policy.resume_at_or_below => {
                AdmissionState::Accepting
            }
            state => state,
        };
        self.state
    }

    pub fn admit_release(&self) -> Result<(), AdmissionError> {
        match self.state {
            AdmissionState::Accepting => Ok(()),
            AdmissionState::Halted => Err(AdmissionError::AdmissionHalted),
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> AdmissionSnapshot {
        let mut snapshot = AdmissionSnapshot {
            policy_epoch: self.policy.epoch,
            state: self.state,
            weighted_backlog: self.weighted_backlog,
            policy_authenticator: self.policy.authenticator,
            authenticator: [0; 32],
        };
        snapshot.authenticator = authenticate_snapshot(snapshot, self.key);
        snapshot
    }
}

pub fn seal_policy(
    epoch: u64,
    pending_weight: u64,
    delivered_weight: u64,
    halt_above: u64,
    resume_at_or_below: u64,
    key: [u8; 32],
) -> Result<AdmissionPolicy, AdmissionError> {
    if key == [0; 32] {
        return Err(AdmissionError::InvalidKey);
    }
    let mut policy = AdmissionPolicy {
        epoch,
        pending_weight,
        delivered_weight,
        halt_above,
        resume_at_or_below,
        authenticator: [0; 32],
    };
    validate_policy_fields(policy)?;
    policy.authenticator = authenticate_policy(policy, key);
    Ok(policy)
}

fn validate_policy(policy: AdmissionPolicy, key: [u8; 32]) -> Result<(), AdmissionError> {
    if key == [0; 32] {
        return Err(AdmissionError::InvalidKey);
    }
    validate_policy_fields(policy)?;
    if policy.authenticator != authenticate_policy(policy, key) {
        return Err(AdmissionError::PolicyAuthenticationFailed);
    }
    Ok(())
}

fn validate_policy_fields(policy: AdmissionPolicy) -> Result<(), AdmissionError> {
    if policy.epoch == 0
        || policy.pending_weight == 0
        || policy.delivered_weight == 0
        || policy.halt_above == 0
        || policy.resume_at_or_below >= policy.halt_above
    {
        return Err(AdmissionError::InvalidPolicy);
    }
    Ok(())
}

fn authenticate_policy(mut value: AdmissionPolicy, key: [u8; 32]) -> [u8; 32] {
    value.authenticator = [0; 32];
    let mut bytes = Vec::with_capacity(POLICY_DOMAIN.len() + 40);
    bytes.extend_from_slice(POLICY_DOMAIN);
    for field in [
        value.epoch,
        value.pending_weight,
        value.delivered_weight,
        value.halt_above,
        value.resume_at_or_below,
    ] {
        bytes.extend_from_slice(&field.to_be_bytes());
    }
    hmac_sha256(key, &bytes)
}

fn authenticate_snapshot(mut value: AdmissionSnapshot, key: [u8; 32]) -> [u8; 32] {
    value.authenticator = [0; 32];
    let mut bytes = Vec::with_capacity(SNAPSHOT_DOMAIN.len() + 49);
    bytes.extend_from_slice(SNAPSHOT_DOMAIN);
    bytes.extend_from_slice(&value.policy_epoch.to_be_bytes());
    bytes.push(value.state as u8);
    bytes.extend_from_slice(&value.weighted_backlog.to_be_bytes());
    bytes.extend_from_slice(&value.policy_authenticator);
    hmac_sha256(key, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    const KEY: [u8; 32] = [7; 32];
    fn policy() -> AdmissionPolicy {
        seal_policy(1, 2, 3, 10, 4, KEY).unwrap()
    }

    #[test]
    fn saturation_halts_and_hysteresis_controls_resume() {
        let mut controller = RecoveryAdmissionController::new(policy(), KEY).unwrap();
        assert_eq!(controller.observe(3, 2), AdmissionState::Halted);
        assert_eq!(
            controller.admit_release(),
            Err(AdmissionError::AdmissionHalted)
        );
        assert_eq!(controller.observe(2, 1), AdmissionState::Halted);
        assert_eq!(controller.observe(2, 0), AdmissionState::Accepting);
        assert_eq!(controller.admit_release(), Ok(()));
    }

    #[test]
    fn restart_preserves_halted_state_until_backlog_is_low() {
        let mut controller = RecoveryAdmissionController::new(policy(), KEY).unwrap();
        controller.observe(u64::MAX, u64::MAX);
        let snapshot = controller.snapshot();
        assert_eq!(snapshot.weighted_backlog, u64::MAX);
        let mut restored = RecoveryAdmissionController::restore(policy(), snapshot, KEY).unwrap();
        assert_eq!(
            restored.admit_release(),
            Err(AdmissionError::AdmissionHalted)
        );
        assert_eq!(restored.observe(0, 0), AdmissionState::Accepting);
    }

    #[test]
    fn policy_and_snapshot_tampering_fail_closed() {
        let mut changed_policy = policy();
        changed_policy.halt_above += 1;
        assert_eq!(
            RecoveryAdmissionController::new(changed_policy, KEY).unwrap_err(),
            AdmissionError::PolicyAuthenticationFailed
        );
        let controller = RecoveryAdmissionController::new(policy(), KEY).unwrap();
        let mut snapshot = controller.snapshot();
        snapshot.state = AdmissionState::Halted;
        assert_eq!(
            RecoveryAdmissionController::restore(policy(), snapshot, KEY).unwrap_err(),
            AdmissionError::SnapshotAuthenticationFailed
        );
    }
}
