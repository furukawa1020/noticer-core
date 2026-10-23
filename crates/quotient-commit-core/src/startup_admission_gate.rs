//! Startup binding between durable outbox backlog and release admission.

use crate::delivery_outbox::{DeliveryIntent, OutboxState};
use crate::receipt::hmac_sha256;
use crate::recovery_admission::{
    AdmissionError, AdmissionPolicy, AdmissionSnapshot, AdmissionState, RecoveryAdmissionController,
};

const DOMAIN: &[u8] = b"noticer.quotient-commit.startup-admission-permit.v1\0";
type OutboxEntry = (DeliveryIntent, OutboxState, [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartupAdmissionPermit {
    pub policy_epoch: u64,
    pub weighted_backlog: u64,
    pub snapshot_authenticator: [u8; 32],
    pub authenticator: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartupAdmissionDecision {
    pub pending: u64,
    pub delivered: u64,
    pub snapshot: AdmissionSnapshot,
    pub permit: Option<StartupAdmissionPermit>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupAdmissionError {
    InvalidKey,
    Admission(AdmissionError),
    PermitAuthenticationFailed,
}

pub fn evaluate_startup_admission(
    controller: &mut RecoveryAdmissionController,
    entries: &[OutboxEntry],
    key: [u8; 32],
) -> Result<StartupAdmissionDecision, StartupAdmissionError> {
    if key == [0; 32] {
        return Err(StartupAdmissionError::InvalidKey);
    }
    let pending = entries
        .iter()
        .filter(|entry| entry.1 == OutboxState::Pending)
        .count() as u64;
    let delivered = entries
        .iter()
        .filter(|entry| entry.1 == OutboxState::Delivered)
        .count() as u64;
    let state = controller.observe(pending, delivered);
    let snapshot = controller.snapshot();
    let permit = if state == AdmissionState::Accepting {
        let mut permit = StartupAdmissionPermit {
            policy_epoch: snapshot.policy_epoch,
            weighted_backlog: snapshot.weighted_backlog,
            snapshot_authenticator: snapshot.authenticator,
            authenticator: [0; 32],
        };
        permit.authenticator = authenticate(permit, key);
        Some(permit)
    } else {
        None
    };
    Ok(StartupAdmissionDecision {
        pending,
        delivered,
        snapshot,
        permit,
    })
}

pub fn verify_startup_admission(
    policy: AdmissionPolicy,
    snapshot: AdmissionSnapshot,
    permit: StartupAdmissionPermit,
    key: [u8; 32],
) -> Result<(), StartupAdmissionError> {
    if key == [0; 32] {
        return Err(StartupAdmissionError::InvalidKey);
    }
    let restored = RecoveryAdmissionController::restore(policy, snapshot, key)
        .map_err(StartupAdmissionError::Admission)?;
    restored
        .admit_release()
        .map_err(StartupAdmissionError::Admission)?;
    if permit.policy_epoch != snapshot.policy_epoch
        || permit.weighted_backlog != snapshot.weighted_backlog
        || permit.snapshot_authenticator != snapshot.authenticator
        || permit.authenticator != authenticate(permit, key)
    {
        return Err(StartupAdmissionError::PermitAuthenticationFailed);
    }
    Ok(())
}

fn authenticate(mut value: StartupAdmissionPermit, key: [u8; 32]) -> [u8; 32] {
    value.authenticator = [0; 32];
    let mut bytes = Vec::with_capacity(DOMAIN.len() + 48);
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&value.policy_epoch.to_be_bytes());
    bytes.extend_from_slice(&value.weighted_backlog.to_be_bytes());
    bytes.extend_from_slice(&value.snapshot_authenticator);
    hmac_sha256(key, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery_admission::seal_policy;
    use crate::TransactionId;
    const KEY: [u8; 32] = [7; 32];
    fn policy() -> AdmissionPolicy {
        seal_policy(1, 2, 3, 10, 4, KEY).unwrap()
    }
    fn entry(value: u8, state: OutboxState) -> OutboxEntry {
        (
            DeliveryIntent {
                transaction_id: TransactionId([value; 32]),
                public_trace_digest: [value + 1; 32],
                release_sequence: value.into(),
                policy_epoch: 4,
                receipt_epoch: 5,
            },
            state,
            if state == OutboxState::Pending {
                [0; 32]
            } else {
                [value + 10; 32]
            },
        )
    }

    #[test]
    fn over_budget_restart_has_no_release_permit() {
        let mut controller = RecoveryAdmissionController::new(policy(), KEY).unwrap();
        let entries = [
            entry(1, OutboxState::Pending),
            entry(2, OutboxState::Delivered),
            entry(3, OutboxState::Delivered),
            entry(4, OutboxState::Delivered),
        ];
        let decision = evaluate_startup_admission(&mut controller, &entries, KEY).unwrap();
        assert_eq!((decision.pending, decision.delivered), (1, 3));
        assert!(decision.permit.is_none());
        let restored =
            RecoveryAdmissionController::restore(policy(), decision.snapshot, KEY).unwrap();
        assert_eq!(
            restored.admit_release(),
            Err(AdmissionError::AdmissionHalted)
        );
    }

    #[test]
    fn recovery_below_low_watermark_issues_verifiable_permit() {
        let mut controller = RecoveryAdmissionController::new(policy(), KEY).unwrap();
        evaluate_startup_admission(&mut controller, &[entry(1, OutboxState::Delivered); 4], KEY)
            .unwrap();
        let decision =
            evaluate_startup_admission(&mut controller, &[entry(2, OutboxState::Pending)], KEY)
                .unwrap();
        let permit = decision.permit.unwrap();
        assert_eq!(
            verify_startup_admission(policy(), decision.snapshot, permit, KEY),
            Ok(())
        );
    }

    #[test]
    fn substituted_snapshot_or_permit_is_rejected() {
        let mut controller = RecoveryAdmissionController::new(policy(), KEY).unwrap();
        let decision = evaluate_startup_admission(&mut controller, &[], KEY).unwrap();
        let mut permit = decision.permit.unwrap();
        permit.weighted_backlog += 1;
        assert_eq!(
            verify_startup_admission(policy(), decision.snapshot, permit, KEY),
            Err(StartupAdmissionError::PermitAuthenticationFailed)
        );
    }
}
