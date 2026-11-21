//! Authorization gate binding revocation, rollback proof, and policy epoch.

use crate::sentinel_revocation::RepairRevocationCertificate;
use crate::sentinel_rollback_plan::CertifiedRollbackPlan;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RollbackPermit {
    pub revocation_digest: [u8; 32],
    pub rollback_plan_digest: [u8; 32],
    pub target_policy_epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollbackGateError {
    DeploymentMismatch,
    EpochMismatch,
    UnauthenticatedRevocation,
    UnauthenticatedPlan,
}

pub fn authorize(
    revocation: RepairRevocationCertificate,
    plan: CertifiedRollbackPlan,
    active_policy_epoch: u64,
    revocation_authenticated: bool,
    plan_authenticated: bool,
) -> Result<RollbackPermit, RollbackGateError> {
    if revocation.deployment_identity_digest != plan.deployment_identity_digest {
        return Err(RollbackGateError::DeploymentMismatch);
    }
    if plan.target_policy_epoch != active_policy_epoch {
        return Err(RollbackGateError::EpochMismatch);
    }
    if !revocation_authenticated {
        return Err(RollbackGateError::UnauthenticatedRevocation);
    }
    if !plan_authenticated {
        return Err(RollbackGateError::UnauthenticatedPlan);
    }
    Ok(RollbackPermit {
        revocation_digest: revocation.digest(),
        rollback_plan_digest: plan.digest(),
        target_policy_epoch: active_policy_epoch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sentinel_revocation::RevocationReason;

    #[test]
    fn unauthenticated_revocation_cannot_rollback() {
        let revocation = RepairRevocationCertificate::new(
            [1; 32],
            [2; 32],
            3,
            RevocationReason::SafetyViolation,
        )
        .unwrap();
        let plan = CertifiedRollbackPlan::new([1; 32], [4; 32], [5; 32], [6; 32], 7).unwrap();
        assert_eq!(
            authorize(revocation, plan, 7, false, true),
            Err(RollbackGateError::UnauthenticatedRevocation)
        );
    }
}
