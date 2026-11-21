//! Certified target and preconditions for rolling back a deployed repair.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertifiedRollbackPlan {
    pub deployment_identity_digest: [u8; 32],
    pub current_configuration_digest: [u8; 32],
    pub target_configuration_digest: [u8; 32],
    pub target_safety_proof_digest: [u8; 32],
    pub target_policy_epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollbackPlanError {
    ZeroBinding,
    SameConfiguration,
    ZeroEpoch,
}

impl CertifiedRollbackPlan {
    pub fn new(
        deployment_identity_digest: [u8; 32],
        current_configuration_digest: [u8; 32],
        target_configuration_digest: [u8; 32],
        target_safety_proof_digest: [u8; 32],
        target_policy_epoch: u64,
    ) -> Result<Self, RollbackPlanError> {
        if [
            deployment_identity_digest,
            current_configuration_digest,
            target_configuration_digest,
            target_safety_proof_digest,
        ]
        .contains(&[0; 32])
        {
            return Err(RollbackPlanError::ZeroBinding);
        }
        if current_configuration_digest == target_configuration_digest {
            return Err(RollbackPlanError::SameConfiguration);
        }
        if target_policy_epoch == 0 {
            return Err(RollbackPlanError::ZeroEpoch);
        }
        Ok(Self {
            deployment_identity_digest,
            current_configuration_digest,
            target_configuration_digest,
            target_safety_proof_digest,
            target_policy_epoch,
        })
    }

    #[must_use]
    pub fn digest(self) -> [u8; 32] {
        let mut bytes = b"noticer.quotient-sentinel.rollback-plan.v1\0".to_vec();
        for digest in [
            self.deployment_identity_digest,
            self.current_configuration_digest,
            self.target_configuration_digest,
            self.target_safety_proof_digest,
        ] {
            bytes.extend_from_slice(&digest);
        }
        bytes.extend_from_slice(&self.target_policy_epoch.to_be_bytes());
        crate::sha256::sha256(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_op_rollback_is_invalid() {
        assert_eq!(
            CertifiedRollbackPlan::new([1; 32], [2; 32], [2; 32], [3; 32], 1),
            Err(RollbackPlanError::SameConfiguration)
        );
    }
}
