//! Immutable identity of the certified repair being monitored.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepairDeploymentIdentity {
    pub repair_certificate_digest: [u8; 32],
    pub deployment_permit_digest: [u8; 32],
    pub policy_epoch: u64,
    pub deployment_sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeploymentIdentityError {
    ZeroDigest,
    ZeroEpoch,
    ZeroSequence,
}

impl RepairDeploymentIdentity {
    pub fn new(
        repair_certificate_digest: [u8; 32],
        deployment_permit_digest: [u8; 32],
        policy_epoch: u64,
        deployment_sequence: u64,
    ) -> Result<Self, DeploymentIdentityError> {
        if repair_certificate_digest == [0; 32] || deployment_permit_digest == [0; 32] {
            return Err(DeploymentIdentityError::ZeroDigest);
        }
        if policy_epoch == 0 {
            return Err(DeploymentIdentityError::ZeroEpoch);
        }
        if deployment_sequence == 0 {
            return Err(DeploymentIdentityError::ZeroSequence);
        }
        Ok(Self {
            repair_certificate_digest,
            deployment_permit_digest,
            policy_epoch,
            deployment_sequence,
        })
    }

    #[must_use]
    pub fn digest(self) -> [u8; 32] {
        let mut bytes = b"noticer.quotient-sentinel.deployment.v1\0".to_vec();
        bytes.extend_from_slice(&self.repair_certificate_digest);
        bytes.extend_from_slice(&self.deployment_permit_digest);
        bytes.extend_from_slice(&self.policy_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.deployment_sequence.to_be_bytes());
        crate::sha256::sha256(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_and_sequence_are_bound() {
        let a = RepairDeploymentIdentity::new([1; 32], [2; 32], 3, 4).unwrap();
        let b = RepairDeploymentIdentity::new([1; 32], [2; 32], 3, 5).unwrap();
        assert_ne!(a.digest(), b.digest());
    }
}
