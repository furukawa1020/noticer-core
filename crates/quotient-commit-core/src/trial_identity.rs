//! Immutable identity for one reproducible comparison trial.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrialIdentity {
    pub system_digest: [u8; 32],
    pub workload_digest: [u8; 32],
    pub environment_digest: [u8; 32],
    pub commit_digest: [u8; 32],
    pub seed: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrialIdentityError {
    ZeroBinding,
}

impl TrialIdentity {
    pub fn new(
        system_digest: [u8; 32],
        workload_digest: [u8; 32],
        environment_digest: [u8; 32],
        commit_digest: [u8; 32],
        seed: u64,
    ) -> Result<Self, TrialIdentityError> {
        if [
            system_digest,
            workload_digest,
            environment_digest,
            commit_digest,
        ]
        .contains(&[0; 32])
        {
            return Err(TrialIdentityError::ZeroBinding);
        }
        Ok(Self {
            system_digest,
            workload_digest,
            environment_digest,
            commit_digest,
            seed,
        })
    }

    #[must_use]
    pub fn digest(self) -> [u8; 32] {
        let mut bytes = b"noticer.quotient-trial.identity.v1\0".to_vec();
        for digest in [
            self.system_digest,
            self.workload_digest,
            self.environment_digest,
            self.commit_digest,
        ] {
            bytes.extend_from_slice(&digest);
        }
        bytes.extend_from_slice(&self.seed.to_be_bytes());
        crate::sha256::sha256(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn seed_is_committed() {
        let a = TrialIdentity::new([1; 32], [2; 32], [3; 32], [4; 32], 5).unwrap();
        let b = TrialIdentity::new([1; 32], [2; 32], [3; 32], [4; 32], 6).unwrap();
        assert_ne!(a.digest(), b.digest());
    }
}
