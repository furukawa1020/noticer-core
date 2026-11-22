//! Reproducibility commitment for toolchain, environment, config, and data.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrialReproManifest {
    pub commit_digest: [u8; 32],
    pub toolchain_digest: [u8; 32],
    pub operating_system_digest: [u8; 32],
    pub configuration_digest: [u8; 32],
    pub dataset_digest: [u8; 32],
    pub root_seed: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifestError {
    ZeroBinding,
}

impl TrialReproManifest {
    pub fn new(
        commit_digest: [u8; 32],
        toolchain_digest: [u8; 32],
        operating_system_digest: [u8; 32],
        configuration_digest: [u8; 32],
        dataset_digest: [u8; 32],
        root_seed: u64,
    ) -> Result<Self, ManifestError> {
        if [
            commit_digest,
            toolchain_digest,
            operating_system_digest,
            configuration_digest,
            dataset_digest,
        ]
        .contains(&[0; 32])
        {
            return Err(ManifestError::ZeroBinding);
        }
        Ok(Self {
            commit_digest,
            toolchain_digest,
            operating_system_digest,
            configuration_digest,
            dataset_digest,
            root_seed,
        })
    }

    #[must_use]
    pub fn digest(self) -> [u8; 32] {
        let mut bytes = b"noticer.quotient-trial.repro.v1\0".to_vec();
        for digest in [
            self.commit_digest,
            self.toolchain_digest,
            self.operating_system_digest,
            self.configuration_digest,
            self.dataset_digest,
        ] {
            bytes.extend_from_slice(&digest);
        }
        bytes.extend_from_slice(&self.root_seed.to_be_bytes());
        crate::sha256::sha256(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dataset_and_seed_are_committed() {
        let a = TrialReproManifest::new([1; 32], [2; 32], [3; 32], [4; 32], [5; 32], 6).unwrap();
        let b = TrialReproManifest::new([1; 32], [2; 32], [3; 32], [4; 32], [5; 32], 7).unwrap();
        assert_ne!(a.digest(), b.digest());
    }
}
