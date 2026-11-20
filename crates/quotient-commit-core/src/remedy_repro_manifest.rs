//! Reproducibility manifest bound to a repair search.

const DOMAIN: &[u8] = b"noticer.quotient-remedy.repro.v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepairReproManifest {
    pub engine_version: String,
    pub model_digest: [u8; 32],
    pub seed: u64,
    pub node_limit: u32,
    pub world_limit: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifestError {
    EmptyVersion,
    NonAsciiVersion,
    ZeroModel,
    ZeroBudget,
}

impl RepairReproManifest {
    pub fn new(
        engine_version: impl Into<String>,
        model_digest: [u8; 32],
        seed: u64,
        node_limit: u32,
        world_limit: u32,
    ) -> Result<Self, ManifestError> {
        let engine_version = engine_version.into();
        if engine_version.is_empty() {
            return Err(ManifestError::EmptyVersion);
        }
        if !engine_version.is_ascii() {
            return Err(ManifestError::NonAsciiVersion);
        }
        if model_digest == [0; 32] {
            return Err(ManifestError::ZeroModel);
        }
        if node_limit == 0 || world_limit == 0 {
            return Err(ManifestError::ZeroBudget);
        }
        Ok(Self {
            engine_version,
            model_digest,
            seed,
            node_limit,
            world_limit,
        })
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(DOMAIN);
        bytes.extend_from_slice(self.engine_version.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&self.model_digest);
        bytes.extend_from_slice(&self.seed.to_be_bytes());
        bytes.extend_from_slice(&self.node_limit.to_be_bytes());
        bytes.extend_from_slice(&self.world_limit.to_be_bytes());
        crate::sha256::sha256(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_and_budget_are_committed() {
        let a = RepairReproManifest::new("1.0", [1; 32], 7, 10, 20).unwrap();
        let b = RepairReproManifest::new("1.0", [1; 32], 8, 10, 20).unwrap();
        assert_ne!(a.digest(), b.digest());
    }
}
