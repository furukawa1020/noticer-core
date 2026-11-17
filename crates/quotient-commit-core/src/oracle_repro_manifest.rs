//! Authenticated reproducibility manifest for an oracle run.

use crate::receipt::hmac_sha256;

const DOMAIN: &[u8] = b"noticer.oracle.reproducibility-manifest.v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReproducibilityManifest {
    pub seed: [u8; 32],
    pub oracle_version: u32,
    pub node_limit: u64,
    pub transition_limit: u64,
    pub depth_limit: u64,
    pub artifact_authenticator: [u8; 32],
    authenticator: [u8; 32],
}

impl ReproducibilityManifest {
    pub fn issue(
        key: [u8; 32],
        seed: [u8; 32],
        oracle_version: u32,
        node_limit: u64,
        transition_limit: u64,
        depth_limit: u64,
        artifact_authenticator: [u8; 32],
    ) -> Self {
        let authenticator = authenticate(
            key,
            seed,
            oracle_version,
            node_limit,
            transition_limit,
            depth_limit,
            artifact_authenticator,
        );
        Self {
            seed,
            oracle_version,
            node_limit,
            transition_limit,
            depth_limit,
            artifact_authenticator,
            authenticator,
        }
    }

    pub fn verify(&self, key: [u8; 32]) -> bool {
        self.authenticator
            == authenticate(
                key,
                self.seed,
                self.oracle_version,
                self.node_limit,
                self.transition_limit,
                self.depth_limit,
                self.artifact_authenticator,
            )
    }
}

#[allow(clippy::too_many_arguments)]
fn authenticate(
    key: [u8; 32],
    seed: [u8; 32],
    oracle_version: u32,
    node_limit: u64,
    transition_limit: u64,
    depth_limit: u64,
    artifact_authenticator: [u8; 32],
) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(DOMAIN.len() + 92);
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&seed);
    bytes.extend_from_slice(&oracle_version.to_be_bytes());
    bytes.extend_from_slice(&node_limit.to_be_bytes());
    bytes.extend_from_slice(&transition_limit.to_be_bytes());
    bytes.extend_from_slice(&depth_limit.to_be_bytes());
    bytes.extend_from_slice(&artifact_authenticator);
    hmac_sha256(key, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> ReproducibilityManifest {
        ReproducibilityManifest::issue([9; 32], [1; 32], 4, 100, 200, 8, [7; 32])
    }

    #[test]
    fn exact_manifest_verifies() {
        assert!(manifest().verify([9; 32]));
    }

    #[test]
    fn changed_limit_is_detected() {
        let mut value = manifest();
        value.node_limit += 1;
        assert!(!value.verify([9; 32]));
    }

    #[test]
    fn changed_seed_is_detected() {
        let mut value = manifest();
        value.seed[0] ^= 1;
        assert!(!value.verify([9; 32]));
    }
}
