//! Authentication envelope for canonical oracle artifacts.

use crate::{
    oracle_artifact::{ArtifactError, OracleArtifact},
    receipt::hmac_sha256,
};

const DOMAIN: &[u8] = b"noticer.oracle.authenticated-artifact.v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedArtifact {
    pub artifact: OracleArtifact,
    authenticator: [u8; 32],
}

impl AuthenticatedArtifact {
    pub fn issue(key: [u8; 32], artifact: OracleArtifact) -> Result<Self, ArtifactError> {
        artifact.validate()?;
        let authenticator = authenticate(key, &artifact);
        Ok(Self {
            artifact,
            authenticator,
        })
    }

    pub fn verify(&self, key: [u8; 32]) -> bool {
        self.artifact.validate().is_ok() && self.authenticator == authenticate(key, &self.artifact)
    }

    pub fn authenticator(&self) -> [u8; 32] {
        self.authenticator
    }
}

fn authenticate(key: [u8; 32], artifact: &OracleArtifact) -> [u8; 32] {
    let canonical = artifact.canonical_bytes();
    let mut bytes = Vec::with_capacity(DOMAIN.len() + canonical.len());
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&canonical);
    hmac_sha256(key, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{oracle_artifact::ExplorationRecord, oracle_verdict::OracleVerdict};

    fn artifact() -> OracleArtifact {
        OracleArtifact::new(
            3,
            OracleVerdict::Verified { explored: 5 },
            vec![],
            ExplorationRecord {
                explored_nodes: 5,
                explored_transitions: 9,
                maximum_depth: 2,
            },
            [[1; 32], [1; 32]],
        )
        .unwrap()
    }

    #[test]
    fn issued_artifact_verifies() {
        let envelope = AuthenticatedArtifact::issue([7; 32], artifact()).unwrap();
        assert!(envelope.verify([7; 32]));
    }

    #[test]
    fn wrong_key_is_rejected() {
        let envelope = AuthenticatedArtifact::issue([7; 32], artifact()).unwrap();
        assert!(!envelope.verify([8; 32]));
    }

    #[test]
    fn modified_exploration_is_rejected() {
        let mut envelope = AuthenticatedArtifact::issue([7; 32], artifact()).unwrap();
        envelope.artifact.exploration.explored_nodes += 1;
        assert!(!envelope.verify([7; 32]));
    }
}
