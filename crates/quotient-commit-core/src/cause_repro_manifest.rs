//! Authenticated reproducibility manifest for QuotientCause runs.

use crate::{cause_budget::CausalLimits, receipt::hmac_sha256};

const DOMAIN: &[u8] = b"noticer.quotient-cause.repro-manifest.v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CausalityManifest {
    pub seed: [u8; 32],
    pub model_digest: [u8; 32],
    pub limits: CausalLimits,
    pub engine_versions: [u32; 2],
    pub certificate_authenticator: [u8; 32],
    authenticator: [u8; 32],
}

impl CausalityManifest {
    pub fn issue(
        key: [u8; 32],
        seed: [u8; 32],
        model_digest: [u8; 32],
        limits: CausalLimits,
        engine_versions: [u32; 2],
        certificate_authenticator: [u8; 32],
    ) -> Self {
        let authenticator = authenticate(
            key,
            seed,
            model_digest,
            limits,
            engine_versions,
            certificate_authenticator,
        );
        Self {
            seed,
            model_digest,
            limits,
            engine_versions,
            certificate_authenticator,
            authenticator,
        }
    }

    pub fn verify(&self, key: [u8; 32]) -> bool {
        self.authenticator
            == authenticate(
                key,
                self.seed,
                self.model_digest,
                self.limits,
                self.engine_versions,
                self.certificate_authenticator,
            )
    }
}

fn authenticate(
    key: [u8; 32],
    seed: [u8; 32],
    model: [u8; 32],
    limits: CausalLimits,
    engines: [u32; 2],
    certificate: [u8; 32],
) -> [u8; 32] {
    let mut bytes = DOMAIN.to_vec();
    bytes.extend_from_slice(&seed);
    bytes.extend_from_slice(&model);
    bytes.extend_from_slice(&limits.maximum_worlds.to_be_bytes());
    bytes.extend_from_slice(&limits.maximum_interventions.to_be_bytes());
    bytes.extend_from_slice(&limits.maximum_depth.to_be_bytes());
    bytes.extend_from_slice(&engines[0].to_be_bytes());
    bytes.extend_from_slice(&engines[1].to_be_bytes());
    bytes.extend_from_slice(&certificate);
    hmac_sha256(key, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> CausalityManifest {
        CausalityManifest::issue(
            [9; 32],
            [1; 32],
            [2; 32],
            CausalLimits {
                maximum_worlds: 10,
                maximum_interventions: 20,
                maximum_depth: 3,
            },
            [1, 2],
            [7; 32],
        )
    }

    #[test]
    fn exact_manifest_verifies() {
        assert!(manifest().verify([9; 32]));
    }

    #[test]
    fn changed_limit_or_engine_is_detected() {
        let mut limits = manifest();
        limits.limits.maximum_worlds += 1;
        assert!(!limits.verify([9; 32]));
        let mut engine = manifest();
        engine.engine_versions[1] += 1;
        assert!(!engine.verify([9; 32]));
    }
}
