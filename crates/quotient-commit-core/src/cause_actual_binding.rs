//! Authenticated binding of an actual world to its causal model.

use crate::{cause_state::CausalState, receipt::hmac_sha256};

const DOMAIN: &[u8] = b"noticer.quotient-cause.actual-world.v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActualWorldBinding {
    pub state_digest: [u8; 32],
    pub model_digest: [u8; 32],
    pub model_version: u32,
    authenticator: [u8; 32],
}

impl ActualWorldBinding {
    pub fn issue(
        key: [u8; 32],
        state: &CausalState,
        model_digest: [u8; 32],
        model_version: u32,
    ) -> Self {
        let state_digest = hmac_sha256([0; 32], &state.canonical_bytes());
        let authenticator = authenticate(key, state_digest, model_digest, model_version);
        Self {
            state_digest,
            model_digest,
            model_version,
            authenticator,
        }
    }

    pub fn verify(
        &self,
        key: [u8; 32],
        state: &CausalState,
        expected_model: [u8; 32],
        expected_version: u32,
    ) -> bool {
        let state_digest = hmac_sha256([0; 32], &state.canonical_bytes());
        self.state_digest == state_digest
            && self.model_digest == expected_model
            && self.model_version == expected_version
            && self.authenticator
                == authenticate(key, state_digest, expected_model, expected_version)
    }
}

fn authenticate(
    key: [u8; 32],
    state_digest: [u8; 32],
    model_digest: [u8; 32],
    version: u32,
) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(DOMAIN.len() + 68);
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&state_digest);
    bytes.extend_from_slice(&model_digest);
    bytes.extend_from_slice(&version.to_be_bytes());
    hmac_sha256(key, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(outcome: bool) -> CausalState {
        CausalState::create(1, vec![], outcome).unwrap()
    }

    #[test]
    fn exact_actual_world_verifies() {
        let binding = ActualWorldBinding::issue([7; 32], &state(true), [3; 32], 2);
        assert!(binding.verify([7; 32], &state(true), [3; 32], 2));
    }

    #[test]
    fn state_substitution_is_rejected() {
        let binding = ActualWorldBinding::issue([7; 32], &state(true), [3; 32], 2);
        assert!(!binding.verify([7; 32], &state(false), [3; 32], 2));
    }

    #[test]
    fn model_substitution_is_rejected() {
        let binding = ActualWorldBinding::issue([7; 32], &state(true), [3; 32], 2);
        assert!(!binding.verify([7; 32], &state(true), [4; 32], 2));
    }
}
