//! Authenticated transition memo entries bound to their oracle context.

use crate::{
    oracle_input::{encode, OracleInput},
    receipt::hmac_sha256,
};

const DOMAIN: &[u8] = b"noticer.oracle.transition-memo.v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransitionMemo {
    pub state_digest: [u8; 32],
    pub input: OracleInput,
    pub oracle_version: u32,
    pub result_digest: [u8; 32],
    authenticator: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoError {
    ContextMismatch,
    AuthenticationFailed,
}

impl TransitionMemo {
    pub fn issue(
        key: [u8; 32],
        state_digest: [u8; 32],
        input: OracleInput,
        oracle_version: u32,
        result_digest: [u8; 32],
    ) -> Self {
        let authenticator = authenticate(key, state_digest, &input, oracle_version, result_digest);
        Self {
            state_digest,
            input,
            oracle_version,
            result_digest,
            authenticator,
        }
    }

    pub fn verify(
        &self,
        key: [u8; 32],
        expected_state: [u8; 32],
        expected_input: &OracleInput,
        expected_version: u32,
    ) -> Result<[u8; 32], MemoError> {
        if self.state_digest != expected_state
            || &self.input != expected_input
            || self.oracle_version != expected_version
        {
            return Err(MemoError::ContextMismatch);
        }
        let expected = authenticate(
            key,
            self.state_digest,
            &self.input,
            self.oracle_version,
            self.result_digest,
        );
        if self.authenticator != expected {
            return Err(MemoError::AuthenticationFailed);
        }
        Ok(self.result_digest)
    }
}

fn authenticate(
    key: [u8; 32],
    state_digest: [u8; 32],
    input: &OracleInput,
    oracle_version: u32,
    result_digest: [u8; 32],
) -> [u8; 32] {
    let encoded_input = encode(input);
    let mut bytes = Vec::with_capacity(DOMAIN.len() + 72 + encoded_input.len());
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&state_digest);
    bytes.extend_from_slice(&(encoded_input.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&encoded_input);
    bytes.extend_from_slice(&oracle_version.to_be_bytes());
    bytes.extend_from_slice(&result_digest);
    hmac_sha256(key, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> OracleInput {
        OracleInput {
            slot: 2,
            symbols: vec![3, 4],
        }
    }

    #[test]
    fn matching_context_reuses_result() {
        let memo = TransitionMemo::issue([7; 32], [1; 32], input(), 5, [9; 32]);
        assert_eq!(memo.verify([7; 32], [1; 32], &input(), 5), Ok([9; 32]));
    }

    #[test]
    fn replay_into_other_state_is_rejected() {
        let memo = TransitionMemo::issue([7; 32], [1; 32], input(), 5, [9; 32]);
        assert_eq!(
            memo.verify([7; 32], [2; 32], &input(), 5),
            Err(MemoError::ContextMismatch)
        );
    }

    #[test]
    fn wrong_key_is_rejected() {
        let memo = TransitionMemo::issue([7; 32], [1; 32], input(), 5, [9; 32]);
        assert_eq!(
            memo.verify([8; 32], [1; 32], &input(), 5),
            Err(MemoError::AuthenticationFailed)
        );
    }
}
