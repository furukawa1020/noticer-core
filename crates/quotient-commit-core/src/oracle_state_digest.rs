//! Domain-separated digest for an oracle state pair.

use crate::{oracle_state_pair::StatePair, receipt::hmac_sha256};

const DOMAIN: &[u8] = b"noticer.oracle.state-pair.v1\0";

/// Computes a deterministic digest bound to the ordered left/right states.
pub fn digest(pair: &StatePair) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(DOMAIN.len() + 16 + pair.left.len() + pair.right.len());
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&pair.slot.to_be_bytes());
    bytes.extend_from_slice(&(pair.left.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&pair.left);
    bytes.extend_from_slice(&(pair.right.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&pair.right);
    hmac_sha256([0; 32], &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(left: &[u8], right: &[u8]) -> StatePair {
        StatePair {
            slot: 4,
            left: left.to_vec(),
            right: right.to_vec(),
        }
    }

    #[test]
    fn digest_is_deterministic() {
        let value = pair(b"left", b"right");
        assert_eq!(digest(&value), digest(&value));
    }

    #[test]
    fn left_right_order_is_bound() {
        assert_ne!(digest(&pair(b"a", b"b")), digest(&pair(b"b", b"a")));
    }

    #[test]
    fn lengths_prevent_concatenation_ambiguity() {
        assert_ne!(digest(&pair(b"a", b"bc")), digest(&pair(b"ab", b"c")));
    }
}
