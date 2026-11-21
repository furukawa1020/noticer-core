//! Sequence and nonce replay protection for runtime assurance artifacts.

use std::collections::BTreeSet;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeReplayProtection {
    last_sequence: u64,
    seen_nonces: BTreeSet<[u8; 16]>,
    nonce_limit: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayProtectionError {
    ZeroLimit,
    SequenceReplay,
    NonceReplay,
    NonceCapacity,
}

impl RuntimeReplayProtection {
    pub fn new(nonce_limit: usize) -> Result<Self, ReplayProtectionError> {
        if nonce_limit == 0 {
            return Err(ReplayProtectionError::ZeroLimit);
        }
        Ok(Self {
            last_sequence: 0,
            seen_nonces: BTreeSet::new(),
            nonce_limit,
        })
    }

    pub fn admit(&mut self, sequence: u64, nonce: [u8; 16]) -> Result<(), ReplayProtectionError> {
        if sequence <= self.last_sequence {
            return Err(ReplayProtectionError::SequenceReplay);
        }
        if self.seen_nonces.contains(&nonce) {
            return Err(ReplayProtectionError::NonceReplay);
        }
        if self.seen_nonces.len() >= self.nonce_limit {
            return Err(ReplayProtectionError::NonceCapacity);
        }
        self.last_sequence = sequence;
        self.seen_nonces.insert(nonce);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_and_nonce_replays_are_rejected() {
        let mut guard = RuntimeReplayProtection::new(2).unwrap();
        assert_eq!(guard.admit(1, [1; 16]), Ok(()));
        assert_eq!(
            guard.admit(1, [2; 16]),
            Err(ReplayProtectionError::SequenceReplay)
        );
        assert_eq!(
            guard.admit(2, [1; 16]),
            Err(ReplayProtectionError::NonceReplay)
        );
    }
}
