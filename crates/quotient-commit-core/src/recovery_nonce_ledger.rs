//! Authenticated replay ledger for recovery handoff nonces.

use crate::receipt::hmac_sha256;
use std::collections::BTreeSet;

const DOMAIN: &[u8] = b"noticer.recovery-nonce-ledger.v1\0";
const MAX_ENTRIES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct NonceEntry {
    pub epoch: u64,
    pub nonce: [u8; 16],
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NonceSnapshot {
    pub version: u8,
    pub generation: u64,
    pub retained_from_epoch: u64,
    pub entries: Vec<NonceEntry>,
    pub authenticator: [u8; 32],
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NonceLedger {
    generation: u64,
    retained_from_epoch: u64,
    entries: BTreeSet<NonceEntry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NonceError {
    InvalidKey,
    InvalidEpoch,
    InvalidNonce,
    Replay,
    CapacityExceeded,
    AuthenticationFailed,
    Rollback,
}

impl NonceLedger {
    pub fn consume(&mut self, epoch: u64, nonce: [u8; 16]) -> Result<(), NonceError> {
        if epoch == 0 {
            return Err(NonceError::InvalidEpoch);
        }
        if nonce == [0; 16] {
            return Err(NonceError::InvalidNonce);
        }
        if epoch < self.retained_from_epoch {
            return Err(NonceError::Replay);
        }
        let entry = NonceEntry { epoch, nonce };
        if self.entries.contains(&entry) {
            return Err(NonceError::Replay);
        }
        if self.entries.len() >= MAX_ENTRIES {
            return Err(NonceError::CapacityExceeded);
        }
        self.entries.insert(entry);
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(NonceError::CapacityExceeded)?;
        Ok(())
    }
    pub fn prune_before(&mut self, epoch: u64) {
        self.entries.retain(|entry| entry.epoch >= epoch);
        self.retained_from_epoch = self.retained_from_epoch.max(epoch);
        self.generation = self.generation.saturating_add(1);
    }
    pub fn snapshot(&self, key: [u8; 32]) -> Result<NonceSnapshot, NonceError> {
        if key == [0; 32] {
            return Err(NonceError::InvalidKey);
        }
        let mut value = NonceSnapshot {
            version: 1,
            generation: self.generation,
            retained_from_epoch: self.retained_from_epoch,
            entries: self.entries.iter().copied().collect(),
            authenticator: [0; 32],
        };
        value.authenticator = authenticate(&value, key);
        Ok(value)
    }
    pub fn restore(
        value: NonceSnapshot,
        minimum_generation: u64,
        key: [u8; 32],
    ) -> Result<Self, NonceError> {
        if key == [0; 32] {
            return Err(NonceError::InvalidKey);
        }
        if value.generation < minimum_generation {
            return Err(NonceError::Rollback);
        }
        if value.version != 1
            || value.entries.len() > MAX_ENTRIES
            || value.authenticator != authenticate(&value, key)
        {
            return Err(NonceError::AuthenticationFailed);
        }
        let entries: BTreeSet<_> = value.entries.iter().copied().collect();
        if entries.len() != value.entries.len()
            || entries
                .iter()
                .any(|entry| entry.epoch < value.retained_from_epoch || entry.nonce == [0; 16])
        {
            return Err(NonceError::AuthenticationFailed);
        }
        Ok(Self {
            generation: value.generation,
            retained_from_epoch: value.retained_from_epoch,
            entries,
        })
    }
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

fn authenticate(value: &NonceSnapshot, key: [u8; 32]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(DOMAIN.len() + 25 + value.entries.len() * 24);
    bytes.extend_from_slice(DOMAIN);
    bytes.push(value.version);
    bytes.extend_from_slice(&value.generation.to_be_bytes());
    bytes.extend_from_slice(&value.retained_from_epoch.to_be_bytes());
    bytes.extend_from_slice(&(value.entries.len() as u64).to_be_bytes());
    for entry in &value.entries {
        bytes.extend_from_slice(&entry.epoch.to_be_bytes());
        bytes.extend_from_slice(&entry.nonce);
    }
    hmac_sha256(key, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    const KEY: [u8; 32] = [4; 32];
    #[test]
    fn replay_is_rejected_across_restore() {
        let mut ledger = NonceLedger::default();
        ledger.consume(3, [1; 16]).unwrap();
        let snapshot = ledger.snapshot(KEY).unwrap();
        let mut restored = NonceLedger::restore(snapshot, ledger.generation(), KEY).unwrap();
        assert_eq!(restored.consume(3, [1; 16]), Err(NonceError::Replay));
    }
    #[test]
    fn rollback_tampering_and_pruned_epochs_are_rejected() {
        let mut ledger = NonceLedger::default();
        ledger.consume(3, [1; 16]).unwrap();
        ledger.prune_before(4);
        let mut snapshot = ledger.snapshot(KEY).unwrap();
        assert_eq!(
            NonceLedger::restore(snapshot.clone(), snapshot.generation + 1, KEY),
            Err(NonceError::Rollback)
        );
        snapshot.authenticator[0] ^= 1;
        assert_eq!(
            NonceLedger::restore(snapshot, 0, KEY),
            Err(NonceError::AuthenticationFailed)
        );
        assert_eq!(ledger.consume(3, [2; 16]), Err(NonceError::Replay));
    }
}
