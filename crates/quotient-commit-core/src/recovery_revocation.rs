//! Authenticated monotonic revocation registry for recovery proofs.

use crate::receipt::hmac_sha256;
use std::collections::BTreeMap;
const DOMAIN: &[u8] = b"noticer.recovery-revocation.v1\0";
const MAX_ENTRIES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RevocationReason {
    Compromised = 1,
    Misissued = 2,
    Superseded = 3,
    PolicyViolation = 4,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevocationEntry {
    pub proof_digest: [u8; 32],
    pub epoch: u64,
    pub reason: RevocationReason,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationSnapshot {
    pub generation: u64,
    pub entries: Vec<RevocationEntry>,
    pub authenticator: [u8; 32],
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RevocationRegistry {
    generation: u64,
    entries: BTreeMap<[u8; 32], RevocationEntry>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationError {
    InvalidDigest,
    InvalidEpoch,
    AlreadyRevoked,
    CapacityExceeded,
    InvalidKey,
    AuthenticationFailed,
    Rollback,
}

impl RevocationRegistry {
    pub fn revoke(
        &mut self,
        proof_digest: [u8; 32],
        epoch: u64,
        reason: RevocationReason,
    ) -> Result<(), RevocationError> {
        if proof_digest == [0; 32] {
            return Err(RevocationError::InvalidDigest);
        }
        if epoch == 0 {
            return Err(RevocationError::InvalidEpoch);
        }
        if self.entries.contains_key(&proof_digest) {
            return Err(RevocationError::AlreadyRevoked);
        }
        if self.entries.len() >= MAX_ENTRIES {
            return Err(RevocationError::CapacityExceeded);
        }
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(RevocationError::CapacityExceeded)?;
        self.entries.insert(
            proof_digest,
            RevocationEntry {
                proof_digest,
                epoch,
                reason,
            },
        );
        Ok(())
    }
    #[must_use]
    pub fn is_revoked(&self, digest: [u8; 32]) -> bool {
        self.entries.contains_key(&digest)
    }
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub fn snapshot(&self, key: [u8; 32]) -> Result<RevocationSnapshot, RevocationError> {
        if key == [0; 32] {
            return Err(RevocationError::InvalidKey);
        }
        let mut value = RevocationSnapshot {
            generation: self.generation,
            entries: self.entries.values().copied().collect(),
            authenticator: [0; 32],
        };
        value.authenticator = authenticate(&value, key);
        Ok(value)
    }
    pub fn restore(
        value: RevocationSnapshot,
        minimum_generation: u64,
        key: [u8; 32],
    ) -> Result<Self, RevocationError> {
        if key == [0; 32] {
            return Err(RevocationError::InvalidKey);
        }
        if value.generation < minimum_generation {
            return Err(RevocationError::Rollback);
        }
        if value.entries.len() > MAX_ENTRIES || value.authenticator != authenticate(&value, key) {
            return Err(RevocationError::AuthenticationFailed);
        }
        let entries: BTreeMap<_, _> = value
            .entries
            .iter()
            .map(|entry| (entry.proof_digest, *entry))
            .collect();
        if entries.len() != value.entries.len()
            || entries
                .values()
                .any(|entry| entry.proof_digest == [0; 32] || entry.epoch == 0)
        {
            return Err(RevocationError::AuthenticationFailed);
        }
        Ok(Self {
            generation: value.generation,
            entries,
        })
    }
}
fn authenticate(value: &RevocationSnapshot, key: [u8; 32]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(DOMAIN.len() + 16 + value.entries.len() * 41);
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&value.generation.to_be_bytes());
    bytes.extend_from_slice(&(value.entries.len() as u64).to_be_bytes());
    for entry in &value.entries {
        bytes.extend_from_slice(&entry.proof_digest);
        bytes.extend_from_slice(&entry.epoch.to_be_bytes());
        bytes.push(entry.reason as u8);
    }
    hmac_sha256(key, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    const KEY: [u8; 32] = [8; 32];
    #[test]
    fn revocation_survives_authenticated_restore() {
        let mut registry = RevocationRegistry::default();
        registry
            .revoke([1; 32], 3, RevocationReason::Compromised)
            .unwrap();
        let snapshot = registry.snapshot(KEY).unwrap();
        let restored = RevocationRegistry::restore(snapshot, registry.generation(), KEY).unwrap();
        assert!(restored.is_revoked([1; 32]));
    }
    #[test]
    fn duplicate_rollback_and_tampering_fail() {
        let mut registry = RevocationRegistry::default();
        registry
            .revoke([1; 32], 3, RevocationReason::Misissued)
            .unwrap();
        assert_eq!(
            registry.revoke([1; 32], 4, RevocationReason::Superseded),
            Err(RevocationError::AlreadyRevoked)
        );
        let mut snapshot = registry.snapshot(KEY).unwrap();
        assert_eq!(
            RevocationRegistry::restore(snapshot.clone(), 2, KEY),
            Err(RevocationError::Rollback)
        );
        snapshot.authenticator[0] ^= 1;
        assert_eq!(
            RevocationRegistry::restore(snapshot, 0, KEY),
            Err(RevocationError::AuthenticationFailed)
        );
    }
}
