//! Append-only fork detection for recovery checkpoint generations.
use crate::receipt::hmac_sha256;
const DOMAIN: &[u8] = b"noticer.quotient-commit.recovery-equivocation-ledger.v1\0";
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EquivocationRecord {
    pub generation: u64,
    pub checkpoint_authenticator: [u8; 32],
    pub previous_authenticator: [u8; 32],
    pub authenticator: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EquivocationError {
    InvalidKey,
    InvalidGeneration,
    InvalidCheckpoint,
    RollbackDetected,
    ForkDetected,
    AuthenticationFailed,
    StoreFailure,
    ResourceLimit,
}
pub trait EquivocationStore {
    fn append_and_sync(&mut self, record: EquivocationRecord) -> Result<(), EquivocationError>;
    fn load(&self) -> Result<Vec<EquivocationRecord>, EquivocationError>;
}
#[derive(Debug)]
pub struct RecoveryEquivocationLedger<S> {
    store: S,
    key: [u8; 32],
    maximum_records: usize,
    records: Vec<EquivocationRecord>,
}
impl<S: EquivocationStore> RecoveryEquivocationLedger<S> {
    pub fn open(
        store: S,
        key: [u8; 32],
        maximum_records: usize,
    ) -> Result<Self, EquivocationError> {
        if key == [0; 32] {
            return Err(EquivocationError::InvalidKey);
        }
        if maximum_records == 0 {
            return Err(EquivocationError::ResourceLimit);
        }
        let records = store.load()?;
        if records.len() > maximum_records {
            return Err(EquivocationError::ResourceLimit);
        }
        verify_chain(&records, key)?;
        Ok(Self {
            store,
            key,
            maximum_records,
            records,
        })
    }
    pub fn observe(
        &mut self,
        generation: u64,
        checkpoint_authenticator: [u8; 32],
    ) -> Result<EquivocationRecord, EquivocationError> {
        if generation == 0 {
            return Err(EquivocationError::InvalidGeneration);
        }
        if checkpoint_authenticator == [0; 32] {
            return Err(EquivocationError::InvalidCheckpoint);
        }
        if let Some(head) = self.records.last().copied() {
            if generation < head.generation {
                return Err(EquivocationError::RollbackDetected);
            }
            if generation == head.generation {
                return if checkpoint_authenticator == head.checkpoint_authenticator {
                    Ok(head)
                } else {
                    Err(EquivocationError::ForkDetected)
                };
            }
            if generation != head.generation + 1 {
                return Err(EquivocationError::InvalidGeneration);
            }
        } else if generation != 1 {
            return Err(EquivocationError::InvalidGeneration);
        }
        if self.records.len() >= self.maximum_records {
            return Err(EquivocationError::ResourceLimit);
        }
        let mut record = EquivocationRecord {
            generation,
            checkpoint_authenticator,
            previous_authenticator: self.records.last().map_or([0; 32], |v| v.authenticator),
            authenticator: [0; 32],
        };
        record.authenticator = authenticate(record, self.key);
        self.store.append_and_sync(record)?;
        self.records.push(record);
        Ok(record)
    }
    #[must_use]
    pub fn head(&self) -> Option<EquivocationRecord> {
        self.records.last().copied()
    }
}
fn verify_chain(records: &[EquivocationRecord], key: [u8; 32]) -> Result<(), EquivocationError> {
    let mut previous = [0; 32];
    for (index, record) in records.iter().copied().enumerate() {
        if record.generation != index as u64 + 1 {
            return Err(EquivocationError::InvalidGeneration);
        }
        if record.previous_authenticator != previous {
            return Err(EquivocationError::ForkDetected);
        }
        if record.authenticator != authenticate(record, key) {
            return Err(EquivocationError::AuthenticationFailed);
        }
        previous = record.authenticator;
    }
    Ok(())
}
fn authenticate(mut r: EquivocationRecord, key: [u8; 32]) -> [u8; 32] {
    r.authenticator = [0; 32];
    let mut b = Vec::with_capacity(DOMAIN.len() + 72);
    b.extend_from_slice(DOMAIN);
    b.extend_from_slice(&r.generation.to_be_bytes());
    b.extend_from_slice(&r.checkpoint_authenticator);
    b.extend_from_slice(&r.previous_authenticator);
    hmac_sha256(key, &b)
}
#[cfg(test)]
mod tests {
    use super::*;
    const KEY: [u8; 32] = [7; 32];
    #[derive(Clone, Default, Debug)]
    struct Store(Vec<EquivocationRecord>);
    impl EquivocationStore for Store {
        fn append_and_sync(&mut self, r: EquivocationRecord) -> Result<(), EquivocationError> {
            self.0.push(r);
            Ok(())
        }
        fn load(&self) -> Result<Vec<EquivocationRecord>, EquivocationError> {
            Ok(self.0.clone())
        }
    }
    #[test]
    fn fork_and_rollback_are_distinct() {
        let mut l = RecoveryEquivocationLedger::open(Store::default(), KEY, 8).unwrap();
        l.observe(1, [1; 32]).unwrap();
        l.observe(2, [2; 32]).unwrap();
        assert_eq!(l.observe(2, [9; 32]), Err(EquivocationError::ForkDetected));
        assert_eq!(
            l.observe(1, [1; 32]),
            Err(EquivocationError::RollbackDetected)
        );
    }
    #[test]
    fn identical_observation_is_idempotent() {
        let mut l = RecoveryEquivocationLedger::open(Store::default(), KEY, 8).unwrap();
        let r = l.observe(1, [1; 32]).unwrap();
        assert_eq!(l.observe(1, [1; 32]), Ok(r));
    }
    #[test]
    fn restart_verifies_chain() {
        let mut l = RecoveryEquivocationLedger::open(Store::default(), KEY, 8).unwrap();
        l.observe(1, [1; 32]).unwrap();
        l.observe(2, [2; 32]).unwrap();
        let mut s = l.store.clone();
        assert!(RecoveryEquivocationLedger::open(s.clone(), KEY, 8).is_ok());
        s.0[1].previous_authenticator = [9; 32];
        assert_eq!(
            RecoveryEquivocationLedger::open(s, KEY, 8).unwrap_err(),
            EquivocationError::ForkDetected
        );
    }
}
