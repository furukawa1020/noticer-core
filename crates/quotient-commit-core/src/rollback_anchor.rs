//! Monotonic authenticated anchor for cross-store rollback detection.

use crate::receipt::hmac_sha256;

const DOMAIN: &[u8] = b"noticer.quotient-commit.rollback-anchor.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreHeads {
    pub outbox: [u8; 32],
    pub vault: [u8; 32],
    pub audit: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RollbackAnchorRecord {
    pub generation: u64,
    pub heads: StoreHeads,
    pub previous_authenticator: [u8; 32],
    pub authenticator: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollbackAnchorError {
    InvalidKey,
    InvalidHeads,
    InvalidGeneration,
    RollbackDetected,
    ForkDetected,
    CrossStoreMismatch,
    AuthenticationFailed,
    StoreFailure,
    ResourceLimit,
}

pub trait RollbackAnchorStore {
    fn append_and_sync(&mut self, record: RollbackAnchorRecord) -> Result<(), RollbackAnchorError>;
    fn load(&self) -> Result<Vec<RollbackAnchorRecord>, RollbackAnchorError>;
}

#[derive(Debug)]
pub struct DurableRollbackAnchor<S> {
    store: S,
    key: [u8; 32],
    maximum_records: usize,
    records: Vec<RollbackAnchorRecord>,
}

impl<S: RollbackAnchorStore> DurableRollbackAnchor<S> {
    pub fn open(
        store: S,
        key: [u8; 32],
        maximum_records: usize,
    ) -> Result<Self, RollbackAnchorError> {
        if key == [0; 32] {
            return Err(RollbackAnchorError::InvalidKey);
        }
        if maximum_records == 0 {
            return Err(RollbackAnchorError::ResourceLimit);
        }
        let records = store.load()?;
        if records.len() > maximum_records {
            return Err(RollbackAnchorError::ResourceLimit);
        }
        verify_chain(&records, key)?;
        Ok(Self {
            store,
            key,
            maximum_records,
            records,
        })
    }

    pub fn advance(
        &mut self,
        heads: StoreHeads,
    ) -> Result<RollbackAnchorRecord, RollbackAnchorError> {
        validate_heads(heads)?;
        if self.records.len() >= self.maximum_records {
            return Err(RollbackAnchorError::ResourceLimit);
        }
        let generation = self.head().map_or(1, |record| record.generation + 1);
        let previous_authenticator = self.head().map_or([0; 32], |record| record.authenticator);
        let mut record = RollbackAnchorRecord {
            generation,
            heads,
            previous_authenticator,
            authenticator: [0; 32],
        };
        record.authenticator = authenticate(record, self.key);
        self.store.append_and_sync(record)?;
        self.records.push(record);
        Ok(record)
    }

    pub fn verify_snapshot(
        &self,
        generation: u64,
        heads: StoreHeads,
    ) -> Result<(), RollbackAnchorError> {
        let head = self.head().ok_or(RollbackAnchorError::InvalidGeneration)?;
        if generation < head.generation {
            return Err(RollbackAnchorError::RollbackDetected);
        }
        if generation > head.generation {
            return Err(RollbackAnchorError::ForkDetected);
        }
        if heads != head.heads {
            return Err(RollbackAnchorError::CrossStoreMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub fn head(&self) -> Option<RollbackAnchorRecord> {
        self.records.last().copied()
    }
}

fn verify_chain(
    records: &[RollbackAnchorRecord],
    key: [u8; 32],
) -> Result<(), RollbackAnchorError> {
    let mut previous = [0; 32];
    for (index, record) in records.iter().enumerate() {
        if record.generation != index as u64 + 1 {
            return Err(RollbackAnchorError::InvalidGeneration);
        }
        validate_heads(record.heads)?;
        if record.previous_authenticator != previous {
            return Err(RollbackAnchorError::ForkDetected);
        }
        if record.authenticator != authenticate(*record, key) {
            return Err(RollbackAnchorError::AuthenticationFailed);
        }
        previous = record.authenticator;
    }
    Ok(())
}

fn validate_heads(heads: StoreHeads) -> Result<(), RollbackAnchorError> {
    if heads.outbox == [0; 32] || heads.vault == [0; 32] || heads.audit == [0; 32] {
        return Err(RollbackAnchorError::InvalidHeads);
    }
    Ok(())
}

fn authenticate(mut record: RollbackAnchorRecord, key: [u8; 32]) -> [u8; 32] {
    record.authenticator = [0; 32];
    let mut bytes = Vec::with_capacity(DOMAIN.len() + 8 + 32 * 4);
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&record.generation.to_be_bytes());
    bytes.extend_from_slice(&record.heads.outbox);
    bytes.extend_from_slice(&record.heads.vault);
    bytes.extend_from_slice(&record.heads.audit);
    bytes.extend_from_slice(&record.previous_authenticator);
    hmac_sha256(key, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7; 32];

    #[derive(Debug, Default)]
    struct MemoryStore {
        records: Vec<RollbackAnchorRecord>,
        fail_next: bool,
    }

    impl RollbackAnchorStore for MemoryStore {
        fn append_and_sync(
            &mut self,
            record: RollbackAnchorRecord,
        ) -> Result<(), RollbackAnchorError> {
            if self.fail_next {
                self.fail_next = false;
                return Err(RollbackAnchorError::StoreFailure);
            }
            self.records.push(record);
            Ok(())
        }

        fn load(&self) -> Result<Vec<RollbackAnchorRecord>, RollbackAnchorError> {
            Ok(self.records.clone())
        }
    }

    fn heads(value: u8) -> StoreHeads {
        StoreHeads {
            outbox: [value; 32],
            vault: [value + 1; 32],
            audit: [value + 2; 32],
        }
    }

    #[test]
    fn rollback_fork_and_cross_store_mix_fail_closed() {
        let mut anchor = DurableRollbackAnchor::open(MemoryStore::default(), KEY, 8).unwrap();
        anchor.advance(heads(1)).unwrap();
        anchor.advance(heads(4)).unwrap();
        assert_eq!(
            anchor.verify_snapshot(1, heads(1)),
            Err(RollbackAnchorError::RollbackDetected)
        );
        assert_eq!(
            anchor.verify_snapshot(3, heads(4)),
            Err(RollbackAnchorError::ForkDetected)
        );
        let mut mixed = heads(4);
        mixed.vault = heads(1).vault;
        assert_eq!(
            anchor.verify_snapshot(2, mixed),
            Err(RollbackAnchorError::CrossStoreMismatch)
        );
    }

    #[test]
    fn failed_partial_advance_preserves_prior_generation() {
        let mut anchor = DurableRollbackAnchor::open(MemoryStore::default(), KEY, 8).unwrap();
        let first = anchor.advance(heads(1)).unwrap();
        anchor.store.fail_next = true;
        assert_eq!(
            anchor.advance(heads(4)),
            Err(RollbackAnchorError::StoreFailure)
        );
        assert_eq!(anchor.head(), Some(first));
        assert_eq!(anchor.verify_snapshot(1, heads(1)), Ok(()));
    }

    #[test]
    fn tampered_or_forked_chain_is_rejected_on_restart() {
        let mut anchor = DurableRollbackAnchor::open(MemoryStore::default(), KEY, 8).unwrap();
        anchor.advance(heads(1)).unwrap();
        anchor.advance(heads(4)).unwrap();
        let mut records = anchor.records.clone();
        records[1].heads.audit[0] ^= 1;
        assert_eq!(
            DurableRollbackAnchor::open(
                MemoryStore {
                    records,
                    fail_next: false
                },
                KEY,
                8
            )
            .unwrap_err(),
            RollbackAnchorError::AuthenticationFailed
        );
        let mut records = anchor.records;
        records[1].previous_authenticator = [9; 32];
        assert_eq!(
            DurableRollbackAnchor::open(
                MemoryStore {
                    records,
                    fail_next: false
                },
                KEY,
                8
            )
            .unwrap_err(),
            RollbackAnchorError::ForkDetected
        );
    }
}
