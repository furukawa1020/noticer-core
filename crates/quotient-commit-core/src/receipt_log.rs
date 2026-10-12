//! Keyed append-only audit chain for sealed delivery receipts.

use crate::receipt::{hmac_sha256, verify_receipt, SealedReceipt};

const DOMAIN: &[u8] = b"noticer.quotient-commit.receipt-log.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiptLogRecord {
    pub sequence: u64,
    pub previous_authenticator: [u8; 32],
    pub receipt: SealedReceipt,
    pub authenticator: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiptCheckpoint {
    pub record_count: u64,
    pub head_authenticator: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptLogError {
    InvalidKey,
    InvalidReceipt,
    InvalidSequence,
    ChainMismatch,
    ResourceLimit,
    CheckpointMismatch,
}

#[derive(Debug)]
pub struct ReceiptLog {
    key: [u8; 32],
    maximum_records: usize,
    records: Vec<ReceiptLogRecord>,
}

impl ReceiptLog {
    pub fn new(key: [u8; 32], maximum_records: usize) -> Result<Self, ReceiptLogError> {
        if key == [0; 32] {
            return Err(ReceiptLogError::InvalidKey);
        }
        if maximum_records == 0 {
            return Err(ReceiptLogError::ResourceLimit);
        }
        Ok(Self {
            key,
            maximum_records,
            records: Vec::new(),
        })
    }

    pub fn replay(
        records: Vec<ReceiptLogRecord>,
        key: [u8; 32],
        maximum_records: usize,
    ) -> Result<Self, ReceiptLogError> {
        if records.len() > maximum_records {
            return Err(ReceiptLogError::ResourceLimit);
        }
        let mut log = Self::new(key, maximum_records)?;
        for record in records {
            let expected_sequence = log.records.len() as u64 + 1;
            let expected_previous = log.head_authenticator();
            if record.sequence != expected_sequence {
                return Err(ReceiptLogError::InvalidSequence);
            }
            if record.previous_authenticator != expected_previous {
                return Err(ReceiptLogError::ChainMismatch);
            }
            if !verify_receipt(&record.receipt, key) {
                return Err(ReceiptLogError::InvalidReceipt);
            }
            let expected = authenticate_record(
                record.sequence,
                record.previous_authenticator,
                record.receipt,
                key,
            );
            if record.authenticator != expected {
                return Err(ReceiptLogError::ChainMismatch);
            }
            log.records.push(record);
        }
        Ok(log)
    }

    pub fn append(&mut self, receipt: SealedReceipt) -> Result<ReceiptLogRecord, ReceiptLogError> {
        if self.records.len() >= self.maximum_records {
            return Err(ReceiptLogError::ResourceLimit);
        }
        if !verify_receipt(&receipt, self.key) {
            return Err(ReceiptLogError::InvalidReceipt);
        }
        let sequence = self.records.len() as u64 + 1;
        let previous_authenticator = self.head_authenticator();
        let record = ReceiptLogRecord {
            sequence,
            previous_authenticator,
            receipt,
            authenticator: authenticate_record(sequence, previous_authenticator, receipt, self.key),
        };
        self.records.push(record);
        Ok(record)
    }

    #[must_use]
    pub fn checkpoint(&self) -> ReceiptCheckpoint {
        ReceiptCheckpoint {
            record_count: self.records.len() as u64,
            head_authenticator: self.head_authenticator(),
        }
    }

    pub fn verify_checkpoint(&self, checkpoint: ReceiptCheckpoint) -> Result<(), ReceiptLogError> {
        if self.checkpoint() == checkpoint {
            Ok(())
        } else {
            Err(ReceiptLogError::CheckpointMismatch)
        }
    }

    #[must_use]
    pub fn records(&self) -> &[ReceiptLogRecord] {
        &self.records
    }

    fn head_authenticator(&self) -> [u8; 32] {
        self.records
            .last()
            .map_or([0; 32], |record| record.authenticator)
    }
}

fn authenticate_record(
    sequence: u64,
    previous: [u8; 32],
    receipt: SealedReceipt,
    key: [u8; 32],
) -> [u8; 32] {
    let mut message = Vec::with_capacity(DOMAIN.len() + 8 + 32 + 32);
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(&sequence.to_be_bytes());
    message.extend_from_slice(&previous);
    message.extend_from_slice(&receipt.authenticator);
    hmac_sha256(key, &message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery::{DeliveryOutcome, DeliveryReceipt};
    use crate::receipt::seal_receipt;
    use crate::TransactionId;

    const KEY: [u8; 32] = [7; 32];

    fn sealed(value: u8) -> SealedReceipt {
        seal_receipt(
            DeliveryReceipt {
                transaction_id: TransactionId([value; 32]),
                public_trace_digest: [value + 1; 32],
                release_sequence: u64::from(value),
                policy_epoch: 4,
                outcome: DeliveryOutcome::Delivered,
            },
            5,
            KEY,
        )
        .unwrap()
    }

    fn fixture() -> (Vec<ReceiptLogRecord>, ReceiptCheckpoint) {
        let mut log = ReceiptLog::new(KEY, 8).unwrap();
        log.append(sealed(1)).unwrap();
        log.append(sealed(2)).unwrap();
        log.append(sealed(3)).unwrap();
        (log.records().to_vec(), log.checkpoint())
    }

    #[test]
    fn intact_chain_replays_and_matches_checkpoint() {
        let (records, checkpoint) = fixture();
        let replayed = ReceiptLog::replay(records, KEY, 8).unwrap();
        assert_eq!(replayed.verify_checkpoint(checkpoint), Ok(()));
    }

    #[test]
    fn reorder_middle_deletion_and_mutation_fail_closed() {
        let (records, _) = fixture();
        let mut reordered = records.clone();
        reordered.swap(0, 1);
        assert!(ReceiptLog::replay(reordered, KEY, 8).is_err());
        let mut deleted = records.clone();
        deleted.remove(1);
        assert!(ReceiptLog::replay(deleted, KEY, 8).is_err());
        let mut mutated = records;
        mutated[1].receipt.receipt.public_trace_digest[0] ^= 1;
        assert_eq!(
            ReceiptLog::replay(mutated, KEY, 8).unwrap_err(),
            ReceiptLogError::InvalidReceipt
        );
    }

    #[test]
    fn checkpoint_detects_tail_truncation_and_wrong_key_is_rejected() {
        let (mut records, checkpoint) = fixture();
        records.pop();
        let truncated = ReceiptLog::replay(records, KEY, 8).unwrap();
        assert_eq!(
            truncated.verify_checkpoint(checkpoint),
            Err(ReceiptLogError::CheckpointMismatch)
        );
        let (records, _) = fixture();
        assert!(ReceiptLog::replay(records, [8; 32], 8).is_err());
    }

    #[test]
    fn resource_limit_is_enforced_before_append() {
        let mut log = ReceiptLog::new(KEY, 1).unwrap();
        log.append(sealed(1)).unwrap();
        assert_eq!(log.append(sealed(2)), Err(ReceiptLogError::ResourceLimit));
    }
}
