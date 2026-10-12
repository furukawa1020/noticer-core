//! Durable coordination between receipt-chain state and its backing store.

use crate::receipt::SealedReceipt;
use crate::receipt_file::{ReceiptFileError, ReceiptStore};
use crate::receipt_log::{ReceiptCheckpoint, ReceiptLog, ReceiptLogError, ReceiptLogRecord};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptCoordinatorError {
    Store(ReceiptFileError),
    Log(ReceiptLogError),
}

#[derive(Debug)]
pub struct DurableReceiptLog<S> {
    log: ReceiptLog,
    store: S,
    key: [u8; 32],
    maximum_records: usize,
}

impl<S: ReceiptStore> DurableReceiptLog<S> {
    pub fn open(
        store: S,
        key: [u8; 32],
        maximum_records: usize,
    ) -> Result<Self, ReceiptCoordinatorError> {
        let records = store.load().map_err(ReceiptCoordinatorError::Store)?;
        let log = ReceiptLog::replay(records, key, maximum_records)
            .map_err(ReceiptCoordinatorError::Log)?;
        Ok(Self {
            log,
            store,
            key,
            maximum_records,
        })
    }

    pub fn append(
        &mut self,
        receipt: SealedReceipt,
    ) -> Result<ReceiptLogRecord, ReceiptCoordinatorError> {
        let mut candidate =
            ReceiptLog::replay(self.log.records().to_vec(), self.key, self.maximum_records)
                .map_err(ReceiptCoordinatorError::Log)?;
        let record = candidate
            .append(receipt)
            .map_err(ReceiptCoordinatorError::Log)?;
        self.store
            .append_and_sync(record)
            .map_err(ReceiptCoordinatorError::Store)?;
        self.log = candidate;
        Ok(record)
    }

    #[must_use]
    pub fn checkpoint(&self) -> ReceiptCheckpoint {
        self.log.checkpoint()
    }

    #[must_use]
    pub fn records(&self) -> &[ReceiptLogRecord] {
        self.log.records()
    }

    pub fn into_store(self) -> S {
        self.store
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery::{DeliveryOutcome, DeliveryReceipt};
    use crate::receipt::seal_receipt;
    use crate::TransactionId;

    const KEY: [u8; 32] = [7; 32];

    #[derive(Debug, Default)]
    struct MemoryReceiptStore {
        records: Vec<ReceiptLogRecord>,
        fail_next: bool,
    }

    impl ReceiptStore for MemoryReceiptStore {
        fn append_and_sync(&mut self, record: ReceiptLogRecord) -> Result<(), ReceiptFileError> {
            if self.fail_next {
                self.fail_next = false;
                return Err(ReceiptFileError::IoFailure);
            }
            self.records.push(record);
            Ok(())
        }

        fn load(&self) -> Result<Vec<ReceiptLogRecord>, ReceiptFileError> {
            Ok(self.records.clone())
        }
    }

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

    #[test]
    fn synced_append_advances_memory_and_survives_restart() {
        let mut durable = DurableReceiptLog::open(MemoryReceiptStore::default(), KEY, 8).unwrap();
        durable.append(sealed(1)).unwrap();
        let checkpoint = durable.checkpoint();
        let recovered = DurableReceiptLog::open(durable.into_store(), KEY, 8).unwrap();
        assert_eq!(recovered.records().len(), 1);
        assert_eq!(recovered.checkpoint(), checkpoint);
    }

    #[test]
    fn failed_sync_never_advances_live_chain() {
        let store = MemoryReceiptStore {
            fail_next: true,
            ..MemoryReceiptStore::default()
        };
        let mut durable = DurableReceiptLog::open(store, KEY, 8).unwrap();
        assert_eq!(
            durable.append(sealed(1)),
            Err(ReceiptCoordinatorError::Store(ReceiptFileError::IoFailure))
        );
        assert!(durable.records().is_empty());
        assert_eq!(durable.checkpoint().record_count, 0);
        durable.append(sealed(1)).unwrap();
        assert_eq!(durable.records().len(), 1);
    }

    #[test]
    fn startup_rejects_tampered_persisted_chain() {
        let mut durable = DurableReceiptLog::open(MemoryReceiptStore::default(), KEY, 8).unwrap();
        durable.append(sealed(1)).unwrap();
        let mut store = durable.into_store();
        store.records[0].authenticator[0] ^= 1;
        assert_eq!(
            DurableReceiptLog::open(store, KEY, 8).unwrap_err(),
            ReceiptCoordinatorError::Log(ReceiptLogError::ChainMismatch)
        );
    }
}
