//! Explicit epoch key selection for delivery receipt authentication.

use crate::delivery::DeliveryReceipt;
use crate::receipt::{seal_receipt, verify_receipt, ReceiptError, SealedReceipt};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyringError {
    InvalidEpoch,
    InvalidKey,
    DuplicateEpoch,
    UnknownEpoch,
    NoActiveEpoch,
    Receipt(ReceiptError),
}

#[derive(Debug, Default)]
pub struct ReceiptKeyring {
    keys: BTreeMap<u64, [u8; 32]>,
    active_epoch: Option<u64>,
}

impl ReceiptKeyring {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, epoch: u64, key: [u8; 32]) -> Result<(), KeyringError> {
        if epoch == 0 {
            return Err(KeyringError::InvalidEpoch);
        }
        if key == [0; 32] {
            return Err(KeyringError::InvalidKey);
        }
        if self.keys.contains_key(&epoch) {
            return Err(KeyringError::DuplicateEpoch);
        }
        self.keys.insert(epoch, key);
        Ok(())
    }

    pub fn activate(&mut self, epoch: u64) -> Result<(), KeyringError> {
        if !self.keys.contains_key(&epoch) {
            return Err(KeyringError::UnknownEpoch);
        }
        self.active_epoch = Some(epoch);
        Ok(())
    }

    pub fn seal(&self, receipt: DeliveryReceipt) -> Result<SealedReceipt, KeyringError> {
        let epoch = self.active_epoch.ok_or(KeyringError::NoActiveEpoch)?;
        let key = self.keys.get(&epoch).ok_or(KeyringError::UnknownEpoch)?;
        seal_receipt(receipt, epoch, *key).map_err(KeyringError::Receipt)
    }

    #[must_use]
    pub fn verify(&self, receipt: &SealedReceipt) -> bool {
        self.keys
            .get(&receipt.sink_epoch)
            .is_some_and(|key| verify_receipt(receipt, *key))
    }

    #[must_use]
    pub fn active_epoch(&self) -> Option<u64> {
        self.active_epoch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery::DeliveryOutcome;
    use crate::TransactionId;

    fn receipt(value: u8) -> DeliveryReceipt {
        DeliveryReceipt {
            transaction_id: TransactionId([value; 32]),
            public_trace_digest: [value + 1; 32],
            release_sequence: u64::from(value),
            policy_epoch: 4,
            outcome: DeliveryOutcome::Delivered,
        }
    }

    #[test]
    fn rotation_preserves_verification_of_prior_epochs() {
        let mut ring = ReceiptKeyring::new();
        ring.register(1, [1; 32]).unwrap();
        ring.activate(1).unwrap();
        let old = ring.seal(receipt(1)).unwrap();
        ring.register(2, [2; 32]).unwrap();
        ring.activate(2).unwrap();
        let current = ring.seal(receipt(2)).unwrap();
        assert_eq!(old.sink_epoch, 1);
        assert_eq!(current.sink_epoch, 2);
        assert!(ring.verify(&old));
        assert!(ring.verify(&current));
    }

    #[test]
    fn duplicate_unknown_and_invalid_material_fail_closed() {
        let mut ring = ReceiptKeyring::new();
        assert_eq!(ring.register(0, [1; 32]), Err(KeyringError::InvalidEpoch));
        assert_eq!(ring.register(1, [0; 32]), Err(KeyringError::InvalidKey));
        ring.register(1, [1; 32]).unwrap();
        assert_eq!(ring.register(1, [2; 32]), Err(KeyringError::DuplicateEpoch));
        assert_eq!(ring.activate(2), Err(KeyringError::UnknownEpoch));
        assert_eq!(ring.seal(receipt(1)), Err(KeyringError::NoActiveEpoch));
    }

    #[test]
    fn unknown_epoch_and_cross_epoch_key_substitution_do_not_verify() {
        let mut first = ReceiptKeyring::new();
        first.register(1, [1; 32]).unwrap();
        first.activate(1).unwrap();
        let sealed = first.seal(receipt(1)).unwrap();

        let mut absent = ReceiptKeyring::new();
        absent.register(2, [2; 32]).unwrap();
        assert!(!absent.verify(&sealed));

        let mut substituted = ReceiptKeyring::new();
        substituted.register(1, [9; 32]).unwrap();
        assert!(!substituted.verify(&sealed));
    }
}
