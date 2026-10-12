//! Tamper-evident authentication for public delivery receipts.

use crate::delivery::{DeliveryOutcome, DeliveryReceipt};
use crate::sha256::sha256;

const DOMAIN: &[u8] = b"noticer.quotient-commit.delivery-receipt.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SealedReceipt {
    pub receipt: DeliveryReceipt,
    pub sink_epoch: u64,
    pub authenticator: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptError {
    InvalidKey,
    InvalidSinkEpoch,
}

pub fn seal_receipt(
    receipt: DeliveryReceipt,
    sink_epoch: u64,
    authentication_key: [u8; 32],
) -> Result<SealedReceipt, ReceiptError> {
    validate(authentication_key, sink_epoch)?;
    Ok(SealedReceipt {
        receipt,
        sink_epoch,
        authenticator: authenticate(receipt, sink_epoch, authentication_key),
    })
}

#[must_use]
pub fn verify_receipt(sealed: &SealedReceipt, authentication_key: [u8; 32]) -> bool {
    if validate(authentication_key, sealed.sink_epoch).is_err() {
        return false;
    }
    constant_time_equal(
        sealed.authenticator,
        authenticate(sealed.receipt, sealed.sink_epoch, authentication_key),
    )
}

fn validate(key: [u8; 32], sink_epoch: u64) -> Result<(), ReceiptError> {
    if key == [0; 32] {
        return Err(ReceiptError::InvalidKey);
    }
    if sink_epoch == 0 {
        return Err(ReceiptError::InvalidSinkEpoch);
    }
    Ok(())
}

fn authenticate(receipt: DeliveryReceipt, sink_epoch: u64, key: [u8; 32]) -> [u8; 32] {
    let mut message = Vec::with_capacity(DOMAIN.len() + 32 + 32 + 8 * 3 + 1);
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(&receipt.transaction_id.0);
    message.extend_from_slice(&receipt.public_trace_digest);
    message.extend_from_slice(&receipt.release_sequence.to_be_bytes());
    message.extend_from_slice(&receipt.policy_epoch.to_be_bytes());
    message.push(match receipt.outcome {
        DeliveryOutcome::Delivered => 1,
        DeliveryOutcome::AlreadyDelivered => 2,
    });
    message.extend_from_slice(&sink_epoch.to_be_bytes());
    hmac_sha256(key, &message)
}

fn hmac_sha256(key: [u8; 32], message: &[u8]) -> [u8; 32] {
    let mut inner_pad = [0x36_u8; 64];
    let mut outer_pad = [0x5c_u8; 64];
    for index in 0..key.len() {
        inner_pad[index] ^= key[index];
        outer_pad[index] ^= key[index];
    }
    let mut inner = Vec::with_capacity(64 + message.len());
    inner.extend_from_slice(&inner_pad);
    inner.extend_from_slice(message);
    let inner_digest = sha256(&inner);
    let mut outer = Vec::with_capacity(96);
    outer.extend_from_slice(&outer_pad);
    outer.extend_from_slice(&inner_digest);
    sha256(&outer)
}

fn constant_time_equal(left: [u8; 32], right: [u8; 32]) -> bool {
    let mut difference = 0_u8;
    for index in 0..left.len() {
        difference |= left[index] ^ right[index];
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TransactionId;

    const KEY: [u8; 32] = [7; 32];

    fn receipt() -> DeliveryReceipt {
        DeliveryReceipt {
            transaction_id: TransactionId([1; 32]),
            public_trace_digest: [2; 32],
            release_sequence: 3,
            policy_epoch: 4,
            outcome: DeliveryOutcome::Delivered,
        }
    }

    #[test]
    fn deterministic_receipt_verifies() {
        let first = seal_receipt(receipt(), 5, KEY).unwrap();
        let second = seal_receipt(receipt(), 5, KEY).unwrap();
        assert_eq!(first, second);
        assert!(verify_receipt(&first, KEY));
    }

    #[test]
    fn every_public_binding_is_authenticated() {
        let sealed = seal_receipt(receipt(), 5, KEY).unwrap();
        let mut mutations = [sealed; 6];
        mutations[0].receipt.transaction_id.0[0] ^= 1;
        mutations[1].receipt.public_trace_digest[0] ^= 1;
        mutations[2].receipt.release_sequence += 1;
        mutations[3].receipt.policy_epoch += 1;
        mutations[4].receipt.outcome = DeliveryOutcome::AlreadyDelivered;
        mutations[5].sink_epoch += 1;
        assert!(mutations.iter().all(|value| !verify_receipt(value, KEY)));
    }

    #[test]
    fn wrong_key_and_invalid_configuration_fail_closed() {
        let sealed = seal_receipt(receipt(), 5, KEY).unwrap();
        assert!(!verify_receipt(&sealed, [8; 32]));
        assert_eq!(
            seal_receipt(receipt(), 5, [0; 32]),
            Err(ReceiptError::InvalidKey)
        );
        assert_eq!(
            seal_receipt(receipt(), 0, KEY),
            Err(ReceiptError::InvalidSinkEpoch)
        );
    }
}
