//! Deterministic certification of reachable outbox/vault/audit state products.

use crate::delivery_outbox::{DeliveryIntent, OutboxState};
use crate::receipt::hmac_sha256;
use crate::receipt_log::ReceiptLogRecord;
use crate::sealed_receipt_vault::SealedReceiptRecord;
use crate::TransactionId;
use std::collections::BTreeMap;

const DOMAIN: &[u8] = b"noticer.quotient-commit.cross-store-certificate.v1\0";
type OutboxEntry = (DeliveryIntent, OutboxState, [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsistencyCertificate {
    pub transactions: u64,
    pub pending: u64,
    pub delivered: u64,
    pub audited: u64,
    pub state_digest: [u8; 32],
    pub authenticator: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsistencyError {
    InvalidKey,
    DuplicateOutbox(TransactionId),
    DuplicateVault(TransactionId),
    DuplicateAudit(TransactionId),
    ExtraVault(TransactionId),
    ExtraAudit(TransactionId),
    MissingVault(TransactionId),
    MissingAudit(TransactionId),
    ImpossiblePendingAudit(TransactionId),
    BindingSubstitution(TransactionId),
}

pub fn certify_cross_store_state(
    outbox: &[OutboxEntry],
    vault: &[SealedReceiptRecord],
    audit: &[ReceiptLogRecord],
    key: [u8; 32],
) -> Result<ConsistencyCertificate, ConsistencyError> {
    if key == [0; 32] {
        return Err(ConsistencyError::InvalidKey);
    }
    let outbox = unique_outbox(outbox)?;
    let vault = unique_vault(vault)?;
    let audit = unique_audit(audit)?;
    for transaction_id in vault.keys() {
        if !outbox.contains_key(transaction_id) {
            return Err(ConsistencyError::ExtraVault(*transaction_id));
        }
    }
    for transaction_id in audit.keys() {
        if !outbox.contains_key(transaction_id) {
            return Err(ConsistencyError::ExtraAudit(*transaction_id));
        }
    }

    let mut pending = 0;
    let mut delivered = 0;
    let mut audited = 0;
    let mut state = Vec::new();
    for (transaction_id, (intent, outbox_state, receipt_authenticator)) in &outbox {
        let receipt = vault.get(transaction_id).copied();
        let audit_record = audit.get(transaction_id).copied();
        match outbox_state {
            OutboxState::Pending => {
                pending += 1;
                if audit_record.is_some() {
                    return Err(ConsistencyError::ImpossiblePendingAudit(*transaction_id));
                }
            }
            OutboxState::Delivered => {
                delivered += 1;
                if receipt.is_none() {
                    return Err(ConsistencyError::MissingVault(*transaction_id));
                }
            }
            OutboxState::Audited => {
                audited += 1;
                if receipt.is_none() {
                    return Err(ConsistencyError::MissingVault(*transaction_id));
                }
                if audit_record.is_none() {
                    return Err(ConsistencyError::MissingAudit(*transaction_id));
                }
            }
        }
        if let Some(record) = receipt {
            if !receipt_matches(*intent, *outbox_state, *receipt_authenticator, record) {
                return Err(ConsistencyError::BindingSubstitution(*transaction_id));
            }
        }
        if let Some(record) = audit_record {
            let Some(vault_record) = receipt else {
                return Err(ConsistencyError::MissingVault(*transaction_id));
            };
            if record.receipt != vault_record.receipt {
                return Err(ConsistencyError::BindingSubstitution(*transaction_id));
            }
        }
        state.extend_from_slice(&transaction_id.0);
        state.push(*outbox_state as u8);
        state.extend_from_slice(&intent.public_trace_digest);
        state.extend_from_slice(receipt_authenticator);
        state.extend_from_slice(&receipt.map_or([0; 32], |record| record.authenticator));
        state.extend_from_slice(&audit_record.map_or([0; 32], |record| record.authenticator));
    }
    let state_digest = hmac_sha256(key, &state);
    let mut certificate = ConsistencyCertificate {
        transactions: outbox.len() as u64,
        pending,
        delivered,
        audited,
        state_digest,
        authenticator: [0; 32],
    };
    certificate.authenticator = authenticate(certificate, key);
    Ok(certificate)
}

fn unique_outbox(
    entries: &[OutboxEntry],
) -> Result<BTreeMap<TransactionId, OutboxEntry>, ConsistencyError> {
    let mut result = BTreeMap::new();
    for entry in entries {
        if result.insert(entry.0.transaction_id, *entry).is_some() {
            return Err(ConsistencyError::DuplicateOutbox(entry.0.transaction_id));
        }
    }
    Ok(result)
}

fn unique_vault(
    entries: &[SealedReceiptRecord],
) -> Result<BTreeMap<TransactionId, SealedReceiptRecord>, ConsistencyError> {
    let mut result = BTreeMap::new();
    for entry in entries {
        let id = entry.receipt.receipt.transaction_id;
        if result.insert(id, *entry).is_some() {
            return Err(ConsistencyError::DuplicateVault(id));
        }
    }
    Ok(result)
}

fn unique_audit(
    entries: &[ReceiptLogRecord],
) -> Result<BTreeMap<TransactionId, ReceiptLogRecord>, ConsistencyError> {
    let mut result = BTreeMap::new();
    for entry in entries {
        let id = entry.receipt.receipt.transaction_id;
        if result.insert(id, *entry).is_some() {
            return Err(ConsistencyError::DuplicateAudit(id));
        }
    }
    Ok(result)
}

fn receipt_matches(
    intent: DeliveryIntent,
    state: OutboxState,
    receipt_authenticator: [u8; 32],
    record: SealedReceiptRecord,
) -> bool {
    let receipt = record.receipt;
    intent.transaction_id == receipt.receipt.transaction_id
        && intent.public_trace_digest == receipt.receipt.public_trace_digest
        && intent.release_sequence == receipt.receipt.release_sequence
        && intent.policy_epoch == receipt.receipt.policy_epoch
        && intent.receipt_epoch == receipt.sink_epoch
        && (state == OutboxState::Pending || receipt_authenticator == receipt.authenticator)
}

fn authenticate(mut value: ConsistencyCertificate, key: [u8; 32]) -> [u8; 32] {
    value.authenticator = [0; 32];
    let mut bytes = Vec::with_capacity(DOMAIN.len() + 8 * 4 + 32);
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&value.transactions.to_be_bytes());
    bytes.extend_from_slice(&value.pending.to_be_bytes());
    bytes.extend_from_slice(&value.delivered.to_be_bytes());
    bytes.extend_from_slice(&value.audited.to_be_bytes());
    bytes.extend_from_slice(&value.state_digest);
    hmac_sha256(key, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery::{DeliveryOutcome, DeliveryReceipt};
    use crate::receipt::SealedReceipt;

    const KEY: [u8; 32] = [7; 32];

    fn intent(value: u8) -> DeliveryIntent {
        DeliveryIntent {
            transaction_id: TransactionId([value; 32]),
            public_trace_digest: [value + 1; 32],
            release_sequence: value.into(),
            policy_epoch: 4,
            receipt_epoch: 5,
        }
    }

    fn sealed(value: u8) -> SealedReceipt {
        SealedReceipt {
            receipt: DeliveryReceipt {
                transaction_id: TransactionId([value; 32]),
                public_trace_digest: [value + 1; 32],
                release_sequence: value.into(),
                policy_epoch: 4,
                outcome: DeliveryOutcome::Delivered,
            },
            sink_epoch: 5,
            authenticator: [value + 10; 32],
        }
    }

    fn vault(value: u8) -> SealedReceiptRecord {
        SealedReceiptRecord {
            receipt: sealed(value),
            outbox_authenticator: [value + 20; 32],
            authenticator: [value + 30; 32],
        }
    }

    fn audit(value: u8) -> ReceiptLogRecord {
        ReceiptLogRecord {
            sequence: value.into(),
            previous_authenticator: [value + 40; 32],
            receipt: sealed(value),
            authenticator: [value + 50; 32],
        }
    }

    #[test]
    fn all_reachable_state_products_are_accepted_deterministically() {
        let outbox = vec![
            (intent(1), OutboxState::Pending, [0; 32]),
            (intent(2), OutboxState::Pending, [0; 32]),
            (intent(3), OutboxState::Delivered, [13; 32]),
            (intent(4), OutboxState::Delivered, [14; 32]),
            (intent(5), OutboxState::Audited, [15; 32]),
        ];
        let vault = vec![vault(2), vault(3), vault(4), vault(5)];
        let audit = vec![audit(4), audit(5)];
        let first = certify_cross_store_state(&outbox, &vault, &audit, KEY).unwrap();
        let mut reversed = outbox.clone();
        reversed.reverse();
        let second = certify_cross_store_state(&reversed, &vault, &audit, KEY).unwrap();
        assert_eq!(first, second);
        assert_eq!((first.pending, first.delivered, first.audited), (2, 2, 1));
    }

    #[test]
    fn missing_extra_and_substituted_records_have_counterexamples() {
        let delivered = vec![(intent(3), OutboxState::Delivered, [13; 32])];
        assert_eq!(
            certify_cross_store_state(&delivered, &[], &[], KEY),
            Err(ConsistencyError::MissingVault(TransactionId([3; 32])))
        );
        assert_eq!(
            certify_cross_store_state(&[], &[vault(3)], &[], KEY),
            Err(ConsistencyError::ExtraVault(TransactionId([3; 32])))
        );
        let mut substituted = vault(3);
        substituted.receipt.receipt.public_trace_digest[0] ^= 1;
        assert_eq!(
            certify_cross_store_state(&delivered, &[substituted], &[], KEY),
            Err(ConsistencyError::BindingSubstitution(TransactionId(
                [3; 32]
            )))
        );
    }

    #[test]
    fn impossible_pending_audit_and_missing_audit_are_rejected() {
        let pending = vec![(intent(1), OutboxState::Pending, [0; 32])];
        assert_eq!(
            certify_cross_store_state(&pending, &[vault(1)], &[audit(1)], KEY),
            Err(ConsistencyError::ImpossiblePendingAudit(TransactionId(
                [1; 32]
            )))
        );
        let audited = vec![(intent(5), OutboxState::Audited, [15; 32])];
        assert_eq!(
            certify_cross_store_state(&audited, &[vault(5)], &[], KEY),
            Err(ConsistencyError::MissingAudit(TransactionId([5; 32])))
        );
    }
}
