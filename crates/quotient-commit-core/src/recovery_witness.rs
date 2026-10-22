//! Privacy-safe authenticated witnesses for deterministic recovery decisions.

use crate::receipt::hmac_sha256;

const ENTRY_DOMAIN: &[u8] = b"noticer.quotient-commit.recovery-witness-entry.v1\0";
const BATCH_DOMAIN: &[u8] = b"noticer.quotient-commit.recovery-witness-batch.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessState {
    Pending = 1,
    Delivered = 2,
    Audited = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessAction {
    RetryDelivery = 1,
    RetryAudit = 2,
    Noop = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessResult {
    Succeeded = 1,
    FailedClosed = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryWitness {
    pub ordinal: u64,
    pub public_binding_digest: [u8; 32],
    pub state: WitnessState,
    pub action: WitnessAction,
    pub result: WitnessResult,
    pub previous_authenticator: [u8; 32],
    pub authenticator: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryWitnessBatch {
    pub entry_count: u64,
    pub succeeded: u64,
    pub failed_closed: u64,
    pub head_authenticator: [u8; 32],
    pub authenticator: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryWitnessError {
    InvalidKey,
    InvalidDigest,
    InvalidOrdinal,
    ChainMismatch,
    AuthenticationFailed,
    BatchMismatch,
}

pub fn build_witness_batch(
    decisions: &[([u8; 32], WitnessState, WitnessAction, WitnessResult)],
    key: [u8; 32],
) -> Result<(Vec<RecoveryWitness>, RecoveryWitnessBatch), RecoveryWitnessError> {
    if key == [0; 32] {
        return Err(RecoveryWitnessError::InvalidKey);
    }
    let mut entries = Vec::with_capacity(decisions.len());
    let mut previous = [0; 32];
    let mut succeeded = 0;
    let mut failed_closed = 0;
    for (index, (digest, state, action, result)) in decisions.iter().copied().enumerate() {
        if digest == [0; 32] {
            return Err(RecoveryWitnessError::InvalidDigest);
        }
        match result {
            WitnessResult::Succeeded => succeeded += 1,
            WitnessResult::FailedClosed => failed_closed += 1,
        }
        let mut entry = RecoveryWitness {
            ordinal: index as u64 + 1,
            public_binding_digest: digest,
            state,
            action,
            result,
            previous_authenticator: previous,
            authenticator: [0; 32],
        };
        entry.authenticator = authenticate_entry(entry, key);
        previous = entry.authenticator;
        entries.push(entry);
    }
    let mut batch = RecoveryWitnessBatch {
        entry_count: entries.len() as u64,
        succeeded,
        failed_closed,
        head_authenticator: previous,
        authenticator: [0; 32],
    };
    batch.authenticator = authenticate_batch(batch, key);
    Ok((entries, batch))
}

pub fn verify_witness_batch(
    entries: &[RecoveryWitness],
    batch: RecoveryWitnessBatch,
    key: [u8; 32],
) -> Result<(), RecoveryWitnessError> {
    if key == [0; 32] {
        return Err(RecoveryWitnessError::InvalidKey);
    }
    let mut previous = [0; 32];
    let mut succeeded = 0;
    let mut failed_closed = 0;
    for (index, entry) in entries.iter().copied().enumerate() {
        if entry.ordinal != index as u64 + 1 {
            return Err(RecoveryWitnessError::InvalidOrdinal);
        }
        if entry.previous_authenticator != previous {
            return Err(RecoveryWitnessError::ChainMismatch);
        }
        if entry.authenticator != authenticate_entry(entry, key) {
            return Err(RecoveryWitnessError::AuthenticationFailed);
        }
        match entry.result {
            WitnessResult::Succeeded => succeeded += 1,
            WitnessResult::FailedClosed => failed_closed += 1,
        }
        previous = entry.authenticator;
    }
    if batch.entry_count != entries.len() as u64
        || batch.succeeded != succeeded
        || batch.failed_closed != failed_closed
        || batch.head_authenticator != previous
    {
        return Err(RecoveryWitnessError::BatchMismatch);
    }
    if batch.authenticator != authenticate_batch(batch, key) {
        return Err(RecoveryWitnessError::AuthenticationFailed);
    }
    Ok(())
}

#[must_use]
pub fn canonical_json(batch: RecoveryWitnessBatch) -> String {
    format!("{{\"schema\":\"noticer.recovery-witness.v1\",\"entry_count\":{},\"succeeded\":{},\"failed_closed\":{},\"head_authenticator\":\"{}\",\"authenticator\":\"{}\"}}", batch.entry_count, batch.succeeded, batch.failed_closed, hex(batch.head_authenticator), hex(batch.authenticator))
}

fn authenticate_entry(mut value: RecoveryWitness, key: [u8; 32]) -> [u8; 32] {
    value.authenticator = [0; 32];
    let mut bytes = Vec::with_capacity(ENTRY_DOMAIN.len() + 8 + 32 * 2 + 3);
    bytes.extend_from_slice(ENTRY_DOMAIN);
    bytes.extend_from_slice(&value.ordinal.to_be_bytes());
    bytes.extend_from_slice(&value.public_binding_digest);
    bytes.extend_from_slice(&[value.state as u8, value.action as u8, value.result as u8]);
    bytes.extend_from_slice(&value.previous_authenticator);
    hmac_sha256(key, &bytes)
}

fn authenticate_batch(mut value: RecoveryWitnessBatch, key: [u8; 32]) -> [u8; 32] {
    value.authenticator = [0; 32];
    let mut bytes = Vec::with_capacity(BATCH_DOMAIN.len() + 24 + 32);
    bytes.extend_from_slice(BATCH_DOMAIN);
    bytes.extend_from_slice(&value.entry_count.to_be_bytes());
    bytes.extend_from_slice(&value.succeeded.to_be_bytes());
    bytes.extend_from_slice(&value.failed_closed.to_be_bytes());
    bytes.extend_from_slice(&value.head_authenticator);
    hmac_sha256(key, &bytes)
}

fn hex(value: [u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(64);
    for byte in value {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 15) as usize] as char);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    const KEY: [u8; 32] = [7; 32];

    fn fixture() -> Vec<([u8; 32], WitnessState, WitnessAction, WitnessResult)> {
        vec![
            (
                [1; 32],
                WitnessState::Pending,
                WitnessAction::RetryDelivery,
                WitnessResult::Succeeded,
            ),
            (
                [2; 32],
                WitnessState::Delivered,
                WitnessAction::RetryAudit,
                WitnessResult::FailedClosed,
            ),
            (
                [3; 32],
                WitnessState::Audited,
                WitnessAction::Noop,
                WitnessResult::Succeeded,
            ),
        ]
    }

    #[test]
    fn deterministic_batch_verifies() {
        let first = build_witness_batch(&fixture(), KEY).unwrap();
        let second = build_witness_batch(&fixture(), KEY).unwrap();
        assert_eq!(first, second);
        assert_eq!(verify_witness_batch(&first.0, first.1, KEY), Ok(()));
    }

    #[test]
    fn tampering_and_reordering_are_detected() {
        let (entries, batch) = build_witness_batch(&fixture(), KEY).unwrap();
        let mut reordered = entries.clone();
        reordered.swap(0, 1);
        assert!(verify_witness_batch(&reordered, batch, KEY).is_err());
        let mut tampered = entries;
        tampered[1].result = WitnessResult::Succeeded;
        assert_eq!(
            verify_witness_batch(&tampered, batch, KEY),
            Err(RecoveryWitnessError::AuthenticationFailed)
        );
    }

    #[test]
    fn canonical_artifact_excludes_private_identifiers() {
        let (_, batch) = build_witness_batch(&fixture(), KEY).unwrap();
        let json = canonical_json(batch);
        assert_eq!(json, canonical_json(batch));
        for forbidden in [
            "biosignal",
            "subject",
            "transaction",
            "receipt",
            "raw_payload",
            "identity",
        ] {
            assert!(!json.contains(forbidden));
        }
    }
}
