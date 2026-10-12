//! Independently authenticated checkpoints for receipt audit logs.

use crate::receipt::hmac_sha256;
use crate::receipt_log::ReceiptCheckpoint;

const DOMAIN: &[u8] = b"noticer.quotient-commit.receipt-checkpoint.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SealedCheckpoint {
    pub log_id: [u8; 32],
    pub checkpoint: ReceiptCheckpoint,
    pub checkpoint_epoch: u64,
    pub authenticator: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointError {
    InvalidLogId,
    InvalidEpoch,
    InvalidKey,
}

pub fn seal_checkpoint(
    log_id: [u8; 32],
    checkpoint: ReceiptCheckpoint,
    checkpoint_epoch: u64,
    key: [u8; 32],
) -> Result<SealedCheckpoint, CheckpointError> {
    validate(log_id, checkpoint_epoch, key)?;
    Ok(SealedCheckpoint {
        log_id,
        checkpoint,
        checkpoint_epoch,
        authenticator: authenticate(log_id, checkpoint, checkpoint_epoch, key),
    })
}

#[must_use]
pub fn verify_checkpoint(checkpoint: &SealedCheckpoint, key: [u8; 32]) -> bool {
    if validate(checkpoint.log_id, checkpoint.checkpoint_epoch, key).is_err() {
        return false;
    }
    constant_time_equal(
        checkpoint.authenticator,
        authenticate(
            checkpoint.log_id,
            checkpoint.checkpoint,
            checkpoint.checkpoint_epoch,
            key,
        ),
    )
}

fn validate(log_id: [u8; 32], epoch: u64, key: [u8; 32]) -> Result<(), CheckpointError> {
    if log_id == [0; 32] {
        return Err(CheckpointError::InvalidLogId);
    }
    if epoch == 0 {
        return Err(CheckpointError::InvalidEpoch);
    }
    if key == [0; 32] {
        return Err(CheckpointError::InvalidKey);
    }
    Ok(())
}

fn authenticate(
    log_id: [u8; 32],
    checkpoint: ReceiptCheckpoint,
    epoch: u64,
    key: [u8; 32],
) -> [u8; 32] {
    let mut message = Vec::with_capacity(DOMAIN.len() + 80);
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(&log_id);
    message.extend_from_slice(&checkpoint.record_count.to_be_bytes());
    message.extend_from_slice(&checkpoint.head_authenticator);
    message.extend_from_slice(&epoch.to_be_bytes());
    hmac_sha256(key, &message)
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

    const KEY: [u8; 32] = [7; 32];

    fn checkpoint() -> ReceiptCheckpoint {
        ReceiptCheckpoint {
            record_count: 9,
            head_authenticator: [3; 32],
        }
    }

    #[test]
    fn intact_checkpoint_verifies() {
        let sealed = seal_checkpoint([1; 32], checkpoint(), 2, KEY).unwrap();
        assert!(verify_checkpoint(&sealed, KEY));
    }

    #[test]
    fn every_binding_and_wrong_key_are_rejected_after_mutation() {
        let sealed = seal_checkpoint([1; 32], checkpoint(), 2, KEY).unwrap();
        let mut mutations = [sealed; 4];
        mutations[0].log_id[0] ^= 1;
        mutations[1].checkpoint.record_count += 1;
        mutations[2].checkpoint.head_authenticator[0] ^= 1;
        mutations[3].checkpoint_epoch += 1;
        assert!(mutations.iter().all(|value| !verify_checkpoint(value, KEY)));
        assert!(!verify_checkpoint(&sealed, [8; 32]));
    }

    #[test]
    fn invalid_configuration_fails_closed() {
        assert_eq!(
            seal_checkpoint([0; 32], checkpoint(), 1, KEY),
            Err(CheckpointError::InvalidLogId)
        );
        assert_eq!(
            seal_checkpoint([1; 32], checkpoint(), 0, KEY),
            Err(CheckpointError::InvalidEpoch)
        );
        assert_eq!(
            seal_checkpoint([1; 32], checkpoint(), 1, [0; 32]),
            Err(CheckpointError::InvalidKey)
        );
    }
}
