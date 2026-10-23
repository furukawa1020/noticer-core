//! Fail-closed startup gate binding cross-store certification to a rollback anchor.

use crate::cross_store_certifier::{
    certify_cross_store_state, ConsistencyCertificate, ConsistencyError,
};
use crate::delivery_outbox::{DeliveryIntent, OutboxState};
use crate::receipt::hmac_sha256;
use crate::receipt_log::ReceiptLogRecord;
use crate::rollback_anchor::{
    DurableRollbackAnchor, RollbackAnchorError, RollbackAnchorStore, StoreHeads,
};
use crate::sealed_receipt_vault::SealedReceiptRecord;

const DOMAIN: &[u8] = b"noticer.quotient-commit.startup-security-gate.v1\0";
type OutboxEntry = (DeliveryIntent, OutboxState, [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartupAuthorization {
    pub anchor_generation: u64,
    pub certificate_authenticator: [u8; 32],
    pub anchor_authenticator: [u8; 32],
    pub authenticator: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupGateError {
    InvalidKey,
    Certification(ConsistencyError),
    Anchor(RollbackAnchorError),
    MissingAnchor,
    AuthorizationFailed,
}

pub fn authorize_startup<S: RollbackAnchorStore>(
    outbox: &[OutboxEntry],
    vault: &[SealedReceiptRecord],
    audit: &[ReceiptLogRecord],
    anchor: &DurableRollbackAnchor<S>,
    generation: u64,
    heads: StoreHeads,
    key: [u8; 32],
) -> Result<(ConsistencyCertificate, StartupAuthorization), StartupGateError> {
    if key == [0; 32] {
        return Err(StartupGateError::InvalidKey);
    }
    let certificate = certify_cross_store_state(outbox, vault, audit, key)
        .map_err(StartupGateError::Certification)?;
    anchor
        .verify_snapshot(generation, heads)
        .map_err(StartupGateError::Anchor)?;
    let anchor_record = anchor.head().ok_or(StartupGateError::MissingAnchor)?;
    let mut authorization = StartupAuthorization {
        anchor_generation: generation,
        certificate_authenticator: certificate.authenticator,
        anchor_authenticator: anchor_record.authenticator,
        authenticator: [0; 32],
    };
    authorization.authenticator = authenticate(authorization, key);
    Ok((certificate, authorization))
}

pub fn verify_startup_authorization(
    authorization: StartupAuthorization,
    certificate: ConsistencyCertificate,
    anchor_generation: u64,
    anchor_authenticator: [u8; 32],
    key: [u8; 32],
) -> Result<(), StartupGateError> {
    if key == [0; 32] {
        return Err(StartupGateError::InvalidKey);
    }
    if authorization.anchor_generation != anchor_generation
        || authorization.certificate_authenticator != certificate.authenticator
        || authorization.anchor_authenticator != anchor_authenticator
        || authorization.authenticator != authenticate(authorization, key)
    {
        return Err(StartupGateError::AuthorizationFailed);
    }
    Ok(())
}

fn authenticate(mut value: StartupAuthorization, key: [u8; 32]) -> [u8; 32] {
    value.authenticator = [0; 32];
    let mut bytes = Vec::with_capacity(DOMAIN.len() + 72);
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&value.anchor_generation.to_be_bytes());
    bytes.extend_from_slice(&value.certificate_authenticator);
    bytes.extend_from_slice(&value.anchor_authenticator);
    hmac_sha256(key, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rollback_anchor::{RollbackAnchorRecord, RollbackAnchorStore};
    use crate::TransactionId;

    const KEY: [u8; 32] = [7; 32];

    #[derive(Debug, Default)]
    struct MemoryStore {
        records: Vec<RollbackAnchorRecord>,
    }
    impl RollbackAnchorStore for MemoryStore {
        fn append_and_sync(
            &mut self,
            record: RollbackAnchorRecord,
        ) -> Result<(), RollbackAnchorError> {
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
    fn intent() -> DeliveryIntent {
        DeliveryIntent {
            transaction_id: TransactionId([1; 32]),
            public_trace_digest: [2; 32],
            release_sequence: 3,
            policy_epoch: 4,
            receipt_epoch: 5,
        }
    }

    #[test]
    fn valid_certificate_and_anchor_authorize_release() {
        let mut anchor = DurableRollbackAnchor::open(MemoryStore::default(), KEY, 4).unwrap();
        let record = anchor.advance(heads(1)).unwrap();
        let (certificate, authorization) =
            authorize_startup(&[], &[], &[], &anchor, 1, heads(1), KEY).unwrap();
        assert_eq!(
            verify_startup_authorization(authorization, certificate, 1, record.authenticator, KEY),
            Ok(())
        );
    }

    #[test]
    fn inconsistent_store_or_stale_anchor_never_authorizes() {
        let mut anchor = DurableRollbackAnchor::open(MemoryStore::default(), KEY, 4).unwrap();
        anchor.advance(heads(1)).unwrap();
        let duplicate = [
            (intent(), OutboxState::Pending, [0; 32]),
            (intent(), OutboxState::Pending, [0; 32]),
        ];
        assert!(matches!(
            authorize_startup(&duplicate, &[], &[], &anchor, 1, heads(1), KEY),
            Err(StartupGateError::Certification(_))
        ));
        assert_eq!(
            authorize_startup(&[], &[], &[], &anchor, 1, heads(9), KEY).unwrap_err(),
            StartupGateError::Anchor(RollbackAnchorError::CrossStoreMismatch)
        );
    }

    #[test]
    fn phase_binding_tampering_is_rejected() {
        let mut anchor = DurableRollbackAnchor::open(MemoryStore::default(), KEY, 4).unwrap();
        let record = anchor.advance(heads(1)).unwrap();
        let (certificate, mut authorization) =
            authorize_startup(&[], &[], &[], &anchor, 1, heads(1), KEY).unwrap();
        authorization.anchor_generation += 1;
        assert_eq!(
            verify_startup_authorization(authorization, certificate, 1, record.authenticator, KEY),
            Err(StartupGateError::AuthorizationFailed)
        );
    }
}
