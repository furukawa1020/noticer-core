#![forbid(unsafe_code)]

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::BTreeMap;

pub const RECEIPT_SIZE: usize = 160;
const AUTHENTICATED_PREFIX_SIZE: usize = 120;
const AUTHENTICATOR_OFFSET: usize = 120;
const AUTHENTICATOR_END: usize = 152;
const MAGIC: [u8; 4] = *b"AQPR";
const VERSION: u8 = 1;
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReservationId(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceId(pub [u8; 16]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordKind {
    Prepare = 1,
    Commit = 2,
}

impl RecordKind {
    fn decode(value: u8) -> Result<Self, LedgerError> {
        match value {
            1 => Ok(Self::Prepare),
            2 => Ok(Self::Commit),
            _ => Err(LedgerError::MalformedReceipt),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivacyReceipt {
    pub bytes: [u8; RECEIPT_SIZE],
}

impl PrivacyReceipt {
    #[must_use]
    pub fn authenticator(&self) -> [u8; 32] {
        self.bytes[AUTHENTICATOR_OFFSET..AUTHENTICATOR_END]
            .try_into()
            .expect("fixed receipt slice")
    }
}

pub trait DurableStore {
    fn append_and_sync(&mut self, receipt: PrivacyReceipt) -> Result<(), StoreError>;
    fn load(&self) -> Result<Vec<PrivacyReceipt>, StoreError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreError {
    IoFailure,
}

#[derive(Clone, Debug, Default)]
pub struct MemoryStore {
    records: Vec<PrivacyReceipt>,
    fail_next_sync: bool,
}

impl MemoryStore {
    pub fn fail_next_sync(&mut self) {
        self.fail_next_sync = true;
    }

    #[must_use]
    pub fn records_mut(&mut self) -> &mut [PrivacyReceipt] {
        &mut self.records
    }
}

impl DurableStore for MemoryStore {
    fn append_and_sync(&mut self, receipt: PrivacyReceipt) -> Result<(), StoreError> {
        if self.fail_next_sync {
            self.fail_next_sync = false;
            return Err(StoreError::IoFailure);
        }
        self.records.push(receipt);
        Ok(())
    }

    fn load(&self) -> Result<Vec<PrivacyReceipt>, StoreError> {
        Ok(self.records.clone())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReservationState {
    Prepared,
    Committed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Reservation {
    service_id: ServiceId,
    amount_q64_64: u128,
    trace_commitment: [u8; 32],
    state: ReservationState,
}

#[derive(Debug)]
pub struct CrashConsistentLedger<S> {
    store: S,
    authentication_key: [u8; 32],
    maximum_records: usize,
    sequence: u64,
    chain_head: [u8; 32],
    charged_q64_64: u128,
    reservations: BTreeMap<ReservationId, Reservation>,
}

impl<S: DurableStore> CrashConsistentLedger<S> {
    pub fn new(
        store: S,
        authentication_key: [u8; 32],
        maximum_records: usize,
    ) -> Result<Self, LedgerError> {
        if authentication_key == [0; 32] || maximum_records == 0 {
            return Err(LedgerError::InvalidConfig);
        }
        let mut ledger = Self {
            store,
            authentication_key,
            maximum_records,
            sequence: 0,
            chain_head: [0; 32],
            charged_q64_64: 0,
            reservations: BTreeMap::new(),
        };
        ledger.replay()?;
        Ok(ledger)
    }

    pub fn prepare(
        &mut self,
        reservation_id: ReservationId,
        service_id: ServiceId,
        amount_q64_64: u128,
        trace_commitment: [u8; 32],
    ) -> Result<PrivacyReceipt, LedgerError> {
        if reservation_id.0 == 0
            || service_id.0 == [0; 16]
            || amount_q64_64 == 0
            || trace_commitment == [0; 32]
        {
            return Err(LedgerError::InvalidReservation);
        }
        if self.reservations.contains_key(&reservation_id) {
            return Err(LedgerError::ReservationAlreadyExists);
        }
        self.ensure_capacity()?;
        let sequence = next_sequence(self.sequence)?;
        let charged = self
            .charged_q64_64
            .checked_add(amount_q64_64)
            .ok_or(LedgerError::ArithmeticOverflow)?;
        let receipt = encode_receipt(
            &self.authentication_key,
            RecordKind::Prepare,
            sequence,
            reservation_id,
            service_id,
            amount_q64_64,
            trace_commitment,
            self.chain_head,
        )?;
        self.store
            .append_and_sync(receipt)
            .map_err(LedgerError::Store)?;
        self.sequence = sequence;
        self.chain_head = receipt.authenticator();
        self.charged_q64_64 = charged;
        self.reservations.insert(
            reservation_id,
            Reservation {
                service_id,
                amount_q64_64,
                trace_commitment,
                state: ReservationState::Prepared,
            },
        );
        Ok(receipt)
    }

    pub fn commit(&mut self, reservation_id: ReservationId) -> Result<PrivacyReceipt, LedgerError> {
        self.ensure_capacity()?;
        let reservation = self
            .reservations
            .get(&reservation_id)
            .copied()
            .ok_or(LedgerError::UnknownReservation)?;
        if reservation.state != ReservationState::Prepared {
            return Err(LedgerError::ReservationNotPending);
        }
        let sequence = next_sequence(self.sequence)?;
        let receipt = encode_receipt(
            &self.authentication_key,
            RecordKind::Commit,
            sequence,
            reservation_id,
            reservation.service_id,
            reservation.amount_q64_64,
            reservation.trace_commitment,
            self.chain_head,
        )?;
        self.store
            .append_and_sync(receipt)
            .map_err(LedgerError::Store)?;
        self.reservations
            .get_mut(&reservation_id)
            .ok_or(LedgerError::UnknownReservation)?
            .state = ReservationState::Committed;
        self.sequence = sequence;
        self.chain_head = receipt.authenticator();
        Ok(receipt)
    }

    #[must_use]
    pub const fn charged_q64_64(&self) -> u128 {
        self.charged_q64_64
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn into_store(self) -> S {
        self.store
    }

    fn ensure_capacity(&self) -> Result<(), LedgerError> {
        let count =
            usize::try_from(self.sequence).map_err(|_| LedgerError::ResourceLimitExceeded)?;
        if count >= self.maximum_records {
            return Err(LedgerError::ResourceLimitExceeded);
        }
        Ok(())
    }

    fn replay(&mut self) -> Result<(), LedgerError> {
        let records = self.store.load().map_err(LedgerError::Store)?;
        if records.len() > self.maximum_records {
            return Err(LedgerError::ResourceLimitExceeded);
        }
        for receipt in records {
            let decoded = decode_receipt(&self.authentication_key, receipt, self.chain_head)?;
            if decoded.sequence != next_sequence(self.sequence)? {
                return Err(LedgerError::SequenceMismatch);
            }
            match decoded.kind {
                RecordKind::Prepare => {
                    if self.reservations.contains_key(&decoded.reservation_id) {
                        return Err(LedgerError::ReservationAlreadyExists);
                    }
                    self.charged_q64_64 = self
                        .charged_q64_64
                        .checked_add(decoded.amount_q64_64)
                        .ok_or(LedgerError::ArithmeticOverflow)?;
                    self.reservations.insert(
                        decoded.reservation_id,
                        Reservation {
                            service_id: decoded.service_id,
                            amount_q64_64: decoded.amount_q64_64,
                            trace_commitment: decoded.trace_commitment,
                            state: ReservationState::Prepared,
                        },
                    );
                }
                RecordKind::Commit => {
                    let reservation = self
                        .reservations
                        .get_mut(&decoded.reservation_id)
                        .ok_or(LedgerError::CommitWithoutPrepare)?;
                    if reservation.state != ReservationState::Prepared
                        || reservation.service_id != decoded.service_id
                        || reservation.amount_q64_64 != decoded.amount_q64_64
                        || reservation.trace_commitment != decoded.trace_commitment
                    {
                        return Err(LedgerError::CommitMismatch);
                    }
                    reservation.state = ReservationState::Committed;
                }
            }
            self.sequence = decoded.sequence;
            self.chain_head = receipt.authenticator();
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct DecodedReceipt {
    kind: RecordKind,
    sequence: u64,
    reservation_id: ReservationId,
    service_id: ServiceId,
    amount_q64_64: u128,
    trace_commitment: [u8; 32],
}

fn encode_receipt(
    key: &[u8; 32],
    kind: RecordKind,
    sequence: u64,
    reservation_id: ReservationId,
    service_id: ServiceId,
    amount_q64_64: u128,
    trace_commitment: [u8; 32],
    previous_authenticator: [u8; 32],
) -> Result<PrivacyReceipt, LedgerError> {
    let mut bytes = [0_u8; RECEIPT_SIZE];
    bytes[0..4].copy_from_slice(&MAGIC);
    bytes[4] = VERSION;
    bytes[5] = kind as u8;
    bytes[8..16].copy_from_slice(&sequence.to_be_bytes());
    bytes[16..24].copy_from_slice(&reservation_id.0.to_be_bytes());
    bytes[24..40].copy_from_slice(&service_id.0);
    bytes[40..56].copy_from_slice(&amount_q64_64.to_be_bytes());
    bytes[56..88].copy_from_slice(&trace_commitment);
    bytes[88..120].copy_from_slice(&previous_authenticator);
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| LedgerError::InvalidConfig)?;
    mac.update(&bytes[..AUTHENTICATED_PREFIX_SIZE]);
    bytes[AUTHENTICATOR_OFFSET..AUTHENTICATOR_END].copy_from_slice(&mac.finalize().into_bytes());
    Ok(PrivacyReceipt { bytes })
}

fn decode_receipt(
    key: &[u8; 32],
    receipt: PrivacyReceipt,
    expected_previous: [u8; 32],
) -> Result<DecodedReceipt, LedgerError> {
    let bytes = receipt.bytes;
    if bytes[0..4] != MAGIC
        || bytes[4] != VERSION
        || bytes[6..8] != [0; 2]
        || bytes[152..160] != [0; 8]
    {
        return Err(LedgerError::MalformedReceipt);
    }
    if bytes[88..120] != expected_previous {
        return Err(LedgerError::HashChainMismatch);
    }
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| LedgerError::InvalidConfig)?;
    mac.update(&bytes[..AUTHENTICATED_PREFIX_SIZE]);
    mac.verify_slice(&bytes[AUTHENTICATOR_OFFSET..AUTHENTICATOR_END])
        .map_err(|_| LedgerError::AuthenticationFailed)?;
    Ok(DecodedReceipt {
        kind: RecordKind::decode(bytes[5])?,
        sequence: u64::from_be_bytes(
            bytes[8..16]
                .try_into()
                .map_err(|_| LedgerError::MalformedReceipt)?,
        ),
        reservation_id: ReservationId(u64::from_be_bytes(
            bytes[16..24]
                .try_into()
                .map_err(|_| LedgerError::MalformedReceipt)?,
        )),
        service_id: ServiceId(
            bytes[24..40]
                .try_into()
                .map_err(|_| LedgerError::MalformedReceipt)?,
        ),
        amount_q64_64: u128::from_be_bytes(
            bytes[40..56]
                .try_into()
                .map_err(|_| LedgerError::MalformedReceipt)?,
        ),
        trace_commitment: bytes[56..88]
            .try_into()
            .map_err(|_| LedgerError::MalformedReceipt)?,
    })
}

fn next_sequence(sequence: u64) -> Result<u64, LedgerError> {
    sequence
        .checked_add(1)
        .ok_or(LedgerError::ArithmeticOverflow)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LedgerError {
    InvalidConfig,
    InvalidReservation,
    ReservationAlreadyExists,
    UnknownReservation,
    ReservationNotPending,
    CommitWithoutPrepare,
    CommitMismatch,
    MalformedReceipt,
    AuthenticationFailed,
    HashChainMismatch,
    SequenceMismatch,
    ResourceLimitExceeded,
    ArithmeticOverflow,
    Store(StoreError),
}

#[cfg(test)]
mod tests {
    use super::*;
    const KEY: [u8; 32] = [9; 32];
    const SERVICE: ServiceId = ServiceId([4; 16]);

    #[test]
    fn prepare_commit_and_recovery_preserve_charge() {
        let mut ledger = CrashConsistentLedger::new(MemoryStore::default(), KEY, 8).unwrap();
        assert_eq!(core::mem::size_of::<PrivacyReceipt>(), RECEIPT_SIZE);
        ledger
            .prepare(ReservationId(1), SERVICE, 40, [7; 32])
            .unwrap();
        ledger.commit(ReservationId(1)).unwrap();
        let recovered = CrashConsistentLedger::new(ledger.into_store(), KEY, 8).unwrap();
        assert_eq!(recovered.charged_q64_64(), 40);
        assert_eq!(recovered.sequence(), 2);
    }

    #[test]
    fn uncertain_prepared_release_is_charged_after_crash() {
        let mut ledger = CrashConsistentLedger::new(MemoryStore::default(), KEY, 8).unwrap();
        ledger
            .prepare(ReservationId(1), SERVICE, 50, [8; 32])
            .unwrap();
        let recovered = CrashConsistentLedger::new(ledger.into_store(), KEY, 8).unwrap();
        assert_eq!(recovered.charged_q64_64(), 50);
        assert_eq!(recovered.sequence(), 1);
    }

    #[test]
    fn tampering_is_detected_during_recovery() {
        let mut ledger = CrashConsistentLedger::new(MemoryStore::default(), KEY, 8).unwrap();
        ledger
            .prepare(ReservationId(1), SERVICE, 50, [8; 32])
            .unwrap();
        let mut store = ledger.into_store();
        store.records_mut()[0].bytes[40] ^= 1;
        assert_eq!(
            CrashConsistentLedger::new(store, KEY, 8).unwrap_err(),
            LedgerError::AuthenticationFailed
        );
    }

    #[test]
    fn failed_sync_does_not_charge_or_advance() {
        let mut store = MemoryStore::default();
        store.fail_next_sync();
        let mut ledger = CrashConsistentLedger::new(store, KEY, 8).unwrap();
        assert_eq!(
            ledger.prepare(ReservationId(1), SERVICE, 50, [8; 32]),
            Err(LedgerError::Store(StoreError::IoFailure))
        );
        assert_eq!(ledger.charged_q64_64(), 0);
        assert_eq!(ledger.sequence(), 0);
    }

    #[test]
    fn receipt_chain_rejects_reordering() {
        let mut ledger = CrashConsistentLedger::new(MemoryStore::default(), KEY, 8).unwrap();
        ledger
            .prepare(ReservationId(1), SERVICE, 10, [1; 32])
            .unwrap();
        ledger.commit(ReservationId(1)).unwrap();
        let mut store = ledger.into_store();
        store.records.reverse();
        assert_eq!(
            CrashConsistentLedger::new(store, KEY, 8).unwrap_err(),
            LedgerError::HashChainMismatch
        );
    }
}
