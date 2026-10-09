use crate::sha256::sha256;
use crate::{TransactionId, TransactionState};
use std::collections::BTreeMap;

const JOURNAL_DOMAIN: &[u8] = b"noticer.quotient-commit.journal.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordKind {
    Prepare = 1,
    MonitorAccept = 2,
    BudgetReserve = 3,
    Commit = 4,
    Reject = 5,
    Abort = 6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalRecord {
    pub sequence: u64,
    pub transaction_id: TransactionId,
    pub kind: RecordKind,
    pub evidence_digest: [u8; 32],
    pub previous_authenticator: [u8; 32],
    pub authenticator: [u8; 32],
}

pub trait DurableStore {
    fn append_and_sync(&mut self, record: JournalRecord) -> Result<(), StoreError>;
    fn load(&self) -> Result<Vec<JournalRecord>, StoreError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreError {
    IoFailure,
}

#[derive(Clone, Debug, Default)]
pub struct MemoryStore {
    records: Vec<JournalRecord>,
    fail_next_sync: bool,
}

impl MemoryStore {
    pub fn fail_next_sync(&mut self) {
        self.fail_next_sync = true;
    }

    #[must_use]
    pub fn records_mut(&mut self) -> &mut [JournalRecord] {
        &mut self.records
    }
}

impl DurableStore for MemoryStore {
    fn append_and_sync(&mut self, record: JournalRecord) -> Result<(), StoreError> {
        if self.fail_next_sync {
            self.fail_next_sync = false;
            return Err(StoreError::IoFailure);
        }
        self.records.push(record);
        Ok(())
    }

    fn load(&self) -> Result<Vec<JournalRecord>, StoreError> {
        Ok(self.records.clone())
    }
}

#[derive(Debug)]
pub struct DurableJournal<S> {
    store: S,
    authentication_key: [u8; 32],
    maximum_records: usize,
    sequence: u64,
    chain_head: [u8; 32],
    states: BTreeMap<TransactionId, TransactionState>,
}

impl<S: DurableStore> DurableJournal<S> {
    pub fn new(
        store: S,
        authentication_key: [u8; 32],
        maximum_records: usize,
    ) -> Result<Self, JournalError> {
        if is_zero(authentication_key) || maximum_records == 0 {
            return Err(JournalError::InvalidConfig);
        }
        let mut journal = Self {
            store,
            authentication_key,
            maximum_records,
            sequence: 0,
            chain_head: [0; 32],
            states: BTreeMap::new(),
        };
        journal.replay()?;
        Ok(journal)
    }

    pub fn append(
        &mut self,
        transaction_id: TransactionId,
        kind: RecordKind,
        evidence_digest: [u8; 32],
    ) -> Result<JournalRecord, JournalError> {
        validate_identity(transaction_id, evidence_digest)?;
        self.ensure_capacity()?;
        let next_state = transition(self.states.get(&transaction_id).copied(), kind)?;
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(JournalError::ArithmeticOverflow)?;
        let mut record = JournalRecord {
            sequence,
            transaction_id,
            kind,
            evidence_digest,
            previous_authenticator: self.chain_head,
            authenticator: [0; 32],
        };
        record.authenticator = authenticate(&self.authentication_key, &record);
        self.store
            .append_and_sync(record)
            .map_err(JournalError::Store)?;
        self.sequence = sequence;
        self.chain_head = record.authenticator;
        self.states.insert(transaction_id, next_state);
        Ok(record)
    }

    #[must_use]
    pub fn state(&self, transaction_id: TransactionId) -> Option<TransactionState> {
        self.states.get(&transaction_id).copied()
    }

    #[must_use]
    pub fn release_committed(&self, transaction_id: TransactionId) -> bool {
        self.state(transaction_id) == Some(TransactionState::Committed)
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn into_store(self) -> S {
        self.store
    }

    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    pub fn records_for(
        &self,
        transaction_id: TransactionId,
    ) -> Result<Vec<JournalRecord>, JournalError> {
        Ok(self
            .store
            .load()
            .map_err(JournalError::Store)?
            .into_iter()
            .filter(|record| record.transaction_id == transaction_id)
            .collect())
    }

    fn ensure_capacity(&self) -> Result<(), JournalError> {
        let count = usize::try_from(self.sequence).map_err(|_| JournalError::ResourceLimit)?;
        if count >= self.maximum_records {
            Err(JournalError::ResourceLimit)
        } else {
            Ok(())
        }
    }

    fn replay(&mut self) -> Result<(), JournalError> {
        let records = self.store.load().map_err(JournalError::Store)?;
        if records.len() > self.maximum_records {
            return Err(JournalError::ResourceLimit);
        }
        for record in records {
            let expected_sequence = self
                .sequence
                .checked_add(1)
                .ok_or(JournalError::ArithmeticOverflow)?;
            if record.sequence != expected_sequence {
                return Err(JournalError::SequenceMismatch);
            }
            validate_identity(record.transaction_id, record.evidence_digest)?;
            if record.previous_authenticator != self.chain_head {
                return Err(JournalError::ChainMismatch);
            }
            let expected = authenticate(&self.authentication_key, &record);
            if !constant_time_equal(expected, record.authenticator) {
                return Err(JournalError::AuthenticationFailed);
            }
            let next_state = transition(
                self.states.get(&record.transaction_id).copied(),
                record.kind,
            )?;
            self.sequence = record.sequence;
            self.chain_head = record.authenticator;
            self.states.insert(record.transaction_id, next_state);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalError {
    InvalidConfig,
    InvalidIdentity,
    InvalidTransition,
    Replay,
    TerminalState,
    SequenceMismatch,
    ChainMismatch,
    AuthenticationFailed,
    ResourceLimit,
    ArithmeticOverflow,
    Store(StoreError),
}

fn transition(
    current: Option<TransactionState>,
    kind: RecordKind,
) -> Result<TransactionState, JournalError> {
    match (current, kind) {
        (None, RecordKind::Prepare) => Ok(TransactionState::Prepared),
        (None, _) => Err(JournalError::InvalidTransition),
        (Some(_), RecordKind::Prepare) => Err(JournalError::Replay),
        (Some(TransactionState::Prepared), RecordKind::MonitorAccept) => {
            Ok(TransactionState::MonitorAccepted)
        }
        (Some(TransactionState::MonitorAccepted), RecordKind::BudgetReserve) => {
            Ok(TransactionState::BudgetReserved)
        }
        (Some(TransactionState::BudgetReserved), RecordKind::Commit) => {
            Ok(TransactionState::Committed)
        }
        (
            Some(
                TransactionState::Prepared
                | TransactionState::MonitorAccepted
                | TransactionState::BudgetReserved,
            ),
            RecordKind::Reject,
        ) => Ok(TransactionState::Rejected),
        (
            Some(
                TransactionState::Prepared
                | TransactionState::MonitorAccepted
                | TransactionState::BudgetReserved,
            ),
            RecordKind::Abort,
        ) => Ok(TransactionState::Aborted),
        (
            Some(
                TransactionState::Committed
                | TransactionState::Rejected
                | TransactionState::Aborted,
            ),
            _,
        ) => Err(JournalError::TerminalState),
        (Some(_), _) => Err(JournalError::InvalidTransition),
    }
}

fn validate_identity(
    transaction_id: TransactionId,
    evidence_digest: [u8; 32],
) -> Result<(), JournalError> {
    if is_zero(transaction_id.0) || is_zero(evidence_digest) {
        Err(JournalError::InvalidIdentity)
    } else {
        Ok(())
    }
}

fn authenticate(key: &[u8; 32], record: &JournalRecord) -> [u8; 32] {
    let mut message = Vec::with_capacity(JOURNAL_DOMAIN.len() + 8 + 32 + 1 + 32 + 32);
    message.extend_from_slice(JOURNAL_DOMAIN);
    message.extend_from_slice(&record.sequence.to_be_bytes());
    message.extend_from_slice(&record.transaction_id.0);
    message.push(record.kind as u8);
    message.extend_from_slice(&record.evidence_digest);
    message.extend_from_slice(&record.previous_authenticator);
    hmac_sha256(key, &message)
}

fn hmac_sha256(key: &[u8; 32], message: &[u8]) -> [u8; 32] {
    let mut inner_pad = [0x36_u8; 64];
    let mut outer_pad = [0x5c_u8; 64];
    for index in 0..key.len() {
        inner_pad[index] ^= key[index];
        outer_pad[index] ^= key[index];
    }
    let mut inner = Vec::with_capacity(inner_pad.len() + message.len());
    inner.extend_from_slice(&inner_pad);
    inner.extend_from_slice(message);
    let inner_digest = sha256(&inner);
    let mut outer = Vec::with_capacity(outer_pad.len() + inner_digest.len());
    outer.extend_from_slice(&outer_pad);
    outer.extend_from_slice(&inner_digest);
    sha256(&outer)
}

fn constant_time_equal(left: [u8; 32], right: [u8; 32]) -> bool {
    left.iter()
        .zip(right.iter())
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

const fn is_zero(value: [u8; 32]) -> bool {
    let mut index = 0;
    while index < value.len() {
        if value[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [9; 32];
    const TX: TransactionId = TransactionId([7; 32]);

    fn append_path(journal: &mut DurableJournal<MemoryStore>, through: RecordKind) {
        let path = [
            RecordKind::Prepare,
            RecordKind::MonitorAccept,
            RecordKind::BudgetReserve,
            RecordKind::Commit,
        ];
        for (index, kind) in path.into_iter().enumerate() {
            journal.append(TX, kind, [index as u8 + 1; 32]).unwrap();
            if kind == through {
                break;
            }
        }
    }

    #[test]
    fn committed_transaction_survives_authenticated_replay() {
        let mut journal = DurableJournal::new(MemoryStore::default(), KEY, 8).unwrap();
        append_path(&mut journal, RecordKind::Commit);
        assert!(journal.release_committed(TX));
        let recovered = DurableJournal::new(journal.into_store(), KEY, 8).unwrap();
        assert_eq!(recovered.state(TX), Some(TransactionState::Committed));
        assert_eq!(recovered.sequence(), 4);
    }

    #[test]
    fn uncertain_reservation_recovers_without_release() {
        let mut journal = DurableJournal::new(MemoryStore::default(), KEY, 8).unwrap();
        append_path(&mut journal, RecordKind::BudgetReserve);
        let recovered = DurableJournal::new(journal.into_store(), KEY, 8).unwrap();
        assert_eq!(recovered.state(TX), Some(TransactionState::BudgetReserved));
        assert!(!recovered.release_committed(TX));
    }

    #[test]
    fn failed_sync_does_not_advance_memory_state() {
        let mut store = MemoryStore::default();
        store.fail_next_sync();
        let mut journal = DurableJournal::new(store, KEY, 8).unwrap();
        assert_eq!(
            journal.append(TX, RecordKind::Prepare, [1; 32]),
            Err(JournalError::Store(StoreError::IoFailure))
        );
        assert_eq!(journal.state(TX), None);
        assert_eq!(journal.sequence(), 0);
    }

    #[test]
    fn tampering_and_reordering_fail_closed_during_replay() {
        let mut journal = DurableJournal::new(MemoryStore::default(), KEY, 8).unwrap();
        append_path(&mut journal, RecordKind::MonitorAccept);
        let mut tampered = journal.into_store();
        tampered.records_mut()[0].evidence_digest[0] ^= 1;
        assert_eq!(
            DurableJournal::new(tampered, KEY, 8).unwrap_err(),
            JournalError::AuthenticationFailed
        );

        let mut journal = DurableJournal::new(MemoryStore::default(), KEY, 8).unwrap();
        append_path(&mut journal, RecordKind::MonitorAccept);
        let mut reordered = journal.into_store();
        reordered.records.reverse();
        assert_eq!(
            DurableJournal::new(reordered, KEY, 8).unwrap_err(),
            JournalError::SequenceMismatch
        );
    }

    #[test]
    fn invalid_order_replay_and_terminal_extension_are_rejected() {
        let mut journal = DurableJournal::new(MemoryStore::default(), KEY, 8).unwrap();
        assert_eq!(
            journal.append(TX, RecordKind::Commit, [1; 32]),
            Err(JournalError::InvalidTransition)
        );
        journal.append(TX, RecordKind::Prepare, [1; 32]).unwrap();
        assert_eq!(
            journal.append(TX, RecordKind::Prepare, [1; 32]),
            Err(JournalError::Replay)
        );
        journal.append(TX, RecordKind::Abort, [2; 32]).unwrap();
        assert_eq!(
            journal.append(TX, RecordKind::MonitorAccept, [3; 32]),
            Err(JournalError::TerminalState)
        );
    }

    #[test]
    fn hmac_matches_independent_fixed_vector() {
        assert_eq!(
            hmac_sha256(&KEY, b"quotient-commit-hmac-vector"),
            [
                0xed, 0x08, 0xd0, 0x85, 0x58, 0xfa, 0xba, 0x71, 0x6e, 0x99, 0x9f, 0x1f, 0xb6, 0x4e,
                0xcf, 0xec, 0x03, 0x4d, 0x4f, 0x1b, 0x3e, 0xa5, 0x3c, 0x3b, 0x9c, 0x3f, 0xef, 0x39,
                0xc3, 0xfa, 0xec, 0xab,
            ]
        );
    }
}
