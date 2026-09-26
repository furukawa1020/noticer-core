#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::Mutex;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ServiceId(pub [u8; 16]);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReservationId(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReservationState {
    Reserved,
    Committed,
    Aborted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LedgerConfig {
    pub capacity_epsilon_q64_64: u128,
    pub maximum_reservation_ids: usize,
}

impl LedgerConfig {
    pub const fn validate(self) -> Result<(), LedgerError> {
        if self.capacity_epsilon_q64_64 == 0 || self.maximum_reservation_ids == 0 {
            return Err(LedgerError::InvalidConfig);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LedgerReceipt {
    pub sequence: u64,
    pub reservation_id: ReservationId,
    pub service_id: ServiceId,
    pub state: ReservationState,
    pub amount_epsilon_q64_64: u128,
    pub committed_epsilon_q64_64: u128,
    pub reserved_epsilon_q64_64: u128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LedgerSnapshot {
    pub sequence: u64,
    pub committed_epsilon_q64_64: u128,
    pub reserved_epsilon_q64_64: u128,
    pub reservation_ids_seen: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Reservation {
    service_id: ServiceId,
    amount_epsilon_q64_64: u128,
    state: ReservationState,
}

#[derive(Debug)]
struct LedgerState {
    sequence: u64,
    committed_epsilon_q64_64: u128,
    reserved_epsilon_q64_64: u128,
    reservations: BTreeMap<ReservationId, Reservation>,
}

#[derive(Debug)]
pub struct ConcurrentLedger {
    config: LedgerConfig,
    state: Mutex<LedgerState>,
}

impl ConcurrentLedger {
    pub fn new(config: LedgerConfig) -> Result<Self, LedgerError> {
        config.validate()?;
        Ok(Self {
            config,
            state: Mutex::new(LedgerState {
                sequence: 0,
                committed_epsilon_q64_64: 0,
                reserved_epsilon_q64_64: 0,
                reservations: BTreeMap::new(),
            }),
        })
    }

    pub fn reserve(
        &self,
        reservation_id: ReservationId,
        service_id: ServiceId,
        amount_epsilon_q64_64: u128,
    ) -> Result<LedgerReceipt, LedgerError> {
        if reservation_id.0 == 0 || amount_epsilon_q64_64 == 0 {
            return Err(LedgerError::InvalidReservation);
        }
        let mut state = self.state.lock().map_err(|_| LedgerError::LockPoisoned)?;
        if state.reservations.contains_key(&reservation_id) {
            return Err(LedgerError::ReservationIdAlreadyUsed);
        }
        if state.reservations.len() >= self.config.maximum_reservation_ids {
            return Err(LedgerError::ResourceLimitExceeded);
        }
        let exposure = state
            .committed_epsilon_q64_64
            .checked_add(state.reserved_epsilon_q64_64)
            .and_then(|value| value.checked_add(amount_epsilon_q64_64))
            .ok_or(LedgerError::ArithmeticOverflow)?;
        if exposure > self.config.capacity_epsilon_q64_64 {
            return Err(LedgerError::BudgetExceeded);
        }
        let sequence = state
            .sequence
            .checked_add(1)
            .ok_or(LedgerError::ArithmeticOverflow)?;
        let reserved = state
            .reserved_epsilon_q64_64
            .checked_add(amount_epsilon_q64_64)
            .ok_or(LedgerError::ArithmeticOverflow)?;
        state.reservations.insert(
            reservation_id,
            Reservation {
                service_id,
                amount_epsilon_q64_64,
                state: ReservationState::Reserved,
            },
        );
        state.sequence = sequence;
        state.reserved_epsilon_q64_64 = reserved;
        Ok(receipt(&state, reservation_id))
    }

    pub fn commit(
        &self,
        reservation_id: ReservationId,
        service_id: ServiceId,
    ) -> Result<LedgerReceipt, LedgerError> {
        let mut state = self.state.lock().map_err(|_| LedgerError::LockPoisoned)?;
        let sequence = state
            .sequence
            .checked_add(1)
            .ok_or(LedgerError::ArithmeticOverflow)?;
        let amount = {
            let reservation = state
                .reservations
                .get(&reservation_id)
                .ok_or(LedgerError::UnknownReservation)?;
            validate_owner_and_state(reservation, service_id)?;
            reservation.amount_epsilon_q64_64
        };
        let committed = state
            .committed_epsilon_q64_64
            .checked_add(amount)
            .ok_or(LedgerError::ArithmeticOverflow)?;
        let reserved = state
            .reserved_epsilon_q64_64
            .checked_sub(amount)
            .ok_or(LedgerError::ArithmeticOverflow)?;
        state
            .reservations
            .get_mut(&reservation_id)
            .ok_or(LedgerError::UnknownReservation)?
            .state = ReservationState::Committed;
        state.sequence = sequence;
        state.committed_epsilon_q64_64 = committed;
        state.reserved_epsilon_q64_64 = reserved;
        Ok(receipt(&state, reservation_id))
    }

    pub fn abort(
        &self,
        reservation_id: ReservationId,
        service_id: ServiceId,
    ) -> Result<LedgerReceipt, LedgerError> {
        let mut state = self.state.lock().map_err(|_| LedgerError::LockPoisoned)?;
        let sequence = state
            .sequence
            .checked_add(1)
            .ok_or(LedgerError::ArithmeticOverflow)?;
        let amount = {
            let reservation = state
                .reservations
                .get(&reservation_id)
                .ok_or(LedgerError::UnknownReservation)?;
            validate_owner_and_state(reservation, service_id)?;
            reservation.amount_epsilon_q64_64
        };
        let reserved = state
            .reserved_epsilon_q64_64
            .checked_sub(amount)
            .ok_or(LedgerError::ArithmeticOverflow)?;
        state
            .reservations
            .get_mut(&reservation_id)
            .ok_or(LedgerError::UnknownReservation)?
            .state = ReservationState::Aborted;
        state.sequence = sequence;
        state.reserved_epsilon_q64_64 = reserved;
        Ok(receipt(&state, reservation_id))
    }

    pub fn snapshot(&self) -> Result<LedgerSnapshot, LedgerError> {
        let state = self.state.lock().map_err(|_| LedgerError::LockPoisoned)?;
        Ok(LedgerSnapshot {
            sequence: state.sequence,
            committed_epsilon_q64_64: state.committed_epsilon_q64_64,
            reserved_epsilon_q64_64: state.reserved_epsilon_q64_64,
            reservation_ids_seen: state.reservations.len(),
        })
    }
}

fn validate_owner_and_state(
    reservation: &Reservation,
    service_id: ServiceId,
) -> Result<(), LedgerError> {
    if reservation.service_id != service_id {
        return Err(LedgerError::ServiceMismatch);
    }
    if reservation.state != ReservationState::Reserved {
        return Err(LedgerError::ReservationNotPending);
    }
    Ok(())
}

fn receipt(state: &LedgerState, reservation_id: ReservationId) -> LedgerReceipt {
    let reservation = state.reservations[&reservation_id];
    LedgerReceipt {
        sequence: state.sequence,
        reservation_id,
        service_id: reservation.service_id,
        state: reservation.state,
        amount_epsilon_q64_64: reservation.amount_epsilon_q64_64,
        committed_epsilon_q64_64: state.committed_epsilon_q64_64,
        reserved_epsilon_q64_64: state.reserved_epsilon_q64_64,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LedgerError {
    InvalidConfig,
    InvalidReservation,
    ReservationIdAlreadyUsed,
    ResourceLimitExceeded,
    BudgetExceeded,
    UnknownReservation,
    ServiceMismatch,
    ReservationNotPending,
    ArithmeticOverflow,
    LockPoisoned,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    const SERVICE: ServiceId = ServiceId([7; 16]);

    #[test]
    fn reservation_commit_and_abort_are_linearized() {
        let ledger = ConcurrentLedger::new(LedgerConfig {
            capacity_epsilon_q64_64: 100,
            maximum_reservation_ids: 4,
        })
        .unwrap();
        ledger.reserve(ReservationId(1), SERVICE, 40).unwrap();
        let committed = ledger.commit(ReservationId(1), SERVICE).unwrap();
        assert_eq!(committed.state, ReservationState::Committed);
        ledger.reserve(ReservationId(2), SERVICE, 50).unwrap();
        let aborted = ledger.abort(ReservationId(2), SERVICE).unwrap();
        assert_eq!(aborted.state, ReservationState::Aborted);
        let snapshot = ledger.snapshot().unwrap();
        assert_eq!(snapshot.sequence, 4);
        assert_eq!(snapshot.committed_epsilon_q64_64, 40);
        assert_eq!(snapshot.reserved_epsilon_q64_64, 0);
    }

    #[test]
    fn concurrent_reservations_cannot_overspend() {
        let ledger = Arc::new(
            ConcurrentLedger::new(LedgerConfig {
                capacity_epsilon_q64_64: 100,
                maximum_reservation_ids: 32,
            })
            .unwrap(),
        );
        let handles: Vec<_> = (1..=16)
            .map(|id| {
                let ledger = Arc::clone(&ledger);
                thread::spawn(move || ledger.reserve(ReservationId(id), SERVICE, 10).is_ok())
            })
            .collect();
        let accepted = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(|accepted| *accepted)
            .count();
        assert_eq!(accepted, 10);
        assert_eq!(ledger.snapshot().unwrap().reserved_epsilon_q64_64, 100);
    }

    #[test]
    fn reservation_id_cannot_be_reused_after_abort() {
        let ledger = ConcurrentLedger::new(LedgerConfig {
            capacity_epsilon_q64_64: 10,
            maximum_reservation_ids: 2,
        })
        .unwrap();
        ledger.reserve(ReservationId(1), SERVICE, 5).unwrap();
        ledger.abort(ReservationId(1), SERVICE).unwrap();
        assert_eq!(
            ledger.reserve(ReservationId(1), SERVICE, 5),
            Err(LedgerError::ReservationIdAlreadyUsed)
        );
    }

    #[test]
    fn wrong_service_and_double_commit_fail_closed() {
        let ledger = ConcurrentLedger::new(LedgerConfig {
            capacity_epsilon_q64_64: 10,
            maximum_reservation_ids: 2,
        })
        .unwrap();
        ledger.reserve(ReservationId(1), SERVICE, 5).unwrap();
        assert_eq!(
            ledger.commit(ReservationId(1), ServiceId([8; 16])),
            Err(LedgerError::ServiceMismatch)
        );
        ledger.commit(ReservationId(1), SERVICE).unwrap();
        assert_eq!(
            ledger.commit(ReservationId(1), SERVICE),
            Err(LedgerError::ReservationNotPending)
        );
    }
}
