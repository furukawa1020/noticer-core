#![forbid(unsafe_code)]

use quotient_ledger::ServiceId;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CoalitionId(pub u64);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ObserverId(pub [u8; 16]);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ChargeId(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoalitionConfig {
    pub maximum_coalitions: usize,
    pub maximum_services: usize,
    pub maximum_observers_per_coalition: usize,
    pub maximum_charge_ids: usize,
}

impl CoalitionConfig {
    pub const fn validate(self) -> Result<(), CoalitionError> {
        if self.maximum_coalitions == 0
            || self.maximum_services == 0
            || self.maximum_observers_per_coalition == 0
            || self.maximum_charge_ids == 0
        {
            return Err(CoalitionError::InvalidConfig);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Coalition {
    observers: Vec<ObserverId>,
    capacity_epsilon_q64_64: u128,
    spent_epsilon_q64_64: u128,
}

#[derive(Debug)]
struct State {
    sequence: u64,
    coalitions: BTreeMap<CoalitionId, Coalition>,
    observer_owner: BTreeMap<ObserverId, CoalitionId>,
    service_owner: BTreeMap<ServiceId, CoalitionId>,
    charge_ids: BTreeSet<ChargeId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoalitionReceipt {
    pub sequence: u64,
    pub charge_id: ChargeId,
    pub coalition_id: CoalitionId,
    pub service_id: ServiceId,
    pub amount_epsilon_q64_64: u128,
    pub joint_spent_epsilon_q64_64: u128,
    pub joint_capacity_epsilon_q64_64: u128,
    pub trace_commitment: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoalitionSnapshot {
    pub sequence: u64,
    pub coalition_id: CoalitionId,
    pub observer_count: usize,
    pub service_count: usize,
    pub spent_epsilon_q64_64: u128,
    pub capacity_epsilon_q64_64: u128,
}

#[derive(Debug)]
pub struct CoalitionAccountant {
    config: CoalitionConfig,
    state: Mutex<State>,
}

impl CoalitionAccountant {
    pub fn new(config: CoalitionConfig) -> Result<Self, CoalitionError> {
        config.validate()?;
        Ok(Self {
            config,
            state: Mutex::new(State {
                sequence: 0,
                coalitions: BTreeMap::new(),
                observer_owner: BTreeMap::new(),
                service_owner: BTreeMap::new(),
                charge_ids: BTreeSet::new(),
            }),
        })
    }

    pub fn declare_coalition(
        &self,
        coalition_id: CoalitionId,
        observers: &[ObserverId],
        capacity_epsilon_q64_64: u128,
    ) -> Result<u64, CoalitionError> {
        if coalition_id.0 == 0 || capacity_epsilon_q64_64 == 0 || observers.is_empty() {
            return Err(CoalitionError::InvalidDeclaration);
        }
        if observers.len() > self.config.maximum_observers_per_coalition {
            return Err(CoalitionError::ResourceLimitExceeded);
        }
        if observers.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(CoalitionError::ObserversNotCanonical);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| CoalitionError::LockPoisoned)?;
        if state.coalitions.contains_key(&coalition_id) {
            return Err(CoalitionError::CoalitionAlreadyDeclared);
        }
        if state.coalitions.len() >= self.config.maximum_coalitions {
            return Err(CoalitionError::ResourceLimitExceeded);
        }
        if observers
            .iter()
            .any(|observer| state.observer_owner.contains_key(observer))
        {
            return Err(CoalitionError::ObserverAlreadyAssigned);
        }
        let sequence = next_sequence(state.sequence)?;
        state.coalitions.insert(
            coalition_id,
            Coalition {
                observers: observers.to_vec(),
                capacity_epsilon_q64_64,
                spent_epsilon_q64_64: 0,
            },
        );
        for observer in observers {
            state.observer_owner.insert(*observer, coalition_id);
        }
        state.sequence = sequence;
        Ok(sequence)
    }

    pub fn register_service(
        &self,
        service_id: ServiceId,
        coalition_id: CoalitionId,
    ) -> Result<u64, CoalitionError> {
        if service_id.0 == [0; 16] {
            return Err(CoalitionError::InvalidService);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| CoalitionError::LockPoisoned)?;
        if !state.coalitions.contains_key(&coalition_id) {
            return Err(CoalitionError::UnknownCoalition);
        }
        if state.service_owner.contains_key(&service_id) {
            return Err(CoalitionError::ServiceAlreadyRegistered);
        }
        if state.service_owner.len() >= self.config.maximum_services {
            return Err(CoalitionError::ResourceLimitExceeded);
        }
        let sequence = next_sequence(state.sequence)?;
        state.service_owner.insert(service_id, coalition_id);
        state.sequence = sequence;
        Ok(sequence)
    }

    pub fn charge(
        &self,
        charge_id: ChargeId,
        service_id: ServiceId,
        claimed_coalition_id: CoalitionId,
        amount_epsilon_q64_64: u128,
        trace_commitment: [u8; 32],
    ) -> Result<CoalitionReceipt, CoalitionError> {
        if charge_id.0 == 0 || amount_epsilon_q64_64 == 0 || trace_commitment == [0; 32] {
            return Err(CoalitionError::InvalidCharge);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| CoalitionError::LockPoisoned)?;
        let assigned = state
            .service_owner
            .get(&service_id)
            .copied()
            .ok_or(CoalitionError::UntrackedService)?;
        if assigned != claimed_coalition_id {
            return Err(CoalitionError::CoalitionMismatch);
        }
        if state.charge_ids.contains(&charge_id) {
            return Err(CoalitionError::ChargeIdAlreadyUsed);
        }
        if state.charge_ids.len() >= self.config.maximum_charge_ids {
            return Err(CoalitionError::ResourceLimitExceeded);
        }
        let coalition = state
            .coalitions
            .get(&assigned)
            .ok_or(CoalitionError::UnknownCoalition)?;
        let spent = coalition
            .spent_epsilon_q64_64
            .checked_add(amount_epsilon_q64_64)
            .ok_or(CoalitionError::ArithmeticOverflow)?;
        if spent > coalition.capacity_epsilon_q64_64 {
            return Err(CoalitionError::JointBudgetExceeded);
        }
        let capacity = coalition.capacity_epsilon_q64_64;
        let sequence = next_sequence(state.sequence)?;
        state
            .coalitions
            .get_mut(&assigned)
            .ok_or(CoalitionError::UnknownCoalition)?
            .spent_epsilon_q64_64 = spent;
        state.charge_ids.insert(charge_id);
        state.sequence = sequence;
        Ok(CoalitionReceipt {
            sequence,
            charge_id,
            coalition_id: assigned,
            service_id,
            amount_epsilon_q64_64,
            joint_spent_epsilon_q64_64: spent,
            joint_capacity_epsilon_q64_64: capacity,
            trace_commitment,
        })
    }

    pub fn snapshot(&self, coalition_id: CoalitionId) -> Result<CoalitionSnapshot, CoalitionError> {
        let state = self
            .state
            .lock()
            .map_err(|_| CoalitionError::LockPoisoned)?;
        let coalition = state
            .coalitions
            .get(&coalition_id)
            .ok_or(CoalitionError::UnknownCoalition)?;
        let service_count = state
            .service_owner
            .values()
            .filter(|owner| **owner == coalition_id)
            .count();
        Ok(CoalitionSnapshot {
            sequence: state.sequence,
            coalition_id,
            observer_count: coalition.observers.len(),
            service_count,
            spent_epsilon_q64_64: coalition.spent_epsilon_q64_64,
            capacity_epsilon_q64_64: coalition.capacity_epsilon_q64_64,
        })
    }
}

fn next_sequence(sequence: u64) -> Result<u64, CoalitionError> {
    sequence
        .checked_add(1)
        .ok_or(CoalitionError::ArithmeticOverflow)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoalitionError {
    InvalidConfig,
    InvalidDeclaration,
    InvalidService,
    InvalidCharge,
    ObserversNotCanonical,
    CoalitionAlreadyDeclared,
    ObserverAlreadyAssigned,
    ServiceAlreadyRegistered,
    UnknownCoalition,
    UntrackedService,
    CoalitionMismatch,
    ChargeIdAlreadyUsed,
    JointBudgetExceeded,
    ResourceLimitExceeded,
    ArithmeticOverflow,
    LockPoisoned,
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: ServiceId = ServiceId([1; 16]);
    const B: ServiceId = ServiceId([2; 16]);
    const C: ServiceId = ServiceId([3; 16]);
    const COALITION: CoalitionId = CoalitionId(7);

    fn accountant() -> CoalitionAccountant {
        let accountant = CoalitionAccountant::new(CoalitionConfig {
            maximum_coalitions: 2,
            maximum_services: 4,
            maximum_observers_per_coalition: 4,
            maximum_charge_ids: 8,
        })
        .unwrap();
        accountant
            .declare_coalition(COALITION, &[ObserverId([1; 16]), ObserverId([2; 16])], 100)
            .unwrap();
        accountant.register_service(A, COALITION).unwrap();
        accountant.register_service(B, COALITION).unwrap();
        accountant
    }

    #[test]
    fn split_services_share_one_joint_budget() {
        let accountant = accountant();
        accountant
            .charge(ChargeId(1), A, COALITION, 60, [1; 32])
            .unwrap();
        assert_eq!(
            accountant.charge(ChargeId(2), B, COALITION, 50, [2; 32]),
            Err(CoalitionError::JointBudgetExceeded)
        );
        let receipt = accountant
            .charge(ChargeId(3), B, COALITION, 40, [3; 32])
            .unwrap();
        assert_eq!(receipt.joint_spent_epsilon_q64_64, 100);
    }

    #[test]
    fn untracked_service_and_false_coalition_fail_closed() {
        let accountant = accountant();
        assert_eq!(
            accountant.charge(ChargeId(1), C, COALITION, 1, [1; 32]),
            Err(CoalitionError::UntrackedService)
        );
        assert_eq!(
            accountant.charge(ChargeId(2), A, CoalitionId(8), 1, [2; 32]),
            Err(CoalitionError::CoalitionMismatch)
        );
    }

    #[test]
    fn observers_cannot_span_declared_coalitions() {
        let accountant = accountant();
        assert_eq!(
            accountant.declare_coalition(CoalitionId(8), &[ObserverId([2; 16])], 10),
            Err(CoalitionError::ObserverAlreadyAssigned)
        );
    }

    #[test]
    fn charge_ids_are_single_use_even_across_services() {
        let accountant = accountant();
        accountant
            .charge(ChargeId(1), A, COALITION, 10, [1; 32])
            .unwrap();
        assert_eq!(
            accountant.charge(ChargeId(1), B, COALITION, 10, [2; 32]),
            Err(CoalitionError::ChargeIdAlreadyUsed)
        );
    }

    #[test]
    fn observer_order_is_canonical_and_strict() {
        let accountant = CoalitionAccountant::new(CoalitionConfig {
            maximum_coalitions: 1,
            maximum_services: 1,
            maximum_observers_per_coalition: 2,
            maximum_charge_ids: 1,
        })
        .unwrap();
        assert_eq!(
            accountant
                .declare_coalition(COALITION, &[ObserverId([2; 16]), ObserverId([1; 16])], 1,),
            Err(CoalitionError::ObserversNotCanonical)
        );
    }
}
