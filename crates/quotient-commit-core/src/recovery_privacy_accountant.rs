//! Transactional privacy-budget accounting for recovery exports.
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportClass {
    Incident,
    Telemetry,
    Audit,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BudgetReservation {
    pub id: [u8; 16],
    pub class: ExportClass,
    pub amount: u64,
    pub epoch: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetError {
    InvalidPolicy,
    InvalidReservation,
    EpochMismatch,
    Duplicate,
    Exceeded,
    UnknownReservation,
    Replay,
}
pub struct RecoveryPrivacyAccountant {
    epoch: u64,
    limit: u64,
    spent: u64,
    reserved: u64,
    pending: BTreeMap<[u8; 16], BudgetReservation>,
    committed: BTreeSet<[u8; 16]>,
}
impl RecoveryPrivacyAccountant {
    pub fn new(epoch: u64, limit: u64) -> Result<Self, BudgetError> {
        if epoch == 0 || limit == 0 {
            return Err(BudgetError::InvalidPolicy);
        }
        Ok(Self {
            epoch,
            limit,
            spent: 0,
            reserved: 0,
            pending: BTreeMap::new(),
            committed: BTreeSet::new(),
        })
    }
    pub fn reserve(&mut self, r: BudgetReservation) -> Result<(), BudgetError> {
        if r.id == [0; 16] || r.amount == 0 {
            return Err(BudgetError::InvalidReservation);
        }
        if r.epoch != self.epoch {
            return Err(BudgetError::EpochMismatch);
        }
        if self.pending.contains_key(&r.id) || self.committed.contains(&r.id) {
            return Err(BudgetError::Duplicate);
        }
        if self
            .spent
            .saturating_add(self.reserved)
            .saturating_add(r.amount)
            > self.limit
        {
            return Err(BudgetError::Exceeded);
        }
        self.reserved += r.amount;
        self.pending.insert(r.id, r);
        Ok(())
    }
    pub fn commit(&mut self, id: [u8; 16]) -> Result<(), BudgetError> {
        if self.committed.contains(&id) {
            return Err(BudgetError::Replay);
        }
        let r = self
            .pending
            .remove(&id)
            .ok_or(BudgetError::UnknownReservation)?;
        self.reserved -= r.amount;
        self.spent += r.amount;
        self.committed.insert(id);
        Ok(())
    }
    pub fn cancel(&mut self, id: [u8; 16]) -> Result<(), BudgetError> {
        let r = self
            .pending
            .remove(&id)
            .ok_or(BudgetError::UnknownReservation)?;
        self.reserved -= r.amount;
        Ok(())
    }
    #[must_use]
    pub const fn spent(&self) -> u64 {
        self.spent
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn r(id: u8, amount: u64) -> BudgetReservation {
        BudgetReservation {
            id: [id; 16],
            class: ExportClass::Audit,
            amount,
            epoch: 2,
        }
    }
    #[test]
    fn reservation_commit_is_exactly_once() {
        let mut a = RecoveryPrivacyAccountant::new(2, 10).unwrap();
        a.reserve(r(1, 6)).unwrap();
        a.commit([1; 16]).unwrap();
        assert_eq!(a.spent(), 6);
        assert_eq!(a.commit([1; 16]), Err(BudgetError::Replay))
    }
    #[test]
    fn reservations_cannot_overbook() {
        let mut a = RecoveryPrivacyAccountant::new(2, 10).unwrap();
        a.reserve(r(1, 6)).unwrap();
        assert_eq!(a.reserve(r(2, 5)), Err(BudgetError::Exceeded));
        a.cancel([1; 16]).unwrap();
        assert_eq!(a.reserve(r(2, 5)), Ok(()));
    }
}
