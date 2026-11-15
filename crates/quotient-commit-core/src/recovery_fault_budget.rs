#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultClass {
    Authentication,
    Integrity,
    Availability,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultLimits {
    pub authentication: u32,
    pub integrity: u32,
    pub availability: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultBudgetError {
    EpochMismatch,
    Exhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultBudget {
    epoch: u64,
    limits: FaultLimits,
    used: FaultLimits,
}

impl FaultBudget {
    pub fn new(epoch: u64, limits: FaultLimits) -> Self {
        Self {
            epoch,
            limits,
            used: FaultLimits {
                authentication: 0,
                integrity: 0,
                availability: 0,
            },
        }
    }
    pub fn consume(&mut self, epoch: u64, class: FaultClass) -> Result<(), FaultBudgetError> {
        if epoch != self.epoch {
            return Err(FaultBudgetError::EpochMismatch);
        }
        let (used, limit) = match class {
            FaultClass::Authentication => {
                (&mut self.used.authentication, self.limits.authentication)
            }
            FaultClass::Integrity => (&mut self.used.integrity, self.limits.integrity),
            FaultClass::Availability => (&mut self.used.availability, self.limits.availability),
        };
        if *used >= limit {
            return Err(FaultBudgetError::Exhausted);
        }
        *used += 1;
        Ok(())
    }
    pub fn remaining(&self, class: FaultClass) -> u32 {
        match class {
            FaultClass::Authentication => self
                .limits
                .authentication
                .saturating_sub(self.used.authentication),
            FaultClass::Integrity => self.limits.integrity.saturating_sub(self.used.integrity),
            FaultClass::Availability => self
                .limits
                .availability
                .saturating_sub(self.used.availability),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accounts_for_fault_classes_independently() {
        let mut budget = FaultBudget::new(
            3,
            FaultLimits {
                authentication: 1,
                integrity: 2,
                availability: 1,
            },
        );
        assert_eq!(budget.consume(3, FaultClass::Authentication), Ok(()));
        assert_eq!(
            budget.consume(3, FaultClass::Authentication),
            Err(FaultBudgetError::Exhausted)
        );
        assert_eq!(budget.remaining(FaultClass::Integrity), 2);
    }
    #[test]
    fn rejects_cross_epoch_consumption() {
        let mut budget = FaultBudget::new(
            3,
            FaultLimits {
                authentication: 1,
                integrity: 1,
                availability: 1,
            },
        );
        assert_eq!(
            budget.consume(2, FaultClass::Integrity),
            Err(FaultBudgetError::EpochMismatch)
        );
    }
}
