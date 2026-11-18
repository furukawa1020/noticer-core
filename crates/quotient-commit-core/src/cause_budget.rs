//! Explicit resource accounting for bounded causality search.

use crate::cause_verdict::CausalInconclusiveReason;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CausalLimits {
    pub maximum_worlds: u64,
    pub maximum_interventions: u64,
    pub maximum_depth: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CausalBudget {
    limits: CausalLimits,
    pub worlds: u64,
    pub interventions: u64,
}

impl CausalBudget {
    pub fn new(limits: CausalLimits) -> Self {
        Self {
            limits,
            worlds: 0,
            interventions: 0,
        }
    }

    pub fn charge_world(&mut self, depth: u64) -> Result<(), CausalInconclusiveReason> {
        if depth > self.limits.maximum_depth {
            return Err(CausalInconclusiveReason::DepthLimit);
        }
        if self.worlds >= self.limits.maximum_worlds {
            return Err(CausalInconclusiveReason::NodeLimit);
        }
        self.worlds += 1;
        Ok(())
    }

    pub fn charge_intervention(&mut self) -> Result<(), CausalInconclusiveReason> {
        if self.interventions >= self.limits.maximum_interventions {
            return Err(CausalInconclusiveReason::InterventionLimit);
        }
        self.interventions += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget() -> CausalBudget {
        CausalBudget::new(CausalLimits {
            maximum_worlds: 1,
            maximum_interventions: 1,
            maximum_depth: 2,
        })
    }

    #[test]
    fn world_limit_is_inconclusive() {
        let mut value = budget();
        assert_eq!(value.charge_world(1), Ok(()));
        assert_eq!(
            value.charge_world(1),
            Err(CausalInconclusiveReason::NodeLimit)
        );
    }

    #[test]
    fn intervention_limit_is_distinct() {
        let mut value = budget();
        assert_eq!(value.charge_intervention(), Ok(()));
        assert_eq!(
            value.charge_intervention(),
            Err(CausalInconclusiveReason::InterventionLimit)
        );
    }

    #[test]
    fn depth_limit_does_not_consume_world() {
        let mut value = budget();
        assert_eq!(
            value.charge_world(3),
            Err(CausalInconclusiveReason::DepthLimit)
        );
        assert_eq!(value.worlds, 0);
    }
}
