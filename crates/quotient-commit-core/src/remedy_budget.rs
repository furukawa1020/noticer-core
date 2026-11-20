//! Monotonic node/world accounting for bounded repair search.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepairExplorationBudget {
    node_limit: u32,
    world_limit: u32,
    nodes: u32,
    worlds: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetError {
    ZeroLimit,
    NodeLimit,
    WorldLimit,
}

impl RepairExplorationBudget {
    pub fn new(node_limit: u32, world_limit: u32) -> Result<Self, BudgetError> {
        if node_limit == 0 || world_limit == 0 {
            return Err(BudgetError::ZeroLimit);
        }
        Ok(Self {
            node_limit,
            world_limit,
            nodes: 0,
            worlds: 0,
        })
    }

    pub fn consume_node(&mut self) -> Result<(), BudgetError> {
        if self.nodes >= self.node_limit {
            return Err(BudgetError::NodeLimit);
        }
        self.nodes += 1;
        Ok(())
    }

    pub fn consume_world(&mut self) -> Result<(), BudgetError> {
        if self.worlds >= self.world_limit {
            return Err(BudgetError::WorldLimit);
        }
        self.worlds += 1;
        Ok(())
    }

    #[must_use]
    pub const fn consumed(self) -> (u32, u32) {
        (self.nodes, self.worlds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_are_exact_and_monotonic() {
        let mut budget = RepairExplorationBudget::new(1, 1).unwrap();
        assert_eq!(budget.consume_node(), Ok(()));
        assert_eq!(budget.consume_node(), Err(BudgetError::NodeLimit));
        assert_eq!(budget.consume_world(), Ok(()));
        assert_eq!(budget.consume_world(), Err(BudgetError::WorldLimit));
        assert_eq!(budget.consumed(), (1, 1));
    }
}
