use crate::oracle_verdict::InconclusiveReason;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExplorationLimits {
    pub nodes: u64,
    pub transitions: u64,
    pub depth: u64,
}
pub struct ExplorationBudget {
    limits: ExplorationLimits,
    nodes: u64,
    transitions: u64,
}
impl ExplorationBudget {
    pub fn new(limits: ExplorationLimits) -> Self {
        Self {
            limits,
            nodes: 0,
            transitions: 0,
        }
    }
    pub fn consume_node(&mut self) -> Result<(), InconclusiveReason> {
        if self.nodes >= self.limits.nodes {
            return Err(InconclusiveReason::NodeLimit);
        }
        self.nodes += 1;
        Ok(())
    }
    pub fn consume_transition(&mut self) -> Result<(), InconclusiveReason> {
        if self.transitions >= self.limits.transitions {
            return Err(InconclusiveReason::TransitionLimit);
        }
        self.transitions += 1;
        Ok(())
    }
    pub fn check_depth(&self, depth: u64) -> Result<(), InconclusiveReason> {
        if depth > self.limits.depth {
            Err(InconclusiveReason::DepthLimit)
        } else {
            Ok(())
        }
    }
    pub fn counts(&self) -> (u64, u64) {
        (self.nodes, self.transitions)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn limits_are_independent() {
        let mut b = ExplorationBudget::new(ExplorationLimits {
            nodes: 1,
            transitions: 2,
            depth: 3,
        });
        assert_eq!(b.consume_node(), Ok(()));
        assert_eq!(b.consume_node(), Err(InconclusiveReason::NodeLimit));
        assert_eq!(b.consume_transition(), Ok(()))
    }
    #[test]
    fn depth_cutoff_is_inconclusive() {
        let b = ExplorationBudget::new(ExplorationLimits {
            nodes: 1,
            transitions: 1,
            depth: 2,
        });
        assert_eq!(b.check_depth(3), Err(InconclusiveReason::DepthLimit));
    }
}
