//! Algorithmic effort independent of wall-clock noise.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifierEffortMetric {
    pub explored_nodes: u64,
    pub simulated_worlds: u64,
    pub replay_steps: u64,
    pub hash_bytes: u64,
    pub verifier_steps: u64,
}

impl VerifierEffortMetric {
    pub fn work_units(self) -> Option<u64> {
        [
            self.explored_nodes,
            self.simulated_worlds,
            self.replay_steps,
            self.hash_bytes,
            self.verifier_steps,
        ]
        .into_iter()
        .try_fold(0_u64, u64::checked_add)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn effort_is_overflow_safe() {
        let metric = VerifierEffortMetric {
            explored_nodes: 1,
            simulated_worlds: 2,
            replay_steps: 3,
            hash_bytes: 4,
            verifier_steps: 5,
        };
        assert_eq!(metric.work_units(), Some(15));
    }
}
