//! Domain-separated seeds for paired experiment components.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeterministicSeedPlan {
    root: u64,
}

impl DeterministicSeedPlan {
    #[must_use]
    pub const fn new(root: u64) -> Self {
        Self { root }
    }

    #[must_use]
    pub fn derive(self, component: &str, repetition: u32) -> u64 {
        let mut bytes = b"noticer.quotient-trial.seed.v1\0".to_vec();
        bytes.extend_from_slice(&self.root.to_be_bytes());
        bytes.extend_from_slice(component.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&repetition.to_be_bytes());
        let digest = crate::sha256::sha256(&bytes);
        u64::from_be_bytes(digest[..8].try_into().expect("fixed digest width"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn component_seeds_are_stable_and_separated() {
        let plan = DeterministicSeedPlan::new(7);
        assert_eq!(plan.derive("workload", 1), plan.derive("workload", 1));
        assert_ne!(plan.derive("workload", 1), plan.derive("attack", 1));
    }
}
