//! Evidence threshold for expanding a certified repair beyond canary traffic.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeCanaryGate {
    required_samples: u32,
    maximum_violations: u32,
    samples: u32,
    violations: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanaryDecision {
    Collecting,
    Promote,
    Reject,
}

impl RuntimeCanaryGate {
    pub fn new(required_samples: u32, maximum_violations: u32) -> Option<Self> {
        (required_samples > 0).then_some(Self {
            required_samples,
            maximum_violations,
            samples: 0,
            violations: 0,
        })
    }

    pub fn observe(&mut self, violated: bool) -> CanaryDecision {
        self.samples = self.samples.saturating_add(1);
        self.violations = self.violations.saturating_add(u32::from(violated));
        if self.violations > self.maximum_violations {
            CanaryDecision::Reject
        } else if self.samples >= self.required_samples {
            CanaryDecision::Promote
        } else {
            CanaryDecision::Collecting
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn violation_rejects_before_full_rollout() {
        let mut gate = RuntimeCanaryGate::new(3, 0).unwrap();
        assert_eq!(gate.observe(false), CanaryDecision::Collecting);
        assert_eq!(gate.observe(true), CanaryDecision::Reject);
    }

    #[test]
    fn clean_evidence_promotes_at_exact_threshold() {
        let mut gate = RuntimeCanaryGate::new(2, 0).unwrap();
        assert_eq!(gate.observe(false), CanaryDecision::Collecting);
        assert_eq!(gate.observe(false), CanaryDecision::Promote);
    }
}
