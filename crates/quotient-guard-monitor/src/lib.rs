#![no_std]
#![forbid(unsafe_code)]

use quotient_guard_shadow::{DivergenceClass, PublicProjection, ShadowStepOutcome};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MonitorLimits {
    pub maximum_slots: u64,
    pub minimum_shadows: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelationWitness {
    pub first_divergent_slot: u64,
    pub class: DivergenceClass,
    pub equivalent_prefix_slots: u64,
    pub compared_shadows: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SinkReason {
    RelationViolation,
    SlotDiscontinuity,
    ShadowCountBelowContract,
    ResourceExhaustion,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MonitorVerdict {
    Running {
        checked_slots: u64,
        projection: PublicProjection,
    },
    RelationViolation(RelationWitness),
    FailClosed {
        reason: SinkReason,
        checked_slots: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Running,
    Violated(RelationWitness),
    Sink(SinkReason),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationMonitor {
    limits: MonitorLimits,
    expected_slot: u64,
    state: State,
}

impl RelationMonitor {
    pub const fn new(limits: MonitorLimits) -> Self {
        Self {
            limits,
            expected_slot: 0,
            state: State::Running,
        }
    }

    pub fn observe(&mut self, outcome: ShadowStepOutcome) -> MonitorVerdict {
        match self.state {
            State::Violated(witness) => return MonitorVerdict::RelationViolation(witness),
            State::Sink(reason) => {
                return MonitorVerdict::FailClosed {
                    reason,
                    checked_slots: self.expected_slot,
                };
            }
            State::Running => {}
        }
        if self.expected_slot >= self.limits.maximum_slots {
            return self.enter_sink(SinkReason::ResourceExhaustion);
        }
        let (slot, compared_shadows) = match outcome {
            ShadowStepOutcome::Equivalent {
                slot,
                compared_shadows,
                ..
            }
            | ShadowStepOutcome::Diverged {
                slot,
                compared_shadows,
                ..
            } => (slot, compared_shadows),
        };
        if slot != self.expected_slot {
            return self.enter_sink(SinkReason::SlotDiscontinuity);
        }
        if compared_shadows < self.limits.minimum_shadows {
            return self.enter_sink(SinkReason::ShadowCountBelowContract);
        }
        match outcome {
            ShadowStepOutcome::Equivalent { projection, .. } => {
                self.expected_slot += 1;
                MonitorVerdict::Running {
                    checked_slots: self.expected_slot,
                    projection,
                }
            }
            ShadowStepOutcome::Diverged { class, .. } => {
                let witness = RelationWitness {
                    first_divergent_slot: slot,
                    class,
                    equivalent_prefix_slots: self.expected_slot,
                    compared_shadows,
                };
                self.state = State::Violated(witness);
                MonitorVerdict::RelationViolation(witness)
            }
        }
    }

    pub fn enter_safe_sink(&mut self, reason: SinkReason) -> MonitorVerdict {
        if let State::Violated(witness) = self.state {
            return MonitorVerdict::RelationViolation(witness);
        }
        self.enter_sink(reason)
    }

    pub const fn checked_slots(&self) -> u64 {
        self.expected_slot
    }

    fn enter_sink(&mut self, reason: SinkReason) -> MonitorVerdict {
        self.state = State::Sink(reason);
        MonitorVerdict::FailClosed {
            reason,
            checked_slots: self.expected_slot,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROJECTION: PublicProjection = PublicProjection {
        release_symbol: Some(7),
        public_state: 1,
        public_error: 0,
    };

    fn monitor(maximum_slots: u64) -> RelationMonitor {
        RelationMonitor::new(MonitorLimits {
            maximum_slots,
            minimum_shadows: 2,
        })
    }

    fn equivalent(slot: u64) -> ShadowStepOutcome {
        ShadowStepOutcome::Equivalent {
            slot,
            projection: PROJECTION,
            compared_shadows: 2,
        }
    }

    #[test]
    fn equivalent_prefix_advances_monotonically() {
        let mut monitor = monitor(4);
        assert_eq!(
            monitor.observe(equivalent(0)),
            MonitorVerdict::Running {
                checked_slots: 1,
                projection: PROJECTION,
            }
        );
        assert_eq!(
            monitor.observe(equivalent(1)),
            MonitorVerdict::Running {
                checked_slots: 2,
                projection: PROJECTION
            }
        );
    }

    #[test]
    fn first_divergence_is_sticky_and_minimal() {
        let mut monitor = monitor(4);
        monitor.observe(equivalent(0));
        let divergence = ShadowStepOutcome::Diverged {
            slot: 1,
            class: DivergenceClass::ReleaseSymbol,
            compared_shadows: 2,
        };
        let expected = MonitorVerdict::RelationViolation(RelationWitness {
            first_divergent_slot: 1,
            class: DivergenceClass::ReleaseSymbol,
            equivalent_prefix_slots: 1,
            compared_shadows: 2,
        });
        assert_eq!(monitor.observe(divergence), expected);
        assert_eq!(monitor.observe(equivalent(1)), expected);
    }

    #[test]
    fn skipped_or_replayed_slot_fails_closed() {
        let mut skipped = monitor(4);
        assert_eq!(
            skipped.observe(equivalent(1)),
            MonitorVerdict::FailClosed {
                reason: SinkReason::SlotDiscontinuity,
                checked_slots: 0
            }
        );
        let mut replayed = monitor(4);
        replayed.observe(equivalent(0));
        assert_eq!(
            replayed.observe(equivalent(0)),
            MonitorVerdict::FailClosed {
                reason: SinkReason::SlotDiscontinuity,
                checked_slots: 1
            }
        );
    }

    #[test]
    fn resource_limit_is_not_a_security_success() {
        let mut monitor = monitor(1);
        monitor.observe(equivalent(0));
        assert_eq!(
            monitor.observe(equivalent(1)),
            MonitorVerdict::FailClosed {
                reason: SinkReason::ResourceExhaustion,
                checked_slots: 1
            }
        );
    }

    #[test]
    fn too_few_shadows_and_explicit_sink_are_terminal() {
        let mut count = monitor(4);
        let outcome = ShadowStepOutcome::Equivalent {
            slot: 0,
            projection: PROJECTION,
            compared_shadows: 1,
        };
        assert_eq!(
            count.observe(outcome),
            MonitorVerdict::FailClosed {
                reason: SinkReason::ShadowCountBelowContract,
                checked_slots: 0
            }
        );
        let mut explicit = monitor(4);
        let verdict = explicit.enter_safe_sink(SinkReason::RelationViolation);
        assert_eq!(
            verdict,
            MonitorVerdict::FailClosed {
                reason: SinkReason::RelationViolation,
                checked_slots: 0
            }
        );
        assert_eq!(explicit.observe(equivalent(0)), verdict);
    }
}
