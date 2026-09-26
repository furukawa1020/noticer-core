#![no_std]
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultPolicy {
    pub maximum_clock_skew_ms: u32,
    pub maximum_consecutive_missing: u16,
    pub maximum_delay_slots: u16,
    pub reorder_window: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeFault {
    Frame {
        sequence: u64,
        clock_skew_ms: i32,
    },
    MissingFrame,
    Delayed {
        slots: u16,
    },
    Disconnect,
    Reconnect {
        capsule_verified: bool,
        new_epoch: u64,
        explicit_public_reset: bool,
    },
    ResourceExhaustion,
    ConfigEpoch {
        epoch: u64,
    },
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SinkReason {
    ClockBoundExceeded,
    MissingFrameBoundExceeded,
    DelayBoundExceeded,
    DuplicateFrame,
    ReorderBoundExceeded,
    ResourceExhaustion,
    ConfigRollback,
    InvalidRecovery,
    UnknownFault,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultOutcome {
    Continue { epoch: u64, sequence: u64 },
    HoldNoRelease,
    FailClosed(SinkReason),
    Recovered { epoch: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Active,
    Disconnected,
    Sink(SinkReason),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FaultGuard {
    policy: FaultPolicy,
    epoch: u64,
    last_sequence: Option<u64>,
    consecutive_missing: u16,
    state: State,
}

impl FaultGuard {
    pub const fn new(policy: FaultPolicy, epoch: u64) -> Self {
        Self {
            policy,
            epoch,
            last_sequence: None,
            consecutive_missing: 0,
            state: State::Active,
        }
    }

    pub fn observe(&mut self, fault: RuntimeFault) -> FaultOutcome {
        match self.state {
            State::Sink(reason) => return FaultOutcome::FailClosed(reason),
            State::Disconnected => return self.observe_disconnected(fault),
            State::Active => {}
        }
        match fault {
            RuntimeFault::Frame {
                sequence,
                clock_skew_ms,
            } => self.observe_frame(sequence, clock_skew_ms),
            RuntimeFault::MissingFrame => {
                self.consecutive_missing = self.consecutive_missing.saturating_add(1);
                if self.consecutive_missing > self.policy.maximum_consecutive_missing {
                    self.enter_sink(SinkReason::MissingFrameBoundExceeded)
                } else {
                    FaultOutcome::HoldNoRelease
                }
            }
            RuntimeFault::Delayed { slots } => {
                if slots > self.policy.maximum_delay_slots {
                    self.enter_sink(SinkReason::DelayBoundExceeded)
                } else {
                    FaultOutcome::HoldNoRelease
                }
            }
            RuntimeFault::Disconnect => {
                self.state = State::Disconnected;
                FaultOutcome::HoldNoRelease
            }
            RuntimeFault::Reconnect { .. } => self.enter_sink(SinkReason::InvalidRecovery),
            RuntimeFault::ResourceExhaustion => self.enter_sink(SinkReason::ResourceExhaustion),
            RuntimeFault::ConfigEpoch { epoch } => {
                if epoch < self.epoch {
                    self.enter_sink(SinkReason::ConfigRollback)
                } else {
                    self.epoch = epoch;
                    FaultOutcome::Continue {
                        epoch: self.epoch,
                        sequence: self.last_sequence.unwrap_or(0),
                    }
                }
            }
            RuntimeFault::Unknown => self.enter_sink(SinkReason::UnknownFault),
        }
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub const fn is_fail_closed(&self) -> bool {
        matches!(self.state, State::Sink(_))
    }

    fn observe_frame(&mut self, sequence: u64, clock_skew_ms: i32) -> FaultOutcome {
        if clock_skew_ms.unsigned_abs() > self.policy.maximum_clock_skew_ms {
            return self.enter_sink(SinkReason::ClockBoundExceeded);
        }
        if let Some(last) = self.last_sequence {
            if sequence == last {
                return self.enter_sink(SinkReason::DuplicateFrame);
            }
            if sequence < last && last - sequence > u64::from(self.policy.reorder_window) {
                return self.enter_sink(SinkReason::ReorderBoundExceeded);
            }
        }
        self.last_sequence = Some(
            self.last_sequence
                .map_or(sequence, |last| last.max(sequence)),
        );
        self.consecutive_missing = 0;
        FaultOutcome::Continue {
            epoch: self.epoch,
            sequence,
        }
    }

    fn observe_disconnected(&mut self, fault: RuntimeFault) -> FaultOutcome {
        match fault {
            RuntimeFault::Reconnect {
                capsule_verified: true,
                new_epoch,
                explicit_public_reset: true,
            } if new_epoch > self.epoch => {
                self.epoch = new_epoch;
                self.last_sequence = None;
                self.consecutive_missing = 0;
                self.state = State::Active;
                FaultOutcome::Recovered { epoch: new_epoch }
            }
            RuntimeFault::Disconnect | RuntimeFault::MissingFrame => FaultOutcome::HoldNoRelease,
            RuntimeFault::ResourceExhaustion => self.enter_sink(SinkReason::ResourceExhaustion),
            _ => self.enter_sink(SinkReason::InvalidRecovery),
        }
    }

    fn enter_sink(&mut self, reason: SinkReason) -> FaultOutcome {
        self.state = State::Sink(reason);
        FaultOutcome::FailClosed(reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard() -> FaultGuard {
        FaultGuard::new(
            FaultPolicy {
                maximum_clock_skew_ms: 250,
                maximum_consecutive_missing: 2,
                maximum_delay_slots: 3,
                reorder_window: 4,
            },
            7,
        )
    }

    #[test]
    fn bounded_missing_delay_and_reorder_hold_or_continue() {
        let mut guard = guard();
        assert_eq!(
            guard.observe(RuntimeFault::MissingFrame),
            FaultOutcome::HoldNoRelease
        );
        assert_eq!(
            guard.observe(RuntimeFault::Delayed { slots: 3 }),
            FaultOutcome::HoldNoRelease
        );
        assert_eq!(
            guard.observe(RuntimeFault::Frame {
                sequence: 10,
                clock_skew_ms: -250
            }),
            FaultOutcome::Continue {
                epoch: 7,
                sequence: 10
            }
        );
        assert_eq!(
            guard.observe(RuntimeFault::Frame {
                sequence: 8,
                clock_skew_ms: 0
            }),
            FaultOutcome::Continue {
                epoch: 7,
                sequence: 8
            }
        );
    }

    #[test]
    fn clock_missing_delay_duplicate_and_reorder_bounds_fail_closed() {
        let cases = [
            (
                RuntimeFault::Frame {
                    sequence: 1,
                    clock_skew_ms: 251,
                },
                SinkReason::ClockBoundExceeded,
            ),
            (
                RuntimeFault::Delayed { slots: 4 },
                SinkReason::DelayBoundExceeded,
            ),
            (
                RuntimeFault::ResourceExhaustion,
                SinkReason::ResourceExhaustion,
            ),
            (RuntimeFault::Unknown, SinkReason::UnknownFault),
        ];
        for (fault, reason) in cases {
            assert_eq!(guard().observe(fault), FaultOutcome::FailClosed(reason));
        }
        let mut missing = guard();
        missing.observe(RuntimeFault::MissingFrame);
        missing.observe(RuntimeFault::MissingFrame);
        assert_eq!(
            missing.observe(RuntimeFault::MissingFrame),
            FaultOutcome::FailClosed(SinkReason::MissingFrameBoundExceeded)
        );
        let mut duplicate = guard();
        duplicate.observe(RuntimeFault::Frame {
            sequence: 9,
            clock_skew_ms: 0,
        });
        assert_eq!(
            duplicate.observe(RuntimeFault::Frame {
                sequence: 9,
                clock_skew_ms: 0
            }),
            FaultOutcome::FailClosed(SinkReason::DuplicateFrame)
        );
        let mut reorder = guard();
        reorder.observe(RuntimeFault::Frame {
            sequence: 9,
            clock_skew_ms: 0,
        });
        assert_eq!(
            reorder.observe(RuntimeFault::Frame {
                sequence: 4,
                clock_skew_ms: 0
            }),
            FaultOutcome::FailClosed(SinkReason::ReorderBoundExceeded)
        );
    }

    #[test]
    fn config_epoch_rollback_is_sticky() {
        let mut guard = guard();
        assert_eq!(
            guard.observe(RuntimeFault::ConfigEpoch { epoch: 6 }),
            FaultOutcome::FailClosed(SinkReason::ConfigRollback)
        );
        assert_eq!(
            guard.observe(RuntimeFault::ConfigEpoch { epoch: 8 }),
            FaultOutcome::FailClosed(SinkReason::ConfigRollback)
        );
    }

    #[test]
    fn reconnect_requires_all_three_frozen_conditions() {
        for reconnect in [
            RuntimeFault::Reconnect {
                capsule_verified: false,
                new_epoch: 8,
                explicit_public_reset: true,
            },
            RuntimeFault::Reconnect {
                capsule_verified: true,
                new_epoch: 7,
                explicit_public_reset: true,
            },
            RuntimeFault::Reconnect {
                capsule_verified: true,
                new_epoch: 8,
                explicit_public_reset: false,
            },
        ] {
            let mut guard = guard();
            guard.observe(RuntimeFault::Disconnect);
            assert_eq!(
                guard.observe(reconnect),
                FaultOutcome::FailClosed(SinkReason::InvalidRecovery)
            );
        }
    }

    #[test]
    fn verified_new_epoch_and_public_reset_recover_without_old_sequence() {
        let mut guard = guard();
        guard.observe(RuntimeFault::Frame {
            sequence: 99,
            clock_skew_ms: 0,
        });
        guard.observe(RuntimeFault::Disconnect);
        assert_eq!(
            guard.observe(RuntimeFault::Reconnect {
                capsule_verified: true,
                new_epoch: 8,
                explicit_public_reset: true
            }),
            FaultOutcome::Recovered { epoch: 8 }
        );
        assert_eq!(
            guard.observe(RuntimeFault::Frame {
                sequence: 0,
                clock_skew_ms: 0
            }),
            FaultOutcome::Continue {
                epoch: 8,
                sequence: 0
            }
        );
    }
}
