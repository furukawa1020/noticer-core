#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LivenessState {
    Healthy,
    Stalled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchdogError {
    InvalidTimeout,
    SequenceReplay,
    ClockRollback,
}

pub struct LivenessWatchdog {
    timeout: u64,
    last_sequence: u64,
    last_seen_at: u64,
    initialized: bool,
}

impl LivenessWatchdog {
    pub fn new(timeout: u64) -> Result<Self, WatchdogError> {
        if timeout == 0 {
            return Err(WatchdogError::InvalidTimeout);
        }
        Ok(Self {
            timeout,
            last_sequence: 0,
            last_seen_at: 0,
            initialized: false,
        })
    }
    pub fn observe(&mut self, sequence: u64, observed_at: u64) -> Result<(), WatchdogError> {
        if self.initialized && sequence <= self.last_sequence {
            return Err(WatchdogError::SequenceReplay);
        }
        if self.initialized && observed_at < self.last_seen_at {
            return Err(WatchdogError::ClockRollback);
        }
        self.last_sequence = sequence;
        self.last_seen_at = observed_at;
        self.initialized = true;
        Ok(())
    }
    pub fn evaluate(&self, now: u64) -> Result<LivenessState, WatchdogError> {
        if !self.initialized {
            return Ok(LivenessState::Stalled);
        }
        if now < self.last_seen_at {
            return Err(WatchdogError::ClockRollback);
        }
        Ok(if now - self.last_seen_at > self.timeout {
            LivenessState::Stalled
        } else {
            LivenessState::Healthy
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detects_stalled_heartbeat() {
        let mut watchdog = LivenessWatchdog::new(10).unwrap();
        watchdog.observe(1, 100).unwrap();
        assert_eq!(watchdog.evaluate(110), Ok(LivenessState::Healthy));
        assert_eq!(watchdog.evaluate(111), Ok(LivenessState::Stalled));
    }
    #[test]
    fn rejects_replay_and_clock_rollback() {
        let mut watchdog = LivenessWatchdog::new(10).unwrap();
        watchdog.observe(2, 100).unwrap();
        assert_eq!(watchdog.observe(2, 101), Err(WatchdogError::SequenceReplay));
        assert_eq!(watchdog.observe(3, 99), Err(WatchdogError::ClockRollback));
        assert_eq!(watchdog.evaluate(99), Err(WatchdogError::ClockRollback));
    }
}
