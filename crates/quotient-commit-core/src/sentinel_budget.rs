//! Monotonic accounting for runtime monitoring resources.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeMonitoringBudget {
    sample_limit: u64,
    alarm_limit: u32,
    samples: u64,
    alarms: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MonitoringBudgetError {
    ZeroLimit,
    SampleLimit,
    AlarmLimit,
}

impl RuntimeMonitoringBudget {
    pub fn new(sample_limit: u64, alarm_limit: u32) -> Result<Self, MonitoringBudgetError> {
        if sample_limit == 0 || alarm_limit == 0 {
            return Err(MonitoringBudgetError::ZeroLimit);
        }
        Ok(Self {
            sample_limit,
            alarm_limit,
            samples: 0,
            alarms: 0,
        })
    }

    pub fn consume_sample(&mut self) -> Result<(), MonitoringBudgetError> {
        if self.samples >= self.sample_limit {
            return Err(MonitoringBudgetError::SampleLimit);
        }
        self.samples += 1;
        Ok(())
    }

    pub fn consume_alarm(&mut self) -> Result<(), MonitoringBudgetError> {
        if self.alarms >= self.alarm_limit {
            return Err(MonitoringBudgetError::AlarmLimit);
        }
        self.alarms += 1;
        Ok(())
    }

    #[must_use]
    pub const fn usage(self) -> (u64, u32) {
        (self.samples, self.alarms)
    }

    #[must_use]
    pub const fn remaining(self) -> (u64, u32) {
        (
            self.sample_limit.saturating_sub(self.samples),
            self.alarm_limit.saturating_sub(self.alarms),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_limits_fail_closed() {
        let mut budget = RuntimeMonitoringBudget::new(1, 1).unwrap();
        assert_eq!(budget.consume_sample(), Ok(()));
        assert_eq!(
            budget.consume_sample(),
            Err(MonitoringBudgetError::SampleLimit)
        );
        assert_eq!(budget.consume_alarm(), Ok(()));
        assert_eq!(
            budget.consume_alarm(),
            Err(MonitoringBudgetError::AlarmLimit)
        );
        assert_eq!(budget.remaining(), (0, 0));
    }
}
