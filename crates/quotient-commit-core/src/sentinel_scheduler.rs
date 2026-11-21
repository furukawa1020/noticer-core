//! Deterministic monitoring cadence selected from public risk state.

use crate::sentinel_alarm_fusion::AlarmSeverity;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MonitorSchedule {
    pub sample_every_slots: u32,
    pub full_check_every_samples: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdaptiveMonitorScheduler {
    nominal: MonitorSchedule,
    elevated: MonitorSchedule,
    critical: MonitorSchedule,
}

impl AdaptiveMonitorScheduler {
    pub fn new(
        nominal: MonitorSchedule,
        elevated: MonitorSchedule,
        critical: MonitorSchedule,
    ) -> Option<Self> {
        let valid = nominal.sample_every_slots > 0
            && elevated.sample_every_slots > 0
            && critical.sample_every_slots > 0
            && critical.sample_every_slots <= elevated.sample_every_slots
            && elevated.sample_every_slots <= nominal.sample_every_slots;
        valid.then_some(Self {
            nominal,
            elevated,
            critical,
        })
    }

    #[must_use]
    pub const fn schedule(self, severity: Option<AlarmSeverity>) -> MonitorSchedule {
        match severity {
            Some(AlarmSeverity::Critical) => self.critical,
            Some(AlarmSeverity::Elevated) => self.elevated,
            _ => self.nominal,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risk_can_only_increase_sampling_frequency() {
        let scheduler = AdaptiveMonitorScheduler::new(
            MonitorSchedule {
                sample_every_slots: 8,
                full_check_every_samples: 8,
            },
            MonitorSchedule {
                sample_every_slots: 4,
                full_check_every_samples: 4,
            },
            MonitorSchedule {
                sample_every_slots: 1,
                full_check_every_samples: 1,
            },
        )
        .unwrap();
        assert_eq!(
            scheduler
                .schedule(Some(AlarmSeverity::Critical))
                .sample_every_slots,
            1
        );
    }
}
