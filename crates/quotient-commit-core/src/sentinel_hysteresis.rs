//! Stateful hysteresis that never delays a critical runtime violation.

use crate::sentinel_alarm_fusion::AlarmSeverity;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AlarmHysteresis {
    enter_after: u16,
    clear_after: u16,
    high_streak: u16,
    clear_streak: u16,
    active: bool,
}

impl AlarmHysteresis {
    pub fn new(enter_after: u16, clear_after: u16) -> Option<Self> {
        (enter_after > 0 && clear_after > 0).then_some(Self {
            enter_after,
            clear_after,
            high_streak: 0,
            clear_streak: 0,
            active: false,
        })
    }

    pub fn observe(&mut self, severity: Option<AlarmSeverity>) -> bool {
        if severity == Some(AlarmSeverity::Critical) {
            self.active = true;
            self.high_streak = self.enter_after;
            self.clear_streak = 0;
            return true;
        }
        if severity.is_some_and(|value| value >= AlarmSeverity::Elevated) {
            self.high_streak = self.high_streak.saturating_add(1);
            self.clear_streak = 0;
            if self.high_streak >= self.enter_after {
                self.active = true;
            }
        } else {
            self.high_streak = 0;
            self.clear_streak = self.clear_streak.saturating_add(1);
            if self.clear_streak >= self.clear_after {
                self.active = false;
            }
        }
        self.active
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critical_is_immediate_but_elevated_uses_hysteresis() {
        let mut gate = AlarmHysteresis::new(2, 2).unwrap();
        assert!(!gate.observe(Some(AlarmSeverity::Elevated)));
        assert!(gate.observe(Some(AlarmSeverity::Elevated)));
        assert!(gate.observe(None));
        assert!(!gate.observe(None));
        assert!(gate.observe(Some(AlarmSeverity::Critical)));
    }
}
