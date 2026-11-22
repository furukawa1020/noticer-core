//! Pre-registered repetition bounds and precision stopping rule.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepetitionSchedule {
    pub minimum: u32,
    pub maximum: u32,
    pub target_half_width: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepetitionError {
    ZeroMinimum,
    InvalidRange,
    ZeroTarget,
}

impl RepetitionSchedule {
    pub fn new(
        minimum: u32,
        maximum: u32,
        target_half_width: u64,
    ) -> Result<Self, RepetitionError> {
        if minimum == 0 {
            return Err(RepetitionError::ZeroMinimum);
        }
        if maximum < minimum {
            return Err(RepetitionError::InvalidRange);
        }
        if target_half_width == 0 {
            return Err(RepetitionError::ZeroTarget);
        }
        Ok(Self {
            minimum,
            maximum,
            target_half_width,
        })
    }

    pub const fn should_stop(self, completed: u32, observed_half_width: u64) -> bool {
        completed >= self.maximum
            || (completed >= self.minimum && observed_half_width <= self.target_half_width)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn precision_cannot_stop_before_minimum() {
        let schedule = RepetitionSchedule::new(5, 10, 2).unwrap();
        assert!(!schedule.should_stop(4, 1));
        assert!(schedule.should_stop(5, 1));
        assert!(schedule.should_stop(10, 99));
    }
}
