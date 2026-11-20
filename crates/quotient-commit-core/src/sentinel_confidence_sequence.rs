//! Integer-valued confidence sequence using a precommitted monotone radius schedule.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnytimeConfidenceSequence {
    radii_ppm: Vec<u32>,
    successes: u64,
    trials: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfidenceIntervalPpm {
    pub lower: u32,
    pub upper: u32,
    pub trials: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfidenceSequenceError {
    EmptySchedule,
    InvalidRadius,
    NonMonotoneSchedule,
    ScheduleExhausted,
}

impl AnytimeConfidenceSequence {
    pub fn new(radii_ppm: Vec<u32>) -> Result<Self, ConfidenceSequenceError> {
        if radii_ppm.is_empty() {
            return Err(ConfidenceSequenceError::EmptySchedule);
        }
        if radii_ppm.iter().any(|radius| *radius > 1_000_000) {
            return Err(ConfidenceSequenceError::InvalidRadius);
        }
        if radii_ppm.windows(2).any(|pair| pair[1] > pair[0]) {
            return Err(ConfidenceSequenceError::NonMonotoneSchedule);
        }
        Ok(Self {
            radii_ppm,
            successes: 0,
            trials: 0,
        })
    }

    pub fn observe(
        &mut self,
        success: bool,
    ) -> Result<ConfidenceIntervalPpm, ConfidenceSequenceError> {
        let index =
            usize::try_from(self.trials).map_err(|_| ConfidenceSequenceError::ScheduleExhausted)?;
        let radius = *self
            .radii_ppm
            .get(index)
            .ok_or(ConfidenceSequenceError::ScheduleExhausted)?;
        self.trials += 1;
        self.successes += u64::from(success);
        let estimate = u32::try_from(self.successes.saturating_mul(1_000_000) / self.trials)
            .unwrap_or(1_000_000);
        Ok(ConfidenceIntervalPpm {
            lower: estimate.saturating_sub(radius),
            upper: estimate.saturating_add(radius).min(1_000_000),
            trials: self.trials,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_queries_use_precommitted_boundaries() {
        let mut sequence = AnytimeConfidenceSequence::new(vec![500_000, 400_000]).unwrap();
        assert_eq!(
            sequence.observe(true).unwrap(),
            ConfidenceIntervalPpm {
                lower: 500_000,
                upper: 1_000_000,
                trials: 1
            }
        );
        assert_eq!(sequence.observe(false).unwrap().trials, 2);
        assert_eq!(
            sequence.observe(true),
            Err(ConfidenceSequenceError::ScheduleExhausted)
        );
    }
}
