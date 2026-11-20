//! Integer CUSUM change-point detector for public runtime scores.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SequentialChangePoint {
    reference: i64,
    threshold: i64,
    cumulative: i64,
    observations: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChangePointAlarm {
    pub observation: u64,
    pub score: i64,
}

impl SequentialChangePoint {
    pub fn new(reference: i64, threshold: i64) -> Option<Self> {
        (threshold > 0).then_some(Self {
            reference,
            threshold,
            cumulative: 0,
            observations: 0,
        })
    }

    pub fn observe(&mut self, value: i64) -> Option<ChangePointAlarm> {
        self.observations = self.observations.saturating_add(1);
        self.cumulative = self
            .cumulative
            .saturating_add(value.saturating_sub(self.reference))
            .max(0);
        (self.cumulative >= self.threshold).then_some(ChangePointAlarm {
            observation: self.observations,
            score: self.cumulative,
        })
    }

    pub fn reset(&mut self) {
        self.cumulative = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sustained_shift_triggers_but_isolated_noise_does_not() {
        let mut detector = SequentialChangePoint::new(5, 6).unwrap();
        assert_eq!(detector.observe(8), None);
        assert_eq!(detector.observe(2), None);
        assert_eq!(detector.observe(8), None);
        assert!(detector.observe(8).is_some());
    }
}
