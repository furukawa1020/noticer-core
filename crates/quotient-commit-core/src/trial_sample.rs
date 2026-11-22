//! Typed integer sample with explicit censoring.

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MetricKind {
    LatencyNanos,
    ThroughputMilliPerSecond,
    PeakMemoryBytes,
    ArtifactBytes,
    VerifierSteps,
    LeakagePpm,
    UtilityPpm,
    DetectionDelaySlots,
    FalseAlarmPpm,
    RepairCost,
    RollbackCost,
    EnergyProxy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Censoring {
    None,
    Timeout,
    OutOfMemory,
    BudgetExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrialSample {
    pub run: u32,
    pub repetition: u32,
    pub metric: MetricKind,
    pub value: Option<u64>,
    pub censoring: Censoring,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SampleError {
    ZeroRun,
    MissingValue,
    CensoredWithValue,
}

impl TrialSample {
    pub fn new(
        run: u32,
        repetition: u32,
        metric: MetricKind,
        value: Option<u64>,
        censoring: Censoring,
    ) -> Result<Self, SampleError> {
        if run == 0 {
            return Err(SampleError::ZeroRun);
        }
        match (value, censoring) {
            (None, Censoring::None) => return Err(SampleError::MissingValue),
            (Some(_), Censoring::None) | (None, _) => {}
            (Some(_), _) => return Err(SampleError::CensoredWithValue),
        }
        Ok(Self {
            run,
            repetition,
            metric,
            value,
            censoring,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn censoring_cannot_masquerade_as_zero() {
        assert_eq!(
            TrialSample::new(1, 0, MetricKind::LatencyNanos, Some(0), Censoring::Timeout),
            Err(SampleError::CensoredWithValue)
        );
        assert!(TrialSample::new(1, 0, MetricKind::LatencyNanos, None, Censoring::Timeout).is_ok());
    }
}
