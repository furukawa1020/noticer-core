//! False alarm rate in ppm and per deployment-hour micros.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FalseAlarmMetric {
    pub window_rate_ppm: u32,
    pub per_hour_micro: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FalseAlarmError {
    ZeroWindows,
    ZeroDuration,
    CountMismatch,
}

pub fn measure(
    false_alarms: u64,
    nominal_windows: u64,
    duration_millis: u64,
) -> Result<FalseAlarmMetric, FalseAlarmError> {
    if nominal_windows == 0 {
        return Err(FalseAlarmError::ZeroWindows);
    }
    if duration_millis == 0 {
        return Err(FalseAlarmError::ZeroDuration);
    }
    if false_alarms > nominal_windows {
        return Err(FalseAlarmError::CountMismatch);
    }
    let rate = u32::try_from(u128::from(false_alarms) * 1_000_000 / u128::from(nominal_windows))
        .unwrap_or(1_000_000);
    let per_hour =
        u64::try_from(u128::from(false_alarms) * 3_600_000_000 / u128::from(duration_millis))
            .unwrap_or(u64::MAX);
    Ok(FalseAlarmMetric {
        window_rate_ppm: rate,
        per_hour_micro: per_hour,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn zero_false_alarms_remain_zero() {
        assert_eq!(
            measure(0, 100, 3_600_000).unwrap(),
            FalseAlarmMetric {
                window_rate_ppm: 0,
                per_hour_micro: 0
            }
        );
    }
}
