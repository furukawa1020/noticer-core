//! Deterministic order-statistic interval for integer samples.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfidenceInterval {
    pub lower: i64,
    pub estimate: i64,
    pub upper: i64,
    pub coverage_ppm: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfidenceError {
    Empty,
    InvalidCoverage,
}

pub fn order_statistic_interval(
    mut samples: Vec<i64>,
    coverage_ppm: u32,
) -> Result<ConfidenceInterval, ConfidenceError> {
    if samples.is_empty() {
        return Err(ConfidenceError::Empty);
    }
    if coverage_ppm == 0 || coverage_ppm > 1_000_000 {
        return Err(ConfidenceError::InvalidCoverage);
    }
    samples.sort_unstable();
    let tail_ppm = (1_000_000 - coverage_ppm) / 2;
    let lower_index =
        usize::try_from(u128::from(samples.len() as u64) * u128::from(tail_ppm) / 1_000_000)
            .unwrap_or(0)
            .min(samples.len() - 1);
    let upper_index = samples.len() - 1 - lower_index;
    Ok(ConfidenceInterval {
        lower: samples[lower_index],
        estimate: samples[samples.len() / 2],
        upper: samples[upper_index],
        coverage_ppm,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn interval_is_order_independent() {
        assert_eq!(
            order_statistic_interval(vec![3, 1, 2], 900_000),
            order_statistic_interval(vec![1, 2, 3], 900_000)
        );
    }
}
