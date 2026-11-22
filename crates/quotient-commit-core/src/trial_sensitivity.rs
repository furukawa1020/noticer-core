//! Deterministic Cartesian sensitivity grid.

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SensitivityPoint {
    pub window: u32,
    pub budget: u32,
    pub lease_millis: u64,
    pub threshold_ppm: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SensitivityError {
    EmptyAxis,
    InvalidThreshold,
}

pub fn grid(
    windows: &[u32],
    budgets: &[u32],
    leases: &[u64],
    thresholds: &[u32],
) -> Result<Vec<SensitivityPoint>, SensitivityError> {
    if windows.is_empty() || budgets.is_empty() || leases.is_empty() || thresholds.is_empty() {
        return Err(SensitivityError::EmptyAxis);
    }
    if thresholds.iter().any(|v| *v > 1_000_000) {
        return Err(SensitivityError::InvalidThreshold);
    }
    let mut points = Vec::new();
    for &window in windows {
        for &budget in budgets {
            for &lease_millis in leases {
                for &threshold_ppm in thresholds {
                    points.push(SensitivityPoint {
                        window,
                        budget,
                        lease_millis,
                        threshold_ppm,
                    });
                }
            }
        }
    }
    points.sort();
    points.dedup();
    Ok(points)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn grid_is_complete_and_deduplicated() {
        let points = grid(&[1, 2], &[3], &[4], &[5, 5]).unwrap();
        assert_eq!(points.len(), 2);
    }
}
