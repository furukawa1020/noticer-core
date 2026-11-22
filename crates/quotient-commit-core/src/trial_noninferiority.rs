//! Joint non-inferiority gate for utility and latency.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NonInferiorityMargins {
    pub minimum_utility_difference_ppm: i64,
    pub maximum_latency_difference_ppm: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComparisonBounds {
    pub utility_lower_ppm: i64,
    pub latency_upper_ppm: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NonInferiorityResult {
    Pass,
    UtilityInferior,
    LatencyInferior,
}

pub const fn evaluate(
    margins: NonInferiorityMargins,
    bounds: ComparisonBounds,
) -> NonInferiorityResult {
    if bounds.utility_lower_ppm < margins.minimum_utility_difference_ppm {
        NonInferiorityResult::UtilityInferior
    } else if bounds.latency_upper_ppm > margins.maximum_latency_difference_ppm {
        NonInferiorityResult::LatencyInferior
    } else {
        NonInferiorityResult::Pass
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn both_pre_registered_margins_must_hold() {
        let margins = NonInferiorityMargins {
            minimum_utility_difference_ppm: -10_000,
            maximum_latency_difference_ppm: 50_000,
        };
        assert_eq!(
            evaluate(
                margins,
                ComparisonBounds {
                    utility_lower_ppm: -5_000,
                    latency_upper_ppm: 40_000
                }
            ),
            NonInferiorityResult::Pass
        );
        assert_eq!(
            evaluate(
                margins,
                ComparisonBounds {
                    utility_lower_ppm: -20_000,
                    latency_upper_ppm: 0
                }
            ),
            NonInferiorityResult::UtilityInferior
        );
    }
}
