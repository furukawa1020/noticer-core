//! Separates action preservation, delay, and suppression.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UtilityPreservationMetric {
    pub action_match_ppm: u32,
    pub mean_delay_milli_slots: u64,
    pub suppression_ppm: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UtilityError {
    ZeroEligible,
    CountMismatch,
    Overflow,
}

pub fn measure(
    eligible: u64,
    matched: u64,
    suppressed: u64,
    delay_slots: u64,
) -> Result<UtilityPreservationMetric, UtilityError> {
    if eligible == 0 {
        return Err(UtilityError::ZeroEligible);
    }
    if matched > eligible || suppressed > eligible {
        return Err(UtilityError::CountMismatch);
    }
    let action_match_ppm = u32::try_from(u128::from(matched) * 1_000_000 / u128::from(eligible))
        .map_err(|_| UtilityError::Overflow)?;
    let suppression_ppm = u32::try_from(u128::from(suppressed) * 1_000_000 / u128::from(eligible))
        .map_err(|_| UtilityError::Overflow)?;
    let mean_delay_milli_slots =
        u64::try_from(u128::from(delay_slots) * 1_000 / u128::from(eligible))
            .map_err(|_| UtilityError::Overflow)?;
    Ok(UtilityPreservationMetric {
        action_match_ppm,
        mean_delay_milli_slots,
        suppression_ppm,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn perfect_actions_keep_delay_visible() {
        assert_eq!(
            measure(10, 10, 0, 5).unwrap(),
            UtilityPreservationMetric {
                action_match_ppm: 1_000_000,
                mean_delay_milli_slots: 500,
                suppression_ppm: 0
            }
        );
    }
}
