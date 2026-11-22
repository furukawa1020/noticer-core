//! Paired absolute/relative effects and distributional Cliff delta.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectSize {
    pub paired_difference: i64,
    pub relative_change_ppm: i64,
    pub cliff_delta_ppm: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectSizeError {
    Empty,
    ZeroBaseline,
    Overflow,
}

pub fn measure(baseline: &[i64], candidate: &[i64]) -> Result<EffectSize, EffectSizeError> {
    if baseline.is_empty() || baseline.len() != candidate.len() {
        return Err(EffectSizeError::Empty);
    }
    let baseline_mean = mean(baseline)?;
    let candidate_mean = mean(candidate)?;
    if baseline_mean == 0 {
        return Err(EffectSizeError::ZeroBaseline);
    }
    let difference = candidate_mean
        .checked_sub(baseline_mean)
        .ok_or(EffectSizeError::Overflow)?;
    let relative = i64::try_from(i128::from(difference) * 1_000_000 / i128::from(baseline_mean))
        .map_err(|_| EffectSizeError::Overflow)?;
    let mut wins = 0_i128;
    let mut losses = 0_i128;
    for left in candidate {
        for right in baseline {
            if left > right {
                wins += 1;
            } else if left < right {
                losses += 1;
            }
        }
    }
    let pairs = (candidate.len() * baseline.len()) as i128;
    let cliff = i32::try_from((wins - losses) * 1_000_000 / pairs)
        .map_err(|_| EffectSizeError::Overflow)?;
    Ok(EffectSize {
        paired_difference: difference,
        relative_change_ppm: relative,
        cliff_delta_ppm: cliff,
    })
}

fn mean(values: &[i64]) -> Result<i64, EffectSizeError> {
    let sum = values
        .iter()
        .try_fold(0_i128, |sum, value| sum.checked_add(i128::from(*value)))
        .ok_or(EffectSizeError::Overflow)?;
    i64::try_from(sum / values.len() as i128).map_err(|_| EffectSizeError::Overflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn improvement_sign_is_explicit() {
        let effect = measure(&[100, 100], &[90, 90]).unwrap();
        assert_eq!(effect.paired_difference, -10);
        assert_eq!(effect.relative_change_ppm, -100_000);
    }
}
