//! Fixed-seed paired bootstrap over integer differences.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootstrapInterval {
    pub lower: i64,
    pub estimate: i64,
    pub upper: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapError {
    Empty,
    ZeroResamples,
    Overflow,
}

pub fn paired_mean_interval(
    differences: &[i64],
    seed: u64,
    resamples: u32,
) -> Result<BootstrapInterval, BootstrapError> {
    if differences.is_empty() {
        return Err(BootstrapError::Empty);
    }
    if resamples == 0 {
        return Err(BootstrapError::ZeroResamples);
    }
    let estimate = mean(differences)?;
    let mut state = seed;
    let mut means = Vec::with_capacity(resamples as usize);
    for _ in 0..resamples {
        let mut sample = Vec::with_capacity(differences.len());
        for _ in differences {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            sample.push(differences[(state as usize) % differences.len()]);
        }
        means.push(mean(&sample)?);
    }
    means.sort_unstable();
    let lower = means[means.len() / 40];
    let upper = means[(means.len() * 39 / 40).min(means.len() - 1)];
    Ok(BootstrapInterval {
        lower,
        estimate,
        upper,
    })
}

fn mean(values: &[i64]) -> Result<i64, BootstrapError> {
    let sum = values
        .iter()
        .try_fold(0_i128, |sum, value| sum.checked_add(i128::from(*value)))
        .ok_or(BootstrapError::Overflow)?;
    i64::try_from(sum / values.len() as i128).map_err(|_| BootstrapError::Overflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_seed_is_reproducible() {
        assert_eq!(
            paired_mean_interval(&[-2, -1, 0, 1], 7, 100),
            paired_mean_interval(&[-2, -1, 0, 1], 7, 100)
        );
    }
}
