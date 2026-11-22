//! Conditional public distinctions and attacker advantage in parts per million.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivacyLeakageMetric {
    pub public_distinctions: u32,
    pub attack_accuracy_ppm: u32,
    pub chance_accuracy_ppm: u32,
    pub attack_advantage_ppm: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeakageError {
    ZeroTrials,
    TooFewClasses,
    CountMismatch,
}

pub fn measure(
    public_distinctions: u32,
    correct: u64,
    trials: u64,
    private_classes: u32,
) -> Result<PrivacyLeakageMetric, LeakageError> {
    if trials == 0 {
        return Err(LeakageError::ZeroTrials);
    }
    if private_classes < 2 {
        return Err(LeakageError::TooFewClasses);
    }
    if correct > trials {
        return Err(LeakageError::CountMismatch);
    }
    let attack_accuracy_ppm =
        u32::try_from(u128::from(correct) * 1_000_000 / u128::from(trials)).unwrap_or(1_000_000);
    let chance_accuracy_ppm = 1_000_000 / private_classes;
    Ok(PrivacyLeakageMetric {
        public_distinctions,
        attack_accuracy_ppm,
        chance_accuracy_ppm,
        attack_advantage_ppm: attack_accuracy_ppm.saturating_sub(chance_accuracy_ppm),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn chance_attack_has_zero_advantage() {
        let metric = measure(1, 50, 100, 2).unwrap();
        assert_eq!(metric.attack_accuracy_ppm, 500_000);
        assert_eq!(metric.attack_advantage_ppm, 0);
    }
}
