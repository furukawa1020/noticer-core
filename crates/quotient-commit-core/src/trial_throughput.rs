//! Overflow-safe throughput in milli-slots per second.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThroughputError {
    ZeroDuration,
    Overflow,
}

pub fn milli_slots_per_second(slots: u64, elapsed_nanos: u64) -> Result<u64, ThroughputError> {
    if elapsed_nanos == 0 {
        return Err(ThroughputError::ZeroDuration);
    }
    let numerator = u128::from(slots)
        .checked_mul(1_000_000_000_000)
        .ok_or(ThroughputError::Overflow)?;
    u64::try_from(numerator / u128::from(elapsed_nanos)).map_err(|_| ThroughputError::Overflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn one_thousand_slots_per_second_is_scaled() {
        assert_eq!(milli_slots_per_second(1_000, 1_000_000_000), Ok(1_000_000));
        assert_eq!(
            milli_slots_per_second(1, 0),
            Err(ThroughputError::ZeroDuration)
        );
    }
}
