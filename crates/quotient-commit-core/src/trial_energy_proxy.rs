//! Explicit integer proxy from CPU, hashing, and radio work.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnergyProxyWeights {
    pub cpu_nanojoules_per_step: u64,
    pub hash_nanojoules_per_byte: u64,
    pub radio_nanojoules_per_byte: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnergyProxyError {
    ZeroWeight,
    Overflow,
}

pub fn estimate(
    weights: EnergyProxyWeights,
    cpu_steps: u64,
    hash_bytes: u64,
    radio_bytes: u64,
) -> Result<u128, EnergyProxyError> {
    if weights.cpu_nanojoules_per_step == 0
        || weights.hash_nanojoules_per_byte == 0
        || weights.radio_nanojoules_per_byte == 0
    {
        return Err(EnergyProxyError::ZeroWeight);
    }
    let cpu = u128::from(weights.cpu_nanojoules_per_step) * u128::from(cpu_steps);
    let hash = u128::from(weights.hash_nanojoules_per_byte) * u128::from(hash_bytes);
    let radio = u128::from(weights.radio_nanojoules_per_byte) * u128::from(radio_bytes);
    cpu.checked_add(hash)
        .and_then(|v| v.checked_add(radio))
        .ok_or(EnergyProxyError::Overflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn components_are_explicit() {
        let weights = EnergyProxyWeights {
            cpu_nanojoules_per_step: 1,
            hash_nanojoules_per_byte: 2,
            radio_nanojoules_per_byte: 3,
        };
        assert_eq!(estimate(weights, 10, 20, 30), Ok(140));
    }
}
