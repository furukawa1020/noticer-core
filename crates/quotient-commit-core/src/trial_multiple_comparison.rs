//! Holm step-down control using p-values represented in ppm.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HypothesisPpm {
    pub id: u32,
    pub p_value_ppm: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HolmDecision {
    pub id: u32,
    pub rejected: bool,
    pub threshold_ppm: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HolmError {
    Empty,
    InvalidPValue,
    InvalidAlpha,
}

pub fn holm(
    mut hypotheses: Vec<HypothesisPpm>,
    alpha_ppm: u32,
) -> Result<Vec<HolmDecision>, HolmError> {
    if hypotheses.is_empty() {
        return Err(HolmError::Empty);
    }
    if alpha_ppm == 0 || alpha_ppm > 1_000_000 {
        return Err(HolmError::InvalidAlpha);
    }
    if hypotheses.iter().any(|h| h.p_value_ppm > 1_000_000) {
        return Err(HolmError::InvalidPValue);
    }
    hypotheses.sort_by_key(|h| (h.p_value_ppm, h.id));
    let total = hypotheses.len();
    let mut stopped = false;
    Ok(hypotheses
        .into_iter()
        .enumerate()
        .map(|(index, hypothesis)| {
            let threshold = alpha_ppm / u32::try_from(total - index).unwrap_or(u32::MAX);
            let rejected = !stopped && hypothesis.p_value_ppm <= threshold;
            if !rejected {
                stopped = true;
            }
            HolmDecision {
                id: hypothesis.id,
                rejected,
                threshold_ppm: threshold,
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejection_stops_after_first_failure() {
        let decisions = holm(
            vec![
                HypothesisPpm {
                    id: 1,
                    p_value_ppm: 10_000,
                },
                HypothesisPpm {
                    id: 2,
                    p_value_ppm: 40_000,
                },
                HypothesisPpm {
                    id: 3,
                    p_value_ppm: 45_000,
                },
            ],
            50_000,
        )
        .unwrap();
        assert!(decisions[0].rejected);
        assert!(!decisions[1].rejected);
        assert!(!decisions[2].rejected);
    }
}
