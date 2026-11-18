//! Canonical observer coalitions for joint causal claims.

use crate::cause_verdict::CausalInvalidReason;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObserverCoalition {
    observers: Vec<u16>,
    pub threshold: u16,
}

impl ObserverCoalition {
    pub fn create(mut observers: Vec<u16>, threshold: u16) -> Result<Self, CausalInvalidReason> {
        if observers.is_empty() || observers.len() > 16 || observers.contains(&0) {
            return Err(CausalInvalidReason::Domain);
        }
        observers.sort_unstable();
        if observers.windows(2).any(|pair| pair[0] == pair[1])
            || threshold == 0
            || usize::from(threshold) > observers.len()
        {
            return Err(CausalInvalidReason::NonCanonical);
        }
        Ok(Self {
            observers,
            threshold,
        })
    }

    pub fn observers(&self) -> &[u16] {
        &self.observers
    }

    pub fn supports(&self, evidence_from: &[u16]) -> bool {
        self.observers
            .iter()
            .filter(|observer| evidence_from.contains(observer))
            .count()
            >= usize::from(self.threshold)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coalition_is_sorted_and_thresholded() {
        let coalition = ObserverCoalition::create(vec![3, 1, 2], 2).unwrap();
        assert_eq!(coalition.observers(), &[1, 2, 3]);
        assert!(coalition.supports(&[1, 3]));
        assert!(!coalition.supports(&[1]));
    }

    #[test]
    fn duplicate_observer_is_noncanonical() {
        assert_eq!(
            ObserverCoalition::create(vec![1, 1], 1),
            Err(CausalInvalidReason::NonCanonical)
        );
    }

    #[test]
    fn impossible_threshold_is_noncanonical() {
        assert_eq!(
            ObserverCoalition::create(vec![1, 2], 3),
            Err(CausalInvalidReason::NonCanonical)
        );
    }
}
