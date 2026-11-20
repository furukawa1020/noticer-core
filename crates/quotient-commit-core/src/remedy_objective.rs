//! Integer-only objective for deterministic repair optimization.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepairObjective {
    pub edit_weight: u32,
    pub delay_weight: u32,
    pub semantic_distance_weight: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectiveError {
    ZeroWeight,
    Overflow,
}

impl RepairObjective {
    pub fn new(
        edit_weight: u32,
        delay_weight: u32,
        semantic_distance_weight: u32,
    ) -> Result<Self, ObjectiveError> {
        if edit_weight == 0 || delay_weight == 0 || semantic_distance_weight == 0 {
            return Err(ObjectiveError::ZeroWeight);
        }
        Ok(Self {
            edit_weight,
            delay_weight,
            semantic_distance_weight,
        })
    }

    pub fn score(
        self,
        edits: u32,
        delay_slots: u32,
        semantic_distance: u32,
    ) -> Result<u64, ObjectiveError> {
        let terms = [
            u64::from(self.edit_weight) * u64::from(edits),
            u64::from(self.delay_weight) * u64::from(delay_slots),
            u64::from(self.semantic_distance_weight) * u64::from(semantic_distance),
        ];
        terms
            .into_iter()
            .try_fold(0_u64, |sum, term| sum.checked_add(term))
            .ok_or(ObjectiveError::Overflow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn objective_is_integer_and_reproducible() {
        let objective = RepairObjective::new(100, 10, 1).unwrap();
        assert_eq!(objective.score(2, 3, 4), Ok(234));
    }

    #[test]
    fn unconstrained_zero_weights_are_rejected() {
        assert_eq!(
            RepairObjective::new(1, 0, 1),
            Err(ObjectiveError::ZeroWeight)
        );
    }
}
