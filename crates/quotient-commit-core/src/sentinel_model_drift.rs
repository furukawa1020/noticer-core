//! Public transition support drift against the certified repair model.

use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PublicTransition {
    pub action_class: u16,
    pub from_state: u32,
    pub to_state: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepairModelDriftDetector {
    supported: BTreeSet<PublicTransition>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelDriftError {
    EmptyModel,
    UnsupportedTransition(PublicTransition),
}

impl RepairModelDriftDetector {
    pub fn new(supported: BTreeSet<PublicTransition>) -> Result<Self, ModelDriftError> {
        if supported.is_empty() {
            return Err(ModelDriftError::EmptyModel);
        }
        Ok(Self { supported })
    }

    pub fn observe(&self, transition: PublicTransition) -> Result<(), ModelDriftError> {
        if self.supported.contains(&transition) {
            Ok(())
        } else {
            Err(ModelDriftError::UnsupportedTransition(transition))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unseen_transition_is_model_drift() {
        let known = PublicTransition {
            action_class: 1,
            from_state: 2,
            to_state: 3,
        };
        let detector = RepairModelDriftDetector::new(BTreeSet::from([known])).unwrap();
        let unseen = PublicTransition {
            to_state: 4,
            ..known
        };
        assert_eq!(
            detector.observe(unseen),
            Err(ModelDriftError::UnsupportedTransition(unseen))
        );
    }
}
