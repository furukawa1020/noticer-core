//! Independent replay interface for causal witnesses.

use crate::{
    cause_contingency::Contingency,
    cause_state::CausalState,
    cause_verdict::{CausalInconclusiveReason, CausalInvalidReason},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CausalReplayOutcome {
    Causal {
        witness_digest: [u8; 32],
        cause_size: u32,
    },
    NonCausal {
        examined_interventions: u64,
    },
    Invalid(CausalInvalidReason),
    Inconclusive(CausalInconclusiveReason),
}

pub trait CausalReplayEngine {
    fn replay(&self, actual: &CausalState, witness: &Contingency) -> CausalReplayOutcome;
}

pub fn replay_with<E: CausalReplayEngine>(
    engine: &E,
    actual: &CausalState,
    witness: &Contingency,
) -> CausalReplayOutcome {
    engine.replay(actual, witness)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cause_atom::{create as atom, AtomKind},
        cause_intervention::{create as intervention, InterventionValue},
        cause_intervention_set::InterventionSet,
    };

    struct Stub;
    impl CausalReplayEngine for Stub {
        fn replay(&self, _actual: &CausalState, witness: &Contingency) -> CausalReplayOutcome {
            CausalReplayOutcome::Causal {
                witness_digest: [7; 32],
                cause_size: witness.cause().as_slice().len() as u32,
            }
        }
    }

    #[test]
    fn engine_receives_typed_world_and_witness() {
        let projection = atom(1, AtomKind::ObserverProjection, 1, 1).unwrap();
        let actual = CausalState::create(1, vec![projection], true).unwrap();
        let witness = Contingency::create(
            InterventionSet::canonicalize(vec![intervention(
                projection,
                InterventionValue::SetPublicBranch(0),
            )
            .unwrap()])
            .unwrap(),
            InterventionSet::canonicalize(vec![]).unwrap(),
        )
        .unwrap();
        assert_eq!(
            replay_with(&Stub, &actual, &witness),
            CausalReplayOutcome::Causal {
                witness_digest: [7; 32],
                cause_size: 1
            }
        );
    }
}
