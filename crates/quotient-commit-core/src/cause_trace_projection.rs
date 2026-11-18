//! Redacted projection from a minimal oracle trace into a causal world.

use crate::{
    cause_atom::{create as atom, AtomKind},
    cause_state::CausalState,
    cause_verdict::CausalInvalidReason,
    oracle_trace_step::TraceStep,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectedTrace {
    pub state: CausalState,
    pub first_divergence_slot: Option<u64>,
}

pub fn project(trace: &[TraceStep]) -> Result<ProjectedTrace, CausalInvalidReason> {
    let first = trace.first().ok_or(CausalInvalidReason::Domain)?;
    let mut expected_slot = first.slot;
    let mut atoms = Vec::with_capacity(trace.len() * 2);
    for step in trace {
        if step.slot != expected_slot
            || step.before.slot != step.slot
            || step.after.slot
                != step
                    .slot
                    .checked_add(1)
                    .ok_or(CausalInvalidReason::Domain)?
        {
            return Err(CausalInvalidReason::NonCanonical);
        }
        let diverged = step.after.left != step.after.right;
        atoms.push(atom(step.slot, AtomKind::PublicInput, 1, step.input)?);
        atoms.push(atom(
            step.slot,
            AtomKind::ObserverProjection,
            2,
            u16::from(diverged),
        )?);
        expected_slot = step.slot + 1;
    }
    let first_divergence_slot = trace
        .iter()
        .find(|step| step.after.left != step.after.right)
        .map(|step| step.slot);
    let outcome = first_divergence_slot.is_some();
    let state = CausalState::create(expected_slot, atoms, outcome)?;
    Ok(ProjectedTrace {
        state,
        first_divergence_slot,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oracle_state_pair::StatePair;

    fn step(slot: u64, input: u16, diverged: bool) -> TraceStep {
        TraceStep {
            slot,
            input,
            before: StatePair {
                slot,
                left: vec![1],
                right: vec![1],
            },
            after: StatePair {
                slot: slot + 1,
                left: vec![2],
                right: vec![if diverged { 3 } else { 2 }],
            },
        }
    }

    #[test]
    fn projection_keeps_coordinates_not_private_state_bytes() {
        let projected = project(&[step(4, 7, false), step(5, 8, true)]).unwrap();
        assert_eq!(projected.first_divergence_slot, Some(5));
        assert!(projected.state.outcome);
        assert_eq!(projected.state.atoms().len(), 4);
    }

    #[test]
    fn slot_gap_is_invalid() {
        assert_eq!(
            project(&[step(1, 7, false), step(3, 8, true)]),
            Err(CausalInvalidReason::NonCanonical)
        );
    }

    #[test]
    fn empty_trace_is_invalid() {
        assert_eq!(project(&[]), Err(CausalInvalidReason::Domain));
    }
}
