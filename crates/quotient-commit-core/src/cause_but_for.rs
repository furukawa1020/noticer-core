//! Deterministic search for singleton but-for causes.

use crate::{
    cause_counterfactual_world::generate, cause_equation::StructuralEquation,
    cause_intervention::Intervention, cause_intervention_set::InterventionSet,
    cause_outcome::OutcomePredicate, cause_state::CausalState, cause_verdict::CausalInvalidReason,
};

pub fn find(
    actual: &CausalState,
    candidates: &[Intervention],
    equations: &[StructuralEquation],
    predicate: OutcomePredicate,
) -> Result<Option<Intervention>, CausalInvalidReason> {
    if !predicate.evaluate(actual)? {
        return Err(CausalInvalidReason::ActualWorldMismatch);
    }
    let mut ordered = candidates.to_vec();
    ordered.sort_unstable();
    ordered.dedup();
    for candidate in ordered {
        let set = InterventionSet::canonicalize(vec![candidate])?;
        let counterfactual = generate(actual, &set, equations)?;
        if !predicate.evaluate(&counterfactual)? {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cause_atom::{create as atom, AtomKind},
        cause_intervention::{create as intervention, InterventionValue},
        cause_outcome::OutcomeKind,
    };

    fn predicate() -> OutcomePredicate {
        OutcomePredicate {
            kind: OutcomeKind::ObserverDivergence,
            expected: true,
        }
    }

    #[test]
    fn finds_singleton_but_for_cause() {
        let projection = atom(1, AtomKind::ObserverProjection, 1, 1).unwrap();
        let actual = CausalState::create(1, vec![projection], true).unwrap();
        let candidate = intervention(projection, InterventionValue::SetPublicBranch(0)).unwrap();
        assert_eq!(
            find(&actual, &[candidate], &[], predicate()),
            Ok(Some(candidate))
        );
    }

    #[test]
    fn exhaustive_miss_is_non_cause() {
        let projection = atom(1, AtomKind::ObserverProjection, 1, 1).unwrap();
        let other = atom(1, AtomKind::Transition, 2, 1).unwrap();
        let actual = CausalState::create(1, vec![projection, other], true).unwrap();
        let candidate = intervention(other, InterventionValue::SetPublicBranch(0)).unwrap();
        assert_eq!(find(&actual, &[candidate], &[], predicate()), Ok(None));
    }

    #[test]
    fn false_actual_outcome_is_invalid() {
        let actual = CausalState::create(1, vec![], false).unwrap();
        assert_eq!(
            find(&actual, &[], &[], predicate()),
            Err(CausalInvalidReason::ActualWorldMismatch)
        );
    }
}
