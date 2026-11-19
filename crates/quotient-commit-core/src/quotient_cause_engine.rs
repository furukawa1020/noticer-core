//! End-to-end bounded QuotientCause analysis engine.

use crate::{
    cause_budget::{CausalBudget, CausalLimits},
    cause_contingency::Contingency,
    cause_equation::StructuralEquation,
    cause_normality::NormalityProfile,
    cause_outcome::OutcomePredicate,
    cause_selector,
    cause_state::CausalState,
    cause_verdict::{CausalInvalidReason, CausalityVerdict},
    cause_witness_validator,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EngineResult {
    pub verdict: CausalityVerdict,
    pub witness: Option<Contingency>,
    pub explored_worlds: u64,
}

pub fn analyze(
    actual: &CausalState,
    candidates: &[Contingency],
    equations: &[StructuralEquation],
    predicate: OutcomePredicate,
    normality: &NormalityProfile,
    limits: CausalLimits,
) -> EngineResult {
    let mut budget = CausalBudget::new(limits);
    let mut valid = Vec::new();
    for candidate in candidates {
        let intervention_count =
            candidate.cause().as_slice().len() + candidate.context().as_slice().len();
        for _ in 0..intervention_count {
            if let Err(reason) = budget.charge_intervention() {
                return EngineResult {
                    verdict: CausalityVerdict::Inconclusive(reason),
                    witness: None,
                    explored_worlds: budget.worlds,
                };
            }
        }
        if let Err(reason) = budget.charge_world(intervention_count as u64) {
            return EngineResult {
                verdict: CausalityVerdict::Inconclusive(reason),
                witness: None,
                explored_worlds: budget.worlds,
            };
        }
        match cause_witness_validator::validate(actual, candidate, equations, predicate) {
            Ok(()) => valid.push(candidate.clone()),
            Err(CausalInvalidReason::WitnessRejected) => {}
            Err(reason) => {
                return EngineResult {
                    verdict: CausalityVerdict::Invalid(reason),
                    witness: None,
                    explored_worlds: budget.worlds,
                }
            }
        }
    }
    match cause_selector::select(&valid, normality) {
        Ok(Some(witness)) => EngineResult {
            verdict: CausalityVerdict::Causal {
                cause_size: witness.cause().as_slice().len() as u32,
                contingency_size: witness.context().as_slice().len() as u32,
            },
            witness: Some(witness),
            explored_worlds: budget.worlds,
        },
        Ok(None) => EngineResult {
            verdict: CausalityVerdict::NonCausal {
                examined_interventions: budget.interventions,
            },
            witness: None,
            explored_worlds: budget.worlds,
        },
        Err(reason) => EngineResult {
            verdict: CausalityVerdict::Invalid(reason),
            witness: None,
            explored_worlds: budget.worlds,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cause_atom::{create as atom, AtomKind},
        cause_intervention::{create as intervention, InterventionValue},
        cause_intervention_set::InterventionSet,
        cause_outcome::OutcomeKind,
        cause_verdict::CausalInconclusiveReason,
    };

    fn setup() -> (CausalState, Contingency, NormalityProfile) {
        let projection = atom(1, AtomKind::ObserverProjection, 1, 1).unwrap();
        let change = intervention(projection, InterventionValue::SetPublicBranch(0)).unwrap();
        let witness = Contingency::create(
            InterventionSet::canonicalize(vec![change]).unwrap(),
            InterventionSet::canonicalize(vec![]).unwrap(),
        )
        .unwrap();
        (
            CausalState::create(1, vec![projection], true).unwrap(),
            witness,
            NormalityProfile::create(vec![(projection, 1)]).unwrap(),
        )
    }

    fn predicate() -> OutcomePredicate {
        OutcomePredicate {
            kind: OutcomeKind::ObserverDivergence,
            expected: true,
        }
    }

    #[test]
    fn valid_witness_becomes_causal() {
        let (actual, witness, normality) = setup();
        let result = analyze(
            &actual,
            &[witness],
            &[],
            predicate(),
            &normality,
            CausalLimits {
                maximum_worlds: 2,
                maximum_interventions: 2,
                maximum_depth: 2,
            },
        );
        assert!(result.verdict.is_certified_causal());
        assert!(result.witness.is_some());
    }

    #[test]
    fn empty_exhaustive_search_is_noncausal() {
        let (actual, _, normality) = setup();
        let result = analyze(
            &actual,
            &[],
            &[],
            predicate(),
            &normality,
            CausalLimits {
                maximum_worlds: 2,
                maximum_interventions: 2,
                maximum_depth: 2,
            },
        );
        assert!(matches!(result.verdict, CausalityVerdict::NonCausal { .. }));
    }

    #[test]
    fn budget_stop_is_inconclusive() {
        let (actual, witness, normality) = setup();
        let result = analyze(
            &actual,
            &[witness],
            &[],
            predicate(),
            &normality,
            CausalLimits {
                maximum_worlds: 0,
                maximum_interventions: 2,
                maximum_depth: 2,
            },
        );
        assert_eq!(
            result.verdict,
            CausalityVerdict::Inconclusive(CausalInconclusiveReason::NodeLimit)
        );
    }
}
