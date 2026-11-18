//! Deterministic selection among valid causal witnesses.

use crate::{
    cause_contingency::Contingency, cause_normality::NormalityProfile,
    cause_verdict::CausalInvalidReason,
};

pub fn select(
    candidates: &[Contingency],
    normality: &NormalityProfile,
) -> Result<Option<Contingency>, CausalInvalidReason> {
    let mut ranked = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let combined = candidate.combined()?;
        ranked.push((
            candidate.cause().as_slice().len(),
            candidate.context().as_slice().len(),
            normality.rank(&combined)?,
            combined.canonical_bytes(),
            candidate.clone(),
        ));
    }
    ranked.sort_by(|left, right| {
        (&left.0, &left.1, &left.2, &left.3).cmp(&(&right.0, &right.1, &right.2, &right.3))
    });
    Ok(ranked.into_iter().next().map(|entry| entry.4))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cause_atom::{create as atom, AtomKind},
        cause_intervention::{create as intervention, InterventionValue},
        cause_intervention_set::InterventionSet,
    };

    fn candidate(field: u16) -> (crate::cause_atom::CausalAtom, Contingency) {
        let atom = atom(1, AtomKind::Transition, field, 0).unwrap();
        let intervention = intervention(atom, InterventionValue::SetPublicBranch(1)).unwrap();
        let witness = Contingency::create(
            InterventionSet::canonicalize(vec![intervention]).unwrap(),
            InterventionSet::canonicalize(vec![]).unwrap(),
        )
        .unwrap();
        (atom, witness)
    }

    #[test]
    fn lower_normality_rank_wins_independent_of_input_order() {
        let (a, first) = candidate(1);
        let (b, second) = candidate(2);
        let profile = NormalityProfile::create(vec![(a, 5), (b, 1)]).unwrap();
        assert_eq!(
            select(&[first.clone(), second.clone()], &profile),
            Ok(Some(second.clone()))
        );
        assert_eq!(select(&[second.clone(), first], &profile), Ok(Some(second)));
    }

    #[test]
    fn empty_candidates_return_none() {
        let profile = NormalityProfile::create(vec![]).unwrap();
        assert_eq!(select(&[], &profile), Ok(None));
    }
}
