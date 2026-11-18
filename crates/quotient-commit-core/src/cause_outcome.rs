//! Public-safe outcome predicates for counterfactual worlds.

use crate::{cause_atom::AtomKind, cause_state::CausalState, cause_verdict::CausalInvalidReason};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutcomeKind {
    ObserverDivergence,
    PermitDenied,
    UnauthorizedRelease,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutcomePredicate {
    pub kind: OutcomeKind,
    pub expected: bool,
}

impl OutcomePredicate {
    pub fn evaluate(self, state: &CausalState) -> Result<bool, CausalInvalidReason> {
        let observed = match self.kind {
            OutcomeKind::ObserverDivergence => state.outcome,
            OutcomeKind::PermitDenied => state
                .atoms()
                .iter()
                .rev()
                .find(|atom| atom.kind == AtomKind::PermitDecision)
                .map(|atom| atom.public_branch == 0)
                .ok_or(CausalInvalidReason::Domain)?,
            OutcomeKind::UnauthorizedRelease => state
                .atoms()
                .iter()
                .any(|atom| atom.kind == AtomKind::AuthorizedRelease && atom.public_branch == 0),
        };
        Ok(observed == self.expected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cause_atom::{create as atom, AtomKind};

    #[test]
    fn divergence_reads_only_redacted_outcome() {
        let state = CausalState::create(1, vec![], true).unwrap();
        assert_eq!(
            OutcomePredicate {
                kind: OutcomeKind::ObserverDivergence,
                expected: true
            }
            .evaluate(&state),
            Ok(true)
        );
    }

    #[test]
    fn missing_permit_decision_is_invalid() {
        let state = CausalState::create(1, vec![], false).unwrap();
        assert_eq!(
            OutcomePredicate {
                kind: OutcomeKind::PermitDenied,
                expected: true
            }
            .evaluate(&state),
            Err(CausalInvalidReason::Domain)
        );
    }

    #[test]
    fn unauthorized_release_is_structural() {
        let release = atom(1, AtomKind::AuthorizedRelease, 1, 0).unwrap();
        let state = CausalState::create(1, vec![release], false).unwrap();
        assert!(OutcomePredicate {
            kind: OutcomeKind::UnauthorizedRelease,
            expected: true
        }
        .evaluate(&state)
        .unwrap());
    }
}
