//! Domain-separated digest of a bounded structural causal model.

use crate::{
    cause_atom::canonical_bytes,
    cause_equation::{EquationOperator, StructuralEquation},
    cause_outcome::{OutcomeKind, OutcomePredicate},
    cause_verdict::CausalInvalidReason,
    receipt::hmac_sha256,
};

const DOMAIN: &[u8] = b"noticer.quotient-cause.model.v1\0";

pub fn digest(
    version: u32,
    equations: &[StructuralEquation],
    predicate: OutcomePredicate,
) -> Result<[u8; 32], CausalInvalidReason> {
    let mut ordered = equations.to_vec();
    ordered.sort_by_key(|equation| equation.target);
    if ordered
        .windows(2)
        .any(|pair| pair[0].target == pair[1].target)
    {
        return Err(CausalInvalidReason::NonCanonical);
    }
    let mut bytes = DOMAIN.to_vec();
    bytes.extend_from_slice(&version.to_be_bytes());
    bytes.push(match predicate.kind {
        OutcomeKind::ObserverDivergence => 0,
        OutcomeKind::PermitDenied => 1,
        OutcomeKind::UnauthorizedRelease => 2,
    });
    bytes.push(u8::from(predicate.expected));
    bytes.extend_from_slice(&(ordered.len() as u64).to_be_bytes());
    for equation in ordered {
        bytes.extend_from_slice(&canonical_bytes(equation.target));
        bytes.push(match equation.operator {
            EquationOperator::All => 0,
            EquationOperator::Any => 1,
            EquationOperator::ExactlyOne => 2,
            EquationOperator::NotFirst => 3,
        });
        bytes.extend_from_slice(&(equation.parents().len() as u64).to_be_bytes());
        for parent in equation.parents() {
            bytes.extend_from_slice(&canonical_bytes(*parent));
        }
    }
    Ok(hmac_sha256([0; 32], &bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cause_atom::{create as atom, AtomKind};

    fn equation(target: u16, operator: EquationOperator) -> StructuralEquation {
        StructuralEquation::create(
            atom(1, AtomKind::Transition, target, 0).unwrap(),
            vec![atom(1, AtomKind::PublicInput, target, 0).unwrap()],
            operator,
        )
        .unwrap()
    }

    fn predicate() -> OutcomePredicate {
        OutcomePredicate {
            kind: OutcomeKind::ObserverDivergence,
            expected: true,
        }
    }

    #[test]
    fn equation_order_does_not_change_digest() {
        assert_eq!(
            digest(
                1,
                &[
                    equation(2, EquationOperator::Any),
                    equation(1, EquationOperator::Any)
                ],
                predicate()
            ),
            digest(
                1,
                &[
                    equation(1, EquationOperator::Any),
                    equation(2, EquationOperator::Any)
                ],
                predicate()
            )
        );
    }

    #[test]
    fn operator_change_changes_digest() {
        assert_ne!(
            digest(1, &[equation(1, EquationOperator::Any)], predicate()).unwrap(),
            digest(1, &[equation(1, EquationOperator::All)], predicate()).unwrap()
        );
    }
}
