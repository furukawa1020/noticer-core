#![forbid(unsafe_code)]

//! Sequence-form causal LP for finite Action-Quotient release models.

use quotient_limit_model::{
    InformationSetId, ModelError, ModelLimits, ObserverId, PrivateHistoryId, PrivateHistoryModel,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const DOMAIN_SEQUENCE_MATRIX: &[u8] = b"QUOTIENT_LIMIT_SEQUENCE_MATRIX_V1";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DecisionId(pub u16);
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ObservationId(pub u16);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RationalCoefficient {
    pub numerator: i64,
    pub denominator: u64,
}
impl RationalCoefficient {
    pub const ZERO: Self = Self {
        numerator: 0,
        denominator: 1,
    };
    pub const ONE: Self = Self {
        numerator: 1,
        denominator: 1,
    };
    pub fn new(numerator: i64, denominator: u64) -> Result<Self, SequenceLpError> {
        if denominator == 0 {
            return Err(SequenceLpError::InvalidRational);
        }
        let gcd = gcd(numerator.unsigned_abs(), denominator);
        Ok(Self {
            numerator: numerator / gcd as i64,
            denominator: denominator / gcd,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicEdge {
    pub successor: InformationSetId,
    pub probability: RationalCoefficient,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicDecision {
    pub information_set: InformationSetId,
    pub id: DecisionId,
    pub successors: Vec<PublicEdge>,
    pub cost: i64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SequenceGraph {
    pub root: InformationSetId,
    pub decisions: Vec<PublicDecision>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SequenceVariable {
    Reach(InformationSetId),
    Flow {
        information_set: InformationSetId,
        decision: DecisionId,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SparseTerm {
    pub variable: u32,
    pub coefficient: RationalCoefficient,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RowKind {
    Root,
    Policy(InformationSetId),
    FlowConservation(InformationSetId),
    ExactAetp {
        left: PrivateHistoryId,
        right: PrivateHistoryId,
        observer: ObserverId,
        observation: ObservationId,
    },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EqualityRow {
    pub kind: RowKind,
    pub terms: Vec<SparseTerm>,
    pub rhs: RationalCoefficient,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservationContribution {
    pub history: PrivateHistoryId,
    pub observer: ObserverId,
    pub observation: ObservationId,
    pub information_set: InformationSetId,
    pub decision: DecisionId,
    pub weight: RationalCoefficient,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SequenceFormLp {
    pub variables: Vec<SequenceVariable>,
    pub equalities: Vec<EqualityRow>,
    pub objective: Vec<SparseTerm>,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SequenceLpError {
    #[error("invalid causal model: {0}")]
    InvalidModel(#[from] ModelError),
    #[error("zero denominator or non-canonical rational coefficient")]
    InvalidRational,
    #[error("sequence graph is incomplete, non-canonical, or has an invalid reference")]
    InvalidGraph,
    #[error("public transition probabilities do not sum to one")]
    InvalidProbabilityFlow,
    #[error("observation contribution is incomplete or references an unknown flow")]
    InvalidObservationContribution,
    #[error("sequence LP exceeds a frozen resource limit")]
    ResourceLimit,
}

pub fn build_sequence_form_lp(
    model: &PrivateHistoryModel,
    graph: &SequenceGraph,
    observations: &[ObservationContribution],
    model_limits: ModelLimits,
    max_variables: usize,
    max_constraints: usize,
) -> Result<SequenceFormLp, SequenceLpError> {
    model.validate(model_limits)?;
    let sets: Vec<_> = model
        .information_tree
        .information_sets
        .iter()
        .map(|x| x.id)
        .collect();
    if !sets.contains(&graph.root)
        || !graph
            .decisions
            .windows(2)
            .all(|x| (x[0].information_set, x[0].id) < (x[1].information_set, x[1].id))
    {
        return Err(SequenceLpError::InvalidGraph);
    }
    let declared: BTreeSet<_> = sets.iter().copied().collect();
    let mut by_set: BTreeMap<_, Vec<&PublicDecision>> =
        sets.iter().map(|id| (*id, Vec::new())).collect();
    for decision in &graph.decisions {
        if decision.cost < 0 || !declared.contains(&decision.information_set) {
            return Err(SequenceLpError::InvalidGraph);
        }
        if decision
            .successors
            .windows(2)
            .any(|x| x[0].successor >= x[1].successor)
            || decision
                .successors
                .iter()
                .any(|edge| !declared.contains(&edge.successor) || !canonical(edge.probability))
        {
            return Err(SequenceLpError::InvalidGraph);
        }
        if !decision.successors.is_empty() && !sum_is_one(&decision.successors)? {
            return Err(SequenceLpError::InvalidProbabilityFlow);
        }
        by_set
            .get_mut(&decision.information_set)
            .expect("declared set")
            .push(decision);
    }
    if by_set.values().any(Vec::is_empty) {
        return Err(SequenceLpError::InvalidGraph);
    }

    let mut variables: Vec<_> = sets.iter().copied().map(SequenceVariable::Reach).collect();
    variables.extend(graph.decisions.iter().map(|x| SequenceVariable::Flow {
        information_set: x.information_set,
        decision: x.id,
    }));
    if variables.len() > max_variables {
        return Err(SequenceLpError::ResourceLimit);
    }
    let index: BTreeMap<_, _> = variables
        .iter()
        .enumerate()
        .map(|(i, x)| (*x, i as u32))
        .collect();
    let mut rows = vec![EqualityRow {
        kind: RowKind::Root,
        terms: vec![term(
            &index,
            SequenceVariable::Reach(graph.root),
            RationalCoefficient::ONE,
        )?],
        rhs: RationalCoefficient::ONE,
    }];
    for set in &sets {
        let mut terms = vec![term(
            &index,
            SequenceVariable::Reach(*set),
            RationalCoefficient::new(-1, 1)?,
        )?];
        for decision in &by_set[set] {
            terms.push(term(
                &index,
                SequenceVariable::Flow {
                    information_set: *set,
                    decision: decision.id,
                },
                RationalCoefficient::ONE,
            )?);
        }
        rows.push(EqualityRow {
            kind: RowKind::Policy(*set),
            terms,
            rhs: RationalCoefficient::ZERO,
        });
        if *set != graph.root {
            let mut incoming = vec![term(
                &index,
                SequenceVariable::Reach(*set),
                RationalCoefficient::ONE,
            )?];
            for decision in &graph.decisions {
                for edge in decision
                    .successors
                    .iter()
                    .filter(|edge| edge.successor == *set)
                {
                    incoming.push(term(
                        &index,
                        SequenceVariable::Flow {
                            information_set: decision.information_set,
                            decision: decision.id,
                        },
                        RationalCoefficient::new(
                            -edge.probability.numerator,
                            edge.probability.denominator,
                        )?,
                    )?);
                }
            }
            rows.push(EqualityRow {
                kind: RowKind::FlowConservation(*set),
                terms: incoming,
                rhs: RationalCoefficient::ZERO,
            });
        }
    }
    append_privacy_rows(model, observations, &index, &mut rows)?;
    if rows.len() > max_constraints {
        return Err(SequenceLpError::ResourceLimit);
    }
    let objective = graph
        .decisions
        .iter()
        .map(|x| {
            term(
                &index,
                SequenceVariable::Flow {
                    information_set: x.information_set,
                    decision: x.id,
                },
                RationalCoefficient::new(x.cost, 1).expect("nonnegative integer"),
            )
        })
        .collect::<Result<_, _>>()?;
    Ok(SequenceFormLp {
        variables,
        equalities: rows,
        objective,
    })
}

fn append_privacy_rows(
    model: &PrivateHistoryModel,
    contributions: &[ObservationContribution],
    index: &BTreeMap<SequenceVariable, u32>,
    rows: &mut Vec<EqualityRow>,
) -> Result<(), SequenceLpError> {
    if contributions.iter().any(|x| {
        !canonical(x.weight)
            || !index.contains_key(&SequenceVariable::Flow {
                information_set: x.information_set,
                decision: x.decision,
            })
    }) {
        return Err(SequenceLpError::InvalidObservationContribution);
    }
    for class in &model.action_quotient.classes {
        let members: Vec<_> = model
            .action_quotient
            .class_of_history
            .iter()
            .filter(|x| x.class == class.id)
            .map(|x| x.history)
            .collect();
        let Some(left) = members.first().copied() else {
            continue;
        };
        for right in members.into_iter().skip(1) {
            let keys: BTreeSet<_> = contributions
                .iter()
                .filter(|x| x.history == left || x.history == right)
                .map(|x| (x.observer, x.observation))
                .collect();
            for (observer, observation) in keys {
                let mut terms = Vec::new();
                for item in contributions.iter().filter(|x| {
                    x.observer == observer
                        && x.observation == observation
                        && (x.history == left || x.history == right)
                }) {
                    let coefficient = if item.history == left {
                        item.weight
                    } else {
                        RationalCoefficient::new(-item.weight.numerator, item.weight.denominator)?
                    };
                    terms.push(term(
                        index,
                        SequenceVariable::Flow {
                            information_set: item.information_set,
                            decision: item.decision,
                        },
                        coefficient,
                    )?);
                }
                terms.sort_by_key(|x| x.variable);
                rows.push(EqualityRow {
                    kind: RowKind::ExactAetp {
                        left,
                        right,
                        observer,
                        observation,
                    },
                    terms,
                    rhs: RationalCoefficient::ZERO,
                });
            }
        }
    }
    Ok(())
}

fn term(
    index: &BTreeMap<SequenceVariable, u32>,
    variable: SequenceVariable,
    coefficient: RationalCoefficient,
) -> Result<SparseTerm, SequenceLpError> {
    Ok(SparseTerm {
        variable: *index.get(&variable).ok_or(SequenceLpError::InvalidGraph)?,
        coefficient,
    })
}
fn canonical(x: RationalCoefficient) -> bool {
    x.denominator != 0 && gcd(x.numerator.unsigned_abs(), x.denominator) == 1
}
fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let r = a % b;
        a = b;
        b = r;
    }
    a.max(1)
}
fn sum_is_one(edges: &[PublicEdge]) -> Result<bool, SequenceLpError> {
    let mut n: i128 = 0;
    let mut d: i128 = 1;
    for edge in edges {
        let en = edge.probability.numerator as i128;
        let ed = edge.probability.denominator as i128;
        n = n
            .checked_mul(ed)
            .and_then(|x| x.checked_add(en.checked_mul(d)?))
            .ok_or(SequenceLpError::ResourceLimit)?;
        d = d.checked_mul(ed).ok_or(SequenceLpError::ResourceLimit)?;
    }
    Ok(n == d)
}

impl SequenceFormLp {
    pub fn canonical_digest(&self) -> [u8; 32] {
        let mut d = Sha256::new();
        d.update(DOMAIN_SEQUENCE_MATRIX);
        d.update([0]);
        d.update((self.variables.len() as u64).to_le_bytes());
        for variable in &self.variables {
            d.update(format!("{variable:?}").as_bytes());
            d.update([0]);
        }
        for row in &self.equalities {
            for x in &row.terms {
                d.update(x.variable.to_le_bytes());
                d.update(x.coefficient.numerator.to_le_bytes());
                d.update(x.coefficient.denominator.to_le_bytes());
            }
            d.update([0xff]);
        }
        d.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rational_coefficients_are_canonical() {
        assert_eq!(
            RationalCoefficient::new(2, 4).unwrap(),
            RationalCoefficient {
                numerator: 1,
                denominator: 2
            }
        );
        assert_eq!(
            RationalCoefficient::new(1, 0),
            Err(SequenceLpError::InvalidRational)
        );
    }
    #[test]
    fn public_probability_flow_is_exact() {
        let edges = [
            PublicEdge {
                successor: InformationSetId(1),
                probability: RationalCoefficient::new(1, 3).unwrap(),
            },
            PublicEdge {
                successor: InformationSetId(2),
                probability: RationalCoefficient::new(2, 3).unwrap(),
            },
        ];
        assert!(sum_is_one(&edges).unwrap());
    }
}
