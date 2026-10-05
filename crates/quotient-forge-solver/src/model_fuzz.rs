use std::collections::BTreeMap;

use crate::{parse_solver_output_bounded, ParsedSolverOutput, SolverOutputLimits};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelDifferentialStatus {
    Agree,
    Reject,
    Disagreement,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelDifferentialReport {
    pub status: ModelDifferentialStatus,
    pub category: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QdimacsModelError {
    ResourceLimit,
    UnknownStatus,
    Malformed,
    Duplicate,
    Conflicting,
    Missing,
}

pub fn compare_solver_models(
    smt_output: &str,
    qdimacs_output: &str,
    variables: &[String],
    limits: SolverOutputLimits,
) -> ModelDifferentialReport {
    let left = parse_solver_output_bounded(smt_output, variables, limits);
    let right = parse_qdimacs(qdimacs_output, variables, limits);
    match (left, right) {
        (Ok(ParsedSolverOutput::Unsat), Ok(None)) => agree("unsat"),
        (Ok(ParsedSolverOutput::Sat(left)), Ok(Some(right))) if left == right => agree("sat"),
        (Err(_), Err(_)) => ModelDifferentialReport {
            status: ModelDifferentialStatus::Reject,
            category: "both_reject",
        },
        _ => ModelDifferentialReport {
            status: ModelDifferentialStatus::Disagreement,
            category: "model_disagreement",
        },
    }
}

fn agree(category: &'static str) -> ModelDifferentialReport {
    ModelDifferentialReport {
        status: ModelDifferentialStatus::Agree,
        category,
    }
}

fn parse_qdimacs(
    output: &str,
    variables: &[String],
    limits: SolverOutputLimits,
) -> Result<Option<BTreeMap<String, i64>>, QdimacsModelError> {
    if output.len() > limits.max_bytes || variables.len() > limits.max_variables {
        return Err(QdimacsModelError::ResourceLimit);
    }
    let mut status = None;
    let mut values = BTreeMap::<usize, bool>::new();
    let mut tokens = 0_usize;
    for line in output.lines() {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        tokens = tokens.saturating_add(fields.len());
        if tokens > limits.max_tokens
            || fields
                .iter()
                .any(|field| field.len() > limits.max_atom_bytes)
        {
            return Err(QdimacsModelError::ResourceLimit);
        }
        match fields.as_slice() {
            ["s", "cnf", "0", ..] => status = Some(false),
            ["s", "cnf", "1", ..] => status = Some(true),
            [prefix, literals @ ..] if *prefix == "V" || *prefix == "v" => {
                for literal in literals {
                    let value: i64 = literal.parse().map_err(|_| QdimacsModelError::Malformed)?;
                    if value == 0 {
                        break;
                    }
                    let index = usize::try_from(value.unsigned_abs())
                        .map_err(|_| QdimacsModelError::Malformed)?;
                    if index == 0 || index > variables.len() {
                        return Err(QdimacsModelError::Malformed);
                    }
                    match values.insert(index, value > 0) {
                        Some(old) if old == (value > 0) => {
                            return Err(QdimacsModelError::Duplicate)
                        }
                        Some(_) => return Err(QdimacsModelError::Conflicting),
                        None => {}
                    }
                }
            }
            [] | ["c", ..] => {}
            _ => return Err(QdimacsModelError::Malformed),
        }
    }
    match status {
        Some(false) => Ok(None),
        Some(true) if values.len() == variables.len() => Ok(Some(
            values
                .into_iter()
                .map(|(index, value)| (variables[index - 1].clone(), i64::from(value)))
                .collect(),
        )),
        Some(true) => Err(QdimacsModelError::Missing),
        None => Err(QdimacsModelError::UnknownStatus),
    }
}
