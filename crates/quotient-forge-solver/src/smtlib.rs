use std::fmt::Write;

use quotient_forge_synth::{BlockingClause, DecisionAssignment};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ConstraintKind {
    Security,
    Utility,
    Fault,
}

impl ConstraintKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Security => "security",
            Self::Utility => "utility",
            Self::Fault => "fault",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HardBlocker {
    pub kind: ConstraintKind,
    pub clause: BlockingClause,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ObjectiveCost {
    pub dummy: u64,
    pub latency: u64,
    pub retry: u64,
    pub reconnect: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SmtPhase {
    Feasibility,
    Optimization,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmtEncoding {
    pub state_count: u32,
    pub symbol_count: u32,
    pub output_count: u32,
    pub blockers: Vec<HardBlocker>,
    pub phase: SmtPhase,
    pub output_costs: Vec<ObjectiveCost>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SmtEncodingError {
    EmptyDimension(&'static str),
    ObjectiveCount { expected: usize, actual: usize },
    InvalidBlocker { blocker: usize, assignment: usize },
    EmptyBlocker { blocker: usize },
}

impl std::fmt::Display for SmtEncodingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "SMT encoding error: {self:?}")
    }
}

impl std::error::Error for SmtEncodingError {}

pub fn encode_smtlib(encoding: &SmtEncoding) -> Result<String, SmtEncodingError> {
    validate(encoding)?;
    let mut script = String::new();
    writeln!(script, "; QuotientForge canonical SMT-LIB 2.6").unwrap();
    writeln!(script, "(set-logic QF_LIA)").unwrap();
    writeln!(script, "(set-option :produce-models true)").unwrap();
    if encoding.phase == SmtPhase::Optimization {
        writeln!(script, "(set-option :opt.priority lex)").unwrap();
    }
    writeln!(script, "; phase={:?}", encoding.phase).unwrap();

    for state in 0..encoding.state_count {
        for symbol in 0..encoding.symbol_count {
            writeln!(script, "(declare-fun {} () Int)", next_name(state, symbol)).unwrap();
            writeln!(
                script,
                "(declare-fun {} () Int)",
                output_name(state, symbol)
            )
            .unwrap();
        }
    }
    for state in 0..encoding.state_count {
        for symbol in 0..encoding.symbol_count {
            let next = next_name(state, symbol);
            let output = output_name(state, symbol);
            writeln!(
                script,
                "(assert (! (and (<= 0 {next}) (< {next} {})) :named hard_next_range_{state}_{symbol}))",
                encoding.state_count
            )
            .unwrap();
            writeln!(
                script,
                "(assert (! (and (<= 0 {output}) (< {output} {})) :named hard_output_range_{state}_{symbol}))",
                encoding.output_count
            )
            .unwrap();
        }
    }

    emit_reachability_and_first_use(&mut script, encoding);
    emit_blockers(&mut script, encoding);
    if encoding.phase == SmtPhase::Optimization {
        emit_objectives(&mut script, encoding);
    }
    writeln!(script, "(check-sat)").unwrap();
    writeln!(script, "(get-model)").unwrap();
    Ok(script)
}

#[must_use]
pub fn expected_variable_names(state_count: u32, symbol_count: u32) -> Vec<String> {
    let mut names = Vec::with_capacity(
        usize_index(state_count)
            .saturating_mul(usize_index(symbol_count))
            .saturating_mul(2),
    );
    for state in 0..state_count {
        for symbol in 0..symbol_count {
            names.push(next_name(state, symbol));
            names.push(output_name(state, symbol));
        }
    }
    names
}

fn validate(encoding: &SmtEncoding) -> Result<(), SmtEncodingError> {
    if encoding.state_count == 0 {
        return Err(SmtEncodingError::EmptyDimension("states"));
    }
    if encoding.symbol_count == 0 {
        return Err(SmtEncodingError::EmptyDimension("symbols"));
    }
    if encoding.output_count == 0 {
        return Err(SmtEncodingError::EmptyDimension("outputs"));
    }
    if encoding.phase == SmtPhase::Optimization
        && encoding.output_costs.len() != usize_index(encoding.output_count)
    {
        return Err(SmtEncodingError::ObjectiveCount {
            expected: usize_index(encoding.output_count),
            actual: encoding.output_costs.len(),
        });
    }
    for (blocker_index, blocker) in encoding.blockers.iter().enumerate() {
        if blocker.clause.assignments.is_empty() {
            return Err(SmtEncodingError::EmptyBlocker {
                blocker: blocker_index,
            });
        }
        for (assignment_index, assignment) in blocker.clause.assignments.iter().enumerate() {
            if assignment.machine_state >= encoding.state_count
                || assignment.symbol >= encoding.symbol_count
                || assignment.decision.next_state >= encoding.state_count
                || assignment.decision.output >= encoding.output_count
            {
                return Err(SmtEncodingError::InvalidBlocker {
                    blocker: blocker_index,
                    assignment: assignment_index,
                });
            }
        }
    }
    Ok(())
}

fn emit_reachability_and_first_use(script: &mut String, encoding: &SmtEncoding) {
    for target in 1..encoding.state_count {
        let mut incoming = Vec::new();
        for source in 0..target {
            for symbol in 0..encoding.symbol_count {
                incoming.push(format!("(= {} {target})", next_name(source, symbol)));
            }
        }
        writeln!(
            script,
            "(assert (! (or {}) :named hard_reachable_{target}))",
            incoming.join(" ")
        )
        .unwrap();
    }

    let cells: Vec<_> = (0..encoding.state_count)
        .flat_map(|state| (0..encoding.symbol_count).map(move |symbol| (state, symbol)))
        .collect();
    for (index, (state, symbol)) in cells.iter().copied().enumerate() {
        for target in 2..encoding.state_count {
            let prior: Vec<_> = cells[..index]
                .iter()
                .map(|(prior_state, prior_symbol)| {
                    format!(
                        "(= {} {})",
                        next_name(*prior_state, *prior_symbol),
                        target - 1
                    )
                })
                .collect();
            let prerequisite = if prior.is_empty() {
                "false".to_owned()
            } else {
                format!("(or {})", prior.join(" "))
            };
            writeln!(
                script,
                "(assert (! (=> (= {} {target}) {prerequisite}) :named hard_first_use_{state}_{symbol}_{target}))",
                next_name(state, symbol)
            )
            .unwrap();
        }
    }
}

fn emit_blockers(script: &mut String, encoding: &SmtEncoding) {
    for (index, blocker) in encoding.blockers.iter().enumerate() {
        let assignments: Vec<_> = blocker
            .clause
            .assignments
            .iter()
            .flat_map(assignment_terms)
            .collect();
        writeln!(
            script,
            "(assert (! (not (and {})) :named hard_{}_{index:04}))",
            assignments.join(" "),
            blocker.kind.label()
        )
        .unwrap();
    }
}

fn assignment_terms(assignment: &DecisionAssignment) -> [String; 2] {
    [
        format!(
            "(= {} {})",
            next_name(assignment.machine_state, assignment.symbol),
            assignment.decision.next_state
        ),
        format!(
            "(= {} {})",
            output_name(assignment.machine_state, assignment.symbol),
            assignment.decision.output
        ),
    ]
}

fn emit_objectives(script: &mut String, encoding: &SmtEncoding) {
    writeln!(script, "; Phase B objectives only").unwrap();
    emit_output_objective(script, encoding, "dummy", |cost| cost.dummy);
    emit_output_objective(script, encoding, "latency", |cost| cost.latency);
    writeln!(script, "; objective: state").unwrap();
    writeln!(script, "(minimize {})", encoding.state_count).unwrap();
    emit_output_objective(script, encoding, "retry", |cost| cost.retry);
    emit_output_objective(script, encoding, "reconnect", |cost| cost.reconnect);
}

fn emit_output_objective<F>(script: &mut String, encoding: &SmtEncoding, label: &str, value: F)
where
    F: Fn(ObjectiveCost) -> u64,
{
    let mut terms = Vec::new();
    for state in 0..encoding.state_count {
        for symbol in 0..encoding.symbol_count {
            for (output, cost) in encoding.output_costs.iter().copied().enumerate() {
                terms.push(format!(
                    "(ite (= {} {}) {} 0)",
                    output_name(state, symbol),
                    output,
                    value(cost)
                ));
            }
        }
    }
    writeln!(script, "; objective: {label}").unwrap();
    writeln!(script, "(minimize (+ {}))", terms.join(" ")).unwrap();
}

fn next_name(state: u32, symbol: u32) -> String {
    format!("n_{state}_{symbol}")
}

fn output_name(state: u32, symbol: u32) -> String {
    format!("o_{state}_{symbol}")
}

fn usize_index(value: u32) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}
