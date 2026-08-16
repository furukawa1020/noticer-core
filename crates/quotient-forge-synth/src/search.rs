use std::collections::BTreeMap;
use std::fmt;
use std::time::{Duration, Instant};

use quotient_forge_check::{
    check, CheckLimits, CheckOutcome, Counterexample, ModelError, VerifiedReport,
};

use crate::model::{
    parse_combined_state, MachineCell, ProblemError, ReleaseMachine, SynthesisCost,
    SynthesisProblem,
};

const MAX_ENUMERATION_CELLS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SynthesisLimits {
    pub max_states: u32,
    pub max_candidates: u64,
    pub time_limit: Duration,
    pub checker_limits: CheckLimits,
    pub seed: u64,
}

impl Default for SynthesisLimits {
    fn default() -> Self {
        Self {
            max_states: 4,
            max_candidates: 1_000_000,
            time_limit: Duration::from_secs(30),
            checker_limits: CheckLimits::default(),
            seed: 0,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SearchStats {
    pub generated_candidates: u64,
    pub checker_calls: u64,
    pub counterexamples: u64,
    pub blocked_by_counterexamples: u64,
    pub completed_state_bounds: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InconclusiveReason {
    CandidateLimit { limit: u64 },
    TimeLimit { millis: u128 },
    CheckerResource,
    EnumerationDomain { cells: usize },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SynthesisReport {
    pub machine: ReleaseMachine,
    pub cost: SynthesisCost,
    pub verification: VerifiedReport,
    pub stats: SearchStats,
    pub minimal_state_count: bool,
    pub cost_optimized: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnrealizableReport {
    pub searched_through_states: u32,
    pub stats: SearchStats,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SynthesisOutcome {
    Realizable(Box<SynthesisReport>),
    Unrealizable(UnrealizableReport),
    Inconclusive {
        reason: InconclusiveReason,
        stats: SearchStats,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SynthesisError {
    Problem(ProblemError),
    Checker(ModelError),
    CounterexampleDidNotBlock,
}

impl fmt::Display for SynthesisError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Problem(error) => write!(formatter, "invalid synthesis problem: {error}"),
            Self::Checker(error) => write!(formatter, "checker rejected lowered model: {error}"),
            Self::CounterexampleDidNotBlock => {
                formatter.write_str("counterexample did not exclude its source candidate")
            }
        }
    }
}

impl std::error::Error for SynthesisError {}

impl From<ProblemError> for SynthesisError {
    fn from(error: ProblemError) -> Self {
        Self::Problem(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DecisionAssignment {
    pub machine_state: u32,
    pub symbol: u32,
    pub decision: MachineCell,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockingClause {
    pub assignments: Vec<DecisionAssignment>,
}

impl BlockingClause {
    #[must_use]
    pub fn blocks(&self, machine: &ReleaseMachine) -> bool {
        !self.assignments.is_empty()
            && self.assignments.iter().all(|assignment| {
                assignment.machine_state < machine.state_count
                    && assignment.symbol < machine.symbol_count
                    && machine.cell(assignment.machine_state, assignment.symbol)
                        == assignment.decision
            })
    }
}

#[must_use]
pub fn blocking_clause_from_counterexample(
    problem: &SynthesisProblem,
    machine: &ReleaseMachine,
    counterexample: &Counterexample,
) -> Option<BlockingClause> {
    let mut assignments = BTreeMap::new();
    for step in &counterexample.trace {
        let input = problem
            .inputs
            .iter()
            .position(|input| input.id == step.input.id)?;
        for state_id in [&step.left_state, &step.right_state] {
            let (plant_state, machine_state) = parse_combined_state(state_id)?;
            let plant_transition = problem.plant_transition(plant_state, input);
            let symbol = plant_transition.machine_symbol;
            let decision = machine.cell(machine_state, symbol);
            let key = (machine_state, symbol);
            if assignments
                .insert(key, decision)
                .is_some_and(|prior| prior != decision)
            {
                return None;
            }
        }
    }
    Some(BlockingClause {
        assignments: assignments
            .into_iter()
            .map(|((machine_state, symbol), decision)| DecisionAssignment {
                machine_state,
                symbol,
                decision,
            })
            .collect(),
    })
}

pub fn find_feasible(
    problem: &SynthesisProblem,
    limits: SynthesisLimits,
) -> Result<SynthesisOutcome, SynthesisError> {
    synthesize(problem, limits, SearchMode::Feasibility)
}

pub fn optimize_cost(
    problem: &SynthesisProblem,
    limits: SynthesisLimits,
) -> Result<SynthesisOutcome, SynthesisError> {
    synthesize(problem, limits, SearchMode::Optimize)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SearchMode {
    Feasibility,
    Optimize,
}

#[derive(Clone, Debug)]
struct BestCandidate {
    machine: ReleaseMachine,
    cost: SynthesisCost,
    verification: VerifiedReport,
    canonical: Vec<u8>,
}

struct SearchContext<'a> {
    problem: &'a SynthesisProblem,
    limits: SynthesisLimits,
    mode: SearchMode,
    started: Instant,
    stats: SearchStats,
    blockers: Vec<BlockingClause>,
    best: Option<BestCandidate>,
    halt: Option<SynthesisOutcome>,
    error: Option<SynthesisError>,
}

fn synthesize(
    problem: &SynthesisProblem,
    limits: SynthesisLimits,
    mode: SearchMode,
) -> Result<SynthesisOutcome, SynthesisError> {
    problem.validate()?;
    if limits.max_states == 0 {
        return Err(SynthesisError::Problem(ProblemError::Empty("max_states")));
    }
    let mut context = SearchContext {
        problem,
        limits,
        mode,
        started: Instant::now(),
        stats: SearchStats::default(),
        blockers: Vec::new(),
        best: None,
        halt: None,
        error: None,
    };
    let output_order = seeded_output_order(problem.outputs.len(), limits.seed);

    for state_count in 1..=limits.max_states {
        let cells =
            usize_index(state_count).saturating_mul(usize_index(problem.machine_symbol_count));
        if cells > MAX_ENUMERATION_CELLS {
            return Ok(SynthesisOutcome::Inconclusive {
                reason: InconclusiveReason::EnumerationDomain { cells },
                stats: context.stats,
            });
        }
        let mut table = Vec::with_capacity(cells);
        enumerate_canonical(
            state_count,
            problem.machine_symbol_count,
            &output_order,
            &mut table,
            0,
            0,
            &mut |machine| context.visit(machine),
        );
        if let Some(error) = context.error.take() {
            return Err(error);
        }
        if let Some(outcome) = context.halt.take() {
            return Ok(outcome);
        }
        context.stats.completed_state_bounds = state_count;
        if mode == SearchMode::Optimize {
            if let Some(best) = context.best.take() {
                return Ok(SynthesisOutcome::Realizable(Box::new(SynthesisReport {
                    machine: best.machine,
                    cost: best.cost,
                    verification: best.verification,
                    stats: context.stats,
                    minimal_state_count: true,
                    cost_optimized: true,
                })));
            }
        }
    }

    Ok(SynthesisOutcome::Unrealizable(UnrealizableReport {
        searched_through_states: limits.max_states,
        stats: context.stats,
    }))
}

impl SearchContext<'_> {
    fn visit(&mut self, machine: ReleaseMachine) -> bool {
        if self.started.elapsed() >= self.limits.time_limit {
            self.halt = Some(SynthesisOutcome::Inconclusive {
                reason: InconclusiveReason::TimeLimit {
                    millis: self.limits.time_limit.as_millis(),
                },
                stats: self.stats.clone(),
            });
            return false;
        }
        if self.stats.generated_candidates >= self.limits.max_candidates {
            self.halt = Some(SynthesisOutcome::Inconclusive {
                reason: InconclusiveReason::CandidateLimit {
                    limit: self.limits.max_candidates,
                },
                stats: self.stats.clone(),
            });
            return false;
        }
        self.stats.generated_candidates += 1;
        if self.blockers.iter().any(|blocker| blocker.blocks(&machine)) {
            self.stats.blocked_by_counterexamples += 1;
            return true;
        }

        let checker_model = match self.problem.lower_unchecked(&machine) {
            Ok(model) => model,
            Err(error) => {
                self.error = Some(SynthesisError::Problem(error));
                return false;
            }
        };
        self.stats.checker_calls += 1;
        match check(&checker_model, self.limits.checker_limits) {
            Ok(CheckOutcome::Verified(verification)) => {
                let cost = machine.cost(&self.problem.outputs);
                let canonical = machine.canonical_bytes();
                let candidate = BestCandidate {
                    machine,
                    cost,
                    verification,
                    canonical,
                };
                if self.mode == SearchMode::Feasibility {
                    self.halt = Some(SynthesisOutcome::Realizable(Box::new(SynthesisReport {
                        machine: candidate.machine,
                        cost: candidate.cost,
                        verification: candidate.verification,
                        stats: self.stats.clone(),
                        minimal_state_count: true,
                        cost_optimized: false,
                    })));
                    false
                } else {
                    let replace = self.best.as_ref().is_none_or(|best| {
                        candidate.cost < best.cost
                            || (candidate.cost == best.cost && candidate.canonical < best.canonical)
                    });
                    if replace {
                        self.best = Some(candidate);
                    }
                    true
                }
            }
            Ok(CheckOutcome::Counterexample(counterexample)) => {
                self.stats.counterexamples += 1;
                let Some(blocker) =
                    blocking_clause_from_counterexample(self.problem, &machine, &counterexample)
                else {
                    self.error = Some(SynthesisError::CounterexampleDidNotBlock);
                    return false;
                };
                if !blocker.blocks(&machine) {
                    self.error = Some(SynthesisError::CounterexampleDidNotBlock);
                    return false;
                }
                self.blockers.push(blocker);
                true
            }
            Ok(CheckOutcome::Inconclusive(_)) => {
                self.halt = Some(SynthesisOutcome::Inconclusive {
                    reason: InconclusiveReason::CheckerResource,
                    stats: self.stats.clone(),
                });
                false
            }
            Err(error) => {
                self.error = Some(SynthesisError::Checker(error));
                false
            }
        }
    }
}

fn enumerate_canonical<F>(
    state_count: u32,
    symbol_count: u32,
    output_order: &[u32],
    table: &mut Vec<MachineCell>,
    index: usize,
    highest_seen: u32,
    visitor: &mut F,
) -> bool
where
    F: FnMut(ReleaseMachine) -> bool,
{
    let total = usize_index(state_count) * usize_index(symbol_count);
    if index == total {
        if highest_seen.saturating_add(1) != state_count {
            return true;
        }
        let machine = ReleaseMachine {
            state_count,
            symbol_count,
            cells: table.clone(),
        };
        if machine.validate(symbol_count, output_order.len()).is_err() {
            return true;
        }
        return visitor(machine);
    }

    let highest_destination = highest_seen.saturating_add(1).min(state_count - 1);
    for next_state in 0..=highest_destination {
        let next_highest = highest_seen.max(next_state);
        for output in output_order {
            table.push(MachineCell {
                next_state,
                output: *output,
            });
            if !enumerate_canonical(
                state_count,
                symbol_count,
                output_order,
                table,
                index + 1,
                next_highest,
                visitor,
            ) {
                table.pop();
                return false;
            }
            table.pop();
        }
    }
    true
}

fn seeded_output_order(output_count: usize, seed: u64) -> Vec<u32> {
    let mut outputs: Vec<_> = (0..output_count)
        .map(|output| u32::try_from(output).unwrap_or(u32::MAX))
        .collect();
    if !outputs.is_empty() {
        let offset =
            usize::try_from(seed % u64::try_from(outputs.len()).unwrap_or(u64::MAX)).unwrap_or(0);
        outputs.rotate_left(offset);
    }
    outputs
}

fn usize_index(value: u32) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}
