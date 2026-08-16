use std::collections::{BTreeSet, VecDeque};
use std::fmt;
use std::time::{Duration, Instant};

use quotient_forge_check::{check, CheckLimits, CheckOutcome, ObligationRef, Release};
use quotient_forge_synth::{ProblemError, ReleaseMachine, SynthesisCost, SynthesisProblem};

use crate::operator::{RepairOperator, Variant};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SourceFingerprint([u8; 32]);

impl SourceFingerprint {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RepairDistance {
    pub changed_transitions: u64,
    pub changed_outputs: u64,
    pub added_states: u64,
    pub added_cover_releases: u64,
    pub added_latency: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepairProvenance {
    pub source: SourceFingerprint,
    pub operators: Vec<RepairOperator>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepairPoint {
    pub machine: ReleaseMachine,
    pub outputs: Vec<Release>,
    pub distance: RepairDistance,
    pub runtime_cost: SynthesisCost,
    pub provenance: RepairProvenance,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParetoFrontier {
    pub points: Vec<RepairPoint>,
    pub truncated: bool,
    pub stats: RepairStats,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RepairStats {
    pub variants_examined: u64,
    pub duplicate_variants: u64,
    pub checker_calls: u64,
    pub counterexamples: u64,
    pub verified_variants: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InconclusiveReason {
    VariantLimit { limit: u64 },
    TimeLimit { millis: u128 },
    CheckerResource,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RepairOutcome {
    Repaired(ParetoFrontier),
    NoRepair {
        stats: RepairStats,
    },
    Inconclusive {
        reason: InconclusiveReason,
        stats: RepairStats,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepairLimits {
    pub max_operator_depth: usize,
    pub max_variants: u64,
    pub max_frontier: usize,
    pub time_limit: Duration,
    pub checker_limits: CheckLimits,
}

impl Default for RepairLimits {
    fn default() -> Self {
        Self {
            max_operator_depth: 3,
            max_variants: 100_000,
            max_frontier: 32,
            time_limit: Duration::from_secs(30),
            checker_limits: CheckLimits::default(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RepairError {
    Problem(ProblemError),
    InvalidOperator { index: usize },
    OperatorOrder { index: usize },
    EmptyFrontierLimit,
}

impl fmt::Display for RepairError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "repair error: {self:?}")
    }
}

impl std::error::Error for RepairError {}

impl From<ProblemError> for RepairError {
    fn from(error: ProblemError) -> Self {
        Self::Problem(error)
    }
}

pub fn repair(
    problem: &SynthesisProblem,
    source_machine: &ReleaseMachine,
    operators: &[RepairOperator],
    limits: RepairLimits,
) -> Result<RepairOutcome, RepairError> {
    problem.validate()?;
    source_machine.validate(problem.machine_symbol_count, problem.outputs.len())?;
    validate_operators(operators)?;
    if limits.max_frontier == 0 {
        return Err(RepairError::EmptyFrontierLimit);
    }

    let source = source_fingerprint(source_machine, &problem.outputs);
    let root = Variant {
        problem: problem.clone(),
        machine: source_machine.clone(),
        operators: Vec::new(),
        added_cover_releases: 0,
        added_latency: 0,
    };
    let mut queue = VecDeque::from([(root, 0_usize, 0_usize)]);
    let mut seen = BTreeSet::new();
    seen.insert(variant_fingerprint(source_machine, &problem.outputs));
    let mut frontier = Vec::new();
    let mut frontier_truncated = false;
    let mut stats = RepairStats::default();
    let started = Instant::now();

    while let Some((variant, next_operator, depth)) = queue.pop_front() {
        if started.elapsed() >= limits.time_limit {
            return Ok(RepairOutcome::Inconclusive {
                reason: InconclusiveReason::TimeLimit {
                    millis: limits.time_limit.as_millis(),
                },
                stats,
            });
        }
        if stats.variants_examined >= limits.max_variants {
            return Ok(RepairOutcome::Inconclusive {
                reason: InconclusiveReason::VariantLimit {
                    limit: limits.max_variants,
                },
                stats,
            });
        }
        stats.variants_examined += 1;
        stats.checker_calls += 1;
        let checker_model = variant.problem.lower_candidate(&variant.machine)?;
        match check(&checker_model, limits.checker_limits) {
            Ok(CheckOutcome::Verified(_)) => {
                stats.verified_variants += 1;
                let point = repair_point(problem, source_machine, source, &variant);
                if insert_non_dominated(&mut frontier, point) {
                    frontier.sort_by(compare_points);
                    if frontier.len() > limits.max_frontier {
                        frontier.truncate(limits.max_frontier);
                        frontier_truncated = true;
                    }
                }
            }
            Ok(CheckOutcome::Counterexample(_)) => stats.counterexamples += 1,
            Ok(CheckOutcome::Inconclusive(_)) => {
                return Ok(RepairOutcome::Inconclusive {
                    reason: InconclusiveReason::CheckerResource,
                    stats,
                });
            }
            Err(error) => return Err(RepairError::Problem(ProblemError::Checker(error))),
        }

        if depth >= limits.max_operator_depth {
            continue;
        }
        for (operator_index, operator) in operators.iter().enumerate().skip(next_operator) {
            let Some(next) = variant.apply(operator) else {
                continue;
            };
            let fingerprint = variant_fingerprint(&next.machine, &next.problem.outputs);
            if !seen.insert(fingerprint) {
                stats.duplicate_variants += 1;
                continue;
            }
            queue.push_back((next, operator_index + 1, depth + 1));
        }
    }

    if frontier.is_empty() {
        Ok(RepairOutcome::NoRepair { stats })
    } else {
        Ok(RepairOutcome::Repaired(ParetoFrontier {
            points: frontier,
            truncated: frontier_truncated,
            stats,
        }))
    }
}

fn validate_operators(operators: &[RepairOperator]) -> Result<(), RepairError> {
    let mut previous = None;
    for (index, operator) in operators.iter().enumerate() {
        if !operator.validate() {
            return Err(RepairError::InvalidOperator { index });
        }
        if previous.is_some_and(|rank| rank >= operator.rank()) {
            return Err(RepairError::OperatorOrder { index });
        }
        previous = Some(operator.rank());
    }
    Ok(())
}

fn repair_point(
    source_problem: &SynthesisProblem,
    source_machine: &ReleaseMachine,
    source: SourceFingerprint,
    variant: &Variant,
) -> RepairPoint {
    RepairPoint {
        distance: repair_distance(source_problem, source_machine, variant),
        runtime_cost: variant.machine.cost(&variant.problem.outputs),
        machine: variant.machine.clone(),
        outputs: variant.problem.outputs.clone(),
        provenance: RepairProvenance {
            source,
            operators: variant.operators.clone(),
        },
    }
}

fn repair_distance(
    source_problem: &SynthesisProblem,
    source_machine: &ReleaseMachine,
    variant: &Variant,
) -> RepairDistance {
    let shared_cells = source_machine.cells.len().min(variant.machine.cells.len());
    let changed_transitions = source_machine.cells[..shared_cells]
        .iter()
        .zip(&variant.machine.cells[..shared_cells])
        .filter(|(left, right)| left != right)
        .count()
        .saturating_add(
            source_machine
                .cells
                .len()
                .abs_diff(variant.machine.cells.len()),
        );
    let shared_outputs = source_problem
        .outputs
        .len()
        .min(variant.problem.outputs.len());
    let changed_outputs = source_problem.outputs[..shared_outputs]
        .iter()
        .zip(&variant.problem.outputs[..shared_outputs])
        .filter(|(left, right)| left != right)
        .count()
        .saturating_add(
            source_problem
                .outputs
                .len()
                .abs_diff(variant.problem.outputs.len()),
        );
    RepairDistance {
        changed_transitions: u64::try_from(changed_transitions).unwrap_or(u64::MAX),
        changed_outputs: u64::try_from(changed_outputs).unwrap_or(u64::MAX),
        added_states: u64::from(
            variant
                .machine
                .state_count
                .saturating_sub(source_machine.state_count),
        ),
        added_cover_releases: variant.added_cover_releases,
        added_latency: variant.added_latency,
    }
}

fn insert_non_dominated(frontier: &mut Vec<RepairPoint>, candidate: RepairPoint) -> bool {
    if frontier.iter().any(|point| dominates(point, &candidate)) {
        return false;
    }
    frontier.retain(|point| !dominates(&candidate, point));
    frontier.push(candidate);
    true
}

fn dominates(left: &RepairPoint, right: &RepairPoint) -> bool {
    let left_operators = left.provenance.operators.len();
    let right_operators = right.provenance.operators.len();
    left.distance <= right.distance
        && left.runtime_cost <= right.runtime_cost
        && left_operators <= right_operators
        && (left.distance < right.distance
            || left.runtime_cost < right.runtime_cost
            || left_operators < right_operators)
}

fn compare_points(left: &RepairPoint, right: &RepairPoint) -> std::cmp::Ordering {
    left.distance
        .cmp(&right.distance)
        .then_with(|| left.runtime_cost.cmp(&right.runtime_cost))
        .then_with(|| {
            left.provenance
                .operators
                .len()
                .cmp(&right.provenance.operators.len())
        })
        .then_with(|| {
            variant_fingerprint(&left.machine, &left.outputs)
                .cmp(&variant_fingerprint(&right.machine, &right.outputs))
        })
}

fn source_fingerprint(machine: &ReleaseMachine, outputs: &[Release]) -> SourceFingerprint {
    let canonical = canonical_variant(machine, outputs);
    let seeds = [
        0xcbf2_9ce4_8422_2325,
        0x8422_2325_cbf2_9ce4,
        0x9e37_79b9_7f4a_7c15,
        0x517c_c1b7_2722_0a95,
    ];
    let mut bytes = [0_u8; 32];
    for (index, seed) in seeds.into_iter().enumerate() {
        let mut hash = seed;
        for value in &canonical {
            hash ^= u64::from(*value);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        bytes[index * 8..index * 8 + 8].copy_from_slice(&hash.to_le_bytes());
    }
    SourceFingerprint(bytes)
}

fn variant_fingerprint(machine: &ReleaseMachine, outputs: &[Release]) -> Vec<u8> {
    canonical_variant(machine, outputs)
}

fn canonical_variant(machine: &ReleaseMachine, outputs: &[Release]) -> Vec<u8> {
    let mut bytes = machine.canonical_bytes();
    push_u64(&mut bytes, outputs.len());
    for output in outputs {
        bytes.push(u8::from(output.emitted));
        push_u64(&mut bytes, output.fields.len());
        for (field, value) in &output.fields {
            push_bytes(&mut bytes, field.as_str().as_bytes());
            push_bytes(&mut bytes, value.as_bytes());
        }
        push_u64(&mut bytes, output.actions.len());
        for action in &output.actions {
            match &action.obligation {
                ObligationRef::Authorized(id) => {
                    bytes.push(0);
                    push_bytes(&mut bytes, id.as_str().as_bytes());
                }
                ObligationRef::Recovery {
                    fault,
                    triggered_at,
                } => {
                    bytes.push(1);
                    push_bytes(&mut bytes, fault.as_str().as_bytes());
                    bytes.extend_from_slice(&triggered_at.to_le_bytes());
                }
            }
            push_bytes(&mut bytes, action.action.as_str().as_bytes());
        }
    }
    bytes
}

fn push_u64(bytes: &mut Vec<u8>, value: usize) {
    bytes.extend_from_slice(&u64::try_from(value).unwrap_or(u64::MAX).to_le_bytes());
}

fn push_bytes(bytes: &mut Vec<u8>, value: &[u8]) {
    push_u64(bytes, value.len());
    bytes.extend_from_slice(value);
}
