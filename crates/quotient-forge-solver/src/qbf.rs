//! Bounded AQRS safety-game semantics compiled to the QDIMACS v1 contract.
//!
//! This module is deliberately a finite reference compiler. It makes the
//! machine/trace quantifier boundary executable before an external QBF solver
//! or scalable symbolic transition encoding is introduced.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use quotient_forge_check::{
    ActionId, EnvironmentInput, FaultInput, FaultInputId, ObligationRef, Observer, Release,
    SemanticContract,
};
use quotient_forge_synth::{MachineCell, ProblemError, ReleaseMachine, SynthesisProblem};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::qdimacs::{
    encode_qdimacs, QdimacsArtifact, QdimacsBounds, QdimacsError, QdimacsSpec, QuantifierKind,
    SymbolicClause, SymbolicLiteral, VariableKey, VariableRole,
};

pub const QBF_SEMANTICS_SCHEMA_V1: &str = "noticer.quotient_forge.qbf_semantics.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QbfCompileLimits {
    pub max_machine_states: u32,
    pub max_table_assignments: u64,
    pub max_candidates: usize,
    pub max_scenarios: usize,
    pub seed: u64,
}

impl Default for QbfCompileLimits {
    fn default() -> Self {
        Self {
            max_machine_states: 2,
            max_table_assignments: 1_000_000,
            max_candidates: 100_000,
            max_scenarios: 100_000,
            seed: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QuantifierLayout {
    MachineBeforeTrace,
    MachineAfterTraceMutant,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QbfFiniteBounds {
    pub plant_states: u32,
    pub machine_states: u32,
    pub machine_symbols: u32,
    pub horizon: u32,
    pub outputs: u32,
    pub candidates: u32,
    pub scenarios: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateCellRecord {
    pub machine_state: u32,
    pub symbol: u32,
    pub next_state: u32,
    pub output: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateRecord {
    pub id: u32,
    pub state_count: u32,
    pub symbol_count: u32,
    pub canonical_sha256: String,
    pub cells: Vec<CandidateCellRecord>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioRecord {
    pub id: u32,
    pub initial_pair: u32,
    pub left_plant_state: u32,
    pub right_plant_state: u32,
    pub left_private_history: String,
    pub right_private_history: String,
    pub environment_trace: Vec<String>,
    pub fault_trace: Vec<Option<String>>,
    pub action_equivalent_premise: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceRecord {
    pub candidate: u32,
    pub scenario: u32,
    pub accepted: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QbfSemanticsMetadata {
    pub schema_version: String,
    pub quantifier_layout: QuantifierLayout,
    pub quantifier_prefix: String,
    pub non_production_mutant: bool,
    pub seed: u64,
    pub bounds: QbfFiniteBounds,
    pub hard_obligations: Vec<String>,
    pub candidates: Vec<CandidateRecord>,
    pub scenarios: Vec<ScenarioRecord>,
    pub acceptance: Vec<AcceptanceRecord>,
    pub acceptance_matrix_sha256: String,
    pub qdimacs_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QbfCompilation {
    pub spec: QdimacsSpec,
    pub qdimacs: QdimacsArtifact,
    pub metadata: QbfSemanticsMetadata,
}

/// A bounded truth result with only the outer machine-choice assignment exposed.
///
/// Universal trace values and dependent witnesses are deliberately excluded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QbfReferenceModel {
    pub truth: bool,
    pub candidate_id: Option<u32>,
    pub machine_choice_literals: Vec<i32>,
}

#[derive(Debug, Error)]
pub enum QbfCompileError {
    #[error("invalid synthesis problem: {0}")]
    Problem(#[from] ProblemError),
    #[error("invalid QDIMACS output: {0}")]
    Qdimacs(#[from] QdimacsError),
    #[error("QBF bound must be positive: {0}")]
    EmptyBound(&'static str),
    #[error("action-equivalence premise is vacuous")]
    VacuousActionEquivalence,
    #[error("environment/fault trace domain is empty")]
    EmptyTraceDomain,
    #[error("bounded domain {domain} exceeds limit {limit}")]
    DomainLimit { domain: &'static str, limit: u64 },
    #[error("bounded domain arithmetic overflow: {0}")]
    ArithmeticOverflow(&'static str),
    #[error("bounded candidate domain is empty")]
    EmptyCandidateDomain,
    #[error("internal bounded semantics invariant failed: {0}")]
    InternalInvariant(&'static str),
    #[error("truth evaluator variable limit exceeded: {variables} > {limit}")]
    TruthVariableLimit { variables: usize, limit: usize },
    #[error("could not serialize QBF semantics metadata: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("could not write QBF semantics artifact: {0}")]
    Io(#[from] std::io::Error),
}

impl QbfCompilation {
    pub fn metadata_json_bytes(&self) -> Result<Vec<u8>, QbfCompileError> {
        let mut bytes = serde_json::to_vec_pretty(&self.metadata)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    pub fn write_to_directory(&self, directory: &Path) -> Result<(), QbfCompileError> {
        fs::create_dir_all(directory)?;
        self.qdimacs
            .write_to_directory(&directory.join("qdimacs"))?;
        fs::write(
            directory.join("semantics.json"),
            self.metadata_json_bytes()?,
        )?;
        Ok(())
    }
}

/// Compile the bounded AQRS game using the production quantifier prefix.
pub fn compile_bounded_safety_game(
    problem: &SynthesisProblem,
    limits: QbfCompileLimits,
) -> Result<QbfCompilation, QbfCompileError> {
    compile_with_layout(problem, limits, QuantifierLayout::MachineBeforeTrace)
}

/// Build the intentionally unsound `forall trace. exists machine` fixture.
///
/// This function exists only for regression tests and falsification artifacts.
/// Its metadata is permanently marked `non_production_mutant`.
pub fn compile_quantifier_order_mutant_fixture(
    problem: &SynthesisProblem,
    limits: QbfCompileLimits,
) -> Result<QbfCompilation, QbfCompileError> {
    compile_with_layout(problem, limits, QuantifierLayout::MachineAfterTraceMutant)
}

/// Evaluate a small symbolic QBF independently of the AQRS transition evaluator.
///
/// This is exponential by design and refuses formulas over `max_variables`.
pub fn evaluate_qbf_truth(
    spec: &QdimacsSpec,
    max_variables: usize,
) -> Result<bool, QbfCompileError> {
    let artifact = encode_qdimacs(spec)?;
    let variable_count = artifact.metadata.variables.len();
    if variable_count > max_variables {
        return Err(QbfCompileError::TruthVariableLimit {
            variables: variable_count,
            limit: max_variables,
        });
    }

    let ids = artifact
        .metadata
        .variables
        .iter()
        .map(|record| {
            (
                VariableKey::new(record.role, record.coordinates.clone()),
                usize::try_from(record.id - 1).unwrap_or(usize::MAX),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let quantifiers = artifact
        .metadata
        .variables
        .iter()
        .map(|record| quantifier_for_role(record.role))
        .collect::<Vec<_>>();
    let clauses = spec
        .clauses
        .iter()
        .map(|clause| {
            clause
                .literals
                .iter()
                .map(|literal| {
                    ids.get(&literal.variable)
                        .copied()
                        .map(|id| (id, literal.positive))
                        .ok_or(QbfCompileError::InternalInvariant(
                            "truth clause references an unregistered variable",
                        ))
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut assignment = vec![None; variable_count];
    Ok(evaluate_quantified(
        0,
        &quantifiers,
        &clauses,
        &mut assignment,
    ))
}

/// Evaluate a compiled bounded game and extract its outer one-hot machine choice.
///
/// This reference path is exponential and intended only for small differential
/// tests. The selected candidate is derived from the frozen acceptance matrix
/// after the QDIMACS truth evaluator has independently established the decision.
pub fn evaluate_qbf_reference_model(
    compilation: &QbfCompilation,
    max_variables: usize,
) -> Result<QbfReferenceModel, QbfCompileError> {
    let truth = evaluate_qbf_truth(&compilation.spec, max_variables)?;
    let scenario_count = compilation.metadata.scenarios.len();
    let candidate_id = compilation
        .metadata
        .candidates
        .iter()
        .find(|candidate| {
            let rows = compilation
                .metadata
                .acceptance
                .iter()
                .filter(|row| row.candidate == candidate.id)
                .collect::<Vec<_>>();
            rows.len() == scenario_count && rows.iter().all(|row| row.accepted)
        })
        .map(|candidate| candidate.id);

    if truth != candidate_id.is_some() {
        return Err(QbfCompileError::InternalInvariant(
            "QDIMACS truth and frozen acceptance matrix disagree",
        ));
    }

    let mut selected = 0_usize;
    let mut machine_choice_literals = Vec::new();
    for variable in &compilation.qdimacs.metadata.variables {
        if variable.role != VariableRole::MachineChoice {
            continue;
        }
        let variable_id = i32::try_from(variable.id)
            .map_err(|_| QbfCompileError::ArithmeticOverflow("QDIMACS variable id"))?;
        let is_selected = candidate_id
            .zip(variable.coordinates.first().copied())
            .is_some_and(|(candidate, coordinate)| candidate == coordinate);
        if is_selected {
            selected += 1;
            machine_choice_literals.push(variable_id);
        } else {
            machine_choice_literals.push(-variable_id);
        }
    }
    if truth && selected != 1 {
        return Err(QbfCompileError::InternalInvariant(
            "reference model is not a one-hot machine choice",
        ));
    }

    Ok(QbfReferenceModel {
        truth,
        candidate_id,
        machine_choice_literals,
    })
}

fn compile_with_layout(
    problem: &SynthesisProblem,
    limits: QbfCompileLimits,
    layout: QuantifierLayout,
) -> Result<QbfCompilation, QbfCompileError> {
    validate_compile_inputs(problem, limits)?;
    problem.validate()?;

    let candidates = enumerate_candidates(problem, limits)?;
    if candidates.is_empty() {
        return Err(QbfCompileError::EmptyCandidateDomain);
    }
    let scenarios = enumerate_scenarios(problem, limits.max_scenarios)?;
    if scenarios.is_empty() {
        return Err(QbfCompileError::VacuousActionEquivalence);
    }

    let mut acceptance = Vec::with_capacity(candidates.len().saturating_mul(scenarios.len()));
    for candidate in &candidates {
        for scenario in &scenarios {
            acceptance.push(evaluate_scenario(problem, candidate, scenario)?);
        }
    }

    let spec = build_qdimacs_spec(
        problem,
        limits,
        layout,
        &candidates,
        &scenarios,
        &acceptance,
    )?;
    let qdimacs = encode_qdimacs(&spec)?;
    let metadata = build_metadata(
        problem,
        limits,
        layout,
        &candidates,
        &scenarios,
        &acceptance,
        &qdimacs,
    )?;
    Ok(QbfCompilation {
        spec,
        qdimacs,
        metadata,
    })
}

fn validate_compile_inputs(
    problem: &SynthesisProblem,
    limits: QbfCompileLimits,
) -> Result<(), QbfCompileError> {
    if limits.max_machine_states == 0 {
        return Err(QbfCompileError::EmptyBound("max_machine_states"));
    }
    if limits.max_table_assignments == 0 {
        return Err(QbfCompileError::EmptyBound("max_table_assignments"));
    }
    if limits.max_candidates == 0 {
        return Err(QbfCompileError::EmptyBound("max_candidates"));
    }
    if limits.max_scenarios == 0 {
        return Err(QbfCompileError::EmptyBound("max_scenarios"));
    }
    if problem.initial_pairs.is_empty() {
        return Err(QbfCompileError::VacuousActionEquivalence);
    }
    if problem.inputs.is_empty() {
        return Err(QbfCompileError::EmptyTraceDomain);
    }
    Ok(())
}

fn enumerate_candidates(
    problem: &SynthesisProblem,
    limits: QbfCompileLimits,
) -> Result<Vec<ReleaseMachine>, QbfCompileError> {
    let output_count = u64::try_from(problem.outputs.len())
        .map_err(|_| QbfCompileError::ArithmeticOverflow("outputs"))?;
    let symbol_count = u64::from(problem.machine_symbol_count);
    let mut visited_assignments = 0_u64;
    let mut candidates = Vec::new();

    for state_count in 1..=limits.max_machine_states {
        let cell_count = u64::from(state_count)
            .checked_mul(symbol_count)
            .ok_or(QbfCompileError::ArithmeticOverflow("machine table cells"))?;
        let decision_count = u64::from(state_count)
            .checked_mul(output_count)
            .ok_or(QbfCompileError::ArithmeticOverflow("machine decisions"))?;
        let assignments = checked_pow(decision_count, cell_count)?;
        visited_assignments = visited_assignments
            .checked_add(assignments)
            .ok_or(QbfCompileError::ArithmeticOverflow("table assignments"))?;
        if visited_assignments > limits.max_table_assignments {
            return Err(QbfCompileError::DomainLimit {
                domain: "table_assignments",
                limit: limits.max_table_assignments,
            });
        }

        for ordinal in 0..assignments {
            let mut value = ordinal;
            let mut cells = Vec::with_capacity(
                usize::try_from(cell_count)
                    .map_err(|_| QbfCompileError::ArithmeticOverflow("machine table cells"))?,
            );
            for _ in 0..cell_count {
                let decision = value % decision_count;
                value /= decision_count;
                cells.push(MachineCell {
                    next_state: u32::try_from(decision / output_count)
                        .map_err(|_| QbfCompileError::ArithmeticOverflow("machine next state"))?,
                    output: u32::try_from(decision % output_count)
                        .map_err(|_| QbfCompileError::ArithmeticOverflow("machine output"))?,
                });
            }
            let machine = ReleaseMachine {
                state_count,
                symbol_count: problem.machine_symbol_count,
                cells,
            };
            if machine
                .validate(problem.machine_symbol_count, problem.outputs.len())
                .is_ok()
            {
                candidates.push(machine);
                if candidates.len() > limits.max_candidates {
                    return Err(QbfCompileError::DomainLimit {
                        domain: "candidates",
                        limit: u64::try_from(limits.max_candidates).unwrap_or(u64::MAX),
                    });
                }
            }
        }
    }

    let mut keyed = candidates
        .into_iter()
        .map(|machine| (machine.canonical_bytes(), machine))
        .collect::<Vec<_>>();
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    keyed.dedup_by(|left, right| left.0 == right.0);
    Ok(keyed.into_iter().map(|(_, machine)| machine).collect())
}

fn checked_pow(base: u64, exponent: u64) -> Result<u64, QbfCompileError> {
    let mut value = 1_u64;
    for _ in 0..exponent {
        value = value
            .checked_mul(base)
            .ok_or(QbfCompileError::ArithmeticOverflow(
                "bounded exponentiation",
            ))?;
    }
    Ok(value)
}

#[derive(Clone, Debug)]
struct Scenario {
    id: u32,
    initial_pair: usize,
    left: u32,
    right: u32,
    inputs: Vec<usize>,
}

fn enumerate_scenarios(
    problem: &SynthesisProblem,
    max_scenarios: usize,
) -> Result<Vec<Scenario>, QbfCompileError> {
    let horizon = usize::try_from(problem.horizon)
        .map_err(|_| QbfCompileError::ArithmeticOverflow("horizon"))?;
    let mut trace_count = 1_usize;
    for _ in 0..horizon {
        trace_count = trace_count
            .checked_mul(problem.inputs.len())
            .ok_or(QbfCompileError::ArithmeticOverflow("trace domain"))?;
    }
    let scenario_count = trace_count
        .checked_mul(problem.initial_pairs.len())
        .ok_or(QbfCompileError::ArithmeticOverflow("scenario domain"))?;
    if scenario_count > max_scenarios {
        return Err(QbfCompileError::DomainLimit {
            domain: "scenarios",
            limit: u64::try_from(max_scenarios).unwrap_or(u64::MAX),
        });
    }

    let mut scenarios = Vec::with_capacity(scenario_count);
    for (pair_index, pair) in problem.initial_pairs.iter().enumerate() {
        for ordinal in 0..trace_count {
            let mut value = ordinal;
            let mut inputs = vec![0; horizon];
            for slot in (0..horizon).rev() {
                inputs[slot] = value % problem.inputs.len();
                value /= problem.inputs.len();
            }
            scenarios.push(Scenario {
                id: u32::try_from(scenarios.len())
                    .map_err(|_| QbfCompileError::ArithmeticOverflow("scenario id"))?,
                initial_pair: pair_index,
                left: pair.left,
                right: pair.right,
                inputs,
            });
        }
    }
    Ok(scenarios)
}

#[derive(Clone, Debug)]
struct RuntimeObligation {
    action: ActionId,
    trigger_slot: u32,
    deadline_slot: u32,
    emitted: bool,
}

#[derive(Clone, Debug)]
struct UtilityTracker {
    obligations: BTreeMap<ObligationRef, RuntimeObligation>,
}

#[derive(Clone, Debug)]
struct RuntimeSide {
    plant: u32,
    machine: u32,
    utility: UtilityTracker,
}

fn evaluate_scenario(
    problem: &SynthesisProblem,
    machine: &ReleaseMachine,
    scenario: &Scenario,
) -> Result<bool, QbfCompileError> {
    let left_semantic = semantic_for_plant(problem, scenario.left)?;
    let right_semantic = semantic_for_plant(problem, scenario.right)?;
    if left_semantic.id != right_semantic.id {
        return Err(QbfCompileError::InternalInvariant(
            "initial pair is not action-equivalent",
        ));
    }

    let mut left = RuntimeSide {
        plant: scenario.left,
        machine: 0,
        utility: utility_for_semantic(left_semantic),
    };
    let mut right = RuntimeSide {
        plant: scenario.right,
        machine: 0,
        utility: utility_for_semantic(right_semantic),
    };

    for (slot, input_index) in scenario.inputs.iter().copied().enumerate() {
        let slot =
            u32::try_from(slot).map_err(|_| QbfCompileError::ArithmeticOverflow("trace slot"))?;
        let input = problem
            .inputs
            .get(input_index)
            .ok_or(QbfCompileError::InternalInvariant("scenario input"))?;
        let left_transition = plant_transition(problem, left.plant, input_index)?;
        let right_transition = plant_transition(problem, right.plant, input_index)?;
        let left_cell = machine.cell(left.machine, left_transition.machine_symbol);
        let right_cell = machine.cell(right.machine, right_transition.machine_symbol);
        let left_release = problem
            .outputs
            .get(usize::try_from(left_cell.output).unwrap_or(usize::MAX))
            .ok_or(QbfCompileError::InternalInvariant("left output"))?;
        let right_release = problem
            .outputs
            .get(usize::try_from(right_cell.output).unwrap_or(usize::MAX))
            .ok_or(QbfCompileError::InternalInvariant("right output"))?;

        if problem
            .observers
            .iter()
            .any(|observer| !observations_equal(observer, left_release, right_release))
        {
            return Ok(false);
        }

        activate_recovery(&mut left.utility, input, slot, &problem.faults)?;
        activate_recovery(&mut right.utility, input, slot, &problem.faults)?;
        if !utility_accepts(&mut left.utility, left_release, slot)
            || !utility_accepts(&mut right.utility, right_release, slot)
        {
            return Ok(false);
        }

        left.plant = left_transition.to;
        right.plant = right_transition.to;
        left.machine = left_cell.next_state;
        right.machine = right_cell.next_state;
        let left_next = semantic_for_plant(problem, left.plant)?;
        let right_next = semantic_for_plant(problem, right.plant)?;
        if left_next.id != right_next.id {
            return Ok(true);
        }
        add_semantic_obligations(&mut left.utility, left_next);
        add_semantic_obligations(&mut right.utility, right_next);
    }
    Ok(true)
}

fn plant_transition(
    problem: &SynthesisProblem,
    state: u32,
    input: usize,
) -> Result<&quotient_forge_synth::PlantTransition, QbfCompileError> {
    let state =
        usize::try_from(state).map_err(|_| QbfCompileError::ArithmeticOverflow("plant state"))?;
    problem
        .plant_transitions
        .get(
            state
                .saturating_mul(problem.inputs.len())
                .saturating_add(input),
        )
        .ok_or(QbfCompileError::InternalInvariant("plant transition"))
}

fn semantic_for_plant(
    problem: &SynthesisProblem,
    plant: u32,
) -> Result<&SemanticContract, QbfCompileError> {
    let state = problem
        .plant_states
        .get(usize::try_from(plant).unwrap_or(usize::MAX))
        .ok_or(QbfCompileError::InternalInvariant("plant state"))?;
    problem
        .semantics
        .iter()
        .find(|semantic| semantic.id == state.action_semantics)
        .ok_or(QbfCompileError::InternalInvariant("plant semantics"))
}

fn utility_for_semantic(semantic: &SemanticContract) -> UtilityTracker {
    let mut tracker = UtilityTracker {
        obligations: BTreeMap::new(),
    };
    add_semantic_obligations(&mut tracker, semantic);
    tracker
}

fn add_semantic_obligations(tracker: &mut UtilityTracker, semantic: &SemanticContract) {
    for obligation in &semantic.obligations {
        tracker
            .obligations
            .entry(ObligationRef::Authorized(obligation.id.clone()))
            .or_insert_with(|| RuntimeObligation {
                action: obligation.action.clone(),
                trigger_slot: obligation.trigger_slot,
                deadline_slot: obligation.deadline_slot,
                emitted: false,
            });
    }
}

fn activate_recovery(
    tracker: &mut UtilityTracker,
    input: &EnvironmentInput,
    slot: u32,
    faults: &[FaultInput],
) -> Result<(), QbfCompileError> {
    let Some(fault_id) = &input.fault else {
        return Ok(());
    };
    let fault = faults
        .iter()
        .find(|fault| &fault.id == fault_id)
        .ok_or(QbfCompileError::InternalInvariant("fault input"))?;
    let Some(recovery) = &fault.recovery else {
        return Ok(());
    };
    tracker.obligations.insert(
        ObligationRef::Recovery {
            fault: fault_id.clone(),
            triggered_at: slot,
        },
        RuntimeObligation {
            action: recovery.action.clone(),
            trigger_slot: slot,
            deadline_slot: slot.saturating_add(recovery.deadline_after_slots),
            emitted: false,
        },
    );
    Ok(())
}

fn utility_accepts(tracker: &mut UtilityTracker, release: &Release, slot: u32) -> bool {
    for emission in &release.actions {
        let Some(obligation) = tracker.obligations.get_mut(&emission.obligation) else {
            return false;
        };
        if obligation.emitted
            || obligation.action != emission.action
            || slot < obligation.trigger_slot
            || slot > obligation.deadline_slot
        {
            return false;
        }
        obligation.emitted = true;
    }
    tracker
        .obligations
        .values()
        .all(|obligation| obligation.emitted || obligation.deadline_slot > slot)
}

fn observations_equal(observer: &Observer, left: &Release, right: &Release) -> bool {
    if left.emitted != right.emitted {
        return false;
    }
    if !left.emitted {
        return true;
    }
    if observer
        .visible_fields
        .iter()
        .any(|field| left.fields.get(field) != right.fields.get(field))
    {
        return false;
    }
    !observer.observes_actions || left.actions == right.actions
}

fn build_qdimacs_spec(
    problem: &SynthesisProblem,
    limits: QbfCompileLimits,
    layout: QuantifierLayout,
    candidates: &[ReleaseMachine],
    scenarios: &[Scenario],
    acceptance: &[bool],
) -> Result<QdimacsSpec, QbfCompileError> {
    let candidate_role = match layout {
        QuantifierLayout::MachineBeforeTrace => VariableRole::MachineChoice,
        QuantifierLayout::MachineAfterTraceMutant => VariableRole::DependentWitness,
    };
    let candidate_variables = (0..candidates.len())
        .map(|candidate| {
            Ok(VariableKey::new(
                candidate_role,
                vec![to_u32(candidate, "candidate variable")?],
            ))
        })
        .collect::<Result<Vec<_>, QbfCompileError>>()?;
    let (universal_variables, scenario_assignments) = scenario_variables(problem, scenarios)?;
    let witness_variables = (0..candidates.len())
        .flat_map(|candidate| (0..scenarios.len()).map(move |scenario| (candidate, scenario)))
        .map(|(candidate, scenario)| {
            Ok(VariableKey::new(
                VariableRole::DependentWitness,
                vec![
                    1,
                    to_u32(candidate, "witness candidate")?,
                    to_u32(scenario, "witness scenario")?,
                ],
            ))
        })
        .collect::<Result<Vec<_>, QbfCompileError>>()?;

    let dummy_machine = VariableKey::new(VariableRole::MachineChoice, vec![1_000_000_000]);
    let mut variables = Vec::new();
    if layout == QuantifierLayout::MachineAfterTraceMutant {
        variables.push(dummy_machine.clone());
    }
    variables.extend(candidate_variables.iter().cloned());
    variables.extend(universal_variables.iter().cloned());
    variables.extend(witness_variables.iter().cloned());

    let mut clauses = Vec::new();
    if layout == QuantifierLayout::MachineAfterTraceMutant {
        clauses.push(SymbolicClause {
            literals: vec![SymbolicLiteral::positive(dummy_machine)],
        });
    }
    clauses.push(SymbolicClause {
        literals: candidate_variables
            .iter()
            .cloned()
            .map(SymbolicLiteral::positive)
            .collect(),
    });
    for left in 0..candidate_variables.len() {
        for right in left + 1..candidate_variables.len() {
            clauses.push(SymbolicClause {
                literals: vec![
                    SymbolicLiteral::negative(candidate_variables[left].clone()),
                    SymbolicLiteral::negative(candidate_variables[right].clone()),
                ],
            });
        }
    }

    for (candidate, candidate_variable) in candidate_variables.iter().enumerate() {
        for (scenario, expected_true) in scenario_assignments.iter().enumerate() {
            let matrix_index = candidate
                .checked_mul(scenarios.len())
                .and_then(|value| value.checked_add(scenario))
                .ok_or(QbfCompileError::ArithmeticOverflow("acceptance matrix"))?;
            let witness = witness_variables[matrix_index].clone();
            if !acceptance[matrix_index] {
                clauses.push(SymbolicClause {
                    literals: vec![SymbolicLiteral::negative(witness.clone())],
                });
            }
            let mut literals = vec![SymbolicLiteral::negative(candidate_variable.clone())];
            literals.extend(universal_variables.iter().cloned().map(|variable| {
                if expected_true.contains(&variable) {
                    SymbolicLiteral::negative(variable)
                } else {
                    SymbolicLiteral::positive(variable)
                }
            }));
            literals.push(SymbolicLiteral::positive(witness));
            clauses.push(SymbolicClause { literals });
        }
    }

    Ok(QdimacsSpec {
        bounds: QdimacsBounds {
            plant_states: to_u32(problem.plant_states.len(), "plant states")?,
            machine_states: limits.max_machine_states,
            horizon: problem.horizon,
            action_count: to_u32(problem.outputs.len(), "outputs")?,
        },
        seed: limits.seed,
        variables,
        clauses,
    })
}

fn scenario_variables(
    problem: &SynthesisProblem,
    scenarios: &[Scenario],
) -> Result<(Vec<VariableKey>, Vec<BTreeSet<VariableKey>>), QbfCompileError> {
    let mut universe = BTreeSet::new();
    let mut assignments = Vec::with_capacity(scenarios.len());
    for scenario in scenarios {
        let mut active = BTreeSet::new();
        active.insert(VariableKey::new(
            VariableRole::PrivateHistoryLeft,
            vec![scenario.id, scenario.left],
        ));
        active.insert(VariableKey::new(
            VariableRole::PrivateHistoryRight,
            vec![scenario.id, scenario.right],
        ));
        for (slot, input_index) in scenario.inputs.iter().copied().enumerate() {
            let input = &problem.inputs[input_index];
            active.insert(VariableKey::new(
                VariableRole::EnvironmentTrace,
                vec![
                    scenario.id,
                    to_u32(slot, "environment slot")?,
                    to_u32(input_index, "environment input")?,
                ],
            ));
            active.insert(VariableKey::new(
                VariableRole::FaultTrace,
                vec![
                    scenario.id,
                    to_u32(slot, "fault slot")?,
                    fault_code(&problem.faults, input.fault.as_ref())?,
                ],
            ));
        }
        universe.extend(active.iter().cloned());
        assignments.push(active);
    }
    Ok((universe.into_iter().collect(), assignments))
}

fn fault_code(
    faults: &[FaultInput],
    selected: Option<&FaultInputId>,
) -> Result<u32, QbfCompileError> {
    let Some(selected) = selected else {
        return Ok(0);
    };
    faults
        .iter()
        .position(|fault| &fault.id == selected)
        .map(|index| to_u32(index + 1, "fault input"))
        .transpose()?
        .ok_or(QbfCompileError::InternalInvariant("fault selector"))
}

fn build_metadata(
    problem: &SynthesisProblem,
    limits: QbfCompileLimits,
    layout: QuantifierLayout,
    candidates: &[ReleaseMachine],
    scenarios: &[Scenario],
    acceptance: &[bool],
    qdimacs: &QdimacsArtifact,
) -> Result<QbfSemanticsMetadata, QbfCompileError> {
    let candidate_records = candidates
        .iter()
        .enumerate()
        .map(|(id, machine)| {
            let cells = machine
                .cells
                .iter()
                .enumerate()
                .map(|(index, cell)| CandidateCellRecord {
                    machine_state: u32::try_from(index).unwrap_or(u32::MAX) / machine.symbol_count,
                    symbol: u32::try_from(index).unwrap_or(u32::MAX) % machine.symbol_count,
                    next_state: cell.next_state,
                    output: cell.output,
                })
                .collect();
            Ok(CandidateRecord {
                id: to_u32(id, "candidate id")?,
                state_count: machine.state_count,
                symbol_count: machine.symbol_count,
                canonical_sha256: sha256_hex(&machine.canonical_bytes()),
                cells,
            })
        })
        .collect::<Result<Vec<_>, QbfCompileError>>()?;
    let scenario_records = scenarios
        .iter()
        .map(|scenario| {
            let left = &problem.plant_states[usize::try_from(scenario.left).unwrap_or(usize::MAX)];
            let right =
                &problem.plant_states[usize::try_from(scenario.right).unwrap_or(usize::MAX)];
            ScenarioRecord {
                id: scenario.id,
                initial_pair: u32::try_from(scenario.initial_pair).unwrap_or(u32::MAX),
                left_plant_state: scenario.left,
                right_plant_state: scenario.right,
                left_private_history: left.private_history.as_str().to_owned(),
                right_private_history: right.private_history.as_str().to_owned(),
                environment_trace: scenario
                    .inputs
                    .iter()
                    .map(|input| problem.inputs[*input].id.as_str().to_owned())
                    .collect(),
                fault_trace: scenario
                    .inputs
                    .iter()
                    .map(|input| {
                        problem.inputs[*input]
                            .fault
                            .as_ref()
                            .map(|fault| fault.as_str().to_owned())
                    })
                    .collect(),
                action_equivalent_premise: left.action_semantics == right.action_semantics
                    && left.private_history != right.private_history,
            }
        })
        .collect::<Vec<_>>();
    let acceptance_records = acceptance
        .iter()
        .enumerate()
        .map(|(index, accepted)| AcceptanceRecord {
            candidate: u32::try_from(index / scenarios.len()).unwrap_or(u32::MAX),
            scenario: u32::try_from(index % scenarios.len()).unwrap_or(u32::MAX),
            accepted: *accepted,
        })
        .collect();
    let matrix_bytes = acceptance
        .iter()
        .map(|accepted| u8::from(*accepted))
        .collect::<Vec<_>>();
    let quantifier_prefix = match layout {
        QuantifierLayout::MachineBeforeTrace => {
            "exists machine; forall private/environment/fault trace; exists witness"
        }
        QuantifierLayout::MachineAfterTraceMutant => {
            "exists dummy; forall private/environment/fault trace; exists machine/witness"
        }
    };
    Ok(QbfSemanticsMetadata {
        schema_version: QBF_SEMANTICS_SCHEMA_V1.to_owned(),
        quantifier_layout: layout,
        quantifier_prefix: quantifier_prefix.to_owned(),
        non_production_mutant: layout == QuantifierLayout::MachineAfterTraceMutant,
        seed: limits.seed,
        bounds: QbfFiniteBounds {
            plant_states: to_u32(problem.plant_states.len(), "plant states")?,
            machine_states: limits.max_machine_states,
            machine_symbols: problem.machine_symbol_count,
            horizon: problem.horizon,
            outputs: to_u32(problem.outputs.len(), "outputs")?,
            candidates: to_u32(candidates.len(), "candidates")?,
            scenarios: to_u32(scenarios.len(), "scenarios")?,
        },
        hard_obligations: vec![
            "action_equivalence_premise".to_owned(),
            "complete_observer_trace_equality".to_owned(),
            "authorized_action".to_owned(),
            "exactly_once".to_owned(),
            "deadline".to_owned(),
            "public_retry".to_owned(),
            "reconnect".to_owned(),
            "fault_recovery".to_owned(),
        ],
        candidates: candidate_records,
        scenarios: scenario_records,
        acceptance: acceptance_records,
        acceptance_matrix_sha256: sha256_hex(&matrix_bytes),
        qdimacs_sha256: qdimacs.metadata.qdimacs_sha256.clone(),
    })
}

fn evaluate_quantified(
    index: usize,
    quantifiers: &[QuantifierKind],
    clauses: &[Vec<(usize, bool)>],
    assignment: &mut [Option<bool>],
) -> bool {
    if has_false_clause(clauses, assignment) {
        return false;
    }
    if index == quantifiers.len() {
        return true;
    }
    match quantifiers[index] {
        QuantifierKind::Existential => {
            assignment[index] = Some(false);
            if evaluate_quantified(index + 1, quantifiers, clauses, assignment) {
                assignment[index] = None;
                return true;
            }
            assignment[index] = Some(true);
            let result = evaluate_quantified(index + 1, quantifiers, clauses, assignment);
            assignment[index] = None;
            result
        }
        QuantifierKind::Universal => {
            assignment[index] = Some(false);
            if !evaluate_quantified(index + 1, quantifiers, clauses, assignment) {
                assignment[index] = None;
                return false;
            }
            assignment[index] = Some(true);
            let result = evaluate_quantified(index + 1, quantifiers, clauses, assignment);
            assignment[index] = None;
            result
        }
    }
}

fn has_false_clause(clauses: &[Vec<(usize, bool)>], assignment: &[Option<bool>]) -> bool {
    clauses.iter().any(|clause| {
        let mut unresolved = false;
        for (variable, positive) in clause {
            match assignment[*variable] {
                Some(value) if value == *positive => return false,
                Some(_) => {}
                None => unresolved = true,
            }
        }
        !unresolved
    })
}

const fn quantifier_for_role(role: VariableRole) -> QuantifierKind {
    match role {
        VariableRole::MachineChoice | VariableRole::DependentWitness => QuantifierKind::Existential,
        VariableRole::PrivateHistoryLeft
        | VariableRole::PrivateHistoryRight
        | VariableRole::EnvironmentTrace
        | VariableRole::FaultTrace => QuantifierKind::Universal,
    }
}

fn to_u32(value: usize, domain: &'static str) -> Result<u32, QbfCompileError> {
    u32::try_from(value).map_err(|_| QbfCompileError::ArithmeticOverflow(domain))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
