use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use crate::counterexample::{
    CausalField, Counterexample, CounterexampleKind, Observation, RepairCandidate, Side, TraceStep,
};
use crate::model::{
    ActionId, CheckerModel, EnvironmentInput, FaultInput, FaultInputId, InputId, ModelError,
    ObligationRef, Observer, Release, SemanticContract, SemanticId, State, StateId, Transition,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckLimits {
    pub max_nodes: usize,
    pub max_depth: u32,
    pub time_limit: Duration,
}

impl Default for CheckLimits {
    fn default() -> Self {
        Self {
            max_nodes: 100_000,
            max_depth: 1_024,
            time_limit: Duration::from_secs(30),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedReport {
    pub explored_nodes: usize,
    pub reached_depth: u32,
    pub checked_horizon: u32,
    pub initial_pairs: usize,
    pub observers: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InconclusiveReason {
    NodeLimit { limit: usize },
    DepthLimit { limit: u32 },
    TimeLimit { millis: u128 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InconclusiveReport {
    pub reason: InconclusiveReason,
    pub explored_nodes: usize,
    pub discovered_nodes: usize,
    pub frontier_nodes: usize,
    pub reached_depth: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CheckOutcome {
    Verified(VerifiedReport),
    Counterexample(Box<Counterexample>),
    Inconclusive(InconclusiveReport),
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct RuntimeObligation {
    action: ActionId,
    trigger_slot: u32,
    deadline_slot: u32,
    emitted: bool,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct UtilityTracker {
    obligations: BTreeMap<ObligationRef, RuntimeObligation>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ProductNode {
    left: StateId,
    right: StateId,
    slot: u32,
    left_utility: UtilityTracker,
    right_utility: UtilityTracker,
}

#[derive(Clone, Debug)]
struct ParentRecord {
    previous: ProductNode,
    step: TraceStep,
}

#[derive(Clone, Debug)]
enum UtilityFailure {
    Unauthorized {
        action: ActionId,
        obligation: ObligationRef,
    },
    Duplicate {
        action: ActionId,
        obligation: ObligationRef,
    },
    Deadline {
        action: ActionId,
        obligation: ObligationRef,
    },
    Recovery {
        action: ActionId,
        obligation: ObligationRef,
    },
}

pub fn check(model: &CheckerModel, limits: CheckLimits) -> Result<CheckOutcome, ModelError> {
    model.validate()?;

    if limits.max_nodes == 0 {
        return Ok(CheckOutcome::Inconclusive(InconclusiveReport {
            reason: InconclusiveReason::NodeLimit { limit: 0 },
            explored_nodes: 0,
            discovered_nodes: 0,
            frontier_nodes: model.initial_pairs.len(),
            reached_depth: 0,
        }));
    }

    let started = Instant::now();
    let states = model.state_index();
    let semantics = model.semantic_index();
    let faults = model.fault_index();
    let transitions = model.transition_index();
    let mut inputs: Vec<_> = model.inputs.iter().collect();
    inputs.sort_by(|left, right| left.id.cmp(&right.id));
    let mut observers: Vec<_> = model.observers.iter().collect();
    observers.sort_by(|left, right| left.id.cmp(&right.id));

    let mut queue = VecDeque::new();
    let mut discovered = HashSet::new();
    let mut predecessors = HashMap::new();
    for pair in &model.initial_pairs {
        let semantic = &states[&pair.left].action_semantics;
        let utility = utility_for_semantic(semantics[semantic]);
        let root = ProductNode {
            left: pair.left.clone(),
            right: pair.right.clone(),
            slot: 0,
            left_utility: utility.clone(),
            right_utility: utility,
        };
        if discovered.insert(root.clone()) {
            if discovered.len() > limits.max_nodes {
                return Ok(node_limit_report(
                    limits.max_nodes,
                    0,
                    discovered.len(),
                    queue.len() + 1,
                    0,
                ));
            }
            queue.push_back(root);
        }
    }

    let mut explored = 0;
    let mut reached_depth = 0;
    let mut depth_truncated = false;

    while let Some(node) = queue.pop_front() {
        if started.elapsed() >= limits.time_limit {
            return Ok(time_limit_report(
                limits.time_limit,
                explored,
                discovered.len(),
                queue.len() + 1,
                reached_depth,
            ));
        }
        explored += 1;
        reached_depth = reached_depth.max(node.slot);

        if node.slot >= model.horizon {
            continue;
        }
        if node.slot >= limits.max_depth {
            depth_truncated = true;
            continue;
        }

        for input in &inputs {
            if started.elapsed() >= limits.time_limit {
                return Ok(time_limit_report(
                    limits.time_limit,
                    explored,
                    discovered.len(),
                    queue.len() + 1,
                    reached_depth,
                ));
            }

            let left_transition = transitions[&(node.left.clone(), input.id.clone())];
            let right_transition = transitions[&(node.right.clone(), input.id.clone())];
            let step = trace_step(node.slot, &node, input, left_transition, right_transition);

            for observer in &observers {
                let left_observation = observe(observer, &left_transition.release);
                let right_observation = observe(observer, &right_transition.release);
                if left_observation != right_observation {
                    let causal = first_causal_field(&left_observation, &right_observation);
                    let repairs = security_repairs(observer, causal.as_ref());
                    let mut trace = reconstruct_trace(&node, &predecessors);
                    trace.push(step);
                    return Ok(CheckOutcome::Counterexample(Box::new(Counterexample {
                        kind: CounterexampleKind::SecurityDivergence,
                        slot: node.slot,
                        observer: Some(observer.id.clone()),
                        left_observation: Some(left_observation),
                        right_observation: Some(right_observation),
                        causal_field: causal,
                        trace,
                        repair_candidates: repairs,
                    })));
                }
            }

            let mut left_utility = node.left_utility.clone();
            let mut right_utility = node.right_utility.clone();
            activate_recovery(&mut left_utility, input, node.slot, &faults);
            activate_recovery(&mut right_utility, input, node.slot, &faults);

            if let Some(failure) =
                evaluate_utility(&mut left_utility, &left_transition.release, node.slot)
            {
                return Ok(utility_counterexample(
                    failure,
                    Side::Left,
                    node.slot,
                    &node,
                    &predecessors,
                    step,
                ));
            }
            if let Some(failure) =
                evaluate_utility(&mut right_utility, &right_transition.release, node.slot)
            {
                return Ok(utility_counterexample(
                    failure,
                    Side::Right,
                    node.slot,
                    &node,
                    &predecessors,
                    step,
                ));
            }

            let left_next = states[&left_transition.to];
            let right_next = states[&right_transition.to];
            if left_next.action_semantics != right_next.action_semantics {
                continue;
            }
            add_semantic_obligations(&mut left_utility, semantics[&left_next.action_semantics]);
            add_semantic_obligations(&mut right_utility, semantics[&right_next.action_semantics]);

            let next = ProductNode {
                left: left_transition.to.clone(),
                right: right_transition.to.clone(),
                slot: node.slot + 1,
                left_utility,
                right_utility,
            };
            if discovered.contains(&next) {
                continue;
            }
            if discovered.len() >= limits.max_nodes {
                return Ok(node_limit_report(
                    limits.max_nodes,
                    explored,
                    discovered.len(),
                    queue.len() + 1,
                    reached_depth,
                ));
            }
            discovered.insert(next.clone());
            predecessors.insert(
                next.clone(),
                ParentRecord {
                    previous: node.clone(),
                    step,
                },
            );
            queue.push_back(next);
        }
    }

    if depth_truncated {
        return Ok(CheckOutcome::Inconclusive(InconclusiveReport {
            reason: InconclusiveReason::DepthLimit {
                limit: limits.max_depth,
            },
            explored_nodes: explored,
            discovered_nodes: discovered.len(),
            frontier_nodes: 0,
            reached_depth,
        }));
    }

    Ok(CheckOutcome::Verified(VerifiedReport {
        explored_nodes: explored,
        reached_depth,
        checked_horizon: model.horizon,
        initial_pairs: model.initial_pairs.len(),
        observers: model.observers.len(),
    }))
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
    faults: &BTreeMap<FaultInputId, &FaultInput>,
) {
    let Some(fault_id) = &input.fault else {
        return;
    };
    let Some(requirement) = &faults[fault_id].recovery else {
        return;
    };
    tracker.obligations.insert(
        ObligationRef::Recovery {
            fault: fault_id.clone(),
            triggered_at: slot,
        },
        RuntimeObligation {
            action: requirement.action.clone(),
            trigger_slot: slot,
            deadline_slot: slot.saturating_add(requirement.deadline_after_slots),
            emitted: false,
        },
    );
}

fn evaluate_utility(
    tracker: &mut UtilityTracker,
    release: &Release,
    slot: u32,
) -> Option<UtilityFailure> {
    for emission in &release.actions {
        let Some(obligation) = tracker.obligations.get_mut(&emission.obligation) else {
            return Some(UtilityFailure::Unauthorized {
                action: emission.action.clone(),
                obligation: emission.obligation.clone(),
            });
        };
        if obligation.emitted {
            return Some(UtilityFailure::Duplicate {
                action: emission.action.clone(),
                obligation: emission.obligation.clone(),
            });
        }
        if obligation.action != emission.action
            || slot < obligation.trigger_slot
            || slot > obligation.deadline_slot
        {
            return Some(UtilityFailure::Unauthorized {
                action: emission.action.clone(),
                obligation: emission.obligation.clone(),
            });
        }
        obligation.emitted = true;
    }

    for (reference, obligation) in &tracker.obligations {
        if !obligation.emitted && obligation.deadline_slot <= slot {
            return Some(match reference {
                ObligationRef::Authorized(_) => UtilityFailure::Deadline {
                    action: obligation.action.clone(),
                    obligation: reference.clone(),
                },
                ObligationRef::Recovery { .. } => UtilityFailure::Recovery {
                    action: obligation.action.clone(),
                    obligation: reference.clone(),
                },
            });
        }
    }
    None
}

fn observe(observer: &Observer, release: &Release) -> Observation {
    let fields = if release.emitted {
        release
            .fields
            .iter()
            .filter(|(field, _)| observer.visible_fields.contains(*field))
            .map(|(field, value)| (field.clone(), value.clone()))
            .collect()
    } else {
        BTreeMap::new()
    };
    let actions = if release.emitted && observer.observes_actions {
        release.actions.clone()
    } else {
        Vec::new()
    };
    Observation {
        emitted: release.emitted,
        fields,
        actions,
    }
}

fn first_causal_field(left: &Observation, right: &Observation) -> Option<CausalField> {
    if left.emitted != right.emitted {
        return Some(CausalField::ReleasePresence);
    }
    let fields: BTreeSet<_> = left.fields.keys().chain(right.fields.keys()).collect();
    for field in fields {
        if left.fields.get(field) != right.fields.get(field) {
            return Some(CausalField::Field(field.clone()));
        }
    }
    if left.actions != right.actions {
        return Some(CausalField::Actions);
    }
    None
}

fn security_repairs(observer: &Observer, causal: Option<&CausalField>) -> Vec<RepairCandidate> {
    match causal {
        Some(CausalField::ReleasePresence) => vec![RepairCandidate::EqualizeReleasePresence],
        Some(CausalField::Field(field)) => vec![
            RepairCandidate::NormalizeField(field.clone()),
            RepairCandidate::HideField {
                observer: observer.id.clone(),
                field: field.clone(),
            },
        ],
        Some(CausalField::Actions) => vec![RepairCandidate::NormalizeObservedActions],
        None => Vec::new(),
    }
}

fn trace_step(
    slot: u32,
    node: &ProductNode,
    input: &EnvironmentInput,
    left: &Transition,
    right: &Transition,
) -> TraceStep {
    TraceStep {
        slot,
        input: input.clone(),
        left_state: node.left.clone(),
        right_state: node.right.clone(),
        left_release: left.release.clone(),
        right_release: right.release.clone(),
    }
}

fn reconstruct_trace(
    node: &ProductNode,
    predecessors: &HashMap<ProductNode, ParentRecord>,
) -> Vec<TraceStep> {
    let mut cursor = node;
    let mut trace = Vec::new();
    while let Some(parent) = predecessors.get(cursor) {
        trace.push(parent.step.clone());
        cursor = &parent.previous;
    }
    trace.reverse();
    trace
}

fn utility_counterexample(
    failure: UtilityFailure,
    side: Side,
    slot: u32,
    node: &ProductNode,
    predecessors: &HashMap<ProductNode, ParentRecord>,
    step: TraceStep,
) -> CheckOutcome {
    let (kind, repairs) = match failure {
        UtilityFailure::Unauthorized { action, obligation } => (
            CounterexampleKind::UnauthorizedAction {
                side,
                action,
                obligation: obligation.clone(),
            },
            vec![RepairCandidate::BindAuthorizedAction(obligation)],
        ),
        UtilityFailure::Duplicate { action, obligation } => (
            CounterexampleKind::DuplicateAction {
                side,
                action,
                obligation: obligation.clone(),
            },
            vec![RepairCandidate::SuppressDuplicateAction(obligation)],
        ),
        UtilityFailure::Deadline { action, obligation } => (
            CounterexampleKind::MissedDeadline {
                side,
                action,
                obligation: obligation.clone(),
            },
            vec![RepairCandidate::ScheduleBeforeDeadline(obligation)],
        ),
        UtilityFailure::Recovery { action, obligation } => (
            CounterexampleKind::RecoverableFaultViolation {
                side,
                action,
                obligation: obligation.clone(),
            },
            vec![RepairCandidate::AddRecoveryTransition(obligation)],
        ),
    };
    let mut trace = reconstruct_trace(node, predecessors);
    trace.push(step);
    CheckOutcome::Counterexample(Box::new(Counterexample {
        kind,
        slot,
        observer: None,
        left_observation: None,
        right_observation: None,
        causal_field: None,
        trace,
        repair_candidates: repairs,
    }))
}

fn node_limit_report(
    limit: usize,
    explored_nodes: usize,
    discovered_nodes: usize,
    frontier_nodes: usize,
    reached_depth: u32,
) -> CheckOutcome {
    CheckOutcome::Inconclusive(InconclusiveReport {
        reason: InconclusiveReason::NodeLimit { limit },
        explored_nodes,
        discovered_nodes,
        frontier_nodes,
        reached_depth,
    })
}

fn time_limit_report(
    limit: Duration,
    explored_nodes: usize,
    discovered_nodes: usize,
    frontier_nodes: usize,
    reached_depth: u32,
) -> CheckOutcome {
    CheckOutcome::Inconclusive(InconclusiveReport {
        reason: InconclusiveReason::TimeLimit {
            millis: limit.as_millis(),
        },
        explored_nodes,
        discovered_nodes,
        frontier_nodes,
        reached_depth,
    })
}

#[allow(dead_code)]
fn _assert_indexes_are_solver_independent(
    _states: &BTreeMap<StateId, &State>,
    _semantics: &BTreeMap<SemanticId, &SemanticContract>,
    _transitions: &BTreeMap<(StateId, InputId), &Transition>,
) {
}
