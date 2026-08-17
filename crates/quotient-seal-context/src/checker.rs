use std::collections::{BTreeMap, VecDeque};

use quotient_forge_caqt::RelationPair;
use quotient_seal_relation::RelationVerdict;

use crate::model::{
    project_trace, CallRecord, CommandKind, ContextAutomaton, ContextCommand, ContextFamily,
    ContextViolation, ContextViolationKind, DivergenceKind, EventKind, ExecutionBoundary,
    InductionObligations, InitialRun, Observation, ObserverProfile, OracleInconclusive,
    OracleResult, ProductCheckReport, ProductCounterexample, ProductInconclusive, ProductLimits,
    ProductVerdict, RelationBinding, RunState, RunStep, ValidatedProductSystem, World,
    CONTEXT_FAMILY_COUNT, MAX_PREFIX_HARD_LIMIT,
};

#[derive(Clone)]
struct ProductNode {
    left: RunState,
    right: RunState,
    context_index: usize,
    context_state: u32,
    private_pair: RelationPair,
    observation: Observation,
    depth: u16,
    predecessor: Option<usize>,
    via: Option<CallRecord>,
}

#[derive(Clone, Copy, Default)]
struct ProfileStats {
    visited: usize,
    edges: usize,
    maximum_depth: u16,
}

enum ProfileOutcome {
    Accept(ProfileStats),
    Counterexample(ProductCounterexample),
    Inconclusive(ProductInconclusive),
}

enum OracleFailure {
    Counterexample {
        world: World,
        code: u32,
    },
    Inconclusive {
        world: World,
        reason: OracleInconclusive,
    },
    Nondeterministic,
}

#[must_use]
pub fn check_context_product<S: ValidatedProductSystem>(
    relation: &RelationVerdict,
    system: &S,
    private_pairs: &[RelationPair],
    contexts: &[ContextAutomaton],
    induction: InductionObligations,
    limits: ProductLimits,
) -> ProductVerdict {
    check_profiles(
        relation,
        system,
        private_pairs,
        contexts,
        induction,
        limits,
        &ObserverProfile::ALL,
    )
}

#[must_use]
pub fn check_context_product_profile<S: ValidatedProductSystem>(
    relation: &RelationVerdict,
    system: &S,
    private_pairs: &[RelationPair],
    contexts: &[ContextAutomaton],
    observer: ObserverProfile,
    induction: InductionObligations,
    limits: ProductLimits,
) -> ProductVerdict {
    check_profiles(
        relation,
        system,
        private_pairs,
        contexts,
        induction,
        limits,
        &[observer],
    )
}

#[allow(clippy::too_many_arguments)]
fn check_profiles<S: ValidatedProductSystem>(
    relation: &RelationVerdict,
    system: &S,
    private_pairs: &[RelationPair],
    contexts: &[ContextAutomaton],
    induction: InductionObligations,
    limits: ProductLimits,
    profiles: &[ObserverProfile],
) -> ProductVerdict {
    if !valid_limits(limits) {
        return ProductVerdict::Inconclusive(ProductInconclusive::InvalidLimits);
    }
    if private_pairs.is_empty() {
        return ProductVerdict::Inconclusive(ProductInconclusive::EmptyPrivatePairs);
    }
    if let Err(violation) = validate_private_pairs(private_pairs) {
        return ProductVerdict::Inconclusive(ProductInconclusive::InvalidContext(violation));
    }
    let ordered_contexts = match validate_contexts(contexts, limits) {
        Ok(contexts) => contexts,
        Err(violation) => {
            return ProductVerdict::Inconclusive(ProductInconclusive::InvalidContext(violation));
        }
    };
    let report = match relation {
        RelationVerdict::Valid(report) => report.as_ref(),
        RelationVerdict::Invalid(_) => {
            return ProductVerdict::Counterexample(Box::new(ProductCounterexample {
                observer: profiles[0],
                family: ContextFamily::Tick,
                private_pair: private_pairs[0],
                call_sequence: Vec::new(),
                shared_action: None,
                shared_emitted_action: None,
                divergence: DivergenceKind::RelationGate,
                detail_code: 0,
                left_observation: Observation::empty(),
                right_observation: Observation::empty(),
            }));
        }
        RelationVerdict::Incompatible(_)
        | RelationVerdict::ResourceBound(_)
        | RelationVerdict::Unresolved(_) => {
            return ProductVerdict::Inconclusive(ProductInconclusive::RelationGate);
        }
    };
    let binding = RelationBinding::from_report(report);
    if system.relation_binding() != binding {
        return ProductVerdict::Inconclusive(ProductInconclusive::RelationBinding);
    }
    let system_states = system.finite_state_bound();
    if system_states == 0 || system_states > limits.max_system_states {
        return ProductVerdict::Inconclusive(ProductInconclusive::SystemStateBound {
            actual: system_states,
            limit: limits.max_system_states,
        });
    }
    let declared_product_bound =
        match declared_product_bound(private_pairs.len(), &ordered_contexts, system_states) {
            Some(bound) => bound,
            None => return ProductVerdict::Inconclusive(ProductInconclusive::ArithmeticOverflow),
        };

    let mut aggregate = ProfileStats::default();
    let mut first_inconclusive = None;
    for profile in profiles {
        match check_profile(
            system,
            private_pairs,
            &ordered_contexts,
            *profile,
            induction,
            limits,
        ) {
            ProfileOutcome::Accept(stats) => {
                aggregate.visited = aggregate.visited.saturating_add(stats.visited);
                aggregate.edges = aggregate.edges.saturating_add(stats.edges);
                aggregate.maximum_depth = aggregate.maximum_depth.max(stats.maximum_depth);
            }
            ProfileOutcome::Counterexample(counterexample) => {
                return ProductVerdict::Counterexample(Box::new(counterexample));
            }
            ProfileOutcome::Inconclusive(reason) => {
                if first_inconclusive.is_none() {
                    first_inconclusive = Some(reason);
                }
            }
        }
    }
    if let Some(reason) = first_inconclusive {
        return ProductVerdict::Inconclusive(reason);
    }
    if !induction.closed() {
        return ProductVerdict::Inconclusive(ProductInconclusive::InductionNotClosed);
    }
    ProductVerdict::Accept(Box::new(ProductCheckReport {
        binding,
        observer_profiles: profiles.len(),
        context_families: ordered_contexts.len(),
        private_pairs: private_pairs.len(),
        visited_product_states: aggregate.visited,
        checked_edges: aggregate.edges,
        maximum_shortest_prefix: aggregate.maximum_depth,
        declared_product_bound,
        induction_closed: true,
    }))
}

fn check_profile<S: ValidatedProductSystem>(
    system: &S,
    private_pairs: &[RelationPair],
    contexts: &[&ContextAutomaton],
    observer: ObserverProfile,
    induction: InductionObligations,
    limits: ProductLimits,
) -> ProfileOutcome {
    let mut nodes = Vec::new();
    let mut queue = VecDeque::new();
    let mut visited = BTreeMap::new();
    let mut first_inconclusive = None;

    for (context_index, context) in contexts.iter().enumerate() {
        for pair in private_pairs {
            let left = match deterministic_initial(system, *pair, World::Left) {
                Ok(run) => run,
                Err(failure) => {
                    if let Some(outcome) = root_oracle_failure(
                        failure,
                        observer,
                        context.family,
                        *pair,
                        &mut first_inconclusive,
                    ) {
                        return outcome;
                    }
                    continue;
                }
            };
            let right = match deterministic_initial(system, *pair, World::Right) {
                Ok(run) => run,
                Err(failure) => {
                    if let Some(outcome) = root_oracle_failure(
                        failure,
                        observer,
                        context.family,
                        *pair,
                        &mut first_inconclusive,
                    ) {
                        return outcome;
                    }
                    continue;
                }
            };
            let left_observation = project_trace(&left.target_trace, observer);
            let right_observation = project_trace(&right.target_trace, observer);
            if !left.relation_holds
                || !right.relation_holds
                || left.state.source_state != pair.left
                || right.state.source_state != pair.right
                || left.state.action_semantics_id == 0
                || left.state.action_semantics_id != right.state.action_semantics_id
            {
                return ProfileOutcome::Counterexample(root_counterexample(
                    observer,
                    context.family,
                    *pair,
                    DivergenceKind::StateRelation,
                    left_observation,
                    right_observation,
                    0,
                ));
            }
            if left_observation != right_observation {
                return ProfileOutcome::Counterexample(root_counterexample(
                    observer,
                    context.family,
                    *pair,
                    DivergenceKind::ObserverTrace,
                    left_observation,
                    right_observation,
                    0,
                ));
            }
            if context
                .observations
                .binary_search(&left_observation)
                .is_err()
            {
                first_inconclusive.get_or_insert(ProductInconclusive::UnknownObservation {
                    observer,
                    family: context.family,
                    depth: 0,
                });
                continue;
            }
            let node = ProductNode {
                left: left.state,
                right: right.state,
                context_index,
                context_state: context.initial_state,
                private_pair: *pair,
                observation: left_observation,
                depth: 0,
                predecessor: None,
                via: None,
            };
            let key = node_key(&node);
            if visited.contains_key(&key) {
                continue;
            }
            if nodes.len() >= limits.max_product_states {
                return ProfileOutcome::Inconclusive(ProductInconclusive::ProductStateBound {
                    limit: limits.max_product_states,
                });
            }
            let index = nodes.len();
            visited.insert(key, index);
            nodes.push(node);
            queue.push_back(index);
        }
    }

    let mut stats = ProfileStats::default();
    while let Some(node_index) = queue.pop_front() {
        let node = nodes[node_index].clone();
        stats.maximum_depth = stats.maximum_depth.max(node.depth);
        let context = contexts[node.context_index];
        let Ok(observation_index) = context.observations.binary_search(&node.observation) else {
            first_inconclusive.get_or_insert(ProductInconclusive::UnknownObservation {
                observer,
                family: context.family,
                depth: node.depth,
            });
            continue;
        };
        for randomness in 0..context.randomness_count {
            stats.edges = stats.edges.saturating_add(1);
            let Some(transition) =
                context.transition(node.context_state, observation_index, randomness)
            else {
                first_inconclusive.get_or_insert(ProductInconclusive::ArithmeticOverflow);
                continue;
            };
            let call = CallRecord {
                randomness,
                command: transition.command.clone(),
            };
            if node.depth >= limits.max_prefix {
                first_inconclusive.get_or_insert(ProductInconclusive::PrefixBound {
                    limit: limits.max_prefix,
                });
                continue;
            }
            if call.command.kind == CommandKind::Stop {
                continue;
            }
            let left = match deterministic_step(system, World::Left, &node.left, &call.command) {
                Ok(step) => step,
                Err(failure) => {
                    if let Some(outcome) = step_oracle_failure(
                        failure,
                        observer,
                        context.family,
                        &node,
                        &nodes,
                        &call,
                        &mut first_inconclusive,
                    ) {
                        return outcome;
                    }
                    continue;
                }
            };
            let right = match deterministic_step(system, World::Right, &node.right, &call.command) {
                Ok(step) => step,
                Err(failure) => {
                    if let Some(outcome) = step_oracle_failure(
                        failure,
                        observer,
                        context.family,
                        &node,
                        &nodes,
                        &call,
                        &mut first_inconclusive,
                    ) {
                        return outcome;
                    }
                    continue;
                }
            };
            let left_observation = project_trace(&left.target_trace, observer);
            let right_observation = project_trace(&right.target_trace, observer);
            let shared_emitted_action = shared_emitted_action(&left, &right);

            if !left.relation_holds || !right.relation_holds {
                return ProfileOutcome::Counterexample(step_counterexample(
                    observer,
                    context.family,
                    &node,
                    &nodes,
                    call,
                    DivergenceKind::StateRelation,
                    0,
                    left_observation,
                    right_observation,
                    shared_emitted_action,
                ));
            }
            if !left.utility_holds || !right.utility_holds {
                return ProfileOutcome::Counterexample(step_counterexample(
                    observer,
                    context.family,
                    &node,
                    &nodes,
                    call,
                    DivergenceKind::Utility,
                    0,
                    left_observation,
                    right_observation,
                    shared_emitted_action,
                ));
            }
            if left.source_trace != right.source_trace {
                return ProfileOutcome::Counterexample(step_counterexample(
                    observer,
                    context.family,
                    &node,
                    &nodes,
                    call,
                    DivergenceKind::SourceTrace,
                    first_difference(&left.source_trace, &right.source_trace),
                    left_observation,
                    right_observation,
                    shared_emitted_action,
                ));
            }
            if left.boundary != right.boundary {
                return ProfileOutcome::Counterexample(step_counterexample(
                    observer,
                    context.family,
                    &node,
                    &nodes,
                    call,
                    DivergenceKind::ExecutionBoundary,
                    0,
                    left_observation,
                    right_observation,
                    shared_emitted_action,
                ));
            }
            if left.boundary.is_inconclusive() {
                first_inconclusive.get_or_insert(ProductInconclusive::ExecutionBoundary {
                    world: World::Left,
                    boundary: left.boundary,
                });
                continue;
            }
            if left.boundary == ExecutionBoundary::UnknownFailure {
                return ProfileOutcome::Counterexample(step_counterexample(
                    observer,
                    context.family,
                    &node,
                    &nodes,
                    call,
                    DivergenceKind::UnknownFailure,
                    0,
                    left_observation,
                    right_observation,
                    shared_emitted_action,
                ));
            }
            if left_observation != right_observation {
                return ProfileOutcome::Counterexample(step_counterexample(
                    observer,
                    context.family,
                    &node,
                    &nodes,
                    call,
                    DivergenceKind::ObserverTrace,
                    first_event_difference(&left_observation, &right_observation),
                    left_observation,
                    right_observation,
                    shared_emitted_action,
                ));
            }
            if left.next.action_semantics_id == 0
                || left.next.action_semantics_id != right.next.action_semantics_id
            {
                return ProfileOutcome::Counterexample(step_counterexample(
                    observer,
                    context.family,
                    &node,
                    &nodes,
                    call,
                    DivergenceKind::StateRelation,
                    1,
                    left_observation,
                    right_observation,
                    shared_emitted_action,
                ));
            }
            if left.boundary.is_terminal() {
                continue;
            }
            if context
                .observations
                .binary_search(&left_observation)
                .is_err()
            {
                first_inconclusive.get_or_insert(ProductInconclusive::UnknownObservation {
                    observer,
                    family: context.family,
                    depth: node.depth.saturating_add(1),
                });
                continue;
            }
            let Some(depth) = node.depth.checked_add(1) else {
                first_inconclusive.get_or_insert(ProductInconclusive::ArithmeticOverflow);
                continue;
            };
            let successor = ProductNode {
                left: left.next,
                right: right.next,
                context_index: node.context_index,
                context_state: transition.to_state,
                private_pair: node.private_pair,
                observation: left_observation,
                depth,
                predecessor: Some(node_index),
                via: Some(call),
            };
            let key = node_key(&successor);
            if visited.contains_key(&key) {
                continue;
            }
            if nodes.len() >= limits.max_product_states {
                return ProfileOutcome::Inconclusive(ProductInconclusive::ProductStateBound {
                    limit: limits.max_product_states,
                });
            }
            let successor_index = nodes.len();
            visited.insert(key, successor_index);
            nodes.push(successor);
            queue.push_back(successor_index);
        }
    }
    stats.visited = nodes.len();
    if let Some(reason) = first_inconclusive {
        ProfileOutcome::Inconclusive(reason)
    } else if induction.closed() {
        ProfileOutcome::Accept(stats)
    } else {
        ProfileOutcome::Inconclusive(ProductInconclusive::InductionNotClosed)
    }
}

fn deterministic_initial<S: ValidatedProductSystem>(
    system: &S,
    pair: RelationPair,
    world: World,
) -> Result<InitialRun, OracleFailure> {
    let first = system.initial(pair, world);
    if first != system.initial(pair, world) {
        return Err(OracleFailure::Nondeterministic);
    }
    match first {
        OracleResult::Valid(run) => Ok(run),
        OracleResult::Counterexample(counterexample) => Err(OracleFailure::Counterexample {
            world,
            code: counterexample.code,
        }),
        OracleResult::Inconclusive(reason) => Err(OracleFailure::Inconclusive { world, reason }),
    }
}

fn deterministic_step<S: ValidatedProductSystem>(
    system: &S,
    world: World,
    state: &RunState,
    command: &ContextCommand,
) -> Result<RunStep, OracleFailure> {
    let first = system.step(world, state, command);
    if first != system.step(world, state, command) {
        return Err(OracleFailure::Nondeterministic);
    }
    match first {
        OracleResult::Valid(step) => Ok(step),
        OracleResult::Counterexample(counterexample) => Err(OracleFailure::Counterexample {
            world,
            code: counterexample.code,
        }),
        OracleResult::Inconclusive(reason) => Err(OracleFailure::Inconclusive { world, reason }),
    }
}

fn root_oracle_failure(
    failure: OracleFailure,
    observer: ObserverProfile,
    family: ContextFamily,
    pair: RelationPair,
    first_inconclusive: &mut Option<ProductInconclusive>,
) -> Option<ProfileOutcome> {
    match failure {
        OracleFailure::Counterexample { world, code } => {
            Some(ProfileOutcome::Counterexample(root_counterexample(
                observer,
                family,
                pair,
                DivergenceKind::Oracle,
                Observation::empty(),
                Observation::empty(),
                code | world_code(world),
            )))
        }
        OracleFailure::Inconclusive { world, reason } => {
            first_inconclusive.get_or_insert(ProductInconclusive::Oracle { world, reason });
            None
        }
        OracleFailure::Nondeterministic => {
            first_inconclusive.get_or_insert(ProductInconclusive::NondeterministicOracle);
            None
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn step_oracle_failure(
    failure: OracleFailure,
    observer: ObserverProfile,
    family: ContextFamily,
    node: &ProductNode,
    nodes: &[ProductNode],
    call: &CallRecord,
    first_inconclusive: &mut Option<ProductInconclusive>,
) -> Option<ProfileOutcome> {
    match failure {
        OracleFailure::Counterexample { world, code } => {
            Some(ProfileOutcome::Counterexample(step_counterexample(
                observer,
                family,
                node,
                nodes,
                call.clone(),
                DivergenceKind::Oracle,
                code | world_code(world),
                Observation::empty(),
                Observation::empty(),
                None,
            )))
        }
        OracleFailure::Inconclusive { world, reason } => {
            first_inconclusive.get_or_insert(ProductInconclusive::Oracle { world, reason });
            None
        }
        OracleFailure::Nondeterministic => {
            first_inconclusive.get_or_insert(ProductInconclusive::NondeterministicOracle);
            None
        }
    }
}

fn root_counterexample(
    observer: ObserverProfile,
    family: ContextFamily,
    private_pair: RelationPair,
    divergence: DivergenceKind,
    left_observation: Observation,
    right_observation: Observation,
    detail_code: u32,
) -> ProductCounterexample {
    ProductCounterexample {
        observer,
        family,
        private_pair,
        call_sequence: Vec::new(),
        shared_action: None,
        shared_emitted_action: None,
        divergence,
        detail_code,
        left_observation,
        right_observation,
    }
}

#[allow(clippy::too_many_arguments)]
fn step_counterexample(
    observer: ObserverProfile,
    family: ContextFamily,
    node: &ProductNode,
    nodes: &[ProductNode],
    call: CallRecord,
    divergence: DivergenceKind,
    detail_code: u32,
    left_observation: Observation,
    right_observation: Observation,
    shared_emitted_action: Option<u32>,
) -> ProductCounterexample {
    let mut call_sequence = reconstruct_calls(nodes, node);
    call_sequence.push(call.clone());
    ProductCounterexample {
        observer,
        family,
        private_pair: node.private_pair,
        call_sequence,
        shared_action: Some(call.command),
        shared_emitted_action,
        divergence,
        detail_code,
        left_observation,
        right_observation,
    }
}

fn reconstruct_calls(nodes: &[ProductNode], node: &ProductNode) -> Vec<CallRecord> {
    let mut calls = Vec::new();
    let mut cursor = node.predecessor;
    if let Some(call) = &node.via {
        calls.push(call.clone());
    }
    while let Some(index) = cursor {
        let predecessor = &nodes[index];
        if let Some(call) = &predecessor.via {
            calls.push(call.clone());
        }
        cursor = predecessor.predecessor;
    }
    calls.reverse();
    calls
}

fn shared_emitted_action(left: &RunStep, right: &RunStep) -> Option<u32> {
    let left_actions: Vec<u32> = left
        .target_trace
        .iter()
        .filter(|event| event.kind == EventKind::Action)
        .map(|event| event.label)
        .collect();
    let right_actions: Vec<u32> = right
        .target_trace
        .iter()
        .filter(|event| event.kind == EventKind::Action)
        .map(|event| event.label)
        .collect();
    (left_actions == right_actions && left_actions.len() == 1).then_some(left_actions[0])
}

fn first_difference<T: PartialEq>(left: &[T], right: &[T]) -> u32 {
    let index = left
        .iter()
        .zip(right)
        .position(|(left, right)| left != right)
        .unwrap_or(left.len().min(right.len()));
    u32::try_from(index).unwrap_or(u32::MAX)
}

fn first_event_difference(left: &Observation, right: &Observation) -> u32 {
    first_difference(left.events(), right.events())
}

fn node_key(node: &ProductNode) -> Vec<u8> {
    let mut key = Vec::new();
    key.push(node.context_index as u8);
    key.extend_from_slice(&node.context_state.to_le_bytes());
    key.extend_from_slice(&node.private_pair.left.to_le_bytes());
    key.extend_from_slice(&node.private_pair.right.to_le_bytes());
    encode_state_key(&mut key, &node.left);
    encode_state_key(&mut key, &node.right);
    key.extend_from_slice(
        &u32::try_from(node.observation.events().len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    for event in node.observation.events() {
        key.push(event.kind as u8);
        key.extend_from_slice(&event.label.to_le_bytes());
        key.extend_from_slice(&event.slot.to_le_bytes());
        key.extend_from_slice(&event.value.to_le_bytes());
    }
    key
}

fn encode_state_key(key: &mut Vec<u8>, state: &RunState) {
    key.extend_from_slice(&state.source_state.to_le_bytes());
    key.extend_from_slice(state.target_state_digest.as_bytes());
    key.extend_from_slice(state.public_state_digest.as_bytes());
    key.extend_from_slice(&state.target_pc.to_le_bytes());
    key.extend_from_slice(&state.memory_pages.to_le_bytes());
    key.push(state.execution_status);
    key.extend_from_slice(&state.action_semantics_id.to_le_bytes());
}

fn validate_contexts(
    contexts: &[ContextAutomaton],
    limits: ProductLimits,
) -> Result<Vec<&ContextAutomaton>, ContextViolation> {
    let mut ordered: [Option<&ContextAutomaton>; CONTEXT_FAMILY_COUNT] =
        [None; CONTEXT_FAMILY_COUNT];
    for context in contexts {
        let index = context.family as usize;
        if ordered[index].is_some() {
            return Err(violation(
                ContextViolationKind::DuplicateFamily,
                Some(context.family),
                u32::try_from(index).unwrap_or(u32::MAX),
            ));
        }
        validate_context(context, limits)?;
        ordered[index] = Some(context);
    }
    let mut result = Vec::with_capacity(CONTEXT_FAMILY_COUNT);
    for family in ContextFamily::ALL {
        let Some(context) = ordered[family as usize] else {
            return Err(violation(
                ContextViolationKind::MissingFamily,
                Some(family),
                family as u32,
            ));
        };
        result.push(context);
    }
    Ok(result)
}

fn validate_context(
    context: &ContextAutomaton,
    limits: ProductLimits,
) -> Result<(), ContextViolation> {
    if context.state_count == 0 || context.state_count > limits.max_context_states {
        return Err(violation(
            ContextViolationKind::StateCount,
            Some(context.family),
            0,
        ));
    }
    if context.randomness_count == 0 || context.randomness_count > limits.max_randomness {
        return Err(violation(
            ContextViolationKind::RandomnessCount,
            Some(context.family),
            0,
        ));
    }
    if context.initial_state >= context.state_count {
        return Err(violation(
            ContextViolationKind::InitialState,
            Some(context.family),
            context.initial_state,
        ));
    }
    if context.observations.is_empty() || context.observations.len() > limits.max_observations {
        return Err(violation(
            ContextViolationKind::ObservationCount,
            Some(context.family),
            0,
        ));
    }
    if context
        .observations
        .windows(2)
        .any(|window| window[0] >= window[1])
    {
        return Err(violation(
            ContextViolationKind::ObservationOrder,
            Some(context.family),
            0,
        ));
    }
    let expected_transitions = usize::try_from(context.state_count)
        .ok()
        .and_then(|states| states.checked_mul(context.observations.len()))
        .and_then(|count| {
            usize::try_from(context.randomness_count)
                .ok()
                .and_then(|randomness| count.checked_mul(randomness))
        })
        .ok_or_else(|| {
            violation(
                ContextViolationKind::TransitionCount,
                Some(context.family),
                0,
            )
        })?;
    if context.transitions.len() != expected_transitions
        || context.transitions.len() > limits.max_context_transitions
    {
        return Err(violation(
            ContextViolationKind::TransitionCount,
            Some(context.family),
            u32::try_from(context.transitions.len()).unwrap_or(u32::MAX),
        ));
    }
    let mut index = 0_usize;
    for state in 0..context.state_count {
        for observation_index in 0..context.observations.len() {
            for randomness in 0..context.randomness_count {
                let transition = &context.transitions[index];
                if transition.from_state != state
                    || usize::try_from(transition.observation_index).ok() != Some(observation_index)
                    || transition.randomness != randomness
                {
                    return Err(violation(
                        ContextViolationKind::TransitionOrder,
                        Some(context.family),
                        u32::try_from(index).unwrap_or(u32::MAX),
                    ));
                }
                if transition.to_state >= context.state_count {
                    return Err(violation(
                        ContextViolationKind::TransitionTarget,
                        Some(context.family),
                        u32::try_from(index).unwrap_or(u32::MAX),
                    ));
                }
                validate_command(context.family, &transition.command, index)?;
                index += 1;
            }
        }
    }
    Ok(())
}

fn validate_command(
    family: ContextFamily,
    command: &ContextCommand,
    index: usize,
) -> Result<(), ContextViolation> {
    if command.family != family {
        return Err(violation(
            ContextViolationKind::CommandFamily,
            Some(family),
            u32::try_from(index).unwrap_or(u32::MAX),
        ));
    }
    if command.kind != family.command_kind() {
        return Err(violation(
            ContextViolationKind::CommandKind,
            Some(family),
            u32::try_from(index).unwrap_or(u32::MAX),
        ));
    }
    let valid = match family {
        ContextFamily::FaultTimeout => command.fault == 1 && command.service_alias != 0,
        ContextFamily::FaultReconnect => command.fault == 2 && command.service_alias != 0,
        ContextFamily::FaultLoss => command.fault == 3 && command.service_alias != 0,
        ContextFamily::Reset | ContextFamily::Stop => {
            command.service_alias == 0
                && command.public_slot == 0
                && command.fault == 0
                && command.payload_tag == 0
        }
        ContextFamily::Handoff => {
            command.service_alias == 0 && command.fault == 0 && command.payload_tag == 0
        }
        ContextFamily::Malformed => command.fault == 0,
        ContextFamily::Tick
        | ContextFamily::Retry
        | ContextFamily::Deadline
        | ContextFamily::ServiceCollusion
        | ContextFamily::CrossServiceReplay => command.service_alias != 0 && command.fault == 0,
    };
    if valid {
        Ok(())
    } else {
        Err(violation(
            ContextViolationKind::CommandFields,
            Some(family),
            u32::try_from(index).unwrap_or(u32::MAX),
        ))
    }
}

fn validate_private_pairs(private_pairs: &[RelationPair]) -> Result<(), ContextViolation> {
    let mut previous = None;
    for (index, pair) in private_pairs.iter().copied().enumerate() {
        let ordered = pair.left < pair.right;
        let follows = previous
            .is_none_or(|prior: RelationPair| (prior.left, prior.right) < (pair.left, pair.right));
        if !ordered || !follows {
            return Err(violation(
                ContextViolationKind::PrivatePairOrder,
                None,
                u32::try_from(index).unwrap_or(u32::MAX),
            ));
        }
        previous = Some(pair);
    }
    Ok(())
}

fn valid_limits(limits: ProductLimits) -> bool {
    limits.max_prefix > 0
        && limits.max_prefix <= MAX_PREFIX_HARD_LIMIT
        && limits.max_product_states > 0
        && limits.max_context_states > 0
        && limits.max_observations > 0
        && limits.max_randomness > 0
        && limits.max_context_transitions > 0
        && limits.max_system_states > 0
}

fn declared_product_bound(
    pair_count: usize,
    contexts: &[&ContextAutomaton],
    system_states: usize,
) -> Option<usize> {
    let context_states = contexts.iter().try_fold(0_usize, |sum, context| {
        sum.checked_add(usize::try_from(context.state_count).ok()?)
    })?;
    pair_count
        .checked_mul(context_states)?
        .checked_mul(system_states)?
        .checked_mul(system_states)
}

const fn world_code(world: World) -> u32 {
    match world {
        World::Left => 0x1000_0000,
        World::Right => 0x2000_0000,
    }
}

const fn violation(
    kind: ContextViolationKind,
    family: Option<ContextFamily>,
    index: u32,
) -> ContextViolation {
    ContextViolation {
        kind,
        family,
        index,
    }
}
