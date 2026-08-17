use quotient_forge_caqt::{Digest, RelationPair};
use quotient_seal_context::{
    check_context_product, check_context_product_profile, ContextAutomaton, ContextCommand,
    ContextFamily, ContextTransition, DivergenceKind, EventKind, ExecutionBoundary,
    InductionObligations, InitialRun, Observation, ObserverProfile, OracleInconclusive,
    OracleResult, ProductInconclusive, ProductLimits, ProductVerdict, RelationBinding, RunState,
    RunStep, SourceEvent, SourceEventKind, TargetEvent, ValidatedProductSystem, World,
    CONTEXT_FAMILY_COUNT, MAX_PREFIX_HARD_LIMIT,
};
use quotient_seal_relation::{
    DivergenceKind as RelationDivergenceKind, RelationCounterexample, RelationValidationReport,
    RelationVerdict,
};

#[derive(Clone, Copy)]
enum Mutant {
    Valid,
    ControlAtSecondCall,
    SourceAtFirstCall,
    RelationLost,
    ResourceBound,
    LongChain,
    UnknownObservation,
}

struct FixtureSystem {
    binding: RelationBinding,
    mutant: Mutant,
}

impl ValidatedProductSystem for FixtureSystem {
    fn relation_binding(&self) -> RelationBinding {
        self.binding
    }

    fn finite_state_bound(&self) -> usize {
        if matches!(self.mutant, Mutant::LongChain) {
            512
        } else {
            4
        }
    }

    fn initial(&self, pair: RelationPair, world: World) -> OracleResult<InitialRun> {
        let source_state = match world {
            World::Left => pair.left,
            World::Right => pair.right,
        };
        OracleResult::Valid(InitialRun {
            state: run_state(source_state, world, 0),
            target_trace: Vec::new(),
            relation_holds: true,
        })
    }

    fn step(
        &self,
        world: World,
        state: &RunState,
        command: &ContextCommand,
    ) -> OracleResult<RunStep> {
        if matches!(self.mutant, Mutant::ResourceBound)
            && command.family == ContextFamily::Malformed
        {
            return OracleResult::Inconclusive(OracleInconclusive::ResourceBound);
        }
        let mut source_trace = source_trace();
        if matches!(self.mutant, Mutant::SourceAtFirstCall)
            && world == World::Right
            && command.family == ContextFamily::Retry
        {
            source_trace[1].value = 99;
        }
        let mut target_trace = target_trace();
        if matches!(self.mutant, Mutant::ControlAtSecondCall)
            && world == World::Right
            && command.family == ContextFamily::Deadline
            && state.target_pc >= 1
        {
            target_trace.push(TargetEvent {
                kind: EventKind::Control,
                label: 99,
                slot: 0,
                value: 1,
            });
        }
        if matches!(self.mutant, Mutant::UnknownObservation)
            && command.family == ContextFamily::ServiceCollusion
        {
            target_trace.push(TargetEvent {
                kind: EventKind::HostCall,
                label: 88,
                slot: 0,
                value: 0,
            });
        }
        let next_pc = if matches!(self.mutant, Mutant::LongChain) {
            state.target_pc.saturating_add(1).min(300)
        } else {
            1
        };
        OracleResult::Valid(RunStep {
            next: run_state(1, world, next_pc),
            source_trace,
            target_trace,
            relation_holds: !(matches!(self.mutant, Mutant::RelationLost)
                && world == World::Right
                && command.family == ContextFamily::Tick),
            utility_holds: true,
            boundary: ExecutionBoundary::NormalReturn,
        })
    }
}

fn digest(value: u8) -> Digest {
    Digest::new([value; 32])
}

fn relation_verdict() -> RelationVerdict {
    RelationVerdict::Valid(Box::new(RelationValidationReport {
        relation_digest: digest(1),
        inductive_digest: digest(2),
        target_ir_digest: digest(3),
        reachable_states: 2,
        checked_source_steps: 2,
        checked_lifecycle_calls: 3,
        checked_two_run_cases: 1,
        checked_observer_events: 6,
    }))
}

fn relation_binding() -> RelationBinding {
    let RelationVerdict::Valid(report) = relation_verdict() else {
        unreachable!();
    };
    RelationBinding::from_report(&report)
}

fn system(mutant: Mutant) -> FixtureSystem {
    FixtureSystem {
        binding: relation_binding(),
        mutant,
    }
}

fn run_state(source_state: u32, world: World, pc: u32) -> RunState {
    let world_tag = match world {
        World::Left => 10,
        World::Right => 20,
    };
    RunState {
        source_state,
        target_state_digest: digest(world_tag + u8::try_from(pc % 10).unwrap()),
        public_state_digest: digest(40 + u8::try_from(pc % 10).unwrap()),
        target_pc: pc,
        memory_pages: 1,
        execution_status: 0,
        action_semantics_id: 7,
    }
}

fn source_trace() -> Vec<SourceEvent> {
    vec![
        SourceEvent {
            kind: SourceEventKind::PublicCall,
            label: 1,
            slot: 0,
            value: 0,
        },
        SourceEvent {
            kind: SourceEventKind::PublicReturn,
            label: 2,
            slot: 0,
            value: 0,
        },
        SourceEvent {
            kind: SourceEventKind::AuthorizedAction,
            label: 7,
            slot: 0,
            value: 0,
        },
    ]
}

fn target_trace() -> Vec<TargetEvent> {
    vec![
        TargetEvent {
            kind: EventKind::ApiCall,
            label: 1,
            slot: 0,
            value: 0,
        },
        TargetEvent {
            kind: EventKind::ApiReturn,
            label: 2,
            slot: 0,
            value: 0,
        },
        TargetEvent {
            kind: EventKind::Action,
            label: 7,
            slot: 0,
            value: 0,
        },
    ]
}

fn command(family: ContextFamily, randomness: u32) -> ContextCommand {
    let (service_alias, public_slot, fault, payload_tag) = match family {
        ContextFamily::Reset | ContextFamily::Stop => (0, 0, 0, 0),
        ContextFamily::Handoff => (0, u64::from(randomness), 0, 0),
        ContextFamily::FaultTimeout => (1, u64::from(randomness), 1, 0),
        ContextFamily::FaultReconnect => (1, u64::from(randomness), 2, 0),
        ContextFamily::FaultLoss => (1, u64::from(randomness), 3, 0),
        ContextFamily::Malformed => (0, u64::from(randomness), 0, randomness),
        ContextFamily::ServiceCollusion => (2, u64::from(randomness), 0, randomness),
        ContextFamily::CrossServiceReplay => (3, u64::from(randomness), 0, randomness),
        ContextFamily::Tick | ContextFamily::Retry | ContextFamily::Deadline => {
            (1, u64::from(randomness), 0, randomness)
        }
    };
    ContextCommand {
        family,
        kind: family.command_kind(),
        service_alias,
        public_slot,
        fault,
        payload_tag,
    }
}

fn context(family: ContextFamily) -> ContextAutomaton {
    let observations = vec![Observation::empty(), Observation::new(target_trace())];
    let mut transitions = Vec::new();
    for observation_index in 0..observations.len() {
        for randomness in 0..2 {
            transitions.push(ContextTransition {
                from_state: 0,
                observation_index: u32::try_from(observation_index).unwrap(),
                randomness,
                to_state: 0,
                command: command(family, randomness),
            });
        }
    }
    ContextAutomaton {
        family,
        state_count: 1,
        randomness_count: 2,
        initial_state: 0,
        observations,
        transitions,
    }
}

fn contexts() -> Vec<ContextAutomaton> {
    ContextFamily::ALL.into_iter().map(context).collect()
}

fn pairs() -> Vec<RelationPair> {
    vec![RelationPair { left: 0, right: 1 }]
}

fn check(mutant: Mutant, limits: ProductLimits) -> ProductVerdict {
    check_context_product(
        &relation_verdict(),
        &system(mutant),
        &pairs(),
        &contexts(),
        InductionObligations::default(),
        limits,
    )
}

#[test]
fn all_twelve_context_families_reach_a_finite_product_fixpoint() {
    assert_eq!(ContextFamily::ALL.len(), CONTEXT_FAMILY_COUNT);
    let ProductVerdict::Accept(report) = check(Mutant::Valid, ProductLimits::default()) else {
        panic!("closed product must be accepted");
    };
    assert_eq!(report.context_families, 12);
    assert_eq!(report.observer_profiles, 7);
    assert_eq!(report.private_pairs, 1);
    assert!(report.visited_product_states >= 12);
    assert!(report.checked_edges >= 24);
    assert!(report.induction_closed);
}

#[test]
fn control_only_leak_is_classified_at_o2_with_a_minimum_two_call_witness() {
    let ProductVerdict::Counterexample(counterexample) =
        check(Mutant::ControlAtSecondCall, ProductLimits::default())
    else {
        panic!("control leak must produce a counterexample");
    };
    assert_eq!(counterexample.observer, ObserverProfile::O2Control);
    assert_eq!(counterexample.family, ContextFamily::Deadline);
    assert_eq!(counterexample.private_pair, pairs()[0]);
    assert_eq!(counterexample.call_sequence.len(), 2);
    assert_eq!(counterexample.divergence, DivergenceKind::ObserverTrace);
    assert_eq!(counterexample.shared_emitted_action, Some(7));
    assert!(counterexample.shared_action.is_some());
}

#[test]
fn source_and_state_relation_divergences_are_not_hidden_by_observer_projection() {
    let ProductVerdict::Counterexample(source) =
        check(Mutant::SourceAtFirstCall, ProductLimits::default())
    else {
        panic!("source divergence must fail");
    };
    assert_eq!(source.observer, ObserverProfile::O0Api);
    assert_eq!(source.family, ContextFamily::Retry);
    assert_eq!(source.call_sequence.len(), 1);
    assert_eq!(source.divergence, DivergenceKind::SourceTrace);

    let ProductVerdict::Counterexample(relation) =
        check(Mutant::RelationLost, ProductLimits::default())
    else {
        panic!("relation loss must fail");
    };
    assert_eq!(relation.family, ContextFamily::Tick);
    assert_eq!(relation.divergence, DivergenceKind::StateRelation);
}

#[test]
fn shared_randomness_selects_one_command_for_both_worlds() {
    let ProductVerdict::Counterexample(counterexample) =
        check(Mutant::SourceAtFirstCall, ProductLimits::default())
    else {
        panic!("mutant must fail");
    };
    let call = &counterexample.call_sequence[0];
    assert_eq!(call.randomness, 0);
    assert_eq!(counterexample.shared_action.as_ref(), Some(&call.command));
}

#[test]
fn resource_prefix_and_product_bounds_are_inconclusive() {
    assert!(matches!(
        check(Mutant::ResourceBound, ProductLimits::default()),
        ProductVerdict::Inconclusive(ProductInconclusive::Oracle {
            reason: OracleInconclusive::ResourceBound,
            ..
        })
    ));
    let prefix_limits = ProductLimits {
        max_prefix: 4,
        ..ProductLimits::default()
    };
    assert_eq!(
        check(Mutant::LongChain, prefix_limits),
        ProductVerdict::Inconclusive(ProductInconclusive::PrefixBound { limit: 4 })
    );
    let state_limits = ProductLimits {
        max_product_states: 1,
        ..ProductLimits::default()
    };
    assert_eq!(
        check(Mutant::Valid, state_limits),
        ProductVerdict::Inconclusive(ProductInconclusive::ProductStateBound { limit: 1 })
    );
}

#[test]
fn hard_prefix_gate_is_exactly_256_and_cannot_be_relaxed() {
    assert_eq!(MAX_PREFIX_HARD_LIMIT, 256);
    let limits = ProductLimits {
        max_prefix: 257,
        ..ProductLimits::default()
    };
    assert_eq!(
        check(Mutant::Valid, limits),
        ProductVerdict::Inconclusive(ProductInconclusive::InvalidLimits)
    );
}

#[test]
fn relation_binding_and_non_valid_relation_gate_never_accept() {
    let mut wrong = system(Mutant::Valid);
    wrong.binding.target_ir_digest = digest(90);
    assert_eq!(
        check_context_product(
            &relation_verdict(),
            &wrong,
            &pairs(),
            &contexts(),
            InductionObligations::default(),
            ProductLimits::default(),
        ),
        ProductVerdict::Inconclusive(ProductInconclusive::RelationBinding)
    );

    let invalid = RelationVerdict::Invalid(RelationCounterexample {
        kind: RelationDivergenceKind::ObserverTrace,
        source_state: None,
        flat_input: None,
        pair_left: Some(0),
        pair_right: Some(1),
        event_index: Some(0),
        expected: 0,
        actual: 1,
    });
    assert!(matches!(
        check_context_product(
            &invalid,
            &system(Mutant::Valid),
            &pairs(),
            &contexts(),
            InductionObligations::default(),
            ProductLimits::default(),
        ),
        ProductVerdict::Counterexample(_)
    ));
}

#[test]
fn missing_family_and_noncanonical_pair_are_inconclusive() {
    let mut missing = contexts();
    missing.pop();
    assert!(matches!(
        check_context_product(
            &relation_verdict(),
            &system(Mutant::Valid),
            &pairs(),
            &missing,
            InductionObligations::default(),
            ProductLimits::default(),
        ),
        ProductVerdict::Inconclusive(ProductInconclusive::InvalidContext(_))
    ));
    let bad_pair = [RelationPair { left: 1, right: 0 }];
    assert!(matches!(
        check_context_product(
            &relation_verdict(),
            &system(Mutant::Valid),
            &bad_pair,
            &contexts(),
            InductionObligations::default(),
            ProductLimits::default(),
        ),
        ProductVerdict::Inconclusive(ProductInconclusive::InvalidContext(_))
    ));
}

#[test]
fn observer_specific_unknown_transition_is_not_security_success() {
    assert!(matches!(
        check_context_product_profile(
            &relation_verdict(),
            &system(Mutant::UnknownObservation),
            &pairs(),
            &contexts(),
            ObserverProfile::O0Api,
            InductionObligations::default(),
            ProductLimits::default(),
        ),
        ProductVerdict::Accept(_)
    ));
    assert!(matches!(
        check_context_product_profile(
            &relation_verdict(),
            &system(Mutant::UnknownObservation),
            &pairs(),
            &contexts(),
            ObserverProfile::O5CombinedService,
            InductionObligations::default(),
            ProductLimits::default(),
        ),
        ProductVerdict::Inconclusive(ProductInconclusive::UnknownObservation { .. })
    ));
}

#[test]
fn finite_closure_without_all_induction_obligations_is_inconclusive() {
    let induction = InductionObligations {
        resource_progress: false,
        ..InductionObligations::default()
    };
    assert_eq!(
        check_context_product(
            &relation_verdict(),
            &system(Mutant::Valid),
            &pairs(),
            &contexts(),
            induction,
            ProductLimits::default(),
        ),
        ProductVerdict::Inconclusive(ProductInconclusive::InductionNotClosed)
    );
}

#[test]
fn shortest_counterexample_artifact_is_byte_reproducible() {
    let ProductVerdict::Counterexample(first) =
        check(Mutant::ControlAtSecondCall, ProductLimits::default())
    else {
        panic!("mutant must fail");
    };
    let ProductVerdict::Counterexample(second) =
        check(Mutant::ControlAtSecondCall, ProductLimits::default())
    else {
        panic!("mutant must fail reproducibly");
    };
    assert_eq!(first, second);
    assert_eq!(first.encode(), second.encode());
    assert_eq!(first.digest(), second.digest());
}

#[test]
fn frozen_contract_names_fail_closed_boundary_and_nonclaims() {
    let contract = include_str!("../../../configs/quotient_seal/context_product_v1.yaml");
    let schema = include_str!("../../../schemas/quotient_seal_context_product_v1.schema.json");
    let documentation = include_str!("../../../docs/quotient_seal_context_product.md");
    for required in [
        "QUOTIENT_SEAL_CONTEXT_PRODUCT_V1",
        "CANONICAL_BFS",
        "SHORTEST_THEN_LEXICOGRAPHIC",
        "INCONCLUSIVE",
        "maximum_prefix_hard_limit: 256",
        "SERVICE_COLLUSION",
        "CROSS_SERVICE_REPLAY",
        "NOT_VERIFIED",
    ] {
        assert!(contract.contains(required), "contract missing {required}");
    }
    assert!(schema.contains("QUOTIENT_SEAL_CONTEXT_PRODUCT_V1"));
    assert!(documentation.contains("candidate"));
    assert!(documentation.contains("NOT_VERIFIED"));
    assert!(!documentation.contains("world-first"));
}
