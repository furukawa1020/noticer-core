use std::collections::BTreeMap;

use quotient_forge_synth::lift::{LiftCheckerDecision, LiftMapping, ReducedCandidate};
use quotient_forge_synth::preservation::{
    check_quotient_preservation, FaultTransition, ObserverEvent, PreservationLimits,
    PreservationState, QuotientPreservationArtifact,
};
use quotient_forge_synth::quotient::{
    build_quotient_partition, derive_action_equivalence, ActionSemanticAtom, ActionSemantics,
    QuotientPartition, QuotientState,
};
use quotient_forge_synth::solution_set::{
    compare_small_model_solution_sets, FrozenEnumerationDomain, SmallModelSolutionChecker,
    SolutionDifferenceKind, SolutionSetStatus, SourceCandidate,
};

fn sha256(value: u8) -> String {
    format!("{value:064x}")
}

fn semantics(action: u8) -> ActionSemantics {
    ActionSemantics::new(vec![
        ActionSemanticAtom::new(sha256(1), sha256(action)).unwrap()
    ])
    .unwrap()
}

fn partition() -> QuotientPartition {
    let states = vec![
        QuotientState::new(10, "private-a", semantics(20)).unwrap(),
        QuotientState::new(20, "private-b", semantics(20)).unwrap(),
        QuotientState::new(30, "private-c", semantics(40)).unwrap(),
    ];
    let relation = derive_action_equivalence(&states).unwrap();
    build_quotient_partition(sha256(240), &states, &relation).unwrap()
}

fn preservation(partition: &QuotientPartition) -> QuotientPreservationArtifact {
    let observer = |value| vec![ObserverEvent::new(sha256(2), sha256(value)).unwrap()];
    let fault = |target| vec![FaultTransition::new(sha256(3), target, sha256(4)).unwrap()];
    let states = vec![
        PreservationState::new(10, observer(5), vec![sha256(6)], fault(30)).unwrap(),
        PreservationState::new(20, observer(5), vec![sha256(6)], fault(30)).unwrap(),
        PreservationState::new(30, observer(7), vec![sha256(8)], fault(10)).unwrap(),
    ];
    check_quotient_preservation(
        sha256(240),
        partition,
        &states,
        &PreservationLimits { max_state_pairs: 4 },
    )
    .unwrap()
    .artifact
}

#[derive(Clone, Copy)]
enum CheckerMode {
    Exact,
    MissingZero,
    SpuriousOne,
    InconclusiveZero,
}

struct EquivalenceChecker {
    source_classes: Vec<u32>,
    mode: CheckerMode,
}

impl EquivalenceChecker {
    fn new(partition: &QuotientPartition, mode: CheckerMode) -> Self {
        Self {
            source_classes: partition
                .source_class_pairs()
                .map(|(_, class_id)| class_id)
                .collect(),
            mode,
        }
    }

    fn is_class_uniform(&self, candidate: &SourceCandidate) -> bool {
        let mut decisions = BTreeMap::new();
        for cell in &candidate.cells {
            let class_id = self.source_classes[cell.source_ordinal as usize];
            let key = (cell.control_state, class_id, cell.symbol_id);
            let decision = (cell.next_control_state, &cell.output_sha256);
            if decisions
                .insert(key, decision)
                .is_some_and(|prior| prior != decision)
            {
                return false;
            }
        }
        true
    }
}

impl SmallModelSolutionChecker for EquivalenceChecker {
    fn check_unreduced(&self, candidate: &SourceCandidate) -> LiftCheckerDecision {
        if !self.is_class_uniform(candidate) {
            return LiftCheckerDecision::Invalid;
        }
        if matches!(self.mode, CheckerMode::SpuriousOne)
            && candidate
                .cells
                .iter()
                .all(|cell| cell.output_sha256 == sha256(1))
        {
            return LiftCheckerDecision::Invalid;
        }
        LiftCheckerDecision::Valid
    }

    fn check_reduced(&self, candidate: &ReducedCandidate) -> LiftCheckerDecision {
        let all_zero = candidate
            .cells
            .iter()
            .all(|cell| cell.output_sha256 == sha256(0));
        if all_zero && matches!(self.mode, CheckerMode::MissingZero) {
            LiftCheckerDecision::Invalid
        } else if all_zero && matches!(self.mode, CheckerMode::InconclusiveZero) {
            LiftCheckerDecision::Inconclusive
        } else {
            LiftCheckerDecision::Valid
        }
    }
}

fn domain(seed: u64) -> FrozenEnumerationDomain {
    FrozenEnumerationDomain::new(seed, 1, 1, 2, 100).unwrap()
}

fn run(mode: CheckerMode) -> quotient_forge_synth::solution_set::SolutionSetEquivalenceArtifact {
    let partition = partition();
    let preservation = preservation(&partition);
    let mapping = LiftMapping::from_partition(&partition).unwrap();
    compare_small_model_solution_sets(
        sha256(240),
        domain(17),
        &partition,
        &preservation,
        &mapping,
        &EquivalenceChecker::new(&partition, mode),
    )
    .unwrap()
}

#[test]
fn exhaustive_sets_match_after_quotient_lift() {
    let artifact = run(CheckerMode::Exact);
    assert_eq!(artifact.status, SolutionSetStatus::Pass);
    assert!(artifact.sets_equal);
    assert_eq!(artifact.unreduced_generated_candidates, 8);
    assert_eq!(artifact.reduced_generated_candidates, 4);
    assert_eq!(artifact.unreduced_solution_sha256.len(), 4);
    assert_eq!(
        artifact.unreduced_solution_sha256,
        artifact.reduced_lifted_solution_sha256
    );
    assert_eq!(artifact.checker_disagreement_count, 0);
    artifact.validate().unwrap();
}

#[test]
fn missing_solution_gets_its_own_witness_and_never_passes() {
    let artifact = run(CheckerMode::MissingZero);
    assert_eq!(artifact.status, SolutionSetStatus::Fail);
    assert_eq!(artifact.missing_solution_sha256.len(), 1);
    assert!(artifact.spurious_solution_sha256.is_empty());
    assert_eq!(
        artifact.missing_witness.as_ref().unwrap().kind,
        SolutionDifferenceKind::Missing
    );
}

#[test]
fn spurious_solution_gets_its_own_witness_and_never_passes() {
    let artifact = run(CheckerMode::SpuriousOne);
    assert_eq!(artifact.status, SolutionSetStatus::Fail);
    assert!(artifact.missing_solution_sha256.is_empty());
    assert_eq!(artifact.spurious_solution_sha256.len(), 1);
    assert_eq!(
        artifact.spurious_witness.as_ref().unwrap().kind,
        SolutionDifferenceKind::Spurious
    );
}

#[test]
fn checker_inconclusive_has_priority_over_set_comparison() {
    let artifact = run(CheckerMode::InconclusiveZero);
    assert_eq!(artifact.status, SolutionSetStatus::Inconclusive);
    assert!(artifact.checker_inconclusive_count > 0);
}

#[test]
fn same_seed_and_domain_produce_byte_identical_artifacts() {
    let first = run(CheckerMode::Exact);
    let second = run(CheckerMode::Exact);
    assert_eq!(first, second);
    assert_eq!(
        serde_json::to_vec(&first).unwrap(),
        serde_json::to_vec(&second).unwrap()
    );
}
