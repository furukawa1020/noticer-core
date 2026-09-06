use quotient_forge_synth::lift::{
    lift_reduced_candidate, LiftCheckerDecision, LiftMapEntry, LiftMapping, LiftedCandidate,
    LiftedCandidateChecker, QuotientLiftError, ReducedCandidate, ReducedPolicyCell,
};
use quotient_forge_synth::preservation::{
    check_quotient_preservation, FaultTransition, ObserverEvent, PreservationLimits,
    PreservationState, QuotientPreservationArtifact,
};
use quotient_forge_synth::quotient::{
    build_quotient_partition, derive_action_equivalence, ActionSemanticAtom, ActionSemantics,
    QuotientPartition, QuotientState,
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

fn candidate(class_count: u32) -> ReducedCandidate {
    let mut cells = Vec::new();
    for control_state in 0..2 {
        for class_id in 0..class_count {
            cells.push(
                ReducedPolicyCell::new(
                    control_state,
                    class_id,
                    0,
                    (control_state + 1) % 2,
                    sha256(20 + (control_state * class_count + class_id) as u8),
                )
                .unwrap(),
            );
        }
    }
    ReducedCandidate::new(2, class_count, 1, cells).unwrap()
}

struct FixedChecker(LiftCheckerDecision);

impl LiftedCandidateChecker for FixedChecker {
    fn check(
        &self,
        partition: &QuotientPartition,
        mapping: &LiftMapping,
        reduced_candidate: &ReducedCandidate,
        lifted_candidate: &LiftedCandidate,
    ) -> LiftCheckerDecision {
        assert_eq!(mapping.entries().len(), partition.mapped_state_count());
        assert_eq!(reduced_candidate.cells.len(), 4);
        assert_eq!(lifted_candidate.cells.len(), 6);
        self.0
    }
}

#[test]
fn lifts_each_class_cell_to_every_source_and_requires_checker_acceptance() {
    let partition = partition();
    let preservation = preservation(&partition);
    let mapping = LiftMapping::from_partition(&partition).unwrap();
    let reduced = candidate(partition.artifact.classes.len() as u32);
    let result = lift_reduced_candidate(
        sha256(240),
        &partition,
        &preservation,
        &mapping,
        &reduced,
        &FixedChecker(LiftCheckerDecision::Valid),
    )
    .unwrap();

    assert!(result.artifact.accepted);
    assert_eq!(result.artifact.checker_calls, 1);
    assert_eq!(result.artifact.reduced_cell_count, 4);
    assert_eq!(result.artifact.lifted_cell_count, 6);
    assert_eq!(
        result.lifted_candidate.cells[0].output_sha256,
        result.lifted_candidate.cells[1].output_sha256
    );
    assert!(!result.artifact.source_indices_included);
    result.artifact.validate().unwrap();
}

#[test]
fn missing_duplicate_and_wrong_mapping_entries_fail_closed() {
    let partition = partition();
    let preservation = preservation(&partition);
    let reduced = candidate(partition.artifact.classes.len() as u32);
    let correct = LiftMapping::from_partition(&partition).unwrap();
    let mut missing = correct.entries().to_vec();
    missing.pop();
    let missing = LiftMapping::new(
        sha256(240),
        partition.artifact.artifact_sha256.clone(),
        missing,
    )
    .unwrap();
    assert_eq!(
        lift_reduced_candidate(
            sha256(240),
            &partition,
            &preservation,
            &missing,
            &reduced,
            &FixedChecker(LiftCheckerDecision::Valid),
        )
        .unwrap_err(),
        QuotientLiftError::MappingNotTotal
    );

    let first = correct.entries()[0];
    assert_eq!(
        LiftMapping::new(
            sha256(240),
            partition.artifact.artifact_sha256.clone(),
            vec![first, first],
        )
        .unwrap_err(),
        QuotientLiftError::DuplicateMappingSource
    );

    let mut wrong_entries = correct.entries().to_vec();
    wrong_entries[0].class_id = (wrong_entries[0].class_id + 1) % 2;
    let wrong = LiftMapping::new(
        sha256(240),
        partition.artifact.artifact_sha256.clone(),
        wrong_entries,
    )
    .unwrap();
    assert_eq!(
        lift_reduced_candidate(
            sha256(240),
            &partition,
            &preservation,
            &wrong,
            &reduced,
            &FixedChecker(LiftCheckerDecision::Valid),
        )
        .unwrap_err(),
        QuotientLiftError::IncorrectMappingClass
    );
}

#[test]
fn stale_mapping_is_rejected_before_lift_generation() {
    let partition = partition();
    let preservation = preservation(&partition);
    let reduced = candidate(partition.artifact.classes.len() as u32);
    let mapping = LiftMapping::new(
        sha256(239),
        partition.artifact.artifact_sha256.clone(),
        partition
            .source_class_pairs()
            .map(|(source_index, class_id)| LiftMapEntry::new(source_index, class_id))
            .collect(),
    )
    .unwrap();
    assert_eq!(
        lift_reduced_candidate(
            sha256(240),
            &partition,
            &preservation,
            &mapping,
            &reduced,
            &FixedChecker(LiftCheckerDecision::Valid),
        )
        .unwrap_err(),
        QuotientLiftError::StaleMappingProblem
    );
}

#[test]
fn invalid_and_inconclusive_checker_results_are_never_accepted() {
    let partition = partition();
    let preservation = preservation(&partition);
    let mapping = LiftMapping::from_partition(&partition).unwrap();
    let reduced = candidate(partition.artifact.classes.len() as u32);
    for decision in [
        LiftCheckerDecision::Invalid,
        LiftCheckerDecision::Inconclusive,
    ] {
        let result = lift_reduced_candidate(
            sha256(240),
            &partition,
            &preservation,
            &mapping,
            &reduced,
            &FixedChecker(decision),
        )
        .unwrap();
        assert_eq!(result.artifact.checker_decision, decision);
        assert!(!result.artifact.accepted);
    }
}

#[test]
fn non_total_reduced_candidate_is_rejected() {
    let cells = vec![ReducedPolicyCell::new(0, 0, 0, 0, sha256(10)).unwrap()];
    assert_eq!(
        ReducedCandidate::new(1, 2, 1, cells).unwrap_err(),
        QuotientLiftError::ReducedCandidateNotTotal
    );
}
