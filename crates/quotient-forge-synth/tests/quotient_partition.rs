use quotient_forge_synth::quotient::{
    build_quotient_partition, derive_action_equivalence, ActionSemanticAtom, ActionSemantics,
    QuotientError, QuotientState, RelationEdge,
};

fn sha256(value: u8) -> String {
    format!("{value:064x}")
}

fn semantics(action: u8) -> ActionSemantics {
    ActionSemantics::new(vec![
        ActionSemanticAtom::new(sha256(1), sha256(action)).unwrap(),
        ActionSemanticAtom::new(sha256(2), sha256(action.saturating_add(1))).unwrap(),
    ])
    .unwrap()
}

fn states(labels: [&str; 3]) -> Vec<QuotientState> {
    vec![
        QuotientState::new(10, labels[0], semantics(20)).unwrap(),
        QuotientState::new(20, labels[1], semantics(20)).unwrap(),
        QuotientState::new(30, labels[2], semantics(40)).unwrap(),
    ]
}

#[test]
fn partition_is_invariant_to_input_permutation_and_private_label_rename() {
    let first_states = states(["private-a", "private-b", "private-c"]);
    let first_relation = derive_action_equivalence(&first_states).unwrap();
    let first = build_quotient_partition(sha256(240), &first_states, &first_relation).unwrap();

    let mut renamed = states(["renamed-x", "renamed-y", "renamed-z"]);
    renamed.reverse();
    let renamed_relation = derive_action_equivalence(&renamed).unwrap();
    let second = build_quotient_partition(sha256(240), &renamed, &renamed_relation).unwrap();

    assert_eq!(first.artifact, second.artifact);
    assert_eq!(first.mapped_state_count(), 3);
    assert_eq!(
        first.class_for_source_index(10),
        first.class_for_source_index(20)
    );
    assert_ne!(
        first.class_for_source_index(10),
        first.class_for_source_index(30)
    );
    let json = serde_json::to_string(&first.artifact).unwrap();
    assert!(!json.contains("private-a"));
    assert!(!json.contains("private-b"));
    assert!(!json.contains("private-c"));
    assert!(!first.artifact.private_labels_included);
    first.artifact.validate().unwrap();
}

#[test]
fn relation_cannot_merge_different_action_semantics() {
    let states = vec![
        QuotientState::new(0, "left", semantics(20)).unwrap(),
        QuotientState::new(1, "right", semantics(40)).unwrap(),
    ];
    let relation = vec![
        RelationEdge::new(0, 0),
        RelationEdge::new(0, 1),
        RelationEdge::new(1, 0),
        RelationEdge::new(1, 1),
    ];
    assert_eq!(
        build_quotient_partition(sha256(240), &states, &relation).unwrap_err(),
        QuotientError::DifferentActionSemanticsMerged
    );
}

#[test]
fn malformed_equivalence_relations_fail_closed() {
    let states = vec![
        QuotientState::new(0, "a", semantics(20)).unwrap(),
        QuotientState::new(1, "b", semantics(20)).unwrap(),
        QuotientState::new(2, "c", semantics(20)).unwrap(),
    ];
    assert_eq!(
        build_quotient_partition(sha256(240), &states, &[]).unwrap_err(),
        QuotientError::RelationNotReflexive
    );
    let asymmetric = vec![
        RelationEdge::new(0, 0),
        RelationEdge::new(1, 1),
        RelationEdge::new(2, 2),
        RelationEdge::new(0, 1),
    ];
    assert_eq!(
        build_quotient_partition(sha256(240), &states, &asymmetric).unwrap_err(),
        QuotientError::RelationNotSymmetric
    );
    let non_transitive = vec![
        RelationEdge::new(0, 0),
        RelationEdge::new(1, 1),
        RelationEdge::new(2, 2),
        RelationEdge::new(0, 1),
        RelationEdge::new(1, 0),
        RelationEdge::new(1, 2),
        RelationEdge::new(2, 1),
    ];
    assert_eq!(
        build_quotient_partition(sha256(240), &states, &non_transitive).unwrap_err(),
        QuotientError::RelationNotTransitive
    );
}

#[test]
fn equal_action_semantics_cannot_be_split_into_extra_classes() {
    let states = vec![
        QuotientState::new(0, "a", semantics(20)).unwrap(),
        QuotientState::new(1, "b", semantics(20)).unwrap(),
    ];
    let split = vec![RelationEdge::new(0, 0), RelationEdge::new(1, 1)];
    assert_eq!(
        build_quotient_partition(sha256(240), &states, &split).unwrap_err(),
        QuotientError::EquivalentSemanticsSeparated
    );
}

#[test]
fn duplicate_edges_and_indices_are_rejected() {
    let duplicate_states = vec![
        QuotientState::new(0, "a", semantics(20)).unwrap(),
        QuotientState::new(0, "b", semantics(20)).unwrap(),
    ];
    assert_eq!(
        derive_action_equivalence(&duplicate_states).unwrap_err(),
        QuotientError::DuplicateSourceIndex
    );
    let states = vec![QuotientState::new(0, "a", semantics(20)).unwrap()];
    let duplicate_relation = vec![RelationEdge::new(0, 0), RelationEdge::new(0, 0)];
    assert_eq!(
        build_quotient_partition(sha256(240), &states, &duplicate_relation).unwrap_err(),
        QuotientError::DuplicateRelationEdge
    );
}
