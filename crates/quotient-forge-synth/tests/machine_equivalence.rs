use quotient_forge_synth::machine_equivalence::{
    canonical_machine_sha256, canonicalize_release_machine, compare_to_author_template,
    CanonicalizationError, TemplateRelation,
};
use quotient_forge_synth::{MachineCell, ReleaseMachine};

fn machine(state_count: u32, symbol_count: u32, cells: &[(u32, u32)]) -> ReleaseMachine {
    ReleaseMachine {
        state_count,
        symbol_count,
        cells: cells
            .iter()
            .map(|(next_state, output)| MachineCell {
                next_state: *next_state,
                output: *output,
            })
            .collect(),
    }
}

#[test]
fn state_renaming_and_unreachable_states_have_one_canonical_form() {
    let compact = machine(3, 2, &[(1, 0), (2, 1), (1, 2), (2, 3), (2, 4), (1, 5)]);
    let renamed_with_unreachable = machine(
        5,
        2,
        &[
            (3, 0),
            (1, 1),
            (1, 4),
            (3, 5),
            (2, 90),
            (2, 91),
            (3, 2),
            (1, 3),
            (4, 92),
            (4, 93),
        ],
    );
    assert_eq!(
        canonicalize_release_machine(&compact).unwrap(),
        canonicalize_release_machine(&renamed_with_unreachable).unwrap()
    );
    assert_eq!(
        canonical_machine_sha256(&compact).unwrap(),
        canonical_machine_sha256(&renamed_with_unreachable).unwrap()
    );
    assert_eq!(
        compare_to_author_template(&renamed_with_unreachable, Some(&compact)).unwrap(),
        TemplateRelation::Equivalent
    );
}

#[test]
fn observable_or_transition_changes_are_not_equivalent() {
    let base = machine(2, 2, &[(1, 0), (0, 1), (1, 2), (0, 3)]);
    let output_changed = machine(2, 2, &[(1, 0), (0, 9), (1, 2), (0, 3)]);
    let transition_changed = machine(2, 2, &[(1, 0), (1, 1), (1, 2), (0, 3)]);
    assert_eq!(
        compare_to_author_template(&output_changed, Some(&base)).unwrap(),
        TemplateRelation::NonEquivalent
    );
    assert_eq!(
        compare_to_author_template(&transition_changed, Some(&base)).unwrap(),
        TemplateRelation::NonEquivalent
    );
}

#[test]
fn no_template_still_requires_a_well_formed_discovered_machine() {
    let valid = machine(1, 1, &[(0, 0)]);
    assert_eq!(
        compare_to_author_template(&valid, None).unwrap(),
        TemplateRelation::NoTemplate
    );
    let malformed = machine(1, 1, &[(1, 0)]);
    assert!(matches!(
        compare_to_author_template(&malformed, None),
        Err(CanonicalizationError::UnknownTarget { .. })
    ));
}
