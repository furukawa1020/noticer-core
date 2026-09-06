use quotient_forge_synth::symmetry::{
    canonicalize_state_symmetry, verify_state_renaming, MachineCheckDecision, StateRename,
    SymmetryCell, SymmetryError, SymmetryLimits, SymmetryMachine, SymmetryMachineChecker,
};

fn sha256(value: u8) -> String {
    format!("{value:064x}")
}

fn machine() -> SymmetryMachine {
    let transitions = [
        (0, 0, 1, 10),
        (0, 1, 0, 11),
        (1, 0, 1, 12),
        (1, 1, 0, 13),
        (2, 0, 3, 20),
        (2, 1, 0, 21),
        (3, 0, 2, 22),
        (3, 1, 1, 23),
    ];
    SymmetryMachine::new(
        4,
        2,
        0,
        transitions
            .into_iter()
            .map(|(state, symbol, next, output)| {
                SymmetryCell::new(state, symbol, next, sha256(output)).unwrap()
            })
            .collect(),
    )
    .unwrap()
}

fn permute(machine: &SymmetryMachine, mapping: &[u32]) -> SymmetryMachine {
    SymmetryMachine::new(
        machine.state_count,
        machine.symbol_count,
        mapping[machine.initial_state as usize],
        machine
            .cells
            .iter()
            .map(|cell| {
                SymmetryCell::new(
                    mapping[cell.state as usize],
                    cell.symbol,
                    mapping[cell.next_state as usize],
                    cell.output_sha256.clone(),
                )
                .unwrap()
            })
            .collect(),
    )
    .unwrap()
}

fn limits() -> SymmetryLimits {
    SymmetryLimits {
        max_unreachable_states: 6,
        max_unreachable_permutations: 720,
    }
}

struct AlwaysValid;

impl SymmetryMachineChecker for AlwaysValid {
    fn check(&mut self, _machine: &SymmetryMachine) -> MachineCheckDecision {
        MachineCheckDecision::Valid
    }
}

#[test]
fn every_state_renaming_has_the_same_canonical_machine_digest() {
    let original = machine();
    let renamed = permute(&original, &[2, 3, 0, 1]);
    let first = canonicalize_state_symmetry(&original, &limits(), &mut AlwaysValid).unwrap();
    let second = canonicalize_state_symmetry(&renamed, &limits(), &mut AlwaysValid).unwrap();

    assert_eq!(first.canonical_machine, second.canonical_machine);
    assert_eq!(
        first.artifact.canonical_machine_sha256,
        second.artifact.canonical_machine_sha256
    );
    assert!(first.artifact.canonicalization_enabled);
    assert_eq!(first.artifact.reachable_state_count, 2);
    assert_eq!(first.artifact.unreachable_state_count, 2);
    assert_eq!(first.artifact.unreachable_permutations_evaluated, 2);
    assert!(verify_state_renaming(&original, &first.canonical_machine, first.witness()).unwrap());
    assert!(!first.artifact.witness_persisted);
}

#[test]
fn non_isomorphic_output_machine_does_not_share_a_representative() {
    let original = machine();
    let mut changed = machine();
    changed.cells[0].output_sha256 = sha256(99);
    let first = canonicalize_state_symmetry(&original, &limits(), &mut AlwaysValid).unwrap();
    let second = canonicalize_state_symmetry(&changed, &limits(), &mut AlwaysValid).unwrap();

    assert_ne!(
        first.artifact.canonical_machine_sha256,
        second.artifact.canonical_machine_sha256
    );
}

struct AlternatingChecker {
    calls: u8,
}

impl SymmetryMachineChecker for AlternatingChecker {
    fn check(&mut self, _machine: &SymmetryMachine) -> MachineCheckDecision {
        self.calls += 1;
        if self.calls == 1 {
            MachineCheckDecision::Valid
        } else {
            MachineCheckDecision::Invalid
        }
    }
}

#[test]
fn checker_disagreement_disables_canonicalization() {
    let result =
        canonicalize_state_symmetry(&machine(), &limits(), &mut AlternatingChecker { calls: 0 })
            .unwrap();

    assert!(!result.artifact.decision_preserved);
    assert!(!result.artifact.canonicalization_enabled);
    assert_eq!(result.artifact.checker_calls, 2);
}

#[test]
fn malformed_witness_and_permutation_exhaustion_fail_closed() {
    let original = machine();
    let result = canonicalize_state_symmetry(&original, &limits(), &mut AlwaysValid).unwrap();
    let mut witness = result.witness().to_vec();
    witness[0] = StateRename {
        original_state: 0,
        canonical_state: 3,
    };
    assert!(!verify_state_renaming(&original, &result.canonical_machine, &witness).unwrap());

    assert_eq!(
        canonicalize_state_symmetry(
            &original,
            &SymmetryLimits {
                max_unreachable_states: 1,
                max_unreachable_permutations: 720,
            },
            &mut AlwaysValid,
        )
        .unwrap_err(),
        SymmetryError::PermutationLimitExceeded
    );
}

#[test]
fn non_total_machine_is_rejected() {
    assert_eq!(
        SymmetryMachine::new(
            2,
            1,
            0,
            vec![SymmetryCell::new(0, 0, 1, sha256(1)).unwrap()],
        )
        .unwrap_err(),
        SymmetryError::NonTotalMachine
    );
}
