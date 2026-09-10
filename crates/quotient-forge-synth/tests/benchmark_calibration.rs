use std::fs;
use std::path::{Path, PathBuf};

use quotient_forge_check::{check, CheckLimits, CheckOutcome};
use quotient_forge_syntax::{parse_module, ParseLimits};
use quotient_forge_synth::generic_benchmark::{generic_benchmark_cases, GenericBenchmarkSplit};
use quotient_forge_synth::negative_benchmark::{
    negative_benchmark_cases, NegativeBenchmarkSplit, NegativeExpectedStatus, NegativeLowering,
    RefutationReason,
};
use quotient_forge_synth::noticer_benchmark::{noticer_benchmark_cases, BenchmarkSplit};
use quotient_forge_synth::{
    find_feasible, MachineCell, ReleaseMachine, SynthesisLimits, SynthesisOutcome,
};
use quotient_forge_types::check_module;

fn corpus_dir(category: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../configs/quotient_forge/benchmark_cases")
        .join(category)
}

fn parse(path: &Path) -> quotient_forge_syntax::Module {
    let source = fs::read_to_string(path).unwrap();
    parse_module(
        path.to_string_lossy().as_ref(),
        &source,
        ParseLimits::default(),
    )
    .unwrap()
}

#[test]
fn calibration_witnesses_are_verified_by_the_independent_checker() {
    for case in noticer_benchmark_cases() {
        if case.split == BenchmarkSplit::HeldOut {
            assert!(case.author_template.is_none());
            continue;
        }
        let candidate = case.author_template.as_ref().expect(case.family_id);
        let model = case.problem.lower_candidate(candidate).unwrap();
        let outcome = check(&model, CheckLimits::default()).unwrap();
        assert!(
            matches!(outcome, CheckOutcome::Verified(_)),
            "{}",
            case.family_id
        );
    }
    for case in generic_benchmark_cases() {
        if case.split == GenericBenchmarkSplit::HeldOut {
            assert!(case.author_template.is_none());
            continue;
        }
        let candidate = case.author_template.as_ref().expect(case.family_id);
        let model = case.problem.lower_candidate(candidate).unwrap();
        let outcome = check(&model, CheckLimits::default()).unwrap();
        assert!(
            matches!(outcome, CheckOutcome::Verified(_)),
            "{}",
            case.family_id
        );
    }
}

#[test]
fn calibration_negatives_keep_invalid_unsat_and_inconclusive_disjoint() {
    for case in negative_benchmark_cases() {
        if case.split == NegativeBenchmarkSplit::HeldOut {
            continue;
        }
        let path = corpus_dir("negative").join(format!("{}.qf", case.family_id));
        let parsed = parse(&path);
        let typed = check_module(path.to_string_lossy().as_ref(), &parsed);
        match &case.lowering {
            NegativeLowering::InvalidSpec { diagnostic_code } => {
                assert_eq!(case.expected_status, NegativeExpectedStatus::InvalidSpec);
                let diagnostics = typed.expect_err(case.family_id);
                assert!(diagnostics.iter().any(|item| item.code == *diagnostic_code));
            }
            NegativeLowering::Bounded {
                problem,
                state_bound,
            } => {
                assert_eq!(case.expected_status, NegativeExpectedStatus::UnsatAtBound);
                typed.unwrap();
                let synthesis = find_feasible(
                    problem,
                    SynthesisLimits {
                        max_states: *state_bound,
                        ..SynthesisLimits::default()
                    },
                )
                .unwrap();
                assert!(matches!(synthesis, SynthesisOutcome::Unrealizable(_)));

                let output = usize::from(case.reason == RefutationReason::UnauthorizedCoverAction);
                let probe = ReleaseMachine {
                    state_count: 1,
                    symbol_count: problem.machine_symbol_count,
                    cells: vec![
                        MachineCell {
                            next_state: 0,
                            output: u32::try_from(output).unwrap(),
                        };
                        usize::try_from(problem.machine_symbol_count).unwrap()
                    ],
                };
                let checked = check(
                    &problem.lower_candidate(&probe).unwrap(),
                    CheckLimits::default(),
                )
                .unwrap();
                assert!(matches!(checked, CheckOutcome::Counterexample(_)));
            }
        }
    }
}

#[test]
fn held_out_cases_remain_unobserved_during_calibration() {
    assert!(noticer_benchmark_cases()
        .iter()
        .filter(|case| case.split == BenchmarkSplit::HeldOut)
        .all(|case| case.author_template.is_none()));
    assert!(generic_benchmark_cases()
        .iter()
        .filter(|case| case.split == GenericBenchmarkSplit::HeldOut)
        .all(|case| case.author_template.is_none()));
    assert_eq!(
        negative_benchmark_cases()
            .iter()
            .filter(|case| case.split == NegativeBenchmarkSplit::HeldOut)
            .count(),
        3
    );
}
