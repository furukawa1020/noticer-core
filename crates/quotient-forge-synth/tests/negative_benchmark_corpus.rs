use std::fs;
use std::path::PathBuf;

use quotient_forge_check::{check, CheckLimits, CheckOutcome};
use quotient_forge_syntax::{format_module, parse_module, ParseLimits};
use quotient_forge_synth::negative_benchmark::{
    negative_benchmark_cases, NegativeExpectedStatus, NegativeLowering, RefutationReason,
    NEGATIVE_BENCHMARK_FAMILY_IDS,
};
use quotient_forge_synth::{
    find_feasible, MachineCell, ReleaseMachine, SynthesisLimits, SynthesisOutcome,
};
use quotient_forge_types::check_module;

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../configs/quotient_forge/benchmark_cases/negative")
}

#[test]
fn invalid_and_bounded_negative_cases_remain_disjoint() {
    let cases = negative_benchmark_cases();
    assert_eq!(cases.len(), NEGATIVE_BENCHMARK_FAMILY_IDS.len());
    assert_eq!(
        cases.iter().map(|case| case.family_id).collect::<Vec<_>>(),
        NEGATIVE_BENCHMARK_FAMILY_IDS
    );
    for case in cases {
        let path = corpus_dir().join(format!("{}.qf", case.family_id));
        let source = fs::read_to_string(&path).unwrap();
        let parsed = parse_module(
            path.to_string_lossy().as_ref(),
            &source,
            ParseLimits::default(),
        )
        .unwrap_or_else(|diagnostics| panic!("{}: {diagnostics:?}", case.family_id));
        assert_eq!(format_module(&parsed), source, "{}", case.family_id);
        let typed = check_module(path.to_string_lossy().as_ref(), &parsed);
        match case.lowering {
            NegativeLowering::InvalidSpec { diagnostic_code } => {
                assert_eq!(case.expected_status, NegativeExpectedStatus::InvalidSpec);
                let diagnostics = typed.expect_err(case.family_id);
                assert!(
                    diagnostics.iter().any(|item| item.code == diagnostic_code),
                    "{}: {diagnostics:?}",
                    case.family_id
                );
            }
            NegativeLowering::Bounded {
                problem,
                state_bound,
            } => {
                assert_eq!(case.expected_status, NegativeExpectedStatus::UnsatAtBound);
                typed.unwrap_or_else(|diagnostics| panic!("{}: {diagnostics:?}", case.family_id));
                problem.validate().unwrap();
                let outcome = find_feasible(
                    &problem,
                    SynthesisLimits {
                        max_states: state_bound,
                        ..SynthesisLimits::default()
                    },
                )
                .unwrap();
                assert!(matches!(outcome, SynthesisOutcome::Unrealizable(_)));

                let output = usize::from(case.reason == RefutationReason::UnauthorizedCoverAction);
                let candidate = ReleaseMachine {
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
                    &problem.lower_candidate(&candidate).unwrap(),
                    CheckLimits::default(),
                )
                .unwrap();
                assert!(matches!(checked, CheckOutcome::Counterexample(_)));
            }
        }
    }
}

#[test]
fn every_negative_has_one_machine_readable_refutation_reason() {
    let cases = negative_benchmark_cases();
    let reasons = cases
        .iter()
        .map(|case| case.reason.code())
        .collect::<Vec<_>>();
    assert_eq!(reasons.len(), 8);
    assert_eq!(
        reasons
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        8
    );
}
