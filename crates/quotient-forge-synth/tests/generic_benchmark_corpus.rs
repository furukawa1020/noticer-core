use std::fs;
use std::path::PathBuf;

use quotient_forge_check::{check, CheckLimits, CheckOutcome};
use quotient_forge_syntax::{format_module, parse_module, ParseLimits};
use quotient_forge_synth::generic_benchmark::{
    generic_benchmark_cases, GenericBenchmarkSplit, GENERIC_BENCHMARK_FAMILY_IDS,
};
use quotient_forge_synth::{MachineCell, ReleaseMachine};
use quotient_forge_types::check_module;

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../configs/quotient_forge/benchmark_cases/generic")
}

#[test]
fn all_generic_sources_parse_typecheck_and_lower_to_the_independent_checker() {
    let cases = generic_benchmark_cases();
    assert_eq!(cases.len(), GENERIC_BENCHMARK_FAMILY_IDS.len());
    assert_eq!(
        cases.iter().map(|case| case.family_id).collect::<Vec<_>>(),
        GENERIC_BENCHMARK_FAMILY_IDS
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
        let typed = check_module(path.to_string_lossy().as_ref(), &parsed)
            .unwrap_or_else(|diagnostics| panic!("{}: {diagnostics:?}", case.family_id));
        assert_eq!(typed.name, case.family_id);
        assert_eq!(typed.horizon, u64::from(case.problem.horizon));
        assert_eq!(typed.observers.len(), case.problem.observers.len());

        case.problem.validate().unwrap();
        let candidate = case
            .author_template
            .clone()
            .unwrap_or_else(|| ReleaseMachine {
                state_count: 1,
                symbol_count: case.problem.machine_symbol_count,
                cells: vec![
                    MachineCell {
                        next_state: 0,
                        output: 0,
                    };
                    usize::try_from(case.problem.machine_symbol_count).unwrap()
                ],
            });
        let outcome = check(
            &case.problem.lower_candidate(&candidate).unwrap(),
            CheckLimits::default(),
        )
        .unwrap();
        if case.split == GenericBenchmarkSplit::HeldOut {
            assert!(!matches!(outcome, CheckOutcome::Inconclusive(_)));
        } else {
            assert!(
                matches!(outcome, CheckOutcome::Verified(_)),
                "{}",
                case.family_id
            );
        }
    }
}

#[test]
fn held_out_generic_cases_have_no_author_template() {
    let cases = generic_benchmark_cases();
    assert_eq!(
        cases
            .iter()
            .filter(|case| case.split == GenericBenchmarkSplit::HeldOut)
            .count(),
        3
    );
    assert!(cases
        .iter()
        .filter(|case| case.split == GenericBenchmarkSplit::HeldOut)
        .all(|case| case.author_template.is_none()));
}
