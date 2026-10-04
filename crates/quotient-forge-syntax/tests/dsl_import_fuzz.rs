use quotient_forge_syntax::{run_dsl_import_fuzz, DslFuzzError, DslFuzzLimits};

fn limits() -> DslFuzzLimits {
    DslFuzzLimits {
        max_input_bytes: 4_096,
        max_cases: 128,
        max_tokens: 1_024,
        max_imports: 32,
        max_import_depth: 8,
    }
}

#[test]
fn arbitrary_bytes_and_utf8_boundaries_are_bounded_and_reproducible() {
    let corpus = vec![
        b"module valid version 1 { horizon 1; }".to_vec(),
        vec![0, 0xff, 0xc0, b'{', b'}'],
        vec![b'{'; 4_097],
    ];
    let first = run_dsl_import_fuzz(0x04b3_715b, &corpus, limits()).unwrap();
    let second = run_dsl_import_fuzz(0x04b3_715b, &corpus, limits()).unwrap();

    assert_eq!(first, second);
    assert_eq!(first.executed_cases, 2);
    assert_eq!(first.resource_rejections, 1);
    assert_eq!(first.invalid_utf8_cases, 1);
    assert_eq!(first.accepted_modules, 1);
    assert_eq!(first.rejected_modules, 1);
}

#[test]
fn graph_suite_covers_cycle_depth_and_path_escape_fail_closed() {
    let report = run_dsl_import_fuzz(7, &[], limits()).unwrap();

    assert_eq!(report.graph_acceptances, 1);
    assert_eq!(report.graph_rejections, 5);
    for category in [
        "graph_acyclic_accept",
        "import_cycle",
        "parent_path_escape",
        "absolute_path_escape",
        "backslash_path_escape",
        "import_depth",
    ] {
        assert!(report.coverage.contains(category));
    }
    assert!(!report.coverage.contains("unexpected_graph_accept"));
    assert!(!report.coverage.contains("unexpected_graph_reject"));
}

#[test]
fn invalid_budget_and_oversized_corpus_fail_before_execution() {
    let invalid = DslFuzzLimits {
        max_input_bytes: 0,
        ..limits()
    };
    assert_eq!(
        run_dsl_import_fuzz(1, &[], invalid),
        Err(DslFuzzError::InvalidLimits)
    );

    let corpus = vec![Vec::new(); limits().max_cases + 1];
    assert_eq!(
        run_dsl_import_fuzz(1, &corpus, limits()),
        Err(DslFuzzError::TooManyCases)
    );
}
