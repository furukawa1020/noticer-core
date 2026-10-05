use quotient_forge_solver::{
    compare_solver_models, parse_solver_output_bounded, ModelDifferentialStatus, ParseModelError,
    SolverOutputLimits,
};

fn variables() -> Vec<String> {
    vec!["x".to_owned(), "y".to_owned()]
}

#[test]
fn equivalent_smt_and_qdimacs_models_agree() {
    let smt = "sat (model (define-fun x () Int 1) (define-fun y () Int 0))";
    let qdimacs = "s cnf 1 2 0\nV 1 -2 0\n";
    let report = compare_solver_models(smt, qdimacs, &variables(), SolverOutputLimits::default());
    assert_eq!(report.status, ModelDifferentialStatus::Agree);
}

#[test]
fn duplicate_conflicting_partial_and_status_mismatch_do_not_agree() {
    let smt = "sat (model (define-fun x () Int 1) (define-fun y () Int 0))";
    for qdimacs in [
        "s cnf 1 2 0\nV 1 1 -2 0\n",
        "s cnf 1 2 0\nV 1 -1 -2 0\n",
        "s cnf 1 2 0\nV 1 0\n",
        "s cnf 0 2 0\n",
    ] {
        assert_ne!(
            compare_solver_models(smt, qdimacs, &variables(), SolverOutputLimits::default()).status,
            ModelDifferentialStatus::Agree
        );
    }
}

#[test]
fn bytes_tokens_atoms_depth_and_variables_are_bounded() {
    let base = SolverOutputLimits {
        max_bytes: 32,
        max_tokens: 4,
        max_atom_bytes: 4,
        max_depth: 2,
        max_variables: 1,
    };
    for (output, variables) in [
        ("x".repeat(33), vec![]),
        ("sat a b c d".to_owned(), vec![]),
        ("sat longx".to_owned(), vec![]),
        ("sat ((()))".to_owned(), vec![]),
        ("unsat".to_owned(), vec!["x".to_owned(), "y".to_owned()]),
    ] {
        assert!(matches!(
            parse_solver_output_bounded(&output, &variables, base),
            Err(ParseModelError::ResourceLimit(_))
        ));
    }
}
