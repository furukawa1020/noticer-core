use quotient_forge_synth::unsat_core::{
    audit_unsat_core, AssertionNamespace, AssertionSpec, BoundedDecisionRecord,
    CoreDiagnosticReason, CoreDiagnosticStatus, CoreRecheckDecision, NamedAssertion,
    NamedAssertionRegistry, SolverCoreReport, UnsatCoreAuditContext, UnsatCoreInputError,
    UnsatCoreRechecker,
};

fn sha256(value: u8) -> String {
    format!("{value:064x}")
}

fn context() -> UnsatCoreAuditContext {
    UnsatCoreAuditContext {
        problem_sha256: sha256(240),
        epoch: 9,
    }
}

fn registry() -> NamedAssertionRegistry {
    NamedAssertionRegistry::new(vec![
        AssertionSpec::hard_obligation(AssertionNamespace::Utility, sha256(3), sha256(13)).unwrap(),
        AssertionSpec::hard_obligation(AssertionNamespace::Security, sha256(2), sha256(12))
            .unwrap(),
        AssertionSpec::hard_obligation(AssertionNamespace::Security, sha256(1), sha256(11))
            .unwrap(),
        AssertionSpec::hard_obligation(AssertionNamespace::Fault, sha256(4), sha256(14)).unwrap(),
    ])
    .unwrap()
}

#[test]
fn canonical_names_are_deterministic_and_uniquely_resolvable() {
    let first = registry();
    let second = NamedAssertionRegistry::new(vec![
        AssertionSpec::hard_obligation(AssertionNamespace::Fault, sha256(4), sha256(14)).unwrap(),
        AssertionSpec::hard_obligation(AssertionNamespace::Security, sha256(1), sha256(11))
            .unwrap(),
        AssertionSpec::hard_obligation(AssertionNamespace::Security, sha256(2), sha256(12))
            .unwrap(),
        AssertionSpec::hard_obligation(AssertionNamespace::Utility, sha256(3), sha256(13)).unwrap(),
    ])
    .unwrap();

    assert_eq!(first, second);
    for assertion in &first.assertions {
        assert_eq!(first.resolve(&assertion.name), Some(assertion));
        assert!(assertion.name.starts_with("qf.v1."));
    }
    let security_names = first
        .assertions
        .iter()
        .filter(|assertion| assertion.namespace == AssertionNamespace::Security)
        .map(|assertion| assertion.name.as_str())
        .collect::<Vec<_>>();
    assert!(security_names[0].contains("security.00000000"));
    assert!(security_names[1].contains("security.00000001"));
    first.validate().unwrap();
}

struct RecordingRechecker {
    decision: CoreRecheckDecision,
    calls: usize,
    names: Vec<String>,
}

impl UnsatCoreRechecker for RecordingRechecker {
    fn recheck(&mut self, assertions: &[NamedAssertion]) -> CoreRecheckDecision {
        self.calls += 1;
        self.names = assertions
            .iter()
            .map(|assertion| assertion.name.clone())
            .collect();
        self.decision
    }
}

fn rechecker(decision: CoreRecheckDecision) -> RecordingRechecker {
    RecordingRechecker {
        decision,
        calls: 0,
        names: Vec::new(),
    }
}

#[test]
fn reported_core_is_canonicalized_resolved_and_independently_rechecked() {
    let registry = registry();
    let left = &registry.assertions[0].name;
    let right = &registry.assertions[2].name;
    let raw = format!("({right} {left})");
    let mut checker = rechecker(CoreRecheckDecision::Unsat);
    let artifact = audit_unsat_core(
        &context(),
        BoundedDecisionRecord::Unsat,
        &registry,
        SolverCoreReport::Reported(&raw),
        &mut checker,
    )
    .unwrap();

    assert_eq!(artifact.diagnostic_status, CoreDiagnosticStatus::Validated);
    assert!(artifact.diagnostic_accepted);
    assert!(artifact.diagnostic_only);
    assert_eq!(checker.calls, 1);
    assert_eq!(checker.names, artifact.resolved_assertion_names);
    assert!(artifact
        .resolved_assertion_names
        .windows(2)
        .all(|pair| pair[0] < pair[1]));
    artifact.validate(&registry).unwrap();
}

#[test]
fn malformed_unknown_duplicate_empty_and_missing_cores_are_rejected() {
    let registry = registry();
    let known = &registry.assertions[0].name;
    let unknown = format!("qf.v1.security.99999999.{}", sha256(99));
    let unknown_core = format!("({unknown})");
    let reports = [
        (SolverCoreReport::Reported(""), CoreDiagnosticReason::Empty),
        (
            SolverCoreReport::Reported("(nested (name))"),
            CoreDiagnosticReason::Malformed,
        ),
        (
            SolverCoreReport::Reported(&unknown_core),
            CoreDiagnosticReason::UnknownName,
        ),
    ];
    for (report, expected) in reports {
        let mut checker = rechecker(CoreRecheckDecision::Unsat);
        let artifact = audit_unsat_core(
            &context(),
            BoundedDecisionRecord::Unsat,
            &registry,
            report,
            &mut checker,
        )
        .unwrap();
        assert_eq!(artifact.diagnostic_status, CoreDiagnosticStatus::Rejected);
        assert_eq!(artifact.diagnostic_reason, Some(expected));
        assert_eq!(checker.calls, 0);
    }

    let duplicate = format!("({known} {known})");
    let mut checker = rechecker(CoreRecheckDecision::Unsat);
    let artifact = audit_unsat_core(
        &context(),
        BoundedDecisionRecord::Unsat,
        &registry,
        SolverCoreReport::Reported(&duplicate),
        &mut checker,
    )
    .unwrap();
    assert_eq!(
        artifact.diagnostic_reason,
        Some(CoreDiagnosticReason::DuplicateName)
    );

    let artifact = audit_unsat_core(
        &context(),
        BoundedDecisionRecord::Unsat,
        &registry,
        SolverCoreReport::Missing,
        &mut checker,
    )
    .unwrap();
    assert_eq!(
        artifact.diagnostic_reason,
        Some(CoreDiagnosticReason::Missing)
    );
    assert!(!artifact.diagnostic_accepted);
}

#[test]
fn unsupported_core_has_explicit_fallback_without_changing_bounded_unsat() {
    let registry = registry();
    let mut checker = rechecker(CoreRecheckDecision::Unsat);
    let artifact = audit_unsat_core(
        &context(),
        BoundedDecisionRecord::Unsat,
        &registry,
        SolverCoreReport::Unsupported,
        &mut checker,
    )
    .unwrap();

    assert_eq!(artifact.bounded_decision, BoundedDecisionRecord::Unsat);
    assert_eq!(
        artifact.diagnostic_status,
        CoreDiagnosticStatus::Unavailable
    );
    assert_eq!(
        artifact.diagnostic_reason,
        Some(CoreDiagnosticReason::Unsupported)
    );
    assert!(!artifact.diagnostic_accepted);
    assert_eq!(checker.calls, 0);
}

#[test]
fn failed_or_inconclusive_recheck_never_validates_a_core() {
    let registry = registry();
    let raw = format!("({})", registry.assertions[0].name);
    for (decision, reason) in [
        (CoreRecheckDecision::Sat, CoreDiagnosticReason::RecheckSat),
        (
            CoreRecheckDecision::Inconclusive,
            CoreDiagnosticReason::RecheckInconclusive,
        ),
    ] {
        let mut checker = rechecker(decision);
        let artifact = audit_unsat_core(
            &context(),
            BoundedDecisionRecord::Unsat,
            &registry,
            SolverCoreReport::Reported(&raw),
            &mut checker,
        )
        .unwrap();
        assert_eq!(artifact.diagnostic_status, CoreDiagnosticStatus::Rejected);
        assert_eq!(artifact.diagnostic_reason, Some(reason));
        assert!(!artifact.diagnostic_accepted);
    }
}

#[test]
fn core_diagnostic_cannot_relax_a_non_unsat_bounded_decision() {
    let registry = registry();
    let raw = format!("({})", registry.assertions[0].name);
    let mut checker = rechecker(CoreRecheckDecision::Unsat);
    let artifact = audit_unsat_core(
        &context(),
        BoundedDecisionRecord::Sat,
        &registry,
        SolverCoreReport::Reported(&raw),
        &mut checker,
    )
    .unwrap();

    assert_eq!(artifact.bounded_decision, BoundedDecisionRecord::Sat);
    assert_eq!(
        artifact.diagnostic_status,
        CoreDiagnosticStatus::NotApplicable
    );
    assert!(!artifact.diagnostic_accepted);
    assert_eq!(checker.calls, 0);
}

#[test]
fn duplicate_registry_entries_and_reserved_namespace_are_rejected() {
    let spec =
        AssertionSpec::hard_obligation(AssertionNamespace::Security, sha256(1), sha256(2)).unwrap();
    assert_eq!(
        NamedAssertionRegistry::new(vec![spec.clone(), spec]).unwrap_err(),
        UnsatCoreInputError::DuplicateAssertion
    );
    assert_eq!(
        AssertionSpec::hard_obligation(AssertionNamespace::Blocker, sha256(1), sha256(2))
            .unwrap_err(),
        UnsatCoreInputError::WrongNamespace
    );
}
