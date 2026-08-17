use quotient_forge_caqt::{
    build_inductive_certificate, verify_inductive, verify_inductive_timed, Certificate,
    CertificateLimits, ClosureRecord, CostVector, Digest, DomainHashes, ExpectedContract,
    ExpectedInductiveContract, InductiveCanonicalViolation, InductiveIncompatibleReason,
    InductiveInvalidReason, InductiveLimits, InductiveParseError, InductiveResourceBound,
    InductiveVerdict, ObserverRecord, OutputRecord, RelationPair, TransitionRecord, FORMAT_VERSION,
};

fn base_certificate() -> Certificate {
    let mut certificate = Certificate {
        version: FORMAT_VERSION,
        hashes: DomainHashes::zero(),
        state_count: 3,
        input_count: 1,
        observer_count: 1,
        state_bound: 3,
        claimed_cost: CostVector::default(),
        observers: vec![ObserverRecord {
            id: 0,
            sees_presence: true,
            sees_payload: true,
            sees_actions: true,
        }],
        outputs: (0..3)
            .map(|id| OutputRecord {
                id,
                emitted: true,
                payload: b"same".to_vec(),
                actions: Vec::new(),
            })
            .collect(),
        transitions: vec![
            TransitionRecord {
                from: 0,
                input: 0,
                to: 1,
                output: 0,
                authorized_actions: Vec::new(),
                required_action: None,
                recoverable_fault_action: None,
            },
            TransitionRecord {
                from: 1,
                input: 0,
                to: 2,
                output: 1,
                authorized_actions: Vec::new(),
                required_action: None,
                recoverable_fault_action: None,
            },
            TransitionRecord {
                from: 2,
                input: 0,
                to: 2,
                output: 2,
                authorized_actions: Vec::new(),
                required_action: None,
                recoverable_fault_action: None,
            },
        ],
        relation: vec![
            RelationPair { left: 0, right: 1 },
            RelationPair { left: 1, right: 2 },
        ],
    };
    certificate.seal();
    certificate
}

fn initial_pairs() -> Vec<RelationPair> {
    vec![RelationPair { left: 0, right: 1 }]
}

fn expected(base: &Certificate) -> ExpectedInductiveContract {
    ExpectedInductiveContract {
        base: ExpectedContract {
            version: FORMAT_VERSION,
            hashes: base.hashes,
            state_bound: base.state_bound,
            max_cost: base.claimed_cost,
        },
        initial_pairs: initial_pairs(),
    }
}

#[test]
fn independently_recomputed_inductive_certificate_is_valid() {
    let base = base_certificate();
    let certificate = build_inductive_certificate(&base, initial_pairs()).unwrap();
    let bytes = certificate.encode();
    let verdict = verify_inductive(&bytes, &expected(&base), InductiveLimits::default());
    let InductiveVerdict::Valid(report) = verdict else {
        panic!("expected VALID inductive certificate");
    };
    assert_eq!(report.certificate_bytes, bytes.len());
    assert_eq!(report.initial_pairs, 1);
    assert_eq!(report.product_states, 2);
    assert_eq!(report.closure_records, 2);
    assert_eq!(report.check_work_units, 5);
}

#[test]
fn state_and_edge_deletion_are_rejected() {
    let base = base_certificate();
    let original = build_inductive_certificate(&base, initial_pairs()).unwrap();

    let mut state_deleted = original.clone();
    state_deleted.invariant.pop();
    state_deleted.closure.pop();
    assert!(matches!(
        verify_inductive(
            &state_deleted.encode(),
            &expected(&base),
            InductiveLimits::default()
        ),
        InductiveVerdict::Invalid(InductiveInvalidReason::ClosurePairReference { .. })
            | InductiveVerdict::Invalid(InductiveInvalidReason::NonCanonical(_))
    ));

    let mut edge_deleted = original;
    edge_deleted.closure.pop();
    assert!(matches!(
        verify_inductive(
            &edge_deleted.encode(),
            &expected(&base),
            InductiveLimits::default()
        ),
        InductiveVerdict::Invalid(InductiveInvalidReason::NonCanonical(
            InductiveCanonicalViolation::ClosureCount
        ))
    ));
}

#[test]
fn reordered_closure_and_hidden_reachable_pair_are_rejected() {
    let base = base_certificate();
    let mut reordered = build_inductive_certificate(&base, initial_pairs()).unwrap();
    reordered.closure.swap(0, 1);
    assert!(matches!(
        verify_inductive(
            &reordered.encode(),
            &expected(&base),
            InductiveLimits::default()
        ),
        InductiveVerdict::Invalid(InductiveInvalidReason::NonCanonical(
            InductiveCanonicalViolation::ClosureOrder { .. }
        ))
    ));

    let mut hidden = build_inductive_certificate(&base, initial_pairs()).unwrap();
    hidden.invariant.pop();
    hidden.closure = vec![ClosureRecord {
        pair_index: 0,
        input: 0,
        next_left: 1,
        next_right: 1,
        next_pair_index: None,
    }];
    assert!(matches!(
        verify_inductive(
            &hidden.encode(),
            &expected(&base),
            InductiveLimits::default()
        ),
        InductiveVerdict::Invalid(InductiveInvalidReason::ClosureSuccessor { .. })
    ));
}

#[test]
fn hash_replacement_and_trailing_data_are_rejected() {
    let base = base_certificate();
    let mut replaced = build_inductive_certificate(&base, initial_pairs()).unwrap();
    replaced.bound_hashes.plant = Digest::zero();
    assert_eq!(
        verify_inductive(
            &replaced.encode(),
            &expected(&base),
            InductiveLimits::default()
        ),
        InductiveVerdict::Invalid(InductiveInvalidReason::BoundHashes)
    );

    let mut bytes = build_inductive_certificate(&base, initial_pairs())
        .unwrap()
        .encode();
    bytes.push(0);
    assert!(matches!(
        verify_inductive(&bytes, &expected(&base), InductiveLimits::default()),
        InductiveVerdict::Invalid(InductiveInvalidReason::Parse(
            InductiveParseError::TrailingData { .. }
        ))
    ));
}

#[test]
fn independently_supplied_initial_set_is_hash_bound_by_contract() {
    let base = base_certificate();
    let certificate = build_inductive_certificate(&base, initial_pairs()).unwrap();
    let mut wrong_expected = expected(&base);
    wrong_expected.initial_pairs = vec![RelationPair { left: 1, right: 2 }];
    assert_eq!(
        verify_inductive(
            &certificate.encode(),
            &wrong_expected,
            InductiveLimits::default()
        ),
        InductiveVerdict::Invalid(InductiveInvalidReason::InitialContractMismatch)
    );
}

#[test]
fn checker_resource_exhaustion_is_never_valid() {
    let base = base_certificate();
    let certificate = build_inductive_certificate(&base, initial_pairs()).unwrap();
    let limits = InductiveLimits {
        max_product_states: 1,
        ..InductiveLimits::default()
    };
    assert_eq!(
        verify_inductive(&certificate.encode(), &expected(&base), limits),
        InductiveVerdict::ResourceBound(InductiveResourceBound::ProductStates {
            actual: 2,
            limit: 1,
        })
    );
}

#[test]
fn base_and_inductive_certificate_formats_are_separate() {
    let base = base_certificate();
    assert_eq!(
        verify_inductive(&base.encode(), &expected(&base), InductiveLimits::default()),
        InductiveVerdict::Incompatible(InductiveIncompatibleReason::Magic)
    );
}

#[test]
fn timed_wrapper_reports_size_and_elapsed_check_time() {
    let base = base_certificate();
    let bytes = build_inductive_certificate(&base, initial_pairs())
        .unwrap()
        .encode();
    let measurement = verify_inductive_timed(
        &bytes,
        &expected(&base),
        InductiveLimits {
            base_limits: CertificateLimits::default(),
            ..InductiveLimits::default()
        },
    );
    assert_eq!(measurement.certificate_bytes, bytes.len());
    assert_eq!(measurement.verdict.label(), "VALID");
    assert!(measurement.elapsed.as_nanos() < u128::MAX);
}
