use quotient_forge_caqt::{
    verify, CanonicalViolation, Certificate, CertificateLimits, CertificateVerdict, CostVector,
    Digest, DomainHashes, ExpectedContract, HashDomain, IncompatibleReason, InvalidReason,
    ObserverRecord, OutputRecord, RelationPair, TransitionRecord, UtilityViolation, FORMAT_VERSION,
};

fn certificate() -> Certificate {
    let mut certificate = Certificate {
        version: FORMAT_VERSION,
        hashes: DomainHashes::zero(),
        state_count: 2,
        input_count: 1,
        observer_count: 1,
        state_bound: 2,
        claimed_cost: CostVector::default(),
        observers: vec![ObserverRecord {
            id: 0,
            sees_presence: true,
            sees_payload: true,
            sees_actions: true,
        }],
        outputs: vec![
            OutputRecord {
                id: 0,
                emitted: true,
                payload: b"ok".to_vec(),
                actions: Vec::new(),
            },
            OutputRecord {
                id: 1,
                emitted: true,
                payload: b"ok".to_vec(),
                actions: Vec::new(),
            },
        ],
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
                to: 1,
                output: 1,
                authorized_actions: Vec::new(),
                required_action: None,
                recoverable_fault_action: None,
            },
        ],
        relation: vec![RelationPair { left: 0, right: 1 }],
    };
    certificate.seal();
    certificate
}

fn expected(certificate: &Certificate) -> ExpectedContract {
    ExpectedContract {
        version: FORMAT_VERSION,
        hashes: certificate.hashes,
        state_bound: certificate.state_bound,
        max_cost: certificate.claimed_cost,
    }
}

fn verdict(certificate: &Certificate, expected: ExpectedContract) -> CertificateVerdict {
    verify(
        &certificate.encode(),
        expected,
        CertificateLimits::default(),
    )
}

#[test]
fn canonical_certificate_is_valid() {
    let certificate = certificate();
    let result = verdict(&certificate, expected(&certificate));
    assert_eq!(result.label(), "VALID");
    let CertificateVerdict::Valid(report) = result else {
        panic!("expected a valid certificate");
    };
    assert_eq!(report.states, 2);
    assert_eq!(report.transitions, 2);
    assert_eq!(report.relation_pairs, 1);
}

#[test]
fn transition_output_and_relation_mutations_are_rejected() {
    let original = certificate();
    let contract = expected(&original);

    let mut transition = original.clone();
    transition.transitions[0].to = 0;
    assert!(matches!(
        verdict(&transition, contract),
        CertificateVerdict::Invalid(InvalidReason::HashMismatch(_))
    ));

    let mut output = original.clone();
    output.outputs[1].payload = b"changed".to_vec();
    assert!(matches!(
        verdict(&output, contract),
        CertificateVerdict::Invalid(InvalidReason::HashMismatch(HashDomain::Transducer))
    ));

    let mut relation = original.clone();
    relation.relation[0] = RelationPair { left: 1, right: 0 };
    assert!(matches!(
        verdict(&relation, contract),
        CertificateVerdict::Invalid(InvalidReason::NonCanonical(
            CanonicalViolation::RelationPair { .. }
        ))
    ));
}

#[test]
fn claimed_cost_and_hash_mutations_are_rejected() {
    let original = certificate();
    let contract = expected(&original);

    let mut cost = original.clone();
    cost.claimed_cost.payload_bytes += 1;
    assert!(matches!(
        verdict(&cost, contract),
        CertificateVerdict::Invalid(InvalidReason::CostMismatch { .. })
    ));

    let mut hash = original.clone();
    hash.hashes.plant = Digest::zero();
    assert!(matches!(
        verdict(&hash, contract),
        CertificateVerdict::Invalid(InvalidReason::HashMismatch(HashDomain::Plant))
    ));
}

#[test]
fn version_and_checker_contract_are_incompatible() {
    let original = certificate();
    let contract = expected(&original);

    let mut version = original.clone();
    version.version = FORMAT_VERSION + 1;
    assert_eq!(
        verdict(&version, contract),
        CertificateVerdict::Incompatible(IncompatibleReason::Version {
            expected: FORMAT_VERSION,
            actual: FORMAT_VERSION + 1,
        })
    );

    let incompatible = ExpectedContract {
        hashes: DomainHashes {
            checker_contract: Digest::zero(),
            ..contract.hashes
        },
        ..contract
    };
    assert_eq!(
        verdict(&original, incompatible),
        CertificateVerdict::Incompatible(IncompatibleReason::CheckerContract)
    );
}

#[test]
fn reordered_records_and_trailing_data_are_rejected() {
    let original = certificate();
    let contract = expected(&original);

    let mut reordered = original.clone();
    reordered.transitions.swap(0, 1);
    reordered.seal();
    let reordered_contract = expected(&reordered);
    assert!(matches!(
        verdict(&reordered, reordered_contract),
        CertificateVerdict::Invalid(InvalidReason::NonCanonical(
            CanonicalViolation::TransitionOrder { .. }
        ))
    ));

    let mut bytes = original.encode();
    bytes.push(0);
    assert!(matches!(
        verify(&bytes, contract, CertificateLimits::default()),
        CertificateVerdict::Invalid(InvalidReason::Parse(
            quotient_forge_caqt::ParseError::TrailingData { .. }
        ))
    ));
}

#[test]
fn observer_divergence_is_recomputed_after_valid_reseal() {
    let mut modified = certificate();
    modified.outputs[1].payload = b"different".to_vec();
    modified.seal();
    assert!(matches!(
        verdict(&modified, expected(&modified)),
        CertificateVerdict::Invalid(InvalidReason::ObserverDivergence { .. })
    ));
}

#[test]
fn unauthorized_duplicate_and_required_actions_are_recomputed() {
    let mut unauthorized = certificate();
    unauthorized.outputs[0].actions = vec![7];
    unauthorized.outputs[1].actions = vec![7];
    unauthorized.seal();
    assert!(matches!(
        verdict(&unauthorized, expected(&unauthorized)),
        CertificateVerdict::Invalid(InvalidReason::Utility(
            UtilityViolation::UnauthorizedAction { action: 7, .. }
        ))
    ));

    let mut duplicate = certificate();
    for output in &mut duplicate.outputs {
        output.actions = vec![7, 7];
    }
    for transition in &mut duplicate.transitions {
        transition.authorized_actions = vec![7];
        transition.required_action = Some(7);
    }
    duplicate.seal();
    assert!(matches!(
        verdict(&duplicate, expected(&duplicate)),
        CertificateVerdict::Invalid(InvalidReason::Utility(UtilityViolation::DuplicateAction {
            action: 7,
            ..
        }))
    ));

    let mut required = certificate();
    for transition in &mut required.transitions {
        transition.authorized_actions = vec![7];
        transition.required_action = Some(7);
    }
    required.seal();
    assert!(matches!(
        verdict(&required, expected(&required)),
        CertificateVerdict::Invalid(InvalidReason::Utility(
            UtilityViolation::RequiredActionCount { action: 7, .. }
        ))
    ));
}

#[test]
fn recoverable_fault_obligation_is_recomputed() {
    let mut modified = certificate();
    for transition in &mut modified.transitions {
        transition.authorized_actions = vec![9];
        transition.recoverable_fault_action = Some(9);
    }
    modified.seal();
    assert!(matches!(
        verdict(&modified, expected(&modified)),
        CertificateVerdict::Invalid(InvalidReason::RecoverableFault {
            action: 9,
            actual: 0,
            ..
        })
    ));
}

#[test]
fn totality_state_bound_and_reachability_are_recomputed() {
    let mut partial = certificate();
    partial.transitions.pop();
    partial.seal();
    assert!(matches!(
        verdict(&partial, expected(&partial)),
        CertificateVerdict::Invalid(InvalidReason::NonCanonical(
            CanonicalViolation::TransitionCount
        ))
    ));

    let mut over_bound = certificate();
    over_bound.state_bound = 1;
    over_bound.seal();
    assert!(matches!(
        verdict(&over_bound, expected(&over_bound)),
        CertificateVerdict::Invalid(InvalidReason::StateBound { .. })
    ));

    let mut unreachable = certificate();
    unreachable.state_count = 3;
    unreachable.state_bound = 3;
    unreachable.transitions.push(TransitionRecord {
        from: 2,
        input: 0,
        to: 2,
        output: 1,
        authorized_actions: Vec::new(),
        required_action: None,
        recoverable_fault_action: None,
    });
    unreachable.seal();
    assert_eq!(
        verdict(&unreachable, expected(&unreachable)),
        CertificateVerdict::Invalid(InvalidReason::UnreachableState { state: 2 })
    );
}

#[test]
fn external_cost_budget_is_enforced() {
    let certificate = certificate();
    let mut contract = expected(&certificate);
    contract.max_cost.payload_bytes -= 1;
    assert!(matches!(
        verdict(&certificate, contract),
        CertificateVerdict::Invalid(InvalidReason::CostBudget { .. })
    ));
}
