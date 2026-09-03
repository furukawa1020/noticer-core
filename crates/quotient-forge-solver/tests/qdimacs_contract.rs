use quotient_forge_solver::{
    encode_qdimacs, validate_qdimacs, QdimacsBounds, QdimacsError, QdimacsSpec, SymbolicClause,
    SymbolicLiteral, VariableKey, VariableRole, QDIMACS_SCHEMA_V1,
};

fn key(role: VariableRole, coordinates: &[u32]) -> VariableKey {
    VariableKey::new(role, coordinates.to_vec())
}

fn fixture_spec() -> QdimacsSpec {
    let machine = key(VariableRole::MachineChoice, &[0, 0, 0]);
    let private_left = key(VariableRole::PrivateHistoryLeft, &[0, 0]);
    let private_right = key(VariableRole::PrivateHistoryRight, &[0, 0]);
    let environment = key(VariableRole::EnvironmentTrace, &[0, 0]);
    let fault = key(VariableRole::FaultTrace, &[0, 0]);
    let witness = key(VariableRole::DependentWitness, &[0, 0]);
    QdimacsSpec {
        bounds: QdimacsBounds {
            plant_states: 2,
            machine_states: 2,
            horizon: 4,
            action_count: 2,
        },
        seed: 17,
        variables: vec![
            fault.clone(),
            private_right,
            witness.clone(),
            machine.clone(),
            environment.clone(),
            private_left.clone(),
        ],
        clauses: vec![
            SymbolicClause {
                literals: vec![
                    SymbolicLiteral::positive(witness),
                    SymbolicLiteral::negative(fault),
                ],
            },
            SymbolicClause {
                literals: vec![SymbolicLiteral::positive(environment)],
            },
            SymbolicClause {
                literals: vec![
                    SymbolicLiteral::negative(private_left),
                    SymbolicLiteral::positive(machine),
                ],
            },
        ],
    }
}

#[test]
fn input_order_does_not_change_canonical_bytes() {
    let first = encode_qdimacs(&fixture_spec()).unwrap();
    let mut reordered = fixture_spec();
    reordered.variables.reverse();
    reordered.clauses.reverse();
    for clause in &mut reordered.clauses {
        clause.literals.reverse();
    }
    let second = encode_qdimacs(&reordered).unwrap();

    assert_eq!(first.document.as_bytes(), second.document.as_bytes());
    assert_eq!(first.metadata, second.metadata);
    assert_eq!(first.metadata.schema_version, QDIMACS_SCHEMA_V1);
    assert_eq!(first.metadata.quantifier_blocks.len(), 3);
    assert_eq!(first.metadata.qdimacs_sha256.len(), 64);
    let validation = validate_qdimacs(&first.document).unwrap();
    assert_eq!(validation.variable_count, 6);
    assert_eq!(validation.clause_count, 3);
}

#[test]
fn unregistered_tautological_and_duplicate_clauses_fail_closed() {
    let mut unregistered = fixture_spec();
    unregistered.clauses.push(SymbolicClause {
        literals: vec![SymbolicLiteral::positive(key(
            VariableRole::FaultTrace,
            &[99, 99],
        ))],
    });
    assert!(matches!(
        encode_qdimacs(&unregistered),
        Err(QdimacsError::UnregisteredVariable(_))
    ));

    let mut tautology = fixture_spec();
    let variable = tautology.variables[0].clone();
    tautology.clauses.push(SymbolicClause {
        literals: vec![
            SymbolicLiteral::positive(variable.clone()),
            SymbolicLiteral::negative(variable),
        ],
    });
    assert!(matches!(
        encode_qdimacs(&tautology),
        Err(QdimacsError::TautologicalClause(_))
    ));

    let mut duplicate = fixture_spec();
    duplicate.clauses.push(duplicate.clauses[0].clone());
    assert!(matches!(
        encode_qdimacs(&duplicate),
        Err(QdimacsError::DuplicateClause)
    ));
}

#[test]
fn malformed_literal_and_header_counts_are_rejected() {
    let malformed_literal = "p cnf 2 1\ne 1 0\na 2 0\n1 nope 0\n";
    assert!(matches!(
        validate_qdimacs(malformed_literal),
        Err(QdimacsError::MalformedDocument { .. })
    ));

    let missing_quantified_variable = "p cnf 3 1\ne 1 0\na 2 0\n1 0\n";
    assert!(matches!(
        validate_qdimacs(missing_quantified_variable),
        Err(QdimacsError::HeaderCountMismatch("quantified variables"))
    ));

    let wrong_clause_count = "p cnf 2 2\ne 1 0\na 2 0\n1 0\n";
    assert!(matches!(
        validate_qdimacs(wrong_clause_count),
        Err(QdimacsError::HeaderCountMismatch("clauses"))
    ));
}

#[test]
fn metadata_json_is_byte_reproducible() {
    let first = encode_qdimacs(&fixture_spec()).unwrap();
    let second = encode_qdimacs(&fixture_spec()).unwrap();
    assert_eq!(
        first.metadata_json_bytes().unwrap(),
        second.metadata_json_bytes().unwrap()
    );
    let decoded: serde_json::Value =
        serde_json::from_slice(&first.metadata_json_bytes().unwrap()).unwrap();
    assert_eq!(decoded["seed"], 17);
    assert_eq!(decoded["bounds"]["horizon"], 4);
}
