use std::collections::BTreeMap;

use quotient_seal_engine::{
    ComparisonPoint, ContextCommandRecord, DifferentialCounterexampleKind, DifferentialOracle,
    DifferentialOracleArtifact, DifferentialOracleError, DifferentialVerdict, EngineIdentity,
    EngineRunArtifact, EngineRunVerdict, ExecutionInput, ExecutionLimits, ExecutionTermination,
    HostTapeRecord, ObservableAxis, ObservableEvent, ResourceKind, ScalarValue, UnresolvedEvidence,
    ENGINE_ADAPTER_CONTRACT_VERSION, REFERENCE_ENGINE_NAME,
};

fn digest(character: char) -> String {
    std::iter::repeat_n(character, 64).collect()
}

fn identity(name: &str, character: char) -> EngineIdentity {
    EngineIdentity {
        name: name.to_owned(),
        version: "1.0.0".to_owned(),
        executable_sha256: digest(character),
        adapter_contract_version: ENGINE_ADAPTER_CONTRACT_VERSION,
        configuration: BTreeMap::from([("profile".to_owned(), "frozen-v1".to_owned())]),
    }
}

fn input(name: &str, character: char) -> ExecutionInput {
    ExecutionInput {
        module_sha256: digest('a'),
        abi_sha256: digest('b'),
        engine: identity(name, character),
        host_tape: HostTapeRecord::default(),
        context_sequence: vec![ContextCommandRecord {
            family_code: 1,
            kind_code: 1,
            service_alias: 7,
            public_slot: 11,
            fault: 0,
            payload_tag: 0,
        }],
        limits: ExecutionLimits {
            fuel: 10_000,
            max_memory_pages: 1,
            max_host_calls: 8,
            timeout_ms: 1_000,
        },
    }
}

fn trace(state_digest: char) -> Vec<ObservableEvent> {
    vec![
        ObservableEvent::ApiCall {
            export: "qseal.public.tick".to_owned(),
            arguments: vec![ScalarValue::I32 { bits: 7 }],
        },
        ObservableEvent::EmitFrame {
            label: 1,
            slot: 11,
            value: 0,
        },
        ObservableEvent::ApiReturn {
            export: "qseal.public.tick".to_owned(),
            values: vec![ScalarValue::I32 { bits: 0 }],
        },
        ObservableEvent::PublicState {
            digest_sha256: digest(state_digest),
        },
    ]
}

fn executed(name: &str, character: char, state_digest: char) -> EngineRunArtifact {
    EngineRunArtifact::new(
        input(name, character),
        trace(state_digest),
        ExecutionTermination::Returned {
            values: vec![ScalarValue::I32 { bits: 0 }],
        },
        EngineRunVerdict::Executed,
    )
    .expect("valid run")
}

fn reference(state_digest: char) -> EngineRunArtifact {
    executed(REFERENCE_ENGINE_NAME, 'c', state_digest)
}

fn engines(state_digest: char) -> Vec<EngineRunArtifact> {
    vec![
        executed("wasmi", 'd', state_digest),
        executed("wasmtime", 'e', state_digest),
    ]
}

#[test]
fn all_executed_observables_match_and_engine_order_is_canonical() {
    let first = DifferentialOracle::evaluate(reference('f'), engines('f')).expect("oracle");
    let mut reversed = engines('f');
    reversed.reverse();
    let second = DifferentialOracle::evaluate(reference('f'), reversed).expect("oracle");

    assert_eq!(first.verdict, DifferentialVerdict::Match);
    assert!(first.counterexamples.is_empty());
    assert!(first.unresolved.is_empty());
    assert_eq!(first, second);
    assert_eq!(first.engines[0].input.engine.name, "wasmi");
    assert_eq!(first.engines[1].input.engine.name, "wasmtime");
    assert_eq!(
        first.artifact_sha256().expect("hash"),
        second.artifact_sha256().expect("hash")
    );
}

#[test]
fn engine_and_reference_disagreements_are_separate_minimal_counterexamples() {
    let reference = reference('f');
    let wasmi = executed("wasmi", 'd', 'f');
    let mut wasmtime = executed("wasmtime", 'e', 'f');
    wasmtime.trace[1] = ObservableEvent::EmitFrame {
        label: 1,
        slot: 11,
        value: 9,
    };

    let artifact = DifferentialOracle::evaluate(reference, vec![wasmtime, wasmi]).expect("oracle");

    assert_eq!(artifact.verdict, DifferentialVerdict::Counterexample);
    assert!(artifact.counterexamples.iter().any(|counterexample| {
        counterexample.kind == DifferentialCounterexampleKind::EngineDisagreement
    }));
    assert!(artifact.counterexamples.iter().any(|counterexample| {
        counterexample.kind == DifferentialCounterexampleKind::ReferenceDisagreement
    }));
    assert!(artifact.counterexamples.iter().all(|counterexample| {
        matches!(
            counterexample.first_difference,
            ComparisonPoint::Trace {
                index: 1,
                left_axis: Some(ObservableAxis::Output),
                right_axis: Some(ObservableAxis::Output),
                ..
            }
        )
    }));
}

#[test]
fn reference_only_difference_does_not_become_engine_disagreement() {
    let artifact =
        DifferentialOracle::evaluate(reference('9'), engines('f')).expect("oracle result");

    assert_eq!(artifact.verdict, DifferentialVerdict::Counterexample);
    assert_eq!(artifact.counterexamples.len(), 2);
    assert!(artifact.counterexamples.iter().all(|counterexample| {
        counterexample.kind == DifferentialCounterexampleKind::ReferenceDisagreement
    }));
    assert!(artifact.counterexamples.iter().all(|counterexample| {
        matches!(
            counterexample.first_difference,
            ComparisonPoint::Trace {
                index: 3,
                left_axis: Some(ObservableAxis::PublicState),
                right_axis: Some(ObservableAxis::PublicState),
                ..
            }
        )
    }));
}

#[test]
fn unsupported_resource_bound_and_parser_disagreement_are_unresolved() {
    let unsupported = EngineRunArtifact::new(
        input("wasmtime", 'e'),
        Vec::new(),
        ExecutionTermination::Unsupported {
            feature: "FLOAT_DISABLED".to_owned(),
        },
        EngineRunVerdict::Unresolved,
    )
    .expect("unsupported");
    let unsupported_result = DifferentialOracle::evaluate(
        reference('f'),
        vec![executed("wasmi", 'd', 'f'), unsupported],
    )
    .expect("oracle");
    assert_eq!(unsupported_result.verdict, DifferentialVerdict::Unresolved);
    assert!(unsupported_result
        .unresolved
        .iter()
        .any(|reason| matches!(reason, UnresolvedEvidence::Unsupported { .. })));

    let bounded = EngineRunArtifact::new(
        input("wasmi", 'd'),
        Vec::new(),
        ExecutionTermination::ResourceExhausted {
            resource: ResourceKind::Fuel,
            limit: 10_000,
            observed: None,
        },
        EngineRunVerdict::Unresolved,
    )
    .expect("bounded");
    let bounded_result = DifferentialOracle::evaluate(
        reference('f'),
        vec![bounded, executed("wasmtime", 'e', 'f')],
    )
    .expect("oracle");
    assert!(bounded_result
        .unresolved
        .iter()
        .any(|reason| matches!(reason, UnresolvedEvidence::ResourceBound { .. })));

    let rejected = EngineRunArtifact::new(
        input("wasmi", 'd'),
        Vec::new(),
        ExecutionTermination::InvalidModule {
            reason_code: "PARSER_REJECTED".to_owned(),
            detail_sha256: digest('8'),
        },
        EngineRunVerdict::Rejected,
    )
    .expect("rejected");
    let parser_result = DifferentialOracle::evaluate(
        reference('f'),
        vec![rejected, executed("wasmtime", 'e', 'f')],
    )
    .expect("oracle");
    assert!(parser_result
        .unresolved
        .iter()
        .any(|reason| matches!(reason, UnresolvedEvidence::ParserDisagreement { .. })));
}

#[test]
fn shared_public_input_mismatch_is_unresolved_before_trace_comparison() {
    let mut wasmtime = executed("wasmtime", 'e', 'f');
    wasmtime.input.context_sequence[0].public_slot = 12;
    wasmtime.execution_id_sha256 =
        quotient_seal_engine::compute_execution_id(&wasmtime.input).expect("execution id");

    let artifact =
        DifferentialOracle::evaluate(reference('f'), vec![executed("wasmi", 'd', 'f'), wasmtime])
            .expect("oracle");

    assert_eq!(artifact.verdict, DifferentialVerdict::Unresolved);
    assert!(artifact
        .unresolved
        .iter()
        .any(|reason| matches!(reason, UnresolvedEvidence::InputMismatch { .. })));
    assert!(artifact.counterexamples.is_empty());
}

#[test]
fn stored_verdict_and_counterexample_are_independently_recomputed() {
    let mut artifact =
        DifferentialOracle::evaluate(reference('f'), engines('f')).expect("oracle result");
    artifact.verdict = DifferentialVerdict::Counterexample;

    assert!(matches!(
        artifact.validate(),
        Err(DifferentialOracleError::RecomputedResultMismatch)
    ));
}

#[test]
fn canonical_json_contains_reference_and_both_complete_engine_artifacts() {
    let artifact =
        DifferentialOracle::evaluate(reference('f'), engines('f')).expect("oracle result");
    let encoded = artifact.canonical_json().expect("canonical json");
    let decoded: DifferentialOracleArtifact = serde_json::from_slice(&encoded).expect("round trip");

    assert_eq!(decoded, artifact);
    assert_eq!(decoded.engines.len(), 2);
    assert_eq!(decoded.reference.input.engine.name, REFERENCE_ENGINE_NAME);
    decoded.validate().expect("recomputed artifact");
}
