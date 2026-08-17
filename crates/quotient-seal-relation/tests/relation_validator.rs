use quotient_forge_caqt::{
    artifact_digest, build_inductive_certificate, verify_inductive, Certificate, CostVector,
    Digest, DomainHashes, ExpectedContract, ExpectedInductiveContract, InductiveLimits,
    InductiveVerdict, ObserverRecord, OutputRecord, RelationPair, TransitionRecord, FORMAT_VERSION,
};
use quotient_forge_codegen::{BuildEvidence, TargetKind, TranslationTranscript};
use quotient_seal_relation::{
    validate_relation, DivergenceKind, GlobalPredicate, MemoryPredicate, RelationCertificate,
    RelationIncompatible, RelationLimits, RelationRecord, RelationResourceBound,
    RelationUnresolved, RelationValidationInput, RelationValidationLimits, RelationVerdict,
    RELATION_FORMAT_VERSION,
};
use quotient_seal_target_ir::{
    parse_and_lower, target_ir_hash, CanonicalTargetIr, ConsensusVerdict, ParserLimits,
};

const I32: u8 = 0x7f;

#[derive(Clone, Copy)]
enum Mutant {
    Valid,
    ExtraAction,
    ExtraWrite,
    Trap,
    TraceDivergence,
    BadReset,
}

struct Fixture {
    relation: RelationCertificate,
    relation_bytes: Vec<u8>,
    inductive_bytes: Vec<u8>,
    expected: ExpectedInductiveContract,
    transcript: TranslationTranscript,
    target: CanonicalTargetIr,
}

fn push_u32(out: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            return;
        }
    }
}

fn push_name(out: &mut Vec<u8>, value: &str) {
    push_u32(out, value.len() as u32);
    out.extend_from_slice(value.as_bytes());
}

fn section(module: &mut Vec<u8>, id: u8, payload: &[u8]) {
    module.push(id);
    push_u32(module, payload.len() as u32);
    module.extend_from_slice(payload);
}

fn function_type(params: &[u8], result: Option<u8>) -> Vec<u8> {
    let mut bytes = vec![0x60];
    push_u32(&mut bytes, params.len() as u32);
    bytes.extend_from_slice(params);
    if let Some(result) = result {
        bytes.extend_from_slice(&[1, result]);
    } else {
        bytes.push(0);
    }
    bytes
}

fn call_frame(ops: &mut Vec<u8>) {
    ops.extend_from_slice(&[0x41, 0, 0x41, 4, 0x10, 0]);
}

fn call_action(ops: &mut Vec<u8>) {
    ops.extend_from_slice(&[0x41, 7, 0x41, 0, 0x10, 1]);
}

fn target_module(mutant: Mutant) -> CanonicalTargetIr {
    let mut module = b"\0asm\x01\0\0\0".to_vec();

    let signatures = [
        function_type(&[I32, I32, I32], None),
        function_type(&[], None),
        function_type(&[I32, I32], None),
        function_type(&[I32, I32], None),
    ];
    let mut types = vec![signatures.len() as u8];
    for signature in signatures {
        types.extend_from_slice(&signature);
    }
    section(&mut module, 1, &types);

    let mut imports = vec![2];
    for (name, type_index) in [("emit_frame", 2_u8), ("emit_action", 3_u8)] {
        push_name(&mut imports, "qseal");
        push_name(&mut imports, name);
        imports.extend_from_slice(&[0, type_index]);
    }
    section(&mut module, 2, &imports);
    section(&mut module, 3, &[4, 0, 1, 1, 1]);
    section(&mut module, 5, &[1, 1, 1, 1]);
    section(&mut module, 6, &[1, I32, 1, 0x41, 0, 0x0b]);

    let mut exports = vec![4];
    for (name, index) in [
        ("tick", 2_u8),
        ("reset", 3_u8),
        ("handoff", 4_u8),
        ("status", 5_u8),
    ] {
        push_name(&mut exports, name);
        exports.extend_from_slice(&[0, index]);
    }
    section(&mut module, 7, &exports);

    let mut tick = Vec::new();
    match mutant {
        Mutant::Trap => tick.push(0x00),
        Mutant::TraceDivergence => {
            tick.extend_from_slice(&[0x23, 0, 0x04, 0x40, 0x01, 0x0b]);
            call_frame(&mut tick);
            call_action(&mut tick);
        }
        Mutant::ExtraWrite => {
            tick.extend_from_slice(&[0x41, 8, 0x41, 1, 0x36, 2, 0]);
            call_frame(&mut tick);
            call_action(&mut tick);
        }
        Mutant::ExtraAction => {
            call_frame(&mut tick);
            call_action(&mut tick);
            call_action(&mut tick);
        }
        Mutant::Valid | Mutant::BadReset => {
            call_frame(&mut tick);
            call_action(&mut tick);
        }
    }
    if !matches!(mutant, Mutant::Trap) {
        tick.extend_from_slice(&[0x41, 1, 0x24, 0]);
    }
    let reset = if matches!(mutant, Mutant::BadReset) {
        vec![0x01]
    } else {
        vec![0x41, 0, 0x24, 0]
    };
    let bodies = [tick, reset, vec![0x01], vec![0x01]];
    let mut code = vec![bodies.len() as u8];
    for ops in bodies {
        let mut body = vec![0];
        body.extend_from_slice(&ops);
        body.push(0x0b);
        push_u32(&mut code, body.len() as u32);
        code.extend_from_slice(&body);
    }
    section(&mut module, 10, &code);
    section(
        &mut module,
        11,
        &[1, 0, 0x41, 0, 0x0b, 4, b's', b'a', b'm', b'e'],
    );
    parse_and_lower(&module, ParserLimits::default()).expect("target module must parse")
}

fn source_certificate() -> Certificate {
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
        outputs: vec![OutputRecord {
            id: 0,
            emitted: true,
            payload: b"same".to_vec(),
            actions: vec![7],
        }],
        transitions: vec![
            TransitionRecord {
                from: 0,
                input: 0,
                to: 1,
                output: 0,
                authorized_actions: vec![7],
                required_action: Some(7),
                recoverable_fault_action: Some(7),
            },
            TransitionRecord {
                from: 1,
                input: 0,
                to: 1,
                output: 0,
                authorized_actions: vec![7],
                required_action: Some(7),
                recoverable_fault_action: Some(7),
            },
        ],
        relation: vec![RelationPair { left: 0, right: 1 }],
    };
    certificate.seal();
    certificate
}

fn expected(base: &Certificate) -> ExpectedInductiveContract {
    ExpectedInductiveContract {
        base: ExpectedContract {
            version: FORMAT_VERSION,
            hashes: base.hashes,
            state_bound: base.state_bound,
            max_cost: base.claimed_cost,
        },
        initial_pairs: vec![RelationPair { left: 0, right: 1 }],
    }
}

fn transcript(manifest_digest: Digest) -> TranslationTranscript {
    TranslationTranscript {
        build: BuildEvidence {
            target: TargetKind::Wasm32UnknownUnknown,
            certificate_digest: artifact_digest(b"test-k7", b"certificate"),
            manifest_digest,
            compiler: "rustc".to_owned(),
            compiler_version: "fixture".to_owned(),
            command: "cargo build --target wasm32-unknown-unknown".to_owned(),
        },
        steps: Vec::new(),
        lifecycle: Vec::new(),
        invalid_probes: Vec::new(),
        bounded_sequence: Vec::new(),
    }
}

fn fixture(mutant: Mutant) -> Fixture {
    let base = source_certificate();
    let expected = expected(&base);
    let inductive = build_inductive_certificate(&base, vec![RelationPair { left: 0, right: 1 }])
        .expect("inductive certificate");
    let inductive_bytes = inductive.encode();
    let inductive_report =
        match verify_inductive(&inductive_bytes, &expected, InductiveLimits::default()) {
            InductiveVerdict::Valid(report) => report,
            verdict => panic!("inductive fixture must validate: {verdict:?}"),
        };
    let target = target_module(mutant);
    let manifest_digest = artifact_digest(b"test-k7-manifest", b"manifest");
    let transcript = transcript(manifest_digest);
    let tick_index = target
        .exports()
        .iter()
        .find(|export| export.name() == "tick")
        .expect("tick export")
        .function_index() as usize;
    let tick_end = target.functions()[tick_index - target.imports().len()]
        .instructions()
        .len()
        - 1;
    let mut exit_pcs = vec![1, 2, tick_end as u32];
    exit_pcs.sort_unstable();
    exit_pcs.dedup();
    let records = (0..2)
        .map(|source_state| RelationRecord {
            source_state,
            entry_pcs: vec![0],
            exit_pcs: exit_pcs.clone(),
            globals: vec![GlobalPredicate {
                index: 0,
                value: quotient_seal_small_step::Value::I32(source_state),
            }],
            memory: vec![MemoryPredicate {
                offset: 0,
                bytes: b"same".to_vec(),
            }],
            allowed_writes: Vec::new(),
        })
        .collect();
    let relation = RelationCertificate {
        version: RELATION_FORMAT_VERSION,
        inductive_digest: inductive_report.certificate_digest,
        target_ir_digest: target_ir_hash(&target),
        k7_manifest_digest: manifest_digest,
        quotient_inputs: 1,
        public_inputs: 1,
        fault_inputs: 1,
        action_deadline_steps: 0,
        records,
    };
    let relation_bytes = relation.encode();
    Fixture {
        relation,
        relation_bytes,
        inductive_bytes,
        expected,
        transcript,
        target,
    }
}

fn validate(fixture: &Fixture, limits: RelationValidationLimits) -> RelationVerdict {
    validate_relation(RelationValidationInput {
        relation_bytes: &fixture.relation_bytes,
        inductive_bytes: &fixture.inductive_bytes,
        expected_inductive: &fixture.expected,
        k7_reference: &fixture.transcript,
        k7_observed: &fixture.transcript,
        parser_consensus: ConsensusVerdict::Valid(target_ir_hash(&fixture.target)),
        target_ir: &fixture.target,
        limits,
    })
}

#[test]
fn valid_certificate_recomputes_all_steps_lifecycle_and_two_run() {
    let fixture = fixture(Mutant::Valid);
    let report = match validate(&fixture, RelationValidationLimits::default()) {
        RelationVerdict::Valid(report) => report,
        verdict => panic!("valid fixture must validate: {verdict:?}"),
    };
    assert_eq!(report.reachable_states, 2);
    assert_eq!(report.checked_source_steps, 2);
    assert_eq!(report.checked_lifecycle_calls, 6);
    assert_eq!(report.checked_two_run_cases, 1);
    assert!(report.checked_observer_events > 0);
}

#[test]
fn reachable_state_coverage_and_bindings_are_recomputed() {
    let mut missing = fixture(Mutant::Valid);
    missing.relation.records.pop();
    missing.relation_bytes = missing.relation.encode();
    assert!(matches!(
        validate(&missing, RelationValidationLimits::default()),
        RelationVerdict::Invalid(counterexample)
            if counterexample.kind == DivergenceKind::ReachableCoverage
    ));

    let mut binding = fixture(Mutant::Valid);
    binding.relation.target_ir_digest = Digest::zero();
    binding.relation_bytes = binding.relation.encode();
    assert!(matches!(
        validate(&binding, RelationValidationLimits::default()),
        RelationVerdict::Invalid(counterexample)
            if counterexample.kind == DivergenceKind::Binding
    ));
}

#[test]
fn extra_action_trap_and_extra_write_fail_closed() {
    assert!(matches!(
        validate(
            &fixture(Mutant::ExtraAction),
            RelationValidationLimits::default()
        ),
        RelationVerdict::Invalid(counterexample)
            if counterexample.kind == DivergenceKind::TargetTrap
    ));
    assert!(matches!(
        validate(
            &fixture(Mutant::ExtraWrite),
            RelationValidationLimits::default()
        ),
        RelationVerdict::Invalid(counterexample)
            if counterexample.kind == DivergenceKind::ExtraMemoryWrite
    ));
    assert!(matches!(
        validate(
            &fixture(Mutant::Trap),
            RelationValidationLimits::default()
        ),
        RelationVerdict::Invalid(counterexample)
            if counterexample.kind == DivergenceKind::TargetTrap
    ));
}

#[test]
fn action_equivalent_state_dependent_trace_is_rejected() {
    assert!(matches!(
        validate(
            &fixture(Mutant::TraceDivergence),
            RelationValidationLimits::default()
        ),
        RelationVerdict::Invalid(counterexample)
            if counterexample.kind == DivergenceKind::ObserverTrace
                && counterexample.pair_left == Some(0)
                && counterexample.pair_right == Some(1)
                && counterexample.event_index.is_some()
    ));
}

#[test]
fn reset_must_reestablish_source_state_zero_relation() {
    assert!(matches!(
        validate(
            &fixture(Mutant::BadReset),
            RelationValidationLimits::default()
        ),
        RelationVerdict::Invalid(counterexample)
            if counterexample.kind == DivergenceKind::Reset
    ));
}

#[test]
fn k7_translation_mismatch_is_checked_before_target_execution() {
    let fixture = fixture(Mutant::Valid);
    let mut observed = fixture.transcript.clone();
    observed.build.manifest_digest = Digest::zero();
    let verdict = validate_relation(RelationValidationInput {
        relation_bytes: &fixture.relation_bytes,
        inductive_bytes: &fixture.inductive_bytes,
        expected_inductive: &fixture.expected,
        k7_reference: &fixture.transcript,
        k7_observed: &observed,
        parser_consensus: ConsensusVerdict::Valid(target_ir_hash(&fixture.target)),
        target_ir: &fixture.target,
        limits: RelationValidationLimits::default(),
    });
    assert!(matches!(
        verdict,
        RelationVerdict::Invalid(counterexample)
            if counterexample.kind == DivergenceKind::K7Translation
    ));
}

#[test]
fn parser_disagreement_and_case_budget_never_become_valid() {
    let fixture = fixture(Mutant::Valid);
    let unresolved = validate_relation(RelationValidationInput {
        relation_bytes: &fixture.relation_bytes,
        inductive_bytes: &fixture.inductive_bytes,
        expected_inductive: &fixture.expected,
        k7_reference: &fixture.transcript,
        k7_observed: &fixture.transcript,
        parser_consensus: ConsensusVerdict::Unresolved,
        target_ir: &fixture.target,
        limits: RelationValidationLimits::default(),
    });
    assert_eq!(
        unresolved,
        RelationVerdict::Unresolved(RelationUnresolved::ParserConsensus)
    );

    let limits = RelationValidationLimits {
        max_cases: 1,
        ..RelationValidationLimits::default()
    };
    assert!(matches!(
        validate(&fixture, limits),
        RelationVerdict::ResourceBound(RelationResourceBound::SourceCases { .. })
    ));
}

#[test]
fn malformed_trailing_and_versioned_certificates_are_not_accepted() {
    let mut trailing = fixture(Mutant::Valid);
    trailing.relation_bytes.push(0);
    assert!(matches!(
        validate(&trailing, RelationValidationLimits::default()),
        RelationVerdict::Invalid(counterexample)
            if counterexample.kind == DivergenceKind::RelationCertificate
    ));

    let mut incompatible = fixture(Mutant::Valid);
    incompatible.relation.version = 2;
    incompatible.relation_bytes = incompatible.relation.encode();
    assert_eq!(
        validate(&incompatible, RelationValidationLimits::default()),
        RelationVerdict::Incompatible(RelationIncompatible::RelationVersion(2))
    );
}

#[test]
fn certificate_limits_and_counterexample_artifact_are_reproducible() {
    let valid_fixture = fixture(Mutant::Valid);
    let limits = RelationValidationLimits {
        relation: RelationLimits {
            max_bytes: valid_fixture.relation_bytes.len() - 1,
            ..RelationLimits::default()
        },
        ..RelationValidationLimits::default()
    };
    assert!(matches!(
        validate(&valid_fixture, limits),
        RelationVerdict::ResourceBound(RelationResourceBound::RelationCertificate(_))
    ));

    let mutant = fixture(Mutant::ExtraWrite);
    let RelationVerdict::Invalid(first) = validate(&mutant, RelationValidationLimits::default())
    else {
        panic!("mutant must fail");
    };
    let RelationVerdict::Invalid(second) = validate(&mutant, RelationValidationLimits::default())
    else {
        panic!("mutant must fail reproducibly");
    };
    assert_eq!(first, second);
    assert_eq!(first.encode(), second.encode());
}

#[test]
fn frozen_contract_records_gates_nonclaims_and_hardware_state() {
    let contract = include_str!("../../../configs/quotient_seal/relation_v1.yaml");
    let schema = include_str!("../../../schemas/quotient_seal_relation_v1.schema.json");
    let documentation = include_str!("../../../docs/quotient_seal_relation.md");

    for required in [
        "QUOTIENT_SEAL_RELATION_V1",
        "K7-03",
        "K7-10",
        "K8-03",
        "K8-04",
        "INCONCLUSIVE",
        "UNRESOLVED",
        "first-lexicographic-divergence",
    ] {
        assert!(contract.contains(required), "contract missing {required}");
    }
    assert!(schema.contains("QUOTIENT_SEAL_RELATION_V1"));
    assert!(documentation.contains("candidate"));
    assert!(documentation.contains("NOT_VERIFIED"));
    assert!(!documentation.contains("world-first"));
}
