use std::panic::{catch_unwind, AssertUnwindSafe};

use quotient_seal_target_ir::{
    local_parser_decision, parse_and_lower, reconcile_parser_decisions, target_ir_contract_hash,
    target_ir_hash, ConsensusVerdict, ExternalParserDecision, LocalParserDecision, ParserLimits,
    ResourceKind, TargetIrError, UnsupportedFeature, QUOTIENT_SEAL_TARGET_IR_V1,
};

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

fn type_payload() -> Vec<u8> {
    vec![
        4, 0x60, 2, 0x7f, 0x7f, 0, 0x60, 2, 0x7f, 0x7f, 0, 0x60, 1, 0x7f, 0, 0x60, 0, 0,
    ]
}

fn import_payload() -> Vec<u8> {
    let mut payload = vec![3];
    for (name, type_index) in [
        ("emit_frame", 0_u8),
        ("emit_action", 1_u8),
        ("public_failure", 2_u8),
    ] {
        push_name(&mut payload, "qseal");
        push_name(&mut payload, name);
        payload.push(0);
        payload.push(type_index);
    }
    payload
}

fn valid_module(custom_name: Option<&str>, body_ops: &[u8]) -> Vec<u8> {
    let mut module = b"\0asm\x01\0\0\0".to_vec();
    if let Some(name) = custom_name {
        let mut custom = Vec::new();
        push_name(&mut custom, name);
        custom.extend_from_slice(b"ignored-metadata");
        section(&mut module, 0, &custom);
    }
    section(&mut module, 1, &type_payload());
    section(&mut module, 2, &import_payload());
    section(&mut module, 3, &[1, 3]);
    section(&mut module, 5, &[1, 1, 1, 1]);
    section(&mut module, 6, &[1, 0x7f, 1, 0x41, 0, 0x0b]);

    let mut exports = vec![1];
    push_name(&mut exports, "tick");
    exports.extend_from_slice(&[0, 3]);
    section(&mut module, 7, &exports);

    let mut body = vec![1, 1, 0x7f];
    body.extend_from_slice(body_ops);
    body.push(0x0b);
    let mut code = vec![1];
    push_u32(&mut code, body.len() as u32);
    code.extend_from_slice(&body);
    section(&mut module, 10, &code);

    section(
        &mut module,
        11,
        &[1, 0, 0x41, 0, 0x0b, 4, 0xde, 0xad, 0xbe, 0xef],
    );
    module
}

fn accepted_module() -> Vec<u8> {
    valid_module(
        None,
        &[0x41, 0, 0x41, 7, 0x36, 2, 0, 0x23, 0, 0x1a, 0x20, 0, 0x1a],
    )
}

#[test]
fn accepted_ir_and_hash_are_byte_reproducible() {
    let module = accepted_module();
    let first = parse_and_lower(&module, ParserLimits::default()).expect("accepted module");
    let second = parse_and_lower(&module, ParserLimits::default()).expect("accepted module");

    assert_eq!(first, second);
    assert_eq!(first.canonical_bytes(), second.canonical_bytes());
    assert_eq!(target_ir_hash(&first), target_ir_hash(&second));
    assert_eq!(target_ir_contract_hash(), target_ir_contract_hash());
    assert_eq!(first.memory().pages(), 1);
    assert_eq!(first.data_segments()[0].offset(), 0);
    assert_eq!(QUOTIENT_SEAL_TARGET_IR_V1, "QUOTIENT_SEAL_TARGET_IR_V1");
}

#[test]
fn custom_metadata_is_validated_but_erased_from_hash() {
    let alpha = parse_and_lower(
        &valid_module(Some("producer.alpha"), &[0x01]),
        ParserLimits::default(),
    )
    .expect("alpha module");
    let beta = parse_and_lower(
        &valid_module(Some("producer.beta"), &[0x01]),
        ParserLimits::default(),
    )
    .expect("beta module");

    assert_eq!(alpha.canonical_bytes(), beta.canonical_bytes());
    assert_eq!(target_ir_hash(&alpha), target_ir_hash(&beta));
}

#[test]
fn unsupported_instruction_families_fail_closed() {
    for (body, expected) in [
        (&[0x43, 0, 0, 0, 0][..], UnsupportedFeature::Float),
        (&[0x40, 0][..], UnsupportedFeature::MemoryGrow),
        (&[0x11, 0, 0][..], UnsupportedFeature::CallIndirect),
        (&[0xfd, 0][..], UnsupportedFeature::Simd),
        (&[0xfe, 0][..], UnsupportedFeature::Threads),
        (&[0xfc, 0][..], UnsupportedFeature::BulkMemory),
    ] {
        let error = parse_and_lower(&valid_module(None, body), ParserLimits::default())
            .expect_err("unsupported instruction must be rejected");
        assert_eq!(error, TargetIrError::Incompatible(expected));
    }
}

#[test]
fn malformed_sections_lengths_and_utf8_are_rejected() {
    let mut duplicate = b"\0asm\x01\0\0\0".to_vec();
    section(&mut duplicate, 1, &[0]);
    section(&mut duplicate, 1, &[0]);
    assert!(matches!(
        parse_and_lower(&duplicate, ParserLimits::default()),
        Err(TargetIrError::Invalid(_))
    ));

    let mut unknown = b"\0asm\x01\0\0\0".to_vec();
    section(&mut unknown, 99, &[]);
    assert!(matches!(
        parse_and_lower(&unknown, ParserLimits::default()),
        Err(TargetIrError::Invalid(_))
    ));

    let mut trailing = b"\0asm\x01\0\0\0".to_vec();
    section(&mut trailing, 1, &[0, 0]);
    assert!(matches!(
        parse_and_lower(&trailing, ParserLimits::default()),
        Err(TargetIrError::Invalid(_))
    ));

    let huge = b"\0asm\x01\0\0\0\x01\xff\xff\xff\xff\x0f".to_vec();
    assert!(matches!(
        parse_and_lower(&huge, ParserLimits::default()),
        Err(TargetIrError::Invalid(_))
    ));

    let invalid_utf8 = b"\0asm\x01\0\0\0\x00\x02\x01\xff".to_vec();
    assert!(matches!(
        parse_and_lower(&invalid_utf8, ParserLimits::default()),
        Err(TargetIrError::Invalid(_))
    ));
}

#[test]
fn section_order_and_noncanonical_leb_are_rejected() {
    let mut wrong_order = b"\0asm\x01\0\0\0".to_vec();
    section(&mut wrong_order, 5, &[1, 1, 1, 1]);
    section(&mut wrong_order, 1, &[0]);
    assert!(matches!(
        parse_and_lower(&wrong_order, ParserLimits::default()),
        Err(TargetIrError::Invalid(_))
    ));

    let noncanonical = b"\0asm\x01\0\0\0\x01\x80\x00".to_vec();
    assert!(matches!(
        parse_and_lower(&noncanonical, ParserLimits::default()),
        Err(TargetIrError::Invalid(_))
    ));
}

#[test]
fn resource_bound_is_not_reported_as_success() {
    let module = accepted_module();
    let limits = ParserLimits {
        max_module_bytes: module.len() - 1,
        ..ParserLimits::default()
    };
    let result = parse_and_lower(&module, limits);
    assert!(matches!(
        result,
        Err(TargetIrError::ResourceBound(bound))
            if bound.resource == ResourceKind::ModuleBytes
    ));
    assert_eq!(
        local_parser_decision(&result),
        LocalParserDecision::ResourceBound
    );
}

#[test]
fn any_cross_parser_difference_is_unresolved() {
    let parsed = parse_and_lower(&accepted_module(), ParserLimits::default());
    let local = local_parser_decision(&parsed);
    assert!(matches!(local, LocalParserDecision::Accepted(_)));
    assert!(matches!(
        reconcile_parser_decisions(
            local,
            ExternalParserDecision::Accepted,
            ExternalParserDecision::Accepted
        ),
        ConsensusVerdict::Valid(_)
    ));
    assert_eq!(
        reconcile_parser_decisions(
            local,
            ExternalParserDecision::Rejected,
            ExternalParserDecision::Accepted
        ),
        ConsensusVerdict::Unresolved
    );
    assert_eq!(
        reconcile_parser_decisions(
            local,
            ExternalParserDecision::Accepted,
            ExternalParserDecision::NotRun
        ),
        ConsensusVerdict::Unresolved
    );
}

#[test]
fn arbitrary_bytes_never_panic() {
    let limits = ParserLimits::default();
    let mut state = 0x8a5c_31d2_u32;
    for case in 0..4_096_usize {
        let len = case % 193;
        let mut bytes = Vec::with_capacity(len);
        for _ in 0..len {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            bytes.push((state >> 24) as u8);
        }
        let result = catch_unwind(AssertUnwindSafe(|| parse_and_lower(&bytes, limits)));
        assert!(result.is_ok(), "parser panicked for corpus case {case}");
    }
}

#[test]
fn frozen_contract_files_name_the_fail_closed_boundary() {
    let contract = include_str!("../../../configs/quotient_seal/target_ir_v1.yaml");
    let schema = include_str!("../../../schemas/quotient_seal_target_ir_v1.schema.json");
    let documentation = include_str!("../../../docs/quotient_seal_target_ir.md");

    for required in [
        "QUOTIENT_SEAL_TARGET_IR_V1",
        "UNRESOLVED",
        "memory.grow",
        "call_indirect",
        "wasmparser",
        "wasm-tools",
    ] {
        assert!(contract.contains(required), "contract missing {required}");
    }
    assert!(schema.contains("QUOTIENT_SEAL_TARGET_IR_V1"));
    assert!(documentation.contains("NOT_VERIFIED"));
    assert!(documentation.contains("candidate"));
    assert!(!documentation.contains("world-first"));
}
