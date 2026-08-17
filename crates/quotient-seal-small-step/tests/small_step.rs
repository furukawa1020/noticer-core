use quotient_seal_small_step::{
    ControlEvent, ExecutionEvent, HostDirective, HostOutcome, InterpreterLimits, MachineStatus,
    MemoryAccessKind, PublicHostTape, ResourceExhaustion, TrapCode, Value, WasmMachine,
    EMIT_ACTION_FUEL_COST, QUOTIENT_SEAL_SMALL_STEP_V1,
};
use quotient_seal_target_ir::{parse_and_lower, CanonicalTargetIr, ParserLimits};

const I32: u8 = 0x7f;

#[derive(Clone)]
struct Signature {
    params: Vec<u8>,
    result: Option<u8>,
}

#[derive(Clone)]
struct Body {
    type_index: u32,
    locals: Vec<(u32, u8)>,
    ops: Vec<u8>,
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

fn push_i32(out: &mut Vec<u8>, mut value: i32) {
    loop {
        let byte = (value as u8) & 0x7f;
        value >>= 7;
        let done = (value == 0 && byte & 0x40 == 0) || (value == -1 && byte & 0x40 != 0);
        out.push(if done { byte } else { byte | 0x80 });
        if done {
            return;
        }
    }
}

fn i32_const(out: &mut Vec<u8>, value: i32) {
    out.push(0x41);
    push_i32(out, value);
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

fn module(
    signatures: &[Signature],
    imports: &[(&str, u32)],
    bodies: &[Body],
    export_index: u32,
    data: &[(u32, Vec<u8>)],
) -> Vec<u8> {
    let mut module = b"\0asm\x01\0\0\0".to_vec();

    let mut types = Vec::new();
    push_u32(&mut types, signatures.len() as u32);
    for signature in signatures {
        types.push(0x60);
        push_u32(&mut types, signature.params.len() as u32);
        types.extend_from_slice(&signature.params);
        if let Some(result) = signature.result {
            types.extend_from_slice(&[1, result]);
        } else {
            types.push(0);
        }
    }
    section(&mut module, 1, &types);

    if !imports.is_empty() {
        let mut import_section = Vec::new();
        push_u32(&mut import_section, imports.len() as u32);
        for (name, type_index) in imports {
            push_name(&mut import_section, "qseal");
            push_name(&mut import_section, name);
            import_section.push(0);
            push_u32(&mut import_section, *type_index);
        }
        section(&mut module, 2, &import_section);
    }

    let mut functions = Vec::new();
    push_u32(&mut functions, bodies.len() as u32);
    for body in bodies {
        push_u32(&mut functions, body.type_index);
    }
    section(&mut module, 3, &functions);
    section(&mut module, 5, &[1, 1, 1, 1]);

    let mut exports = vec![1];
    push_name(&mut exports, "tick");
    exports.push(0);
    push_u32(&mut exports, export_index);
    section(&mut module, 7, &exports);

    let mut code = Vec::new();
    push_u32(&mut code, bodies.len() as u32);
    for definition in bodies {
        let mut body = Vec::new();
        push_u32(&mut body, definition.locals.len() as u32);
        for (count, value_type) in &definition.locals {
            push_u32(&mut body, *count);
            body.push(*value_type);
        }
        body.extend_from_slice(&definition.ops);
        body.push(0x0b);
        push_u32(&mut code, body.len() as u32);
        code.extend_from_slice(&body);
    }
    section(&mut module, 10, &code);

    let mut data_section = Vec::new();
    push_u32(&mut data_section, data.len() as u32);
    for (offset, bytes) in data {
        data_section.push(0);
        data_section.push(0x41);
        push_i32(&mut data_section, *offset as i32);
        data_section.push(0x0b);
        push_u32(&mut data_section, bytes.len() as u32);
        data_section.extend_from_slice(bytes);
    }
    section(&mut module, 11, &data_section);
    module
}

fn parse(bytes: &[u8]) -> CanonicalTargetIr {
    parse_and_lower(bytes, ParserLimits::default()).expect("restricted module must parse")
}

fn run(
    ir: &CanonicalTargetIr,
    fuel: u64,
    tape: PublicHostTape,
) -> quotient_seal_small_step::ExecutionReport {
    WasmMachine::instantiate(
        ir,
        "tick",
        Vec::new(),
        fuel,
        tape,
        InterpreterLimits::default(),
    )
    .expect("machine must instantiate")
    .run()
}

fn one_result_module(ops: Vec<u8>) -> CanonicalTargetIr {
    parse(&module(
        &[Signature {
            params: vec![],
            result: Some(I32),
        }],
        &[],
        &[Body {
            type_index: 0,
            locals: vec![],
            ops,
        }],
        0,
        &[],
    ))
}

#[test]
fn identical_module_tape_fuel_and_state_have_identical_trace() {
    let mut ops = Vec::new();
    i32_const(&mut ops, 40);
    i32_const(&mut ops, 2);
    ops.push(0x6a);
    let ir = one_result_module(ops);

    let first = run(&ir, 100, PublicHostTape::default());
    let second = run(&ir, 100, PublicHostTape::default());

    assert_eq!(first, second);
    assert_eq!(
        first.state().status(),
        &MachineStatus::Returned(vec![Value::I32(42)])
    );
    assert!(first
        .state()
        .events()
        .iter()
        .any(|event| matches!(event, ExecutionEvent::FuelCharged { .. })));
}

#[test]
fn if_branch_and_bounded_loop_follow_structured_control() {
    let mut if_ops = Vec::new();
    i32_const(&mut if_ops, 0);
    if_ops.extend_from_slice(&[0x04, I32]);
    i32_const(&mut if_ops, 7);
    if_ops.push(0x05);
    i32_const(&mut if_ops, 9);
    if_ops.push(0x0b);
    let if_report = run(&one_result_module(if_ops), 100, PublicHostTape::default());
    assert_eq!(
        if_report.state().status(),
        &MachineStatus::Returned(vec![Value::I32(9)])
    );

    let mut loop_ops = vec![0x02, 0x40, 0x03, 0x40, 0x20, 0];
    i32_const(&mut loop_ops, 1);
    loop_ops.extend_from_slice(&[0x6a, 0x22, 0]);
    i32_const(&mut loop_ops, 3);
    loop_ops.extend_from_slice(&[0x49, 0x0d, 0, 0x0b, 0x0b, 0x20, 0]);
    let loop_ir = parse(&module(
        &[Signature {
            params: vec![],
            result: Some(I32),
        }],
        &[],
        &[Body {
            type_index: 0,
            locals: vec![(1, I32)],
            ops: loop_ops,
        }],
        0,
        &[],
    ));
    let loop_report = run(&loop_ir, 200, PublicHostTape::default());
    assert_eq!(
        loop_report.state().status(),
        &MachineStatus::Returned(vec![Value::I32(3)])
    );
    assert!(loop_report.state().events().iter().any(|event| matches!(
        event,
        ExecutionEvent::Control {
            event: ControlEvent::Branch { depth: 0 },
            ..
        }
    )));
}

#[test]
fn fixed_memory_load_and_store_are_traced_without_contents() {
    let mut ops = Vec::new();
    i32_const(&mut ops, 4);
    i32_const(&mut ops, 42);
    ops.extend_from_slice(&[0x36, 2, 0]);
    i32_const(&mut ops, 4);
    ops.extend_from_slice(&[0x28, 2, 0]);
    let report = run(&one_result_module(ops), 100, PublicHostTape::default());

    assert_eq!(
        report.state().status(),
        &MachineStatus::Returned(vec![Value::I32(42)])
    );
    let accesses: Vec<_> = report
        .state()
        .events()
        .iter()
        .filter_map(|event| match event {
            ExecutionEvent::Memory {
                kind,
                address,
                width,
                ..
            } => Some((*kind, *address, *width)),
            _ => None,
        })
        .collect();
    assert_eq!(
        accesses,
        vec![
            (MemoryAccessKind::Store, 4, 4),
            (MemoryAccessKind::Load, 4, 4)
        ]
    );
}

#[test]
fn direct_call_and_explicit_return_restore_caller() {
    let mut entry = vec![0x10, 1, 0x0f];
    i32_const(&mut entry, 99);
    let mut callee = Vec::new();
    i32_const(&mut callee, 13);
    let ir = parse(&module(
        &[Signature {
            params: vec![],
            result: Some(I32),
        }],
        &[],
        &[
            Body {
                type_index: 0,
                locals: vec![],
                ops: entry,
            },
            Body {
                type_index: 0,
                locals: vec![],
                ops: callee,
            },
        ],
        0,
        &[],
    ));
    let report = run(&ir, 100, PublicHostTape::default());
    assert_eq!(
        report.state().status(),
        &MachineStatus::Returned(vec![Value::I32(13)])
    );
    assert!(report.state().call_stack().is_empty());
}

#[test]
fn declared_host_call_uses_ordered_tape_and_fixed_public_cost() {
    let mut ops = Vec::new();
    i32_const(&mut ops, 0);
    i32_const(&mut ops, 4);
    ops.extend_from_slice(&[0x10, 0]);
    let ir = parse(&module(
        &[
            Signature {
                params: vec![I32, I32],
                result: None,
            },
            Signature {
                params: vec![],
                result: None,
            },
        ],
        &[("emit_action", 0)],
        &[Body {
            type_index: 1,
            locals: vec![],
            ops,
        }],
        1,
        &[(0, vec![1, 2, 3, 4])],
    ));
    let tape = PublicHostTape::new(vec![HostDirective::new(
        "emit_action",
        HostOutcome::Continue,
    )]);
    let report = run(&ir, 100, tape);

    assert_eq!(report.state().status(), &MachineStatus::Returned(vec![]));
    assert_eq!(report.consumed_host_directives(), 1);
    assert!(report.state().events().iter().any(|event| matches!(
        event,
        ExecutionEvent::HostCall {
            import,
            public_cost,
            ..
        } if import == "emit_action" && *public_cost == EMIT_ACTION_FUEL_COST
    )));

    let mismatch = run(
        &ir,
        100,
        PublicHostTape::new(vec![HostDirective::new(
            "emit_frame",
            HostOutcome::Continue,
        )]),
    );
    assert_eq!(
        mismatch.state().status(),
        &MachineStatus::Trapped(TrapCode::HostTapeMismatch)
    );
}

#[test]
fn host_termination_is_distinct_from_normal_return() {
    let mut ops = Vec::new();
    i32_const(&mut ops, 1);
    ops.extend_from_slice(&[0x10, 0]);
    let ir = parse(&module(
        &[
            Signature {
                params: vec![I32],
                result: None,
            },
            Signature {
                params: vec![],
                result: None,
            },
        ],
        &[("public_failure", 0)],
        &[Body {
            type_index: 1,
            locals: vec![],
            ops,
        }],
        1,
        &[],
    ));
    let report = run(
        &ir,
        100,
        PublicHostTape::new(vec![HostDirective::new(
            "public_failure",
            HostOutcome::Terminate,
        )]),
    );
    assert_eq!(report.state().status(), &MachineStatus::Terminated);
    assert!(report
        .state()
        .events()
        .iter()
        .any(|event| matches!(event, ExecutionEvent::Termination { .. })));
}

#[test]
fn semantic_faults_have_distinct_trap_codes() {
    let unreachable = run(
        &one_result_module(vec![0x00]),
        100,
        PublicHostTape::default(),
    );
    assert_eq!(
        unreachable.state().status(),
        &MachineStatus::Trapped(TrapCode::Unreachable)
    );

    let mut divide_zero = Vec::new();
    i32_const(&mut divide_zero, 1);
    i32_const(&mut divide_zero, 0);
    divide_zero.push(0x6d);
    assert_eq!(
        run(
            &one_result_module(divide_zero),
            100,
            PublicHostTape::default()
        )
        .state()
        .status(),
        &MachineStatus::Trapped(TrapCode::IntegerDivideByZero)
    );

    let mut overflow = Vec::new();
    i32_const(&mut overflow, i32::MIN);
    i32_const(&mut overflow, -1);
    overflow.push(0x6d);
    assert_eq!(
        run(&one_result_module(overflow), 100, PublicHostTape::default())
            .state()
            .status(),
        &MachineStatus::Trapped(TrapCode::IntegerOverflow)
    );

    let mut bounds = Vec::new();
    i32_const(&mut bounds, 65_535);
    bounds.extend_from_slice(&[0x28, 2, 0]);
    assert_eq!(
        run(&one_result_module(bounds), 100, PublicHostTape::default())
            .state()
            .status(),
        &MachineStatus::Trapped(TrapCode::MemoryOutOfBounds)
    );

    let mut invalid_conversion = Vec::new();
    i32_const(&mut invalid_conversion, 1);
    invalid_conversion.push(0xa7);
    assert_eq!(
        run(
            &one_result_module(invalid_conversion),
            100,
            PublicHostTape::default()
        )
        .state()
        .status(),
        &MachineStatus::Trapped(TrapCode::InvalidConversion)
    );
}

#[test]
fn bounded_nontermination_is_resource_bound_and_inconclusive() {
    let ir = parse(&module(
        &[Signature {
            params: vec![],
            result: None,
        }],
        &[],
        &[Body {
            type_index: 0,
            locals: vec![],
            ops: vec![0x03, 0x40, 0x0c, 0, 0x0b],
        }],
        0,
        &[],
    ));
    let report = run(&ir, 7, PublicHostTape::default());
    assert!(matches!(
        report.state().status(),
        MachineStatus::ResourceBound(ResourceExhaustion::Fuel { .. })
    ));
    assert!(report.state().events().iter().any(|event| matches!(
        event,
        ExecutionEvent::ResourceBound {
            resource: ResourceExhaustion::Fuel { .. },
            ..
        }
    )));
}

#[test]
fn frozen_contract_records_nonclaims_and_hardware_state() {
    let contract = include_str!("../../../configs/quotient_seal/small_step_v1.yaml");
    let schema = include_str!("../../../schemas/quotient_seal_small_step_v1.schema.json");
    let documentation = include_str!("../../../docs/quotient_seal_small_step.md");

    for required in [
        "QUOTIENT_SEAL_SMALL_STEP_V1",
        "RESOURCE_BOUND",
        "INCONCLUSIVE",
        "qseal.emit_frame",
        "qseal.emit_action",
        "qseal.public_failure",
    ] {
        assert!(contract.contains(required), "contract missing {required}");
    }
    assert!(schema.contains("QUOTIENT_SEAL_SMALL_STEP_V1"));
    assert!(documentation.contains("candidate"));
    assert!(documentation.contains("NOT_VERIFIED"));
    assert!(!documentation.contains("world-first"));
    assert_eq!(QUOTIENT_SEAL_SMALL_STEP_V1, "QUOTIENT_SEAL_SMALL_STEP_V1");
}
