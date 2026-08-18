use std::fs;
use std::path::PathBuf;

use quotient_seal_context::{CommandKind, ContextCommand, ContextFamily};
use quotient_seal_engine::{
    EngineRunVerdict, ExecutionLimits, ExecutionTermination, ObservableEvent, ResourceKind,
    ScalarValue, TrapClass, WasmiAdapter, WASMI_CRATE_VERSION,
};
use quotient_seal_small_step::{HostDirective, HostOutcome, PublicHostTape};

fn digest(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

fn limits(fuel: u64, host_calls: u64) -> ExecutionLimits {
    ExecutionLimits {
        fuel,
        max_memory_pages: 2,
        max_host_calls: host_calls,
        timeout_ms: 5_000,
    }
}

fn command(kind: CommandKind, family: ContextFamily, slot: u64) -> ContextCommand {
    ContextCommand {
        family,
        kind,
        service_alias: 7,
        public_slot: slot,
        fault: 0,
        payload_tag: 11,
    }
}

fn module(tick_body: &str) -> Vec<u8> {
    wat::parse_str(format!(
        r#"(module
          (import "qseal" "emit_frame" (func $emit_frame (param i32 i64) (result i32)))
          (import "qseal" "emit_action" (func $emit_action (param i32 i32) (result i32)))
          (import "qseal" "public_failure" (func $public_failure (param i32) (result i32)))
          (memory 1 1)
          (global $state (mut i32) (i32.const 0))
          (func (export "qseal.public.tick") (param i32 i64 i32) (result i32)
            {tick_body})
          (func (export "qseal.public.reset") (result i32)
            i32.const 0
            global.set $state
            i32.const 0)
          (func (export "qseal.public.handoff") (result i64)
            global.get $state
            i64.extend_i32_u)
          (func (export "qseal.public.status") (result i32)
            global.get $state))"#
    ))
    .expect("valid WAT fixture")
}

fn normal_module() -> Vec<u8> {
    module(
        r#"
            local.get 0
            local.get 1
            call $emit_frame
            drop
            local.get 0
            i32.const 9
            call $emit_action
            drop
            global.get $state
            i32.const 1
            i32.add
            global.set $state
            i32.const 0"#,
    )
}

#[test]
fn normal_execution_captures_complete_observable_surface() {
    let adapter = WasmiAdapter::new(digest('e')).unwrap();
    let wasm = normal_module();
    let tape = PublicHostTape::new(vec![
        HostDirective::new("qseal.emit_frame", HostOutcome::Continue),
        HostDirective::new("qseal.emit_action", HostOutcome::Continue),
    ]);
    let result = adapter
        .execute(
            &wasm,
            &tape,
            &[command(CommandKind::PublicCall, ContextFamily::Tick, 42)],
            limits(100_000, 8),
        )
        .unwrap();

    assert_eq!(result.verdict, EngineRunVerdict::Executed);
    assert!(matches!(
        result.termination,
        ExecutionTermination::Returned {
            values
        } if values == vec![ScalarValue::I32 { bits: 0 }]
    ));
    assert_eq!(
        result
            .trace
            .iter()
            .filter(|event| matches!(event, ObservableEvent::HostImport { .. }))
            .count(),
        2
    );
    assert!(result
        .trace
        .iter()
        .any(|event| matches!(event, ObservableEvent::EmitFrame { .. })));
    assert!(result
        .trace
        .iter()
        .any(|event| matches!(event, ObservableEvent::EmitAction { .. })));
    assert!(result
        .trace
        .iter()
        .any(|event| matches!(event, ObservableEvent::PublicState { .. })));
}

#[test]
fn reset_handoff_and_repeated_runs_are_reproducible() {
    let adapter = WasmiAdapter::new(digest('e')).unwrap();
    let wasm = normal_module();
    let context = vec![
        command(CommandKind::PublicReset, ContextFamily::Reset, 0),
        command(CommandKind::PublicHandoff, ContextFamily::Handoff, 1),
    ];
    let first = adapter
        .execute(
            &wasm,
            &PublicHostTape::default(),
            &context,
            limits(100_000, 8),
        )
        .unwrap();
    let second = adapter
        .execute(
            &wasm,
            &PublicHostTape::default(),
            &context,
            limits(100_000, 8),
        )
        .unwrap();

    assert_eq!(first, second);
    assert_eq!(
        first.artifact_sha256().unwrap(),
        second.artifact_sha256().unwrap()
    );
    assert!(first
        .trace
        .iter()
        .any(|event| matches!(event, ObservableEvent::Reset { return_code: 0 })));
    assert!(first
        .trace
        .iter()
        .any(|event| matches!(event, ObservableEvent::Handoff { value: 0 })));
}

#[test]
fn wasm_trap_is_executed_not_engine_failure() {
    let adapter = WasmiAdapter::new(digest('e')).unwrap();
    let wasm = module("i32.const 1 i32.const 0 i32.div_s");
    let result = adapter
        .execute(
            &wasm,
            &PublicHostTape::default(),
            &[command(CommandKind::PublicCall, ContextFamily::Tick, 1)],
            limits(100_000, 8),
        )
        .unwrap();

    assert_eq!(result.verdict, EngineRunVerdict::Executed);
    assert!(matches!(
        result.termination,
        ExecutionTermination::Trapped {
            class: TrapClass::IntegerDivideByZero,
            ..
        }
    ));
}

#[test]
fn fuel_and_host_call_bounds_are_unresolved() {
    let adapter = WasmiAdapter::new(digest('e')).unwrap();
    let looping = module("(loop $again br $again) i32.const 0");
    let fuel = adapter
        .execute(
            &looping,
            &PublicHostTape::default(),
            &[command(CommandKind::PublicCall, ContextFamily::Tick, 1)],
            limits(20, 8),
        )
        .unwrap();
    assert!(matches!(
        fuel.termination,
        ExecutionTermination::ResourceExhausted {
            resource: ResourceKind::Fuel,
            ..
        }
    ));
    assert_eq!(fuel.verdict, EngineRunVerdict::Unresolved);

    let two_calls = module(
        "local.get 0 local.get 1 call $emit_frame drop local.get 0 local.get 1 call $emit_frame drop i32.const 0",
    );
    let tape = PublicHostTape::new(vec![
        HostDirective::new("qseal.emit_frame", HostOutcome::Continue),
        HostDirective::new("qseal.emit_frame", HostOutcome::Continue),
    ]);
    let bounded = adapter
        .execute(
            &two_calls,
            &tape,
            &[command(CommandKind::PublicCall, ContextFamily::Tick, 1)],
            limits(100_000, 1),
        )
        .unwrap();
    assert!(matches!(
        bounded.termination,
        ExecutionTermination::ResourceExhausted {
            resource: ResourceKind::HostCalls,
            ..
        }
    ));
    assert_eq!(bounded.verdict, EngineRunVerdict::Unresolved);
}

#[test]
fn abi_rejection_and_engine_feature_rejection_remain_distinct() {
    let adapter = WasmiAdapter::new(digest('e')).unwrap();
    let invalid_abi = wat::parse_str(
        r#"(module
          (func (export "qseal.public.tick") (param i32 i64 i32) (result i32) i32.const 0))"#,
    )
    .unwrap();
    let rejected = adapter
        .execute(
            &invalid_abi,
            &PublicHostTape::default(),
            &[command(CommandKind::PublicCall, ContextFamily::Tick, 1)],
            limits(100_000, 8),
        )
        .unwrap();
    assert_eq!(rejected.verdict, EngineRunVerdict::Rejected);
    assert!(matches!(
        rejected.termination,
        ExecutionTermination::InvalidModule { .. }
    ));

    let floating = module("f32.const nan:0x42 drop i32.const 0");
    let unsupported = adapter
        .execute(
            &floating,
            &PublicHostTape::default(),
            &[command(CommandKind::PublicCall, ContextFamily::Tick, 1)],
            limits(100_000, 8),
        )
        .unwrap();
    assert_eq!(unsupported.verdict, EngineRunVerdict::Unresolved);
    assert!(matches!(
        unsupported.termination,
        ExecutionTermination::Unsupported { .. }
    ));
}

#[test]
fn version_profile_and_input_binding_are_exact() {
    let adapter = WasmiAdapter::new(digest('e')).unwrap();
    assert_eq!(adapter.identity().version, WASMI_CRATE_VERSION);
    assert_eq!(WASMI_CRATE_VERSION, "0.46.0");
    assert_eq!(
        adapter.identity().configuration["timeout_strategy"],
        "ORCHESTRATOR_PLUS_FUEL"
    );

    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../configs/quotient_seal/wasmi_adapter_v1.yaml");
    let profile: serde_json::Value =
        serde_json::from_slice(&fs::read(path).unwrap()).expect("adapter profile");
    assert_eq!(profile["crate_version"], WASMI_CRATE_VERSION);
    assert_eq!(profile["dependency_requirement"], "=0.46.0");

    let wasm = normal_module();
    let mut input = adapter.prepare_input(
        &wasm,
        &PublicHostTape::default(),
        &[command(CommandKind::PublicReset, ContextFamily::Reset, 0)],
        limits(100_000, 8),
    );
    input.module_sha256 = digest('f');
    assert!(adapter.execute_input(&wasm, input).is_err());
}
