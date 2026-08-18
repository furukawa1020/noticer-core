use quotient_seal_abi::quotient_seal_abi_v1_hash;
use quotient_seal_context::CommandKind;
use quotient_seal_engine::{
    ContextCommandRecord, EngineRunVerdict, ExecutionInput, ExecutionLimits, ExecutionTermination,
    HostDirectiveRecord, HostOutcomeRecord, HostTapeRecord, ObservableEvent, ResourceKind,
    TrapClass, WasmtimeAdapter, WASMTIME_ADAPTER_PROFILE_VERSION, WASMTIME_CRATE_VERSION,
};
use sha2::{Digest as _, Sha256};

const BINARY_SHA256: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn limits() -> ExecutionLimits {
    ExecutionLimits {
        fuel: 100_000,
        max_memory_pages: 1,
        max_host_calls: 8,
        timeout_ms: 1_000,
    }
}

fn command(kind: CommandKind) -> ContextCommandRecord {
    ContextCommandRecord {
        family_code: 0,
        kind_code: kind as u8,
        service_alias: 7,
        public_slot: 11,
        fault: 0,
        payload_tag: 0,
    }
}

fn directive(import: &str) -> HostDirectiveRecord {
    HostDirectiveRecord {
        import: import.to_owned(),
        outcome: HostOutcomeRecord::Continue,
    }
}

fn input(
    adapter: &WasmtimeAdapter,
    wasm: &[u8],
    directives: Vec<HostDirectiveRecord>,
    commands: Vec<ContextCommandRecord>,
    limits: ExecutionLimits,
) -> ExecutionInput {
    ExecutionInput {
        module_sha256: sha256_hex(wasm),
        abi_sha256: digest_hex(quotient_seal_abi_v1_hash().as_bytes()),
        engine: adapter.identity().clone(),
        host_tape: HostTapeRecord { directives },
        context_sequence: commands,
        limits,
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
    .expect("test WAT must compile")
}

fn normal_module() -> Vec<u8> {
    module(
        r#"
          local.get 0
          local.get 1
          call $emit_frame
          drop
          local.get 0
          i32.const 0
          call $emit_action
          drop
          i32.const 7
          call $public_failure
          drop
          global.get $state
          i32.const 1
          i32.add
          global.set $state
          global.get $state"#,
    )
}

#[test]
fn actual_wasmtime_execution_captures_complete_observer_surface() {
    let adapter = WasmtimeAdapter::new(BINARY_SHA256).expect("adapter");
    let wasm = normal_module();
    let input = input(
        &adapter,
        &wasm,
        vec![
            directive("qseal.emit_frame"),
            directive("qseal.emit_action"),
            directive("qseal.public_failure"),
        ],
        vec![command(CommandKind::PublicCall)],
        limits(),
    );

    let artifact = adapter.execute_input(&wasm, input).expect("execution");

    assert_eq!(artifact.verdict, EngineRunVerdict::Executed);
    assert!(matches!(
        artifact.termination,
        ExecutionTermination::Returned { .. }
    ));
    assert!(artifact
        .trace
        .iter()
        .any(|event| matches!(event, ObservableEvent::EmitFrame { .. })));
    assert!(artifact
        .trace
        .iter()
        .any(|event| matches!(event, ObservableEvent::EmitAction { .. })));
    assert!(artifact
        .trace
        .iter()
        .any(|event| matches!(event, ObservableEvent::PublicFailure { .. })));
    assert!(artifact
        .trace
        .iter()
        .any(|event| matches!(event, ObservableEvent::PublicState { .. })));
}

#[test]
fn reset_handoff_and_artifact_hash_are_reproducible() {
    let adapter = WasmtimeAdapter::new(BINARY_SHA256).expect("adapter");
    let wasm = normal_module();
    let input = input(
        &adapter,
        &wasm,
        Vec::new(),
        vec![
            command(CommandKind::PublicReset),
            command(CommandKind::PublicHandoff),
        ],
        limits(),
    );

    let first = adapter
        .execute_input(&wasm, input.clone())
        .expect("first execution");
    let second = adapter
        .execute_input(&wasm, input)
        .expect("second execution");

    assert_eq!(first, second);
    assert_eq!(
        first.artifact_sha256().expect("first hash"),
        second.artifact_sha256().expect("second hash")
    );
    assert!(first
        .trace
        .iter()
        .any(|event| matches!(event, ObservableEvent::Reset { .. })));
    assert!(first
        .trace
        .iter()
        .any(|event| matches!(event, ObservableEvent::Handoff { .. })));
}

#[test]
fn wasm_trap_remains_an_executed_typed_trap() {
    let adapter = WasmtimeAdapter::new(BINARY_SHA256).expect("adapter");
    let wasm = module("unreachable");
    let input = input(
        &adapter,
        &wasm,
        Vec::new(),
        vec![command(CommandKind::PublicCall)],
        limits(),
    );

    let artifact = adapter.execute_input(&wasm, input).expect("execution");

    assert_eq!(artifact.verdict, EngineRunVerdict::Executed);
    assert!(matches!(
        artifact.termination,
        ExecutionTermination::Trapped {
            class: TrapClass::Unreachable,
            ..
        }
    ));
}

#[test]
fn fuel_and_host_call_exhaustion_are_unresolved() {
    let adapter = WasmtimeAdapter::new(BINARY_SHA256).expect("adapter");
    let looping = module("loop $again br $again end i32.const 0");
    let mut fuel_limits = limits();
    fuel_limits.fuel = 10;
    let fuel_input = input(
        &adapter,
        &looping,
        Vec::new(),
        vec![command(CommandKind::PublicCall)],
        fuel_limits,
    );
    let fuel_artifact = adapter
        .execute_input(&looping, fuel_input)
        .expect("fuel execution");
    assert_eq!(fuel_artifact.verdict, EngineRunVerdict::Unresolved);
    assert!(matches!(
        fuel_artifact.termination,
        ExecutionTermination::ResourceExhausted {
            resource: ResourceKind::Fuel,
            ..
        }
    ));

    let wasm = normal_module();
    let mut host_limits = limits();
    host_limits.max_host_calls = 1;
    let host_input = input(
        &adapter,
        &wasm,
        vec![
            directive("qseal.emit_frame"),
            directive("qseal.emit_action"),
            directive("qseal.public_failure"),
        ],
        vec![command(CommandKind::PublicCall)],
        host_limits,
    );
    let host_artifact = adapter
        .execute_input(&wasm, host_input)
        .expect("host execution");
    assert_eq!(host_artifact.verdict, EngineRunVerdict::Unresolved);
    assert!(matches!(
        host_artifact.termination,
        ExecutionTermination::ResourceExhausted {
            resource: ResourceKind::HostCalls,
            ..
        }
    ));
}

#[test]
fn invalid_and_unsupported_modules_are_not_successes() {
    let adapter = WasmtimeAdapter::new(BINARY_SHA256).expect("adapter");
    let malformed = b"not-wasm";
    let malformed_input = input(
        &adapter,
        malformed,
        Vec::new(),
        vec![command(CommandKind::PublicCall)],
        limits(),
    );
    let rejected = adapter
        .execute_input(malformed, malformed_input)
        .expect("rejection artifact");
    assert_eq!(rejected.verdict, EngineRunVerdict::Rejected);
    assert!(matches!(
        rejected.termination,
        ExecutionTermination::InvalidModule { .. }
    ));

    let unsupported = module("f32.const nan:0x42 drop i32.const 0");
    let unsupported_input = input(
        &adapter,
        &unsupported,
        Vec::new(),
        vec![command(CommandKind::PublicCall)],
        limits(),
    );
    let unresolved = adapter
        .execute_input(&unsupported, unsupported_input)
        .expect("unsupported artifact");
    assert_eq!(unresolved.verdict, EngineRunVerdict::Unresolved);
    assert!(matches!(
        unresolved.termination,
        ExecutionTermination::Unsupported { .. }
    ));
}

#[test]
fn identity_binds_exact_version_profile_and_host_binary() {
    let adapter = WasmtimeAdapter::new(BINARY_SHA256).expect("adapter");
    let identity = adapter.identity();

    assert_eq!(identity.name, "wasmtime");
    assert_eq!(identity.version, WASMTIME_CRATE_VERSION);
    assert_eq!(identity.executable_sha256, BINARY_SHA256);
    assert_eq!(
        identity.configuration.get("adapter_profile"),
        Some(&WASMTIME_ADAPTER_PROFILE_VERSION.to_owned())
    );
    assert_eq!(
        identity.configuration.get("cargo_features"),
        Some(&"cranelift,runtime,std".to_owned())
    );
    assert_eq!(
        identity.configuration.get("instruction_trace"),
        Some(&"NOT_VERIFIED".to_owned())
    );
}

fn sha256_hex(bytes: &[u8]) -> String {
    digest_hex(&Sha256::digest(bytes))
}

fn digest_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
