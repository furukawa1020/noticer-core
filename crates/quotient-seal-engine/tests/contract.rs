use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use quotient_seal_context::{CommandKind, ContextCommand, ContextFamily};
use quotient_seal_engine::{
    compute_execution_id, ContextCommandRecord, ContractError, EngineIdentity, EngineRunArtifact,
    EngineRunVerdict, ExecutionInput, ExecutionLimits, ExecutionTermination, HostTapeRecord,
    ObservableEvent, ProtocolConfig, ScalarValue, TrapClass, ENGINE_ADAPTER_CONTRACT_VERSION,
};
use quotient_seal_small_step::{HostDirective, HostOutcome, PublicHostFault, PublicHostTape};

fn digest(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

fn command(slot: u64) -> ContextCommand {
    ContextCommand {
        family: ContextFamily::Tick,
        kind: CommandKind::PublicCall,
        service_alias: 7,
        public_slot: slot,
        fault: 0,
        payload_tag: 11,
    }
}

fn input(version: &str) -> ExecutionInput {
    let mut configuration = BTreeMap::new();
    configuration.insert("nan_canonicalization".to_owned(), "false".to_owned());
    configuration.insert("simd".to_owned(), "false".to_owned());
    let tape = PublicHostTape::new(vec![
        HostDirective::new("qseal.emit_frame", HostOutcome::Continue),
        HostDirective::new(
            "qseal.public_failure",
            HostOutcome::Fault(PublicHostFault::Timeout),
        ),
    ]);
    ExecutionInput {
        module_sha256: digest('a'),
        abi_sha256: digest('b'),
        engine: EngineIdentity {
            name: "wasmi".to_owned(),
            version: version.to_owned(),
            executable_sha256: digest('c'),
            adapter_contract_version: ENGINE_ADAPTER_CONTRACT_VERSION,
            configuration,
        },
        host_tape: HostTapeRecord::from(&tape),
        context_sequence: vec![ContextCommandRecord::from(&command(42))],
        limits: ExecutionLimits {
            fuel: 1_000_000,
            max_memory_pages: 16,
            max_host_calls: 64,
            timeout_ms: 5_000,
        },
    }
}

fn returned_artifact(input: ExecutionInput) -> EngineRunArtifact {
    EngineRunArtifact::new(
        input,
        vec![
            ObservableEvent::ApiCall {
                export: "qseal.public.tick".to_owned(),
                arguments: vec![ScalarValue::F32Bits { bits: 0x7fc0_0042 }],
            },
            ObservableEvent::PublicState {
                digest_sha256: digest('d'),
            },
            ObservableEvent::ApiReturn {
                export: "qseal.public.tick".to_owned(),
                values: vec![ScalarValue::I32 { bits: 0 }],
            },
        ],
        ExecutionTermination::Returned {
            values: vec![ScalarValue::I32 { bits: 0 }],
        },
        EngineRunVerdict::Executed,
    )
    .expect("valid returned artifact")
}

#[test]
fn artifact_round_trip_and_hashes_are_stable() {
    let artifact = returned_artifact(input("0.40.0"));
    let canonical = artifact.canonical_json().expect("canonical JSON");
    let decoded = EngineRunArtifact::from_json(&canonical).expect("round trip");
    assert_eq!(decoded, artifact);
    assert_eq!(
        decoded.artifact_sha256().unwrap(),
        artifact.artifact_sha256().unwrap()
    );
    assert_eq!(
        decoded.execution_id_sha256,
        compute_execution_id(&decoded.input).unwrap()
    );
}

#[test]
fn execution_id_binds_version_hash_configuration_and_context() {
    let original = input("0.40.0");
    let original_id = compute_execution_id(&original).unwrap();

    let mut changed_version = original.clone();
    changed_version.engine.version = "0.41.0".to_owned();
    assert_ne!(original_id, compute_execution_id(&changed_version).unwrap());

    let mut changed_binary = original.clone();
    changed_binary.engine.executable_sha256 = digest('e');
    assert_ne!(original_id, compute_execution_id(&changed_binary).unwrap());

    let mut changed_configuration = original.clone();
    changed_configuration
        .engine
        .configuration
        .insert("simd".to_owned(), "true".to_owned());
    assert_ne!(
        original_id,
        compute_execution_id(&changed_configuration).unwrap()
    );

    let mut changed_context = original;
    changed_context.context_sequence = vec![ContextCommandRecord::from(&command(43))];
    assert_ne!(original_id, compute_execution_id(&changed_context).unwrap());
}

#[test]
fn nan_bits_trap_and_unsupported_remain_distinct() {
    let returned = returned_artifact(input("0.40.0"));
    let encoded = String::from_utf8(returned.canonical_json().unwrap()).unwrap();
    assert!(encoded.contains("2143289410"));

    let trapped = EngineRunArtifact::new(
        input("0.40.0"),
        Vec::new(),
        ExecutionTermination::Trapped {
            class: TrapClass::IntegerDivideByZero,
            engine_code: "integer divide by zero".to_owned(),
            detail_sha256: digest('f'),
        },
        EngineRunVerdict::Executed,
    )
    .unwrap();
    let unsupported = EngineRunArtifact::new(
        input("0.40.0"),
        Vec::new(),
        ExecutionTermination::Unsupported {
            feature: "threads".to_owned(),
        },
        EngineRunVerdict::Unresolved,
    )
    .unwrap();
    assert_ne!(trapped.termination, unsupported.termination);
    assert_ne!(trapped.verdict, unsupported.verdict);
}

#[test]
fn incoherent_or_tampered_artifacts_fail_closed() {
    let mismatch = EngineRunArtifact::new(
        input("0.40.0"),
        Vec::new(),
        ExecutionTermination::Unsupported {
            feature: "gc".to_owned(),
        },
        EngineRunVerdict::Executed,
    );
    assert!(matches!(
        mismatch,
        Err(ContractError::VerdictTerminationMismatch)
    ));

    let mut artifact = returned_artifact(input("0.40.0"));
    artifact.input.engine.version = "tampered".to_owned();
    assert!(matches!(
        artifact.validate(),
        Err(ContractError::ExecutionIdMismatch)
    ));

    let mut bad_digest = input("0.40.0");
    bad_digest.module_sha256 = "ABC".to_owned();
    assert!(matches!(
        compute_execution_id(&bad_digest),
        Err(ContractError::InvalidSha256 { .. })
    ));
}

#[test]
fn reference_context_and_host_tape_are_projected_without_loss() {
    let source_command = command(42);
    let command_record = ContextCommandRecord::from(&source_command);
    assert_eq!(command_record.family_code, ContextFamily::Tick as u8);
    assert_eq!(command_record.kind_code, CommandKind::PublicCall as u8);
    assert_eq!(command_record.public_slot, 42);

    let tape = PublicHostTape::new(vec![HostDirective::new(
        "qseal.emit_action",
        HostOutcome::Fault(PublicHostFault::Reconnect),
    )]);
    let record = HostTapeRecord::from(&tape);
    assert_eq!(record.directives.len(), 1);
    assert_eq!(record.directives[0].import, "qseal.emit_action");
}

#[test]
fn frozen_protocol_is_strict_and_complete() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../configs/quotient_seal/cross_engine_v1.yaml");
    let bytes = fs::read(path).expect("protocol config");
    let config = ProtocolConfig::from_json(&bytes).expect("valid frozen protocol");
    assert_eq!(config.required_engines, ["wasmi", "wasmtime"]);
    assert_eq!(config.observer_surface.len(), 7);

    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    value["unknown_field"] = serde_json::json!(true);
    assert!(ProtocolConfig::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
}
