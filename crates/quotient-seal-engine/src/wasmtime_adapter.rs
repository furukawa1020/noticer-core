use std::collections::BTreeMap;

use quotient_seal_abi::{
    quotient_seal_abi_v1_hash, validate_wasm_abi, AbiManifest, AbiVerdict, DeploymentProfile,
    WasmSurfaceLimits,
};
use quotient_seal_context::{CommandKind, ContextCommand};
use quotient_seal_small_step::PublicHostTape;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use wasmparser::{Parser, Payload, ValType};
use wasmtime::{
    Caller, Config, Engine, Error as WasmtimeError, Instance, Linker, Module, OptLevel, Store,
    StoreLimits, StoreLimitsBuilder, Trap,
};

use crate::{
    ContextCommandRecord, ContractError, EngineIdentity, EngineRunArtifact, EngineRunVerdict,
    ExecutionInput, ExecutionLimits, ExecutionTermination, HostFaultRecord, HostOutcomeRecord,
    HostTapeRecord, ObservableEvent, ResourceKind, ScalarValue, TrapClass,
    ENGINE_ADAPTER_CONTRACT_VERSION,
};

pub const WASMTIME_CRATE_VERSION: &str = "34.0.2";
pub const WASMTIME_ADAPTER_PROFILE_VERSION: &str = "quotient-seal-wasmtime-adapter/v1";
const WASM_PAGE_BYTES: u64 = 65_536;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WasmtimeAdapter {
    identity: EngineIdentity,
}

impl WasmtimeAdapter {
    pub fn new(enclosing_binary_sha256: impl Into<String>) -> Result<Self, WasmtimeAdapterError> {
        let executable_sha256 = enclosing_binary_sha256.into();
        if !is_sha256(&executable_sha256) {
            return Err(WasmtimeAdapterError::InvalidExecutableSha256);
        }
        Ok(Self {
            identity: EngineIdentity {
                name: "wasmtime".to_owned(),
                version: WASMTIME_CRATE_VERSION.to_owned(),
                executable_sha256,
                adapter_contract_version: ENGINE_ADAPTER_CONTRACT_VERSION,
                configuration: frozen_configuration(),
            },
        })
    }

    #[must_use]
    pub fn identity(&self) -> &EngineIdentity {
        &self.identity
    }

    #[must_use]
    pub fn prepare_input(
        &self,
        wasm: &[u8],
        host_tape: &PublicHostTape,
        context_sequence: &[ContextCommand],
        limits: ExecutionLimits,
    ) -> ExecutionInput {
        ExecutionInput {
            module_sha256: sha256_hex(wasm),
            abi_sha256: digest_hex(quotient_seal_abi_v1_hash().as_bytes()),
            engine: self.identity.clone(),
            host_tape: HostTapeRecord::from(host_tape),
            context_sequence: context_sequence
                .iter()
                .map(ContextCommandRecord::from)
                .collect(),
            limits,
        }
    }

    pub fn execute(
        &self,
        wasm: &[u8],
        host_tape: &PublicHostTape,
        context_sequence: &[ContextCommand],
        limits: ExecutionLimits,
    ) -> Result<EngineRunArtifact, WasmtimeAdapterError> {
        let input = self.prepare_input(wasm, host_tape, context_sequence, limits);
        self.execute_input(wasm, input)
    }

    pub fn execute_input(
        &self,
        wasm: &[u8],
        input: ExecutionInput,
    ) -> Result<EngineRunArtifact, WasmtimeAdapterError> {
        self.validate_input_binding(wasm, &input)?;

        match validate_wasm_abi(
            wasm,
            AbiManifest::canonical(DeploymentProfile::P0PublicQuotientOnly),
            WasmSurfaceLimits::default(),
        ) {
            AbiVerdict::Valid(_) => {}
            AbiVerdict::Invalid(error) => {
                return artifact(
                    input,
                    Vec::new(),
                    ExecutionTermination::InvalidModule {
                        reason_code: "QUOTIENT_SEAL_ABI_REJECTED".to_owned(),
                        detail_sha256: sha256_hex(format!("{error:?}").as_bytes()),
                    },
                    EngineRunVerdict::Rejected,
                );
            }
            AbiVerdict::Incompatible(error) => {
                return artifact(
                    input,
                    Vec::new(),
                    ExecutionTermination::Unsupported {
                        feature: format!("ABI_INCOMPATIBLE:{error:?}"),
                    },
                    EngineRunVerdict::Unresolved,
                );
            }
            AbiVerdict::ResourceBound(error) => {
                return artifact(
                    input,
                    Vec::new(),
                    ExecutionTermination::ResourceExhausted {
                        resource: ResourceKind::Memory,
                        limit: u64::try_from(WasmSurfaceLimits::default().max_bytes)
                            .unwrap_or(u64::MAX),
                        observed: resource_observed_bytes(&error),
                    },
                    EngineRunVerdict::Unresolved,
                );
            }
        }

        match disabled_engine_feature(wasm) {
            Ok(None) => {}
            Ok(Some(feature)) => {
                return artifact(
                    input,
                    Vec::new(),
                    ExecutionTermination::Unsupported {
                        feature: feature.to_owned(),
                    },
                    EngineRunVerdict::Unresolved,
                );
            }
            Err(error) => {
                return artifact(
                    input,
                    Vec::new(),
                    ExecutionTermination::EngineFailure {
                        stage: "engine_feature_scan".to_owned(),
                        exit_code: None,
                        detail_sha256: sha256_hex(error.to_string().as_bytes()),
                    },
                    EngineRunVerdict::Unresolved,
                );
            }
        }

        let engine = match deterministic_engine() {
            Ok(engine) => engine,
            Err(error) => return engine_failure(input, Vec::new(), "engine_configuration", &error),
        };
        let module = match Module::new(&engine, wasm) {
            Ok(module) => module,
            Err(error) => {
                return artifact(
                    input,
                    Vec::new(),
                    ExecutionTermination::Unsupported {
                        feature: format!(
                            "WASMTIME_REJECTED_ABI_VALID_MODULE:{}",
                            sha256_hex(error.to_string().as_bytes())
                        ),
                    },
                    EngineRunVerdict::Unresolved,
                )
            }
        };
        let memory_bytes = match u64::from(input.limits.max_memory_pages)
            .checked_mul(WASM_PAGE_BYTES)
            .and_then(|value| usize::try_from(value).ok())
        {
            Some(value) => value,
            None => {
                return artifact(
                    input.clone(),
                    Vec::new(),
                    ExecutionTermination::ResourceExhausted {
                        resource: ResourceKind::Memory,
                        limit: u64::from(input.limits.max_memory_pages),
                        observed: None,
                    },
                    EngineRunVerdict::Unresolved,
                )
            }
        };
        let state = HostState::new(&input, memory_bytes);
        let mut store = Store::new(&engine, state);
        store.limiter(|state| &mut state.limits);
        if let Err(error) = store.set_fuel(input.limits.fuel) {
            return engine_failure(input, Vec::new(), "fuel_configuration", &error);
        }
        // Epoch interruption is enabled but clock advancement belongs to the outer
        // orchestrator. A maximal local deadline prevents wall-clock scheduling
        // from becoming part of this deterministic adapter.
        store.set_epoch_deadline(u64::MAX);

        let mut linker = Linker::new(&engine);
        if let Err(error) = define_host_functions(&mut linker) {
            return engine_failure(input, Vec::new(), "host_linker", &error);
        }
        let instance = match linker.instantiate(&mut store, &module) {
            Ok(instance) => instance,
            Err(error) => return classify_execution_error(input, &store, error),
        };

        let commands = input.context_sequence.clone();
        let mut final_values = Vec::new();
        for command in &commands {
            final_values = match invoke_command(&instance, &mut store, command) {
                Ok(values) => values,
                Err(error) => return classify_execution_error(input, &store, error),
            };
            if let Err(error) = probe_public_state(&instance, &mut store) {
                return classify_execution_error(input, &store, error);
            }
        }
        if store.data().tape_cursor != store.data().tape.directives.len() {
            let detail = format!(
                "consumed={} total={}",
                store.data().tape_cursor,
                store.data().tape.directives.len()
            );
            return artifact(
                input,
                store.data().events.clone(),
                ExecutionTermination::EngineFailure {
                    stage: "host_tape_unconsumed".to_owned(),
                    exit_code: None,
                    detail_sha256: sha256_hex(detail.as_bytes()),
                },
                EngineRunVerdict::Unresolved,
            );
        }
        artifact(
            input,
            store.data().events.clone(),
            ExecutionTermination::Returned {
                values: final_values,
            },
            EngineRunVerdict::Executed,
        )
    }

    fn validate_input_binding(
        &self,
        wasm: &[u8],
        input: &ExecutionInput,
    ) -> Result<(), WasmtimeAdapterError> {
        if input.engine != self.identity {
            return Err(WasmtimeAdapterError::EngineIdentityMismatch);
        }
        if input.module_sha256 != sha256_hex(wasm) {
            return Err(WasmtimeAdapterError::ModuleDigestMismatch);
        }
        let expected_abi = digest_hex(quotient_seal_abi_v1_hash().as_bytes());
        if input.abi_sha256 != expected_abi {
            return Err(WasmtimeAdapterError::AbiDigestMismatch);
        }
        Ok(())
    }
}

fn frozen_configuration() -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "adapter_profile".to_owned(),
            WASMTIME_ADAPTER_PROFILE_VERSION.to_owned(),
        ),
        (
            "cargo_features".to_owned(),
            "cranelift,runtime,std".to_owned(),
        ),
        ("compiler".to_owned(), "cranelift".to_owned()),
        ("consume_fuel".to_owned(), "true".to_owned()),
        ("epoch_interruption".to_owned(), "true".to_owned()),
        ("epoch_driver".to_owned(), "outer_orchestrator".to_owned()),
        ("nan_canonicalization".to_owned(), "false".to_owned()),
        ("floats".to_owned(), "false".to_owned()),
        ("optimization_level".to_owned(), "none".to_owned()),
        ("simd".to_owned(), "false".to_owned()),
        ("relaxed_simd".to_owned(), "false".to_owned()),
        ("memory64".to_owned(), "false".to_owned()),
        ("multi_memory".to_owned(), "false".to_owned()),
        ("tail_call".to_owned(), "false".to_owned()),
        ("instruction_trace".to_owned(), "NOT_VERIFIED".to_owned()),
    ])
}

fn deterministic_engine() -> Result<Engine, WasmtimeError> {
    let mut config = Config::new();
    config.consume_fuel(true);
    config.epoch_interruption(true);
    config.cranelift_opt_level(OptLevel::None);
    config.cranelift_nan_canonicalization(false);
    config.wasm_simd(false);
    config.wasm_relaxed_simd(false);
    config.wasm_memory64(false);
    config.wasm_multi_memory(false);
    config.wasm_tail_call(false);
    Engine::new(&config)
}

fn disabled_engine_feature(
    wasm: &[u8],
) -> Result<Option<&'static str>, wasmparser::BinaryReaderError> {
    for payload in Parser::new(0).parse_all(wasm) {
        if let Payload::CodeSectionEntry(body) = payload? {
            for local in body.get_locals_reader()? {
                let (_, value_type) = local?;
                if matches!(value_type, ValType::F32 | ValType::F64) {
                    return Ok(Some("WASMTIME_FLOAT_LOCAL_DISABLED"));
                }
            }
            for operator in body.get_operators_reader()? {
                let operator = format!("{:?}", operator?);
                if operator.contains("F32") || operator.contains("F64") {
                    return Ok(Some("WASMTIME_FLOAT_OPERATOR_DISABLED"));
                }
            }
        }
    }
    Ok(None)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostAbort {
    Terminated,
    Fault(HostFaultRecord),
    HostCallLimit,
    TapeExhausted,
    TapeMismatch,
}

struct HostState {
    tape: HostTapeRecord,
    tape_cursor: usize,
    max_host_calls: u64,
    host_calls: u64,
    events: Vec<ObservableEvent>,
    abort: Option<HostAbort>,
    limits: StoreLimits,
}

impl HostState {
    fn new(input: &ExecutionInput, memory_bytes: usize) -> Self {
        Self {
            tape: input.host_tape.clone(),
            tape_cursor: 0,
            max_host_calls: input.limits.max_host_calls,
            host_calls: 0,
            events: Vec::new(),
            abort: None,
            limits: StoreLimitsBuilder::new()
                .memory_size(memory_bytes)
                .instances(1)
                .memories(1)
                .tables(0)
                .trap_on_grow_failure(true)
                .build(),
        }
    }

    fn invoke(
        &mut self,
        import: &str,
        arguments: Vec<ScalarValue>,
    ) -> Result<HostOutcomeRecord, WasmtimeError> {
        if self.host_calls >= self.max_host_calls {
            self.abort = Some(HostAbort::HostCallLimit);
            return Err(WasmtimeError::msg("qseal host call limit"));
        }
        let Some(directive) = self.tape.directives.get(self.tape_cursor) else {
            self.abort = Some(HostAbort::TapeExhausted);
            return Err(WasmtimeError::msg("qseal host tape exhausted"));
        };
        if directive.import != import {
            self.abort = Some(HostAbort::TapeMismatch);
            return Err(WasmtimeError::msg("qseal host tape mismatch"));
        }
        let outcome = directive.outcome;
        self.host_calls += 1;
        self.tape_cursor += 1;
        self.events.push(ObservableEvent::HostImport {
            import: import.to_owned(),
            arguments,
            outcome,
        });
        match outcome {
            HostOutcomeRecord::Continue => Ok(outcome),
            HostOutcomeRecord::Terminate => {
                self.abort = Some(HostAbort::Terminated);
                Err(WasmtimeError::msg("qseal host termination"))
            }
            HostOutcomeRecord::Fault { fault } => {
                self.abort = Some(HostAbort::Fault(fault));
                Err(WasmtimeError::msg("qseal public host fault"))
            }
        }
    }
}

fn define_host_functions(linker: &mut Linker<HostState>) -> Result<(), WasmtimeError> {
    linker.func_wrap(
        "qseal",
        "emit_frame",
        |mut caller: Caller<'_, HostState>, label: i32, slot: i64| -> Result<i32, WasmtimeError> {
            let state = caller.data_mut();
            state.invoke(
                "qseal.emit_frame",
                vec![
                    ScalarValue::I32 { bits: label as u32 },
                    ScalarValue::I64 { bits: slot as u64 },
                ],
            )?;
            state.events.push(ObservableEvent::EmitFrame {
                label: label as u32,
                slot: slot as u64,
                value: 0,
            });
            Ok(0)
        },
    )?;
    linker.func_wrap(
        "qseal",
        "emit_action",
        |mut caller: Caller<'_, HostState>, action: i32, slot: i32| -> Result<i32, WasmtimeError> {
            let state = caller.data_mut();
            state.invoke(
                "qseal.emit_action",
                vec![
                    ScalarValue::I32 {
                        bits: action as u32,
                    },
                    ScalarValue::I32 { bits: slot as u32 },
                ],
            )?;
            state.events.push(ObservableEvent::EmitAction {
                action: action as u32,
                slot: u64::from(slot as u32),
                return_code: 0,
            });
            Ok(0)
        },
    )?;
    linker.func_wrap(
        "qseal",
        "public_failure",
        |mut caller: Caller<'_, HostState>, code: i32| -> Result<i32, WasmtimeError> {
            let state = caller.data_mut();
            state.invoke(
                "qseal.public_failure",
                vec![ScalarValue::I32 { bits: code as u32 }],
            )?;
            state.events.push(ObservableEvent::PublicFailure { code });
            Ok(0)
        },
    )?;
    Ok(())
}

fn invoke_command(
    instance: &Instance,
    store: &mut Store<HostState>,
    command: &ContextCommandRecord,
) -> Result<Vec<ScalarValue>, WasmtimeError> {
    if command.kind_code == CommandKind::PublicCall as u8
        || command.kind_code == CommandKind::PublicFault as u8
    {
        let export = "qseal.public.tick";
        let arguments = vec![
            ScalarValue::I32 {
                bits: command.service_alias,
            },
            ScalarValue::I64 {
                bits: command.public_slot,
            },
            ScalarValue::I32 {
                bits: u32::from(command.fault),
            },
        ];
        store.data_mut().events.push(ObservableEvent::ApiCall {
            export: export.to_owned(),
            arguments,
        });
        let function = instance.get_typed_func::<(i32, i64, i32), i32>(&mut *store, export)?;
        let value = function.call(
            &mut *store,
            (
                command.service_alias as i32,
                command.public_slot as i64,
                i32::from(command.fault),
            ),
        )?;
        let values = vec![ScalarValue::I32 { bits: value as u32 }];
        store.data_mut().events.push(ObservableEvent::ApiReturn {
            export: export.to_owned(),
            values: values.clone(),
        });
        return Ok(values);
    }
    if command.kind_code == CommandKind::PublicReset as u8 {
        let export = "qseal.public.reset";
        store.data_mut().events.push(ObservableEvent::ApiCall {
            export: export.to_owned(),
            arguments: Vec::new(),
        });
        let function = instance.get_typed_func::<(), i32>(&mut *store, export)?;
        let value = function.call(&mut *store, ())?;
        store
            .data_mut()
            .events
            .push(ObservableEvent::Reset { return_code: value });
        let values = vec![ScalarValue::I32 { bits: value as u32 }];
        store.data_mut().events.push(ObservableEvent::ApiReturn {
            export: export.to_owned(),
            values: values.clone(),
        });
        return Ok(values);
    }
    if command.kind_code == CommandKind::PublicHandoff as u8 {
        let export = "qseal.public.handoff";
        store.data_mut().events.push(ObservableEvent::ApiCall {
            export: export.to_owned(),
            arguments: Vec::new(),
        });
        let function = instance.get_typed_func::<(), i64>(&mut *store, export)?;
        let value = function.call(&mut *store, ())?;
        store.data_mut().events.push(ObservableEvent::Handoff {
            value: value as u64,
        });
        let values = vec![ScalarValue::I64 { bits: value as u64 }];
        store.data_mut().events.push(ObservableEvent::ApiReturn {
            export: export.to_owned(),
            values: values.clone(),
        });
        return Ok(values);
    }
    Err(WasmtimeError::msg("unsupported context command kind"))
}

fn probe_public_state(
    instance: &Instance,
    store: &mut Store<HostState>,
) -> Result<(), WasmtimeError> {
    let export = "qseal.public.status";
    store.data_mut().events.push(ObservableEvent::ApiCall {
        export: export.to_owned(),
        arguments: Vec::new(),
    });
    let function = instance.get_typed_func::<(), i32>(&mut *store, export)?;
    let value = function.call(&mut *store, ())?;
    store.data_mut().events.push(ObservableEvent::ApiReturn {
        export: export.to_owned(),
        values: vec![ScalarValue::I32 { bits: value as u32 }],
    });
    store.data_mut().events.push(ObservableEvent::PublicState {
        digest_sha256: sha256_hex(&value.to_le_bytes()),
    });
    Ok(())
}

fn classify_execution_error(
    input: ExecutionInput,
    store: &Store<HostState>,
    error: WasmtimeError,
) -> Result<EngineRunArtifact, WasmtimeAdapterError> {
    let trace = store.data().events.clone();
    if let Some(abort) = store.data().abort {
        return match abort {
            HostAbort::Terminated => artifact(
                input,
                trace,
                ExecutionTermination::Terminated,
                EngineRunVerdict::Executed,
            ),
            HostAbort::Fault(fault) => {
                let code = format!("HOST_{fault:?}").to_ascii_uppercase();
                artifact(
                    input,
                    trace,
                    ExecutionTermination::Trapped {
                        class: TrapClass::HostFault,
                        engine_code: code.clone(),
                        detail_sha256: sha256_hex(code.as_bytes()),
                    },
                    EngineRunVerdict::Executed,
                )
            }
            HostAbort::HostCallLimit => artifact(
                input.clone(),
                trace,
                ExecutionTermination::ResourceExhausted {
                    resource: ResourceKind::HostCalls,
                    limit: input.limits.max_host_calls,
                    observed: Some(store.data().host_calls.saturating_add(1)),
                },
                EngineRunVerdict::Unresolved,
            ),
            HostAbort::TapeExhausted | HostAbort::TapeMismatch => artifact(
                input,
                trace,
                ExecutionTermination::EngineFailure {
                    stage: "host_tape".to_owned(),
                    exit_code: None,
                    detail_sha256: sha256_hex(format!("{abort:?}").as_bytes()),
                },
                EngineRunVerdict::Unresolved,
            ),
        };
    }
    if let Some(trap) = error.downcast_ref::<Trap>() {
        let code = format!("{trap:?}");
        if matches!(trap, Trap::OutOfFuel) {
            return artifact(
                input.clone(),
                trace,
                ExecutionTermination::ResourceExhausted {
                    resource: ResourceKind::Fuel,
                    limit: input.limits.fuel,
                    observed: None,
                },
                EngineRunVerdict::Unresolved,
            );
        }
        if matches!(trap, Trap::Interrupt) {
            return artifact(
                input.clone(),
                trace,
                ExecutionTermination::TimedOut {
                    limit_ms: input.limits.timeout_ms,
                },
                EngineRunVerdict::Unresolved,
            );
        }
        return artifact(
            input,
            trace,
            ExecutionTermination::Trapped {
                class: trap_class(trap),
                engine_code: code.clone(),
                detail_sha256: sha256_hex(code.as_bytes()),
            },
            EngineRunVerdict::Executed,
        );
    }
    engine_failure(input, trace, "wasmtime_execution", &error)
}

fn trap_class(trap: &Trap) -> TrapClass {
    match trap {
        Trap::UnreachableCodeReached => TrapClass::Unreachable,
        Trap::IntegerDivisionByZero => TrapClass::IntegerDivideByZero,
        Trap::IntegerOverflow => TrapClass::IntegerOverflow,
        Trap::MemoryOutOfBounds => TrapClass::MemoryOutOfBounds,
        Trap::BadConversionToInteger => TrapClass::InvalidConversion,
        _ => TrapClass::EngineSpecific,
    }
}

fn engine_failure(
    input: ExecutionInput,
    trace: Vec<ObservableEvent>,
    stage: &str,
    error: &WasmtimeError,
) -> Result<EngineRunArtifact, WasmtimeAdapterError> {
    artifact(
        input,
        trace,
        ExecutionTermination::EngineFailure {
            stage: stage.to_owned(),
            exit_code: None,
            detail_sha256: sha256_hex(error.to_string().as_bytes()),
        },
        EngineRunVerdict::Unresolved,
    )
}

fn artifact(
    input: ExecutionInput,
    trace: Vec<ObservableEvent>,
    termination: ExecutionTermination,
    verdict: EngineRunVerdict,
) -> Result<EngineRunArtifact, WasmtimeAdapterError> {
    Ok(EngineRunArtifact::new(input, trace, termination, verdict)?)
}

fn resource_observed_bytes(error: &quotient_seal_abi::AbiResourceBound) -> Option<u64> {
    let detail = format!("{:?}", error.error);
    detail
        .split("actual: ")
        .nth(1)
        .and_then(|tail| {
            tail.split(|character: char| !character.is_ascii_digit())
                .next()
        })
        .and_then(|digits| digits.parse().ok())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_hex(bytes: &[u8]) -> String {
    digest_hex(&Sha256::digest(bytes))
}

fn digest_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Debug, Error)]
pub enum WasmtimeAdapterError {
    #[error("enclosing binary SHA-256 must be lowercase hexadecimal")]
    InvalidExecutableSha256,
    #[error("execution input is bound to a different engine identity")]
    EngineIdentityMismatch,
    #[error("module SHA-256 does not match the execution input")]
    ModuleDigestMismatch,
    #[error("ABI SHA-256 does not match the canonical QuotientSeal ABI")]
    AbiDigestMismatch,
    #[error(transparent)]
    Contract(#[from] ContractError),
}
