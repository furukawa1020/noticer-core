use std::collections::BTreeMap;

use quotient_seal_abi::{
    quotient_seal_abi_v1_hash, validate_wasm_abi, AbiManifest, AbiVerdict, DeploymentProfile,
    WasmSurfaceLimits,
};
use quotient_seal_context::{CommandKind, ContextCommand};
use quotient_seal_small_step::PublicHostTape;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use wasmi::{
    Caller, CompilationMode, Config, Engine, Error as WasmiError, Instance, Linker, Module, Store,
    StoreLimits, StoreLimitsBuilder,
};

use crate::{
    ContextCommandRecord, ContractError, EngineIdentity, EngineRunArtifact, EngineRunVerdict,
    ExecutionInput, ExecutionLimits, ExecutionTermination, HostFaultRecord, HostOutcomeRecord,
    HostTapeRecord, ObservableEvent, ResourceKind, ScalarValue, TrapClass,
    ENGINE_ADAPTER_CONTRACT_VERSION,
};

pub const WASMI_CRATE_VERSION: &str = "0.46.0";
pub const WASMI_ADAPTER_PROFILE_VERSION: &str = "quotient-seal-wasmi-adapter/v1";
const WASM_PAGE_BYTES: u64 = 65_536;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WasmiAdapter {
    identity: EngineIdentity,
}

impl WasmiAdapter {
    pub fn new(enclosing_binary_sha256: impl Into<String>) -> Result<Self, WasmiAdapterError> {
        let executable_sha256 = enclosing_binary_sha256.into();
        if !is_sha256(&executable_sha256) {
            return Err(WasmiAdapterError::InvalidExecutableSha256);
        }
        Ok(Self {
            identity: EngineIdentity {
                name: "wasmi".to_owned(),
                version: WASMI_CRATE_VERSION.to_owned(),
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
    ) -> Result<EngineRunArtifact, WasmiAdapterError> {
        let input = self.prepare_input(wasm, host_tape, context_sequence, limits);
        self.execute_input(wasm, input)
    }

    pub fn execute_input(
        &self,
        wasm: &[u8],
        input: ExecutionInput,
    ) -> Result<EngineRunArtifact, WasmiAdapterError> {
        crate::compute_execution_id(&input)?;
        if input.engine != self.identity {
            return Err(WasmiAdapterError::EngineIdentityMismatch);
        }
        if input.module_sha256 != sha256_hex(wasm) {
            return Err(WasmiAdapterError::ModuleDigestMismatch);
        }
        let expected_abi = digest_hex(quotient_seal_abi_v1_hash().as_bytes());
        if input.abi_sha256 != expected_abi {
            return Err(WasmiAdapterError::AbiDigestMismatch);
        }

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
                )
            }
            AbiVerdict::Incompatible(error) => {
                return artifact(
                    input,
                    Vec::new(),
                    ExecutionTermination::Unsupported {
                        feature: format!("ABI_INCOMPATIBLE:{error:?}"),
                    },
                    EngineRunVerdict::Unresolved,
                )
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
                )
            }
        }

        let engine = Engine::new(&frozen_wasmi_config());
        let module = match Module::new(&engine, wasm) {
            Ok(module) => module,
            Err(error) => {
                return artifact(
                    input,
                    Vec::new(),
                    ExecutionTermination::Unsupported {
                        feature: format!(
                            "WASMI_REJECTED_ABI_VALID_MODULE:{}",
                            sha256_hex(error.to_string().as_bytes())
                        ),
                    },
                    EngineRunVerdict::Unresolved,
                )
            }
        };

        let memory_bytes = u64::from(input.limits.max_memory_pages)
            .checked_mul(WASM_PAGE_BYTES)
            .and_then(|bytes| usize::try_from(bytes).ok())
            .ok_or(WasmiAdapterError::MemoryLimitOverflow)?;
        let store_limits = StoreLimitsBuilder::new().memory_size(memory_bytes).build();
        let mut store = Store::new(
            &engine,
            HostState::new(
                input.host_tape.clone(),
                input.limits.max_host_calls,
                store_limits,
            ),
        );
        store.limiter(|state| &mut state.store_limits);
        store
            .set_fuel(input.limits.fuel)
            .map_err(|error| WasmiAdapterError::Setup {
                stage: "set_fuel",
                detail: error.to_string(),
            })?;

        let mut linker = Linker::new(&engine);
        define_host_functions(&mut linker).map_err(|error| WasmiAdapterError::Setup {
            stage: "define_host_functions",
            detail: error.to_string(),
        })?;
        let pre = match linker.instantiate(&mut store, &module) {
            Ok(pre) => pre,
            Err(error) => return classify_execution_error(input, &store, error),
        };
        let instance = match pre.start(&mut store) {
            Ok(instance) => instance,
            Err(error) => return classify_execution_error(input, &store, error),
        };

        let mut final_values = Vec::new();
        for command in &input.context_sequence {
            if command.kind_code == CommandKind::Stop as u8 {
                return artifact(
                    input,
                    store.data().events.clone(),
                    ExecutionTermination::Terminated,
                    EngineRunVerdict::Executed,
                );
            }
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
}

fn frozen_configuration() -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "adapter_profile".to_owned(),
            WASMI_ADAPTER_PROFILE_VERSION.to_owned(),
        ),
        (
            "cargo_features".to_owned(),
            "extra-checks,prefer-btree-collections,std".to_owned(),
        ),
        ("compilation_mode".to_owned(), "EAGER".to_owned()),
        ("consume_fuel".to_owned(), "true".to_owned()),
        ("floats".to_owned(), "false".to_owned()),
        ("post_command_status_probe".to_owned(), "true".to_owned()),
        (
            "proposal_profile".to_owned(),
            "MVP_MUTABLE_GLOBAL_ONLY".to_owned(),
        ),
        (
            "timeout_strategy".to_owned(),
            "ORCHESTRATOR_PLUS_FUEL".to_owned(),
        ),
    ])
}

fn frozen_wasmi_config() -> Config {
    let mut config = Config::default();
    config
        .compilation_mode(CompilationMode::Eager)
        .consume_fuel(true)
        .floats(false)
        .wasm_mutable_global(true)
        .wasm_sign_extension(false)
        .wasm_saturating_float_to_int(false)
        .wasm_multi_value(false)
        .wasm_multi_memory(false)
        .wasm_bulk_memory(false)
        .wasm_reference_types(false)
        .wasm_tail_call(false)
        .wasm_extended_const(false)
        .wasm_custom_page_sizes(false)
        .wasm_memory64(false)
        .wasm_wide_arithmetic(false);
    config
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
    host_calls: u64,
    max_host_calls: u64,
    events: Vec<ObservableEvent>,
    abort: Option<HostAbort>,
    store_limits: StoreLimits,
}

impl HostState {
    fn new(tape: HostTapeRecord, max_host_calls: u64, store_limits: StoreLimits) -> Self {
        Self {
            tape,
            tape_cursor: 0,
            host_calls: 0,
            max_host_calls,
            events: Vec::new(),
            abort: None,
            store_limits,
        }
    }

    fn invoke(
        &mut self,
        import: &str,
        arguments: Vec<ScalarValue>,
    ) -> Result<HostOutcomeRecord, WasmiError> {
        if self.host_calls >= self.max_host_calls {
            self.abort = Some(HostAbort::HostCallLimit);
            return Err(WasmiError::new("qseal host call limit"));
        }
        let Some(directive) = self.tape.directives.get(self.tape_cursor) else {
            self.abort = Some(HostAbort::TapeExhausted);
            return Err(WasmiError::new("qseal host tape exhausted"));
        };
        if directive.import != import {
            self.abort = Some(HostAbort::TapeMismatch);
            return Err(WasmiError::new("qseal host tape mismatch"));
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
                Err(WasmiError::new("qseal host termination"))
            }
            HostOutcomeRecord::Fault { fault } => {
                self.abort = Some(HostAbort::Fault(fault));
                Err(WasmiError::new("qseal public host fault"))
            }
        }
    }
}

fn define_host_functions(linker: &mut Linker<HostState>) -> Result<(), WasmiError> {
    linker.func_wrap(
        "qseal",
        "emit_frame",
        |mut caller: Caller<'_, HostState>, label: i32, slot: i64| -> Result<i32, WasmiError> {
            caller.data_mut().invoke(
                "qseal.emit_frame",
                vec![
                    ScalarValue::I32 { bits: label as u32 },
                    ScalarValue::I64 { bits: slot as u64 },
                ],
            )?;
            caller.data_mut().events.push(ObservableEvent::EmitFrame {
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
        |mut caller: Caller<'_, HostState>, action: i32, slot: i32| -> Result<i32, WasmiError> {
            caller.data_mut().invoke(
                "qseal.emit_action",
                vec![
                    ScalarValue::I32 {
                        bits: action as u32,
                    },
                    ScalarValue::I32 { bits: slot as u32 },
                ],
            )?;
            caller.data_mut().events.push(ObservableEvent::EmitAction {
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
        |mut caller: Caller<'_, HostState>, code: i32| -> Result<i32, WasmiError> {
            caller.data_mut().invoke(
                "qseal.public_failure",
                vec![ScalarValue::I32 { bits: code as u32 }],
            )?;
            caller
                .data_mut()
                .events
                .push(ObservableEvent::PublicFailure { code });
            Ok(0)
        },
    )?;
    Ok(())
}

fn invoke_command(
    instance: &Instance,
    store: &mut Store<HostState>,
    command: &ContextCommandRecord,
) -> Result<Vec<ScalarValue>, WasmiError> {
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
        let function = instance.get_typed_func::<(i32, i64, i32), i32>(&*store, export)?;
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
        let function = instance.get_typed_func::<(), i32>(&*store, export)?;
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
        let function = instance.get_typed_func::<(), i64>(&*store, export)?;
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
    Err(WasmiError::new("unsupported context command kind"))
}

fn probe_public_state(instance: &Instance, store: &mut Store<HostState>) -> Result<(), WasmiError> {
    let export = "qseal.public.status";
    store.data_mut().events.push(ObservableEvent::ApiCall {
        export: export.to_owned(),
        arguments: Vec::new(),
    });
    let function = instance.get_typed_func::<(), i32>(&*store, export)?;
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
    error: WasmiError,
) -> Result<EngineRunArtifact, WasmiAdapterError> {
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
    if let Some(trap) = error.as_trap_code() {
        let code = format!("{trap:?}");
        if code == "OutOfFuel" {
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
        if code == "GrowthOperationLimited" {
            return artifact(
                input.clone(),
                trace,
                ExecutionTermination::ResourceExhausted {
                    resource: ResourceKind::Memory,
                    limit: u64::from(input.limits.max_memory_pages),
                    observed: None,
                },
                EngineRunVerdict::Unresolved,
            );
        }
        return artifact(
            input,
            trace,
            ExecutionTermination::Trapped {
                class: trap_class(&code),
                engine_code: code.clone(),
                detail_sha256: sha256_hex(code.as_bytes()),
            },
            EngineRunVerdict::Executed,
        );
    }
    artifact(
        input,
        trace,
        ExecutionTermination::EngineFailure {
            stage: "wasmi_execution".to_owned(),
            exit_code: None,
            detail_sha256: sha256_hex(error.to_string().as_bytes()),
        },
        EngineRunVerdict::Unresolved,
    )
}

fn trap_class(code: &str) -> TrapClass {
    match code {
        "UnreachableCodeReached" => TrapClass::Unreachable,
        "IntegerDivisionByZero" => TrapClass::IntegerDivideByZero,
        "IntegerOverflow" => TrapClass::IntegerOverflow,
        "MemoryOutOfBounds" => TrapClass::MemoryOutOfBounds,
        "BadConversionToInteger" => TrapClass::InvalidConversion,
        _ => TrapClass::EngineSpecific,
    }
}

fn artifact(
    input: ExecutionInput,
    trace: Vec<ObservableEvent>,
    termination: ExecutionTermination,
    verdict: EngineRunVerdict,
) -> Result<EngineRunArtifact, WasmiAdapterError> {
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

fn digest_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    digest_hex(&Sha256::digest(bytes))
}

#[derive(Debug, Error)]
pub enum WasmiAdapterError {
    #[error("enclosing binary SHA-256 must be lowercase hexadecimal")]
    InvalidExecutableSha256,
    #[error("execution input is bound to a different engine identity")]
    EngineIdentityMismatch,
    #[error("WASM bytes do not match the input module digest")]
    ModuleDigestMismatch,
    #[error("execution input is not bound to the frozen QuotientSeal ABI")]
    AbiDigestMismatch,
    #[error("memory page bound cannot be represented on this platform")]
    MemoryLimitOverflow,
    #[error("wasmi setup failed at {stage}: {detail}")]
    Setup { stage: &'static str, detail: String },
    #[error(transparent)]
    Contract(#[from] ContractError),
}
