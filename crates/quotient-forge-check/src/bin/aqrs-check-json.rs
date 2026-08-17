use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use quotient_forge_check::{
    check, ActionEmission, ActionId, ActionObligation, CausalField, CheckLimits, CheckOutcome,
    CheckerModel, CounterexampleKind, EnvironmentInput, FaultInput, FaultInputId, FieldId,
    InconclusiveReason, InitialPair, InputId, ModelError, ObligationId, ObligationRef, Observer,
    ObserverId, PrivateHistoryId, RecoveryRequirement, Release, SemanticContract, SemanticId, Side,
    State, StateId, Transition,
};
use serde::{Deserialize, Serialize};

const MODEL_FORMAT: &str = "aqrs-check-model-v1";
const REPORT_FORMAT: &str = "aqrs-check-report-v1";

#[derive(Debug)]
struct Arguments {
    input: PathBuf,
    max_nodes: usize,
    max_depth: u32,
    time_limit_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawModel {
    format_version: String,
    horizon: u32,
    states: Vec<RawState>,
    semantics: Vec<RawSemantic>,
    faults: Vec<RawFault>,
    inputs: Vec<RawInput>,
    transitions: Vec<RawTransition>,
    observers: Vec<RawObserver>,
    initial_pairs: Vec<RawInitialPair>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawState {
    id: String,
    action_semantics: String,
    private_history: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSemantic {
    id: String,
    obligations: Vec<RawActionObligation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawActionObligation {
    id: String,
    action: String,
    trigger_slot: u32,
    deadline_slot: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFault {
    id: String,
    recovery: Option<RawRecovery>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRecovery {
    action: String,
    deadline_after_slots: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInput {
    id: String,
    public_symbol: String,
    fault: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTransition {
    from: String,
    input: String,
    to: String,
    release: RawRelease,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRelease {
    emitted: bool,
    fields: BTreeMap<String, String>,
    actions: Vec<RawActionEmission>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawActionEmission {
    obligation: RawObligationRef,
    action: String,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum RawObligationRef {
    Authorized { id: String },
    Recovery { fault: String, triggered_at: u32 },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawObserver {
    id: String,
    visible_fields: Vec<String>,
    observes_actions: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInitialPair {
    left: String,
    right: String,
}

#[derive(Serialize)]
struct Report {
    format_version: &'static str,
    engine: &'static str,
    status: &'static str,
    category: String,
    slot: Option<u32>,
    observer: Option<String>,
    side: Option<&'static str>,
    causal_field: Option<String>,
    obligation: Option<String>,
    action: Option<String>,
    reason: Option<&'static str>,
    checked_horizon: Option<u32>,
    trace: Vec<TraceRecord>,
}

#[derive(Serialize)]
struct TraceRecord {
    slot: u32,
    input: String,
    left_state: String,
    right_state: String,
}

impl Report {
    fn new(status: &'static str, category: impl Into<String>) -> Self {
        Self {
            format_version: REPORT_FORMAT,
            engine: "rust",
            status,
            category: category.into(),
            slot: None,
            observer: None,
            side: None,
            causal_field: None,
            obligation: None,
            action: None,
            reason: None,
            checked_horizon: None,
            trace: Vec::new(),
        }
    }
}

impl RawModel {
    fn into_checker(self) -> Result<CheckerModel, &'static str> {
        if self.format_version != MODEL_FORMAT {
            return Err("unsupported_format");
        }
        Ok(CheckerModel {
            horizon: self.horizon,
            states: self
                .states
                .into_iter()
                .map(|state| State {
                    id: StateId::from(state.id),
                    action_semantics: SemanticId::from(state.action_semantics),
                    private_history: PrivateHistoryId::from(state.private_history),
                })
                .collect(),
            semantics: self
                .semantics
                .into_iter()
                .map(|semantic| SemanticContract {
                    id: SemanticId::from(semantic.id),
                    obligations: semantic
                        .obligations
                        .into_iter()
                        .map(|obligation| ActionObligation {
                            id: ObligationId::from(obligation.id),
                            action: ActionId::from(obligation.action),
                            trigger_slot: obligation.trigger_slot,
                            deadline_slot: obligation.deadline_slot,
                        })
                        .collect(),
                })
                .collect(),
            faults: self
                .faults
                .into_iter()
                .map(|fault| FaultInput {
                    id: FaultInputId::from(fault.id),
                    recovery: fault.recovery.map(|recovery| RecoveryRequirement {
                        action: ActionId::from(recovery.action),
                        deadline_after_slots: recovery.deadline_after_slots,
                    }),
                })
                .collect(),
            inputs: self
                .inputs
                .into_iter()
                .map(|input| EnvironmentInput {
                    id: InputId::from(input.id),
                    public_symbol: input.public_symbol,
                    fault: input.fault.map(FaultInputId::from),
                })
                .collect(),
            transitions: self
                .transitions
                .into_iter()
                .map(|transition| Transition {
                    from: StateId::from(transition.from),
                    input: InputId::from(transition.input),
                    to: StateId::from(transition.to),
                    release: Release {
                        emitted: transition.release.emitted,
                        fields: transition
                            .release
                            .fields
                            .into_iter()
                            .map(|(field, value)| (FieldId::from(field), value))
                            .collect(),
                        actions: transition
                            .release
                            .actions
                            .into_iter()
                            .map(|emission| ActionEmission {
                                obligation: obligation_ref(emission.obligation),
                                action: ActionId::from(emission.action),
                            })
                            .collect(),
                    },
                })
                .collect(),
            observers: self
                .observers
                .into_iter()
                .map(|observer| Observer {
                    id: ObserverId::from(observer.id),
                    visible_fields: observer
                        .visible_fields
                        .into_iter()
                        .map(FieldId::from)
                        .collect::<BTreeSet<_>>(),
                    observes_actions: observer.observes_actions,
                })
                .collect(),
            initial_pairs: self
                .initial_pairs
                .into_iter()
                .map(|pair| InitialPair {
                    left: StateId::from(pair.left),
                    right: StateId::from(pair.right),
                })
                .collect(),
        })
    }
}

fn obligation_ref(reference: RawObligationRef) -> ObligationRef {
    match reference {
        RawObligationRef::Authorized { id } => ObligationRef::Authorized(ObligationId::from(id)),
        RawObligationRef::Recovery {
            fault,
            triggered_at,
        } => ObligationRef::Recovery {
            fault: FaultInputId::from(fault),
            triggered_at,
        },
    }
}

fn parse_arguments(arguments: impl IntoIterator<Item = OsString>) -> Result<Arguments, String> {
    let mut arguments = arguments.into_iter();
    let mut input = None;
    let mut max_nodes = 100_000_usize;
    let mut max_depth = 1_024_u32;
    let mut time_limit_ms = 30_000_u64;
    while let Some(flag) = arguments.next() {
        let flag = flag
            .to_str()
            .ok_or_else(|| "arguments must be UTF-8".to_owned())?;
        let value = arguments
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag {
            "--input" => input = Some(PathBuf::from(value)),
            "--max-nodes" => {
                max_nodes = parse_number(value, flag)?;
            }
            "--max-depth" => {
                max_depth = parse_number(value, flag)?;
            }
            "--time-limit-ms" => {
                time_limit_ms = parse_number(value, flag)?;
            }
            _ => return Err(format!("unknown argument: {flag}")),
        }
    }
    Ok(Arguments {
        input: input.ok_or_else(|| "--input is required".to_owned())?,
        max_nodes,
        max_depth,
        time_limit_ms,
    })
}

fn parse_number<T>(value: OsString, flag: &str) -> Result<T, String>
where
    T: std::str::FromStr,
{
    let value = value
        .to_str()
        .ok_or_else(|| format!("{flag} must be UTF-8"))?;
    value
        .parse()
        .map_err(|_| format!("invalid numeric value for {flag}: {value}"))
}

fn run(arguments: impl IntoIterator<Item = OsString>) -> Result<Report, String> {
    let arguments = parse_arguments(arguments)?;
    let source = std::fs::read_to_string(&arguments.input)
        .map_err(|error| format!("failed to read input: {error}"))?;
    let raw = match serde_json::from_str::<RawModel>(&source) {
        Ok(raw) => raw,
        Err(_) => return Ok(Report::new("invalid", "json_invalid")),
    };
    let model = match raw.into_checker() {
        Ok(model) => model,
        Err(category) => return Ok(Report::new("invalid", category)),
    };
    let limits = CheckLimits {
        max_nodes: arguments.max_nodes,
        max_depth: arguments.max_depth,
        time_limit: Duration::from_millis(arguments.time_limit_ms),
    };
    Ok(report_for(check(&model, limits)))
}

fn report_for(outcome: Result<CheckOutcome, ModelError>) -> Report {
    match outcome {
        Err(error) => Report::new("invalid", model_error_category(&error)),
        Ok(CheckOutcome::Verified(verified)) => {
            let mut report = Report::new("verified", "bounded_verified");
            report.checked_horizon = Some(verified.checked_horizon);
            report
        }
        Ok(CheckOutcome::Inconclusive(inconclusive)) => {
            let reason = match inconclusive.reason {
                InconclusiveReason::NodeLimit { .. } => "node_limit",
                InconclusiveReason::DepthLimit { .. } => "depth_limit",
                InconclusiveReason::TimeLimit { .. } => "time_limit",
            };
            let mut report = Report::new("inconclusive", "resource_limit");
            report.reason = Some(reason);
            report
        }
        Ok(CheckOutcome::Counterexample(counterexample)) => {
            let mut report = Report::new("counterexample", "security_divergence");
            report.slot = Some(counterexample.slot);
            report.observer = counterexample
                .observer
                .as_ref()
                .map(|observer| observer.as_str().to_owned());
            report.causal_field = counterexample.causal_field.as_ref().map(causal_field_name);
            report.trace = counterexample
                .trace
                .iter()
                .map(|step| TraceRecord {
                    slot: step.slot,
                    input: step.input.id.as_str().to_owned(),
                    left_state: step.left_state.as_str().to_owned(),
                    right_state: step.right_state.as_str().to_owned(),
                })
                .collect();
            match &counterexample.kind {
                CounterexampleKind::SecurityDivergence => {}
                CounterexampleKind::UnauthorizedAction {
                    side,
                    action,
                    obligation,
                } => {
                    report.category = "unauthorized_action".to_owned();
                    report.side = Some(side_name(*side));
                    report.action = Some(action.as_str().to_owned());
                    report.obligation = Some(obligation_name(obligation));
                }
                CounterexampleKind::DuplicateAction {
                    side,
                    action,
                    obligation,
                } => {
                    report.category = "duplicate_action".to_owned();
                    report.side = Some(side_name(*side));
                    report.action = Some(action.as_str().to_owned());
                    report.obligation = Some(obligation_name(obligation));
                }
                CounterexampleKind::MissedDeadline {
                    side,
                    action,
                    obligation,
                } => {
                    report.category = "missed_deadline".to_owned();
                    report.side = Some(side_name(*side));
                    report.action = Some(action.as_str().to_owned());
                    report.obligation = Some(obligation_name(obligation));
                }
                CounterexampleKind::RecoverableFaultViolation {
                    side,
                    action,
                    obligation,
                } => {
                    report.category = "recoverable_fault_violation".to_owned();
                    report.side = Some(side_name(*side));
                    report.action = Some(action.as_str().to_owned());
                    report.obligation = Some(obligation_name(obligation));
                }
            }
            report
        }
    }
}

fn side_name(side: Side) -> &'static str {
    match side {
        Side::Left => "left",
        Side::Right => "right",
    }
}

fn causal_field_name(field: &CausalField) -> String {
    match field {
        CausalField::ReleasePresence => "release_presence".to_owned(),
        CausalField::Field(field) => format!("field:{}", field.as_str()),
        CausalField::Actions => "actions".to_owned(),
    }
}

fn obligation_name(obligation: &ObligationRef) -> String {
    match obligation {
        ObligationRef::Authorized(id) => format!("authorized:{}", id.as_str()),
        ObligationRef::Recovery {
            fault,
            triggered_at,
        } => format!("recovery:{}@{triggered_at}", fault.as_str()),
    }
}

fn model_error_category(error: &ModelError) -> &'static str {
    match error {
        ModelError::EmptyDomain(_) => "empty_domain",
        ModelError::EmptyIdentifier(_) => "empty_identifier",
        ModelError::DuplicateIdentifier { .. } => "duplicate_identifier",
        ModelError::UnknownReference { .. } => "unknown_reference",
        ModelError::InvalidInitialPair { .. } => "invalid_initial_pair",
        ModelError::InvalidObligation { .. } => "invalid_obligation",
        ModelError::InvalidRelease { .. } => "invalid_release",
        ModelError::DuplicateTransition { .. } => "duplicate_transition",
        ModelError::MissingTransition { .. } => "missing_transition",
    }
}

fn main() -> ExitCode {
    match run(std::env::args_os().skip(1)) {
        Ok(report) => match serde_json::to_string(&report) {
            Ok(encoded) => {
                println!("{encoded}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("failed to encode report: {error}");
                ExitCode::from(2)
            }
        },
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}
