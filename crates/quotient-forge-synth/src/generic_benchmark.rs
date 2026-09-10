//! Generic reactive-privacy fixtures independent of Noticer product names.

use std::collections::{BTreeMap, BTreeSet};

use quotient_forge_check::{
    ActionEmission, ActionId, ActionObligation, EnvironmentInput, FaultInput, FaultInputId,
    FieldId, InputId, ObligationId, ObligationRef, Observer, ObserverId, PrivateHistoryId, Release,
    SemanticContract, SemanticId,
};

use crate::{
    MachineCell, PlantPair, PlantState, PlantTransition, ReleaseMachine, SynthesisProblem,
};

pub const GENERIC_BENCHMARK_FAMILY_IDS: [&str; 8] = [
    "generic_delayed_notification",
    "generic_fixed_size_release",
    "generic_public_retry",
    "generic_private_scheduler",
    "generic_medical_alert",
    "generic_smart_home_actuator",
    "generic_activity_actuator",
    "generic_fault_tolerant_alarm",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenericBenchmarkSplit {
    Train,
    Development,
    HeldOut,
}

impl GenericBenchmarkSplit {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Train => "train",
            Self::Development => "development",
            Self::HeldOut => "held_out",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenericBenchmarkCase {
    pub family_id: &'static str,
    pub split: GenericBenchmarkSplit,
    pub feature_tags: &'static [&'static str],
    pub obligations: &'static [&'static str],
    pub difficulty_tier: &'static str,
    pub problem: SynthesisProblem,
    pub author_template: Option<ReleaseMachine>,
}

#[derive(Clone, Copy)]
struct ObserverDefinition {
    id: &'static str,
    fields: &'static [&'static str],
    observes_actions: bool,
}

#[derive(Clone, Copy)]
struct Definition {
    family_id: &'static str,
    split: GenericBenchmarkSplit,
    feature_tags: &'static [&'static str],
    obligations: &'static [&'static str],
    difficulty_tier: &'static str,
    horizon: u32,
    input_symbols: &'static [&'static str],
    fault_name: Option<&'static str>,
    observers: &'static [ObserverDefinition],
}

const DELAYED_OBSERVERS: &[ObserverDefinition] = &[
    ObserverDefinition {
        id: "network",
        fields: &["send_slot"],
        observes_actions: false,
    },
    ObserverDefinition {
        id: "service(notification)",
        fields: &[],
        observes_actions: true,
    },
];

const FIXED_SIZE_OBSERVERS: &[ObserverDefinition] = &[
    ObserverDefinition {
        id: "network",
        fields: &["packet_size", "send", "send_slot"],
        observes_actions: false,
    },
    ObserverDefinition {
        id: "service(release)",
        fields: &[],
        observes_actions: true,
    },
];

const RETRY_OBSERVERS: &[ObserverDefinition] = &[
    ObserverDefinition {
        id: "network",
        fields: &["retry_count", "send_slot"],
        observes_actions: false,
    },
    ObserverDefinition {
        id: "service(retry_service)",
        fields: &[],
        observes_actions: true,
    },
];

const SCHEDULER_OBSERVERS: &[ObserverDefinition] = &[
    ObserverDefinition {
        id: "network",
        fields: &["frame_kind", "send_slot"],
        observes_actions: false,
    },
    ObserverDefinition {
        id: "service(scheduler)",
        fields: &[],
        observes_actions: true,
    },
];

const MEDICAL_OBSERVERS: &[ObserverDefinition] = &[
    ObserverDefinition {
        id: "network",
        fields: &["frame_kind", "send_slot"],
        observes_actions: false,
    },
    ObserverDefinition {
        id: "service(clinician)",
        fields: &[],
        observes_actions: true,
    },
];

const HOME_OBSERVERS: &[ObserverDefinition] = &[
    ObserverDefinition {
        id: "network",
        fields: &["packet_size", "send_slot"],
        observes_actions: false,
    },
    ObserverDefinition {
        id: "service(home)",
        fields: &[],
        observes_actions: true,
    },
];

const ACTIVITY_OBSERVERS: &[ObserverDefinition] = &[
    ObserverDefinition {
        id: "network",
        fields: &["send_slot", "service_alias"],
        observes_actions: false,
    },
    ObserverDefinition {
        id: "service(activity)",
        fields: &[],
        observes_actions: true,
    },
];

const ALARM_OBSERVERS: &[ObserverDefinition] = &[
    ObserverDefinition {
        id: "network",
        fields: &["failure", "reconnect", "retry_count", "send_slot"],
        observes_actions: false,
    },
    ObserverDefinition {
        id: "service(alarm)",
        fields: &[],
        observes_actions: true,
    },
];

const DEFINITIONS: [Definition; 8] = [
    Definition {
        family_id: "generic_delayed_notification",
        split: GenericBenchmarkSplit::Train,
        feature_tags: &["silence", "timing"],
        obligations: &["action_window", "exactly_once"],
        difficulty_tier: "D1",
        horizon: 3,
        input_symbols: &["tick"],
        fault_name: None,
        observers: DELAYED_OBSERVERS,
    },
    Definition {
        family_id: "generic_fixed_size_release",
        split: GenericBenchmarkSplit::Train,
        feature_tags: &["silence", "size", "timing"],
        obligations: &["action_window", "exactly_once"],
        difficulty_tier: "D1",
        horizon: 2,
        input_symbols: &["tick"],
        fault_name: None,
        observers: FIXED_SIZE_OBSERVERS,
    },
    Definition {
        family_id: "generic_public_retry",
        split: GenericBenchmarkSplit::Train,
        feature_tags: &["retry", "timing"],
        obligations: &["action_window", "exactly_once"],
        difficulty_tier: "D2",
        horizon: 3,
        input_symbols: &["first-attempt", "public-retry"],
        fault_name: None,
        observers: RETRY_OBSERVERS,
    },
    Definition {
        family_id: "generic_private_scheduler",
        split: GenericBenchmarkSplit::Development,
        feature_tags: &["silence", "timing"],
        obligations: &["action_window", "exactly_once"],
        difficulty_tier: "D3",
        horizon: 4,
        input_symbols: &["tick"],
        fault_name: None,
        observers: SCHEDULER_OBSERVERS,
    },
    Definition {
        family_id: "generic_medical_alert",
        split: GenericBenchmarkSplit::Development,
        feature_tags: &["failure", "timing"],
        obligations: &["action_window", "exactly_once"],
        difficulty_tier: "D3",
        horizon: 4,
        input_symbols: &["routine", "public-alert"],
        fault_name: None,
        observers: MEDICAL_OBSERVERS,
    },
    Definition {
        family_id: "generic_smart_home_actuator",
        split: GenericBenchmarkSplit::HeldOut,
        feature_tags: &["size", "timing"],
        obligations: &["action_window", "exactly_once"],
        difficulty_tier: "D4",
        horizon: 4,
        input_symbols: &["idle", "public-command"],
        fault_name: None,
        observers: HOME_OBSERVERS,
    },
    Definition {
        family_id: "generic_activity_actuator",
        split: GenericBenchmarkSplit::HeldOut,
        feature_tags: &["longitudinal", "timing"],
        obligations: &["action_window", "exactly_once"],
        difficulty_tier: "D4",
        horizon: 5,
        input_symbols: &["inactive", "active"],
        fault_name: None,
        observers: ACTIVITY_OBSERVERS,
    },
    Definition {
        family_id: "generic_fault_tolerant_alarm",
        split: GenericBenchmarkSplit::HeldOut,
        feature_tags: &["failure", "retry", "timing"],
        obligations: &["action_window", "bounded_loss", "exactly_once", "reconnect"],
        difficulty_tier: "D5",
        horizon: 5,
        input_symbols: &["connected", "dropped", "reconnected"],
        fault_name: Some("bounded-link"),
        observers: ALARM_OBSERVERS,
    },
];

#[must_use]
pub fn generic_benchmark_cases() -> Vec<GenericBenchmarkCase> {
    DEFINITIONS.iter().copied().map(build_case).collect()
}

#[must_use]
pub fn generic_benchmark_case(family_id: &str) -> Option<GenericBenchmarkCase> {
    DEFINITIONS
        .iter()
        .copied()
        .find(|definition| definition.family_id == family_id)
        .map(build_case)
}

fn build_case(definition: Definition) -> GenericBenchmarkCase {
    let (inputs, faults) = build_inputs(definition);
    let symbol_count = u32::try_from(inputs.len()).expect("bounded input count");
    let problem = build_problem(definition, inputs, faults, symbol_count);
    let author_template = (definition.split != GenericBenchmarkSplit::HeldOut)
        .then(|| delayed_action_template(definition.horizon, symbol_count));
    GenericBenchmarkCase {
        family_id: definition.family_id,
        split: definition.split,
        feature_tags: definition.feature_tags,
        obligations: definition.obligations,
        difficulty_tier: definition.difficulty_tier,
        problem,
        author_template,
    }
}

fn build_inputs(definition: Definition) -> (Vec<EnvironmentInput>, Vec<FaultInput>) {
    let fault_id = definition.fault_name.map(FaultInputId::from);
    let inputs = definition
        .input_symbols
        .iter()
        .enumerate()
        .map(|(index, symbol)| EnvironmentInput {
            id: InputId::new(format!("input-{index}")),
            public_symbol: (*symbol).to_owned(),
            fault: (index > 0).then(|| fault_id.clone()).flatten(),
        })
        .collect();
    let faults = fault_id
        .map(|id| vec![FaultInput { id, recovery: None }])
        .unwrap_or_default();
    (inputs, faults)
}

fn build_problem(
    definition: Definition,
    inputs: Vec<EnvironmentInput>,
    faults: Vec<FaultInput>,
    symbol_count: u32,
) -> SynthesisProblem {
    let semantic = SemanticId::from("authorized-generic-action");
    let action = ActionId::from("act");
    let obligation = ObligationId::from("authorization");
    let state_count = definition.horizon * 2;
    let states = (0..state_count)
        .map(|id| PlantState {
            id,
            action_semantics: semantic.clone(),
            private_history: if id % 2 == 0 {
                PrivateHistoryId::from("private-left")
            } else {
                PrivateHistoryId::from("private-right")
            },
        })
        .collect();
    let mut transitions = Vec::new();
    for state in 0..state_count {
        let next_slot = (state / 2 + 1).min(definition.horizon - 1);
        for input in 0..symbol_count {
            transitions.push(PlantTransition {
                from: state,
                input,
                to: next_slot * 2 + state % 2,
                machine_symbol: input,
            });
        }
    }
    let fields = release_fields();
    let padding = Release {
        emitted: true,
        fields: fields.clone(),
        actions: Vec::new(),
    };
    let action_release = Release {
        emitted: true,
        fields,
        actions: vec![ActionEmission {
            obligation: ObligationRef::Authorized(obligation.clone()),
            action: action.clone(),
        }],
    };
    SynthesisProblem {
        horizon: definition.horizon,
        machine_symbol_count: symbol_count,
        plant_states: states,
        plant_transitions: transitions,
        inputs,
        semantics: vec![SemanticContract {
            id: semantic,
            obligations: vec![ActionObligation {
                id: obligation,
                action,
                trigger_slot: definition.horizon - 1,
                deadline_slot: definition.horizon - 1,
            }],
        }],
        faults,
        observers: definition
            .observers
            .iter()
            .map(|observer| Observer {
                id: ObserverId::from(observer.id),
                visible_fields: observer
                    .fields
                    .iter()
                    .map(|field| FieldId::from(*field))
                    .collect::<BTreeSet<_>>(),
                observes_actions: observer.observes_actions,
            })
            .collect(),
        initial_pairs: vec![PlantPair { left: 0, right: 1 }],
        outputs: vec![padding, action_release],
    }
}

fn release_fields() -> BTreeMap<FieldId, String> {
    [
        ("failure", "normalized"),
        ("frame_kind", "event"),
        ("packet_size", "32"),
        ("reconnect", "normalized"),
        ("retry_count", "0"),
        ("send", "1"),
        ("send_slot", "bucket"),
        ("service_alias", "generic"),
    ]
    .into_iter()
    .map(|(field, value)| (FieldId::from(field), value.to_owned()))
    .collect()
}

fn delayed_action_template(horizon: u32, symbol_count: u32) -> ReleaseMachine {
    let mut cells = Vec::new();
    for state in 0..horizon {
        for _ in 0..symbol_count {
            cells.push(MachineCell {
                next_state: (state + 1).min(horizon - 1),
                output: u32::from(state == horizon - 1),
            });
        }
    }
    ReleaseMachine {
        state_count: horizon,
        symbol_count,
        cells,
    }
}
