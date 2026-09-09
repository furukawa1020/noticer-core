//! Deterministic lowering fixtures for the eight pre-registered Noticer families.

use std::collections::{BTreeMap, BTreeSet};

use quotient_forge_check::{
    ActionEmission, ActionId, ActionObligation, EnvironmentInput, FaultInput, FaultInputId,
    FieldId, InputId, ObligationId, ObligationRef, Observer, ObserverId, PrivateHistoryId, Release,
    SemanticContract, SemanticId,
};
use sha2::{Digest, Sha256};

use crate::{
    MachineCell, PlantPair, PlantState, PlantTransition, ReleaseMachine, SynthesisProblem,
};

pub const NOTICER_BENCHMARK_FAMILY_IDS: [&str; 8] = [
    "noticer_aets_fixed_cadence",
    "noticer_aplot_bounded_loss",
    "noticer_atv2_action_window",
    "noticer_aepa_public_context",
    "noticer_service_separation",
    "noticer_reconnect_normalization",
    "noticer_multiservice_collusion",
    "noticer_longitudinal_handoff",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BenchmarkSplit {
    Train,
    Development,
    HeldOut,
}

impl BenchmarkSplit {
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
pub struct NoticerBenchmarkCase {
    pub family_id: &'static str,
    pub split: BenchmarkSplit,
    pub feature_tags: &'static [&'static str],
    pub obligations: &'static [&'static str],
    pub difficulty_tier: &'static str,
    pub problem: SynthesisProblem,
    pub author_template: Option<ReleaseMachine>,
}

#[derive(Clone, Copy)]
enum InputLayout {
    Single,
    PublicContext,
    BoundedLoss,
    Services,
    Reconnect,
}

#[derive(Clone, Copy)]
enum ObserverLayout {
    Cadence,
    Loss,
    ActionWindow,
    PublicContext,
    Services,
    Reconnect,
    Collusion,
    Longitudinal,
}

#[derive(Clone, Copy)]
struct Definition {
    family_id: &'static str,
    split: BenchmarkSplit,
    feature_tags: &'static [&'static str],
    obligations: &'static [&'static str],
    difficulty_tier: &'static str,
    horizon: u32,
    inputs: InputLayout,
    observers: ObserverLayout,
}

const DEFINITIONS: [Definition; 8] = [
    Definition {
        family_id: "noticer_aets_fixed_cadence",
        split: BenchmarkSplit::Train,
        feature_tags: &["silence", "size", "timing"],
        obligations: &["action_window", "exactly_once"],
        difficulty_tier: "D1",
        horizon: 2,
        inputs: InputLayout::Single,
        observers: ObserverLayout::Cadence,
    },
    Definition {
        family_id: "noticer_aplot_bounded_loss",
        split: BenchmarkSplit::Train,
        feature_tags: &["failure", "retry", "size"],
        obligations: &["action_window", "bounded_loss", "exactly_once"],
        difficulty_tier: "D2",
        horizon: 3,
        inputs: InputLayout::BoundedLoss,
        observers: ObserverLayout::Loss,
    },
    Definition {
        family_id: "noticer_atv2_action_window",
        split: BenchmarkSplit::Train,
        feature_tags: &["silence", "timing"],
        obligations: &["action_window", "exactly_once"],
        difficulty_tier: "D2",
        horizon: 3,
        inputs: InputLayout::Single,
        observers: ObserverLayout::ActionWindow,
    },
    Definition {
        family_id: "noticer_aepa_public_context",
        split: BenchmarkSplit::Development,
        feature_tags: &["silence", "timing"],
        obligations: &["action_window", "exactly_once"],
        difficulty_tier: "D2",
        horizon: 3,
        inputs: InputLayout::PublicContext,
        observers: ObserverLayout::PublicContext,
    },
    Definition {
        family_id: "noticer_service_separation",
        split: BenchmarkSplit::Development,
        feature_tags: &["size", "timing"],
        obligations: &["action_window", "exactly_once"],
        difficulty_tier: "D3",
        horizon: 4,
        inputs: InputLayout::Services,
        observers: ObserverLayout::Services,
    },
    Definition {
        family_id: "noticer_reconnect_normalization",
        split: BenchmarkSplit::Development,
        feature_tags: &["failure", "retry", "timing"],
        obligations: &["action_window", "exactly_once", "reconnect"],
        difficulty_tier: "D3",
        horizon: 4,
        inputs: InputLayout::Reconnect,
        observers: ObserverLayout::Reconnect,
    },
    Definition {
        family_id: "noticer_multiservice_collusion",
        split: BenchmarkSplit::HeldOut,
        feature_tags: &["collusion", "size", "timing"],
        obligations: &["action_window", "exactly_once"],
        difficulty_tier: "D4",
        horizon: 4,
        inputs: InputLayout::Services,
        observers: ObserverLayout::Collusion,
    },
    Definition {
        family_id: "noticer_longitudinal_handoff",
        split: BenchmarkSplit::HeldOut,
        feature_tags: &["longitudinal", "size", "timing"],
        obligations: &["action_window", "exactly_once", "reconnect"],
        difficulty_tier: "D5",
        horizon: 5,
        inputs: InputLayout::Services,
        observers: ObserverLayout::Longitudinal,
    },
];

#[must_use]
pub fn noticer_benchmark_cases() -> Vec<NoticerBenchmarkCase> {
    DEFINITIONS.iter().copied().map(build_case).collect()
}

#[must_use]
pub fn noticer_benchmark_case(family_id: &str) -> Option<NoticerBenchmarkCase> {
    DEFINITIONS
        .iter()
        .copied()
        .find(|definition| definition.family_id == family_id)
        .map(build_case)
}

#[must_use]
pub fn release_machine_sha256(machine: &ReleaseMachine) -> String {
    format!("{:x}", Sha256::digest(machine.canonical_bytes()))
}

fn build_case(definition: Definition) -> NoticerBenchmarkCase {
    let (inputs, faults) = build_inputs(definition.inputs);
    let machine_symbol_count = u32::try_from(inputs.len()).expect("bounded input count");
    let problem = build_problem(definition, inputs, faults, machine_symbol_count);
    let author_template = (definition.split != BenchmarkSplit::HeldOut)
        .then(|| delayed_action_template(definition.horizon, machine_symbol_count));
    NoticerBenchmarkCase {
        family_id: definition.family_id,
        split: definition.split,
        feature_tags: definition.feature_tags,
        obligations: definition.obligations,
        difficulty_tier: definition.difficulty_tier,
        problem,
        author_template,
    }
}

fn build_problem(
    definition: Definition,
    inputs: Vec<EnvironmentInput>,
    faults: Vec<FaultInput>,
    machine_symbol_count: u32,
) -> SynthesisProblem {
    let semantic = SemanticId::from("authorized-notification");
    let action = ActionId::from("notify");
    let obligation = ObligationId::from("permit");
    let plant_state_count = definition.horizon * 2;
    let plant_states = (0..plant_state_count)
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
    let mut plant_transitions = Vec::new();
    for state in 0..plant_state_count {
        let slot = state / 2;
        let side = state % 2;
        let next_slot = (slot + 1).min(definition.horizon - 1);
        for input in 0..machine_symbol_count {
            plant_transitions.push(PlantTransition {
                from: state,
                input,
                to: next_slot * 2 + side,
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
    let authorized = Release {
        emitted: true,
        fields,
        actions: vec![ActionEmission {
            obligation: ObligationRef::Authorized(obligation.clone()),
            action: action.clone(),
        }],
    };

    SynthesisProblem {
        horizon: definition.horizon,
        machine_symbol_count,
        plant_states,
        plant_transitions,
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
        observers: build_observers(definition.observers),
        initial_pairs: vec![PlantPair { left: 0, right: 1 }],
        outputs: vec![padding, authorized],
    }
}

fn build_inputs(layout: InputLayout) -> (Vec<EnvironmentInput>, Vec<FaultInput>) {
    let plain = |id: &'static str, public_symbol: &'static str| EnvironmentInput {
        id: InputId::from(id),
        public_symbol: public_symbol.to_owned(),
        fault: None,
    };
    match layout {
        InputLayout::Single => (vec![plain("tick", "tick")], Vec::new()),
        InputLayout::PublicContext => (
            vec![
                plain("context-low", "context-low"),
                plain("context-high", "context-high"),
            ],
            Vec::new(),
        ),
        InputLayout::Services => (
            vec![
                plain("service-alpha", "alpha"),
                plain("service-beta", "beta"),
            ],
            Vec::new(),
        ),
        InputLayout::BoundedLoss => fault_inputs("bounded-loss", &["delivered", "dropped"]),
        InputLayout::Reconnect => {
            fault_inputs("link-cycle", &["connected", "disconnected", "reconnected"])
        }
    }
}

fn fault_inputs(
    name: &'static str,
    symbols: &[&'static str],
) -> (Vec<EnvironmentInput>, Vec<FaultInput>) {
    let fault_id = FaultInputId::from(name);
    let inputs = symbols
        .iter()
        .enumerate()
        .map(|(index, symbol)| EnvironmentInput {
            id: InputId::new(format!("{name}-{index}")),
            public_symbol: (*symbol).to_owned(),
            fault: (index > 0).then(|| fault_id.clone()),
        })
        .collect();
    (
        inputs,
        vec![FaultInput {
            id: fault_id,
            recovery: None,
        }],
    )
}

fn build_observers(layout: ObserverLayout) -> Vec<Observer> {
    match layout {
        ObserverLayout::Cadence => vec![
            observer("network", &["packet_size", "send", "send_slot"], false),
            observer("service(menfugu)", &[], true),
        ],
        ObserverLayout::Loss => vec![
            observer(
                "network",
                &["packet_size", "retry_count", "send", "send_slot"],
                false,
            ),
            observer("service(menfugu)", &[], true),
        ],
        ObserverLayout::ActionWindow => vec![
            observer("network", &["send_slot"], false),
            observer("service(menfugu)", &[], true),
        ],
        ObserverLayout::PublicContext => vec![
            observer("network", &["frame_kind", "send_slot"], false),
            observer("service(menfugu)", &[], true),
        ],
        ObserverLayout::Services => vec![
            observer("network", &["send_slot", "service_alias"], false),
            observer("service(alpha)", &[], true),
            observer("service(beta)", &[], true),
        ],
        ObserverLayout::Reconnect => vec![
            observer("network", &["connection", "reconnect", "send_slot"], false),
            observer("service(menfugu)", &[], true),
        ],
        ObserverLayout::Collusion => vec![
            observer(
                "network",
                &["packet_size", "send_slot", "service_alias"],
                false,
            ),
            observer("service(alpha)", &[], true),
            observer("service(beta)", &[], true),
            observer(
                "coalition",
                &["packet_size", "send_slot", "service_alias"],
                true,
            ),
        ],
        ObserverLayout::Longitudinal => vec![
            observer("network", &["send_slot", "service_alias"], false),
            observer("service(alpha)", &[], true),
            observer("service(beta)", &[], true),
            observer("longitudinal", &["send_slot", "service_alias"], true),
        ],
    }
}

fn observer(id: &'static str, fields: &[&'static str], observes_actions: bool) -> Observer {
    Observer {
        id: ObserverId::from(id),
        visible_fields: fields.iter().map(|field| FieldId::from(*field)).collect(),
        observes_actions,
    }
}

fn release_fields() -> BTreeMap<FieldId, String> {
    [
        ("connection", "normalized"),
        ("frame_kind", "token"),
        ("packet_size", "32"),
        ("reconnect", "normalized"),
        ("retry_count", "0"),
        ("send", "1"),
        ("send_slot", "bucket"),
        ("service_alias", "normalized"),
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

#[allow(dead_code)]
fn _assert_observer_fields_are_sets(values: &[Observer]) -> Vec<&BTreeSet<FieldId>> {
    values
        .iter()
        .map(|observer| &observer.visible_fields)
        .collect()
}
