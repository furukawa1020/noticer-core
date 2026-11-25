//! Export a native synthesis and hand-written comparator for a finite recovery study.

#![forbid(unsafe_code)]

use std::time::Duration;

use quotient_forge_check::{
    ActionEmission, ActionObligation, CheckerModel, EnvironmentInput, FaultInput, ObligationRef,
    Observer, Release, SemanticContract,
};
use quotient_forge_synth::{
    find_feasible, optimize_cost, MachineCell, PlantPair, PlantState, PlantTransition,
    ReleaseMachine, SynthesisLimits, SynthesisOutcome, SynthesisProblem,
};
use serde_json::{json, Value};

const RESERVED: u32 = 0;
const EARLY: u32 = 1;
const FINAL_LEFT: u32 = 2;
const FINAL_RIGHT: u32 = 3;

fn failure_fixture(strict: bool) -> SynthesisProblem {
    let obligations: Vec<ActionObligation> = ["a", "b"]
        .into_iter()
        .map(|service| ActionObligation {
            id: service.into(),
            action: format!("notify-{service}").into(),
            trigger_slot: 0,
            deadline_slot: 1,
        })
        .collect();
    let deliver = Release {
        emitted: true,
        fields: Default::default(),
        actions: obligations
            .iter()
            .map(|item| ActionEmission {
                obligation: ObligationRef::Authorized(item.id.clone()),
                action: item.action.clone(),
            })
            .collect(),
    };
    let mut plant_states = Vec::new();
    let mut plant_transitions = Vec::new();
    for group in 0..if strict { 6 } else { 4 } {
        let is_idle = (2..4).contains(&group);
        let semantics = if is_idle {
            "idle"
        } else if !strict {
            "notify-both"
        } else if group < 2 {
            "normal"
        } else {
            "recovered"
        };
        for stage in 0..2 {
            let id = 2 * group + stage;
            plant_states.push(PlantState {
                id,
                action_semantics: semantics.into(),
                private_history: format!("synthetic-world-{group}").into(),
            });
            for input in 0..if strict { 1 } else { 2 } {
                let symbol = if is_idle {
                    RESERVED
                } else if stage == 0 {
                    if (!strict && input == 0) || (strict && group < 2) {
                        EARLY
                    } else {
                        RESERVED
                    }
                } else if group % 2 == 0 {
                    FINAL_LEFT
                } else {
                    FINAL_RIGHT
                };
                plant_transitions.push(PlantTransition {
                    from: id,
                    input,
                    to: 2 * group + 1,
                    machine_symbol: symbol,
                });
            }
        }
    }
    let mut diag_left = deliver.clone();
    diag_left.fields.insert("receipt-b".into(), "0".to_owned());
    let mut diag_right = deliver.clone();
    diag_right.fields.insert("receipt-b".into(), "1".to_owned());
    let mut problem = SynthesisProblem {
        horizon: 2,
        machine_symbol_count: 4,
        plant_states,
        plant_transitions,
        inputs: vec![
            EnvironmentInput {
                id: "available".into(),
                public_symbol: "available".to_owned(),
                fault: None,
            },
            EnvironmentInput {
                id: "loss".into(),
                public_symbol: "loss".to_owned(),
                fault: Some("first-opportunity-lost".into()),
            },
        ],
        semantics: vec![
            SemanticContract {
                id: "notify-both".into(),
                obligations,
            },
            SemanticContract {
                id: "idle".into(),
                obligations: Vec::new(),
            },
        ],
        faults: vec![FaultInput {
            id: "first-opportunity-lost".into(),
            recovery: None,
        }],
        observers: vec![Observer {
            id: "recipient-coalition".into(),
            visible_fields: ["receipt-b".into()].into_iter().collect(),
            observes_actions: true,
        }],
        initial_pairs: vec![
            PlantPair { left: 0, right: 2 },
            PlantPair { left: 4, right: 6 },
        ],
        outputs: vec![Release::silent(), deliver, diag_left, diag_right],
    };
    if strict {
        // The scenario is declared in trusted public context before the
        // clock starts. One clock symbol drives both fixed availability tapes.
        problem.inputs = vec![EnvironmentInput {
            id: "public-tick".into(),
            public_symbol: "public-tick".to_owned(),
            fault: None,
        }];
        problem.faults.clear();
        problem.semantics[0].id = "normal".into();
        for action in &mut problem.semantics[0].obligations {
            action.deadline_slot = 0;
        }
        let mut recovered = problem.semantics[0].clone();
        recovered.id = "recovered".into();
        for action in &mut recovered.obligations {
            action.trigger_slot = 1;
            action.deadline_slot = 1;
        }
        problem.semantics.push(recovered);
        problem.initial_pairs.push(PlantPair { left: 8, right: 10 });
        problem.outputs.truncate(2);
    }
    problem
}

fn hand_written(mutant: bool) -> ReleaseMachine {
    // State 0: both pending. State 1: both already issued.
    // The fault-path mutant is only a synthetic checker sensitivity control.
    let outputs = if mutant { [0, 1, 2, 3] } else { [0, 1, 1, 1] };
    let mut cells: Vec<MachineCell> = outputs
        .iter()
        .map(|&output| MachineCell {
            next_state: u32::from(output != 0),
            output,
        })
        .collect();
    cells.extend(
        [MachineCell {
            next_state: 1,
            output: 0,
        }; 4],
    );
    ReleaseMachine {
        state_count: 2,
        symbol_count: 4,
        cells,
    }
}

fn release_json(release: &Release) -> Value {
    let actions: Vec<Value> = release
        .actions
        .iter()
        .map(|item| {
            let ObligationRef::Authorized(id) = &item.obligation else {
                unreachable!("fixture uses only authorized obligations");
            };
            json!({
                "obligation": {"kind": "authorized", "id": id.as_str()},
                "action": item.action.as_str(),
            })
        })
        .collect();
    let fields: serde_json::Map<String, Value> = release
        .fields
        .iter()
        .map(|(id, value)| (id.as_str().to_owned(), json!(value)))
        .collect();
    json!({"emitted": release.emitted, "fields": fields, "actions": actions})
}

fn model_json(model: &CheckerModel) -> Value {
    json!({
        "format_version": "aqrs-check-model-v1",
        "horizon": model.horizon,
        "states": model.states.iter().map(|x| json!({
            "id": x.id.as_str(), "action_semantics": x.action_semantics.as_str(),
            "private_history": x.private_history.as_str(),
        })).collect::<Vec<_>>(),
        "inputs": model.inputs.iter().map(|x| json!({
            "id": x.id.as_str(), "public_symbol": x.public_symbol,
            "fault": x.fault.as_ref().map(|id| id.as_str()),
        })).collect::<Vec<_>>(),
        "faults": model.faults.iter().map(|x| json!({
            "id": x.id.as_str(), "recovery": null,
        })).collect::<Vec<_>>(),
        "semantics": model.semantics.iter().map(|x| json!({
            "id": x.id.as_str(),
            "obligations": x.obligations.iter().map(|obligation| json!({
                "id": obligation.id.as_str(), "action": obligation.action.as_str(),
                "trigger_slot": obligation.trigger_slot, "deadline_slot": obligation.deadline_slot,
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "observers": model.observers.iter().map(|x| json!({
            "id": x.id.as_str(), "observes_actions": x.observes_actions,
            "visible_fields": x.visible_fields.iter().map(|name| name.as_str()).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "initial_pairs": model.initial_pairs.iter().map(|x| json!({
            "left": x.left.as_str(), "right": x.right.as_str(),
        })).collect::<Vec<_>>(),
        "transitions": model.transitions.iter().map(|x| json!({
            "from": x.from.as_str(), "input": x.input.as_str(), "to": x.to.as_str(),
            "release": release_json(&x.release),
        })).collect::<Vec<_>>(),
    })
}

fn model_entry(
    problem: &SynthesisProblem,
    machine: &ReleaseMachine,
) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(json!({
        "state_count": machine.state_count,
        "symbols": machine.symbol_count,
        "cells": machine.cells.iter().map(|x| [x.next_state, x.output]).collect::<Vec<_>>(),
        "checker_model": model_json(&problem.lower_candidate(machine)?),
    }))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let strict = std::env::args().nth(1).as_deref() == Some("--strict-deadline");
    let problem = failure_fixture(strict);
    let limits = SynthesisLimits {
        max_states: 2,
        max_candidates: if strict { 100_000 } else { 10_000 },
        time_limit: Duration::from_secs(15),
        ..SynthesisLimits::default()
    };
    let outcome = if strict {
        find_feasible(&problem, limits)?
    } else {
        optimize_cost(&problem, limits)?
    };
    let report = match outcome {
        SynthesisOutcome::Realizable(report) => report,
        failure => return Err(format!("no bounded synthesized machine: {failure:?}").into()),
    };
    let mut cases = json!({
        "synthesized": model_entry(&problem, &report.machine)?,
        "handwritten": model_entry(&problem, &hand_written(false))?,
    });
    if strict {
        let always_wait = ReleaseMachine {
            state_count: 1,
            symbol_count: 4,
            cells: [0, 0, 1, 1]
                .into_iter()
                .map(|output| MachineCell {
                    next_state: 0,
                    output,
                })
                .collect(),
        };
        cases["always_wait"] = model_entry(&problem, &always_wait)?;
    } else {
        cases["synthetic_mutant"] = model_entry(&problem, &hand_written(true))?;
    }
    let product = json!({
        "schema": "noticer.popets.recovery-synthesis-pilot.v1",
        "evidence": "synthetic public loss/recovery, not deployment evidence",
        "deadline_contract": if strict { "context-specific" } else { "common-final-slot" },
        "synthesis": {
            "cost_optimized": report.cost_optimized,
            "minimal_state_count": report.minimal_state_count,
            "candidates": report.stats.generated_candidates,
            "checker_calls": report.stats.checker_calls,
            "max_states": limits.max_states,
            "cost": {
                "states": report.cost.states,
                "emitting_cells": report.cost.emitting_cells,
                "payload_bytes": report.cost.payload_bytes,
                "action_emissions": report.cost.action_emissions,
            },
        },
        "cases": cases,
        "plant": problem.plant_transitions.iter()
            .map(|x| [x.from, x.input, x.to, x.machine_symbol]).collect::<Vec<_>>(),
        "outputs": problem.outputs.iter().map(release_json).collect::<Vec<_>>(),
    });
    println!("{}", serde_json::to_string(&product)?);
    Ok(())
}
