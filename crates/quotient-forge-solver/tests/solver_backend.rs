use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Mutex;
use std::time::Duration;

use quotient_forge_check::{
    EnvironmentInput, InputId, Observer, ObserverId, PrivateHistoryId, Release, SemanticContract,
    SemanticId,
};
use quotient_forge_solver::{
    encode_smtlib, parse_solver_output, solve, BackendConfig, BackendStatus, ConstraintKind,
    HardBlocker, ObjectiveCost, ParseModelError, ParsedSolverOutput, RuntimeError, RuntimeOutput,
    SmtEncoding, SmtPhase, SolverKind, SolverRuntime, SolverSelection,
};
use quotient_forge_synth::{
    BlockingClause, DecisionAssignment, MachineCell, PlantPair, PlantState, PlantTransition,
    SynthesisLimits, SynthesisProblem,
};

fn problem() -> SynthesisProblem {
    let semantic = SemanticId::from("same");
    SynthesisProblem {
        horizon: 1,
        machine_symbol_count: 1,
        plant_states: vec![
            PlantState {
                id: 0,
                action_semantics: semantic.clone(),
                private_history: PrivateHistoryId::from("left"),
            },
            PlantState {
                id: 1,
                action_semantics: semantic.clone(),
                private_history: PrivateHistoryId::from("right"),
            },
        ],
        plant_transitions: vec![
            PlantTransition {
                from: 0,
                input: 0,
                to: 0,
                machine_symbol: 0,
            },
            PlantTransition {
                from: 1,
                input: 0,
                to: 1,
                machine_symbol: 0,
            },
        ],
        inputs: vec![EnvironmentInput {
            id: InputId::from("tick"),
            public_symbol: "tick".to_owned(),
            fault: None,
        }],
        semantics: vec![SemanticContract {
            id: semantic,
            obligations: Vec::new(),
        }],
        faults: Vec::new(),
        observers: vec![Observer {
            id: ObserverId::from("network"),
            visible_fields: BTreeSet::new(),
            observes_actions: false,
        }],
        initial_pairs: vec![PlantPair { left: 0, right: 1 }],
        outputs: vec![Release::emitted()],
    }
}

fn blocker(kind: ConstraintKind) -> HardBlocker {
    HardBlocker {
        kind,
        clause: BlockingClause {
            assignments: vec![DecisionAssignment {
                machine_state: 0,
                symbol: 0,
                decision: MachineCell {
                    next_state: 0,
                    output: 0,
                },
            }],
        },
    }
}

#[test]
fn phase_a_has_only_hard_constraints() {
    let script = encode_smtlib(&SmtEncoding {
        state_count: 1,
        symbol_count: 1,
        output_count: 1,
        blockers: vec![
            blocker(ConstraintKind::Security),
            blocker(ConstraintKind::Utility),
            blocker(ConstraintKind::Fault),
        ],
        phase: SmtPhase::Feasibility,
        output_costs: Vec::new(),
    })
    .unwrap();
    assert!(script.contains(":named hard_security_0000"));
    assert!(script.contains(":named hard_utility_0001"));
    assert!(script.contains(":named hard_fault_0002"));
    assert!(!script.contains("(minimize"));
    assert_eq!(
        script,
        encode_smtlib(&SmtEncoding {
            state_count: 1,
            symbol_count: 1,
            output_count: 1,
            blockers: vec![
                blocker(ConstraintKind::Security),
                blocker(ConstraintKind::Utility),
                blocker(ConstraintKind::Fault),
            ],
            phase: SmtPhase::Feasibility,
            output_costs: Vec::new(),
        })
        .unwrap()
    );
}

#[test]
fn phase_b_objective_order_is_canonical() {
    let script = encode_smtlib(&SmtEncoding {
        state_count: 1,
        symbol_count: 1,
        output_count: 1,
        blockers: Vec::new(),
        phase: SmtPhase::Optimization,
        output_costs: vec![ObjectiveCost {
            dummy: 1,
            latency: 2,
            retry: 3,
            reconnect: 4,
        }],
    })
    .unwrap();
    let dummy = script.find("objective: dummy").unwrap();
    let latency = script.find("objective: latency").unwrap();
    let state = script.find("objective: state").unwrap();
    let retry = script.find("objective: retry").unwrap();
    let reconnect = script.find("objective: reconnect").unwrap();
    assert!(dummy < latency && latency < state && state < retry && retry < reconnect);
    assert_eq!(script.matches("(minimize").count(), 5);
}

#[test]
fn sat_and_unsat_outputs_parse() {
    let variables = vec!["n_0_0".to_owned(), "o_0_0".to_owned()];
    let sat = "sat\n(model (define-fun n_0_0 () Int 0) (define-fun o_0_0 () Int 0))";
    assert_eq!(
        parse_solver_output(sat, &variables).unwrap(),
        ParsedSolverOutput::Sat(BTreeMap::from([
            ("n_0_0".to_owned(), 0),
            ("o_0_0".to_owned(), 0),
        ]))
    );
    assert_eq!(
        parse_solver_output("unsat", &variables).unwrap(),
        ParsedSolverOutput::Unsat
    );
}

#[test]
fn malformed_solver_outputs_are_rejected() {
    let variables = vec!["n_0_0".to_owned()];
    assert_eq!(
        parse_solver_output("", &variables),
        Err(ParseModelError::Empty)
    );
    assert!(matches!(
        parse_solver_output("maybe", &variables),
        Err(ParseModelError::UnknownStatus(_))
    ));
    assert_eq!(
        parse_solver_output("sat (model", &variables),
        Err(ParseModelError::UnclosedList)
    );
    assert_eq!(
        parse_solver_output("sat (model)", &variables),
        Err(ParseModelError::MissingDefinition("n_0_0".to_owned()))
    );
    assert!(matches!(
        parse_solver_output("sat (model (define-fun n_0_0 () Int x))", &variables),
        Err(ParseModelError::InvalidInteger { .. })
    ));
}

struct FakeRuntime {
    versions: BTreeMap<SolverKind, Result<String, RuntimeError>>,
    outputs: Mutex<VecDeque<Result<RuntimeOutput, RuntimeError>>>,
}

impl FakeRuntime {
    fn unavailable() -> Self {
        Self {
            versions: BTreeMap::from([
                (SolverKind::Cvc5, Err(RuntimeError::NotInstalled)),
                (SolverKind::Z3, Err(RuntimeError::NotInstalled)),
            ]),
            outputs: Mutex::new(VecDeque::new()),
        }
    }

    fn with_output(output: RuntimeOutput) -> Self {
        Self {
            versions: BTreeMap::from([
                (SolverKind::Cvc5, Ok("cvc5 1.test".to_owned())),
                (SolverKind::Z3, Ok("Z3 4.test".to_owned())),
            ]),
            outputs: Mutex::new(VecDeque::from([Ok(output)])),
        }
    }
}

impl SolverRuntime for FakeRuntime {
    fn version(&self, solver: SolverKind) -> Result<String, RuntimeError> {
        self.versions
            .get(&solver)
            .cloned()
            .unwrap_or(Err(RuntimeError::NotInstalled))
    }

    fn run(
        &self,
        _solver: SolverKind,
        _script: &str,
        _timeout: Duration,
    ) -> Result<RuntimeOutput, RuntimeError> {
        self.outputs
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Err(RuntimeError::Io("no fake output".to_owned())))
    }
}

fn config() -> BackendConfig {
    BackendConfig {
        state_bound: 1,
        exhaustive_limits: SynthesisLimits {
            max_states: 1,
            max_candidates: 100,
            time_limit: Duration::from_secs(2),
            checker_limits: quotient_forge_check::CheckLimits {
                max_nodes: 100,
                max_depth: 4,
                time_limit: Duration::from_secs(2),
            },
            seed: 0,
        },
        ..BackendConfig::default()
    }
}

#[test]
fn auto_detection_records_order_and_versions() {
    let runtime = FakeRuntime::with_output(RuntimeOutput::Completed {
        stdout: "unsat".to_owned(),
        stderr: String::new(),
        success: true,
    });
    let result = solve(&problem(), &config(), &runtime).unwrap();
    assert_eq!(result.status, BackendStatus::Unsat);
    assert_eq!(result.artifact.selected, Some(SolverKind::Cvc5));
    assert_eq!(result.artifact.detection_order.len(), 2);
    assert_eq!(result.artifact.detection_order[0].solver, SolverKind::Cvc5);
    assert_eq!(result.artifact.detection_order[1].solver, SolverKind::Z3);
    assert_eq!(
        result.artifact.selected_version.as_deref(),
        Some("cvc5 1.test")
    );
}

#[test]
fn small_auto_problem_falls_back_to_exhaustive() {
    let result = solve(&problem(), &config(), &FakeRuntime::unavailable()).unwrap();
    assert_eq!(result.status, BackendStatus::Sat);
    assert_eq!(result.artifact.selected, Some(SolverKind::Exhaustive));
    assert!(result.machine.is_some());
}

#[test]
fn unavailable_large_or_explicit_solver_does_not_fallback() {
    let mut large = config();
    large.exhaustive_fallback_max_cells = 0;
    assert_eq!(
        solve(&problem(), &large, &FakeRuntime::unavailable())
            .unwrap()
            .status,
        BackendStatus::NotInstalled
    );

    let mut explicit = config();
    explicit.selection = SolverSelection::Explicit(SolverKind::Cvc5);
    assert_eq!(
        solve(&problem(), &explicit, &FakeRuntime::unavailable())
            .unwrap()
            .status,
        BackendStatus::NotInstalled
    );
}

#[test]
fn external_statuses_remain_distinct() {
    let timeout = FakeRuntime::with_output(RuntimeOutput::TimedOut);
    assert_eq!(
        solve(&problem(), &config(), &timeout).unwrap().status,
        BackendStatus::Timeout
    );

    let malformed = FakeRuntime::with_output(RuntimeOutput::Completed {
        stdout: "sat (broken".to_owned(),
        stderr: String::new(),
        success: true,
    });
    assert_eq!(
        solve(&problem(), &config(), &malformed).unwrap().status,
        BackendStatus::MalformedOutput
    );
}

#[test]
fn sat_model_is_rechecked_independently() {
    let runtime = FakeRuntime::with_output(RuntimeOutput::Completed {
        stdout: "sat\n(model (define-fun n_0_0 () Int 0) (define-fun o_0_0 () Int 0))".to_owned(),
        stderr: String::new(),
        success: true,
    });
    let result = solve(&problem(), &config(), &runtime).unwrap();
    assert_eq!(result.status, BackendStatus::Sat);
    assert_eq!(result.machine.unwrap().cells[0].output, 0);
    assert_eq!(result.artifact.phases.len(), 1);
}
