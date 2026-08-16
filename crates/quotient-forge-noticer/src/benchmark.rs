use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use quotient_forge_check::{
    check, CheckLimits, CheckOutcome, CheckerModel, Counterexample, EnvironmentInput, FaultInput,
    FaultInputId, FieldId, InitialPair, InputId, ModelError, Observer, ObserverId,
    PrivateHistoryId, Release, SemanticContract, SemanticId, State, StateId, Transition,
    VerifiedReport,
};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum HandwrittenPlan {
    ImmediateRelease,
    FixedSizeOnly,
    CoarseBucket,
    EvidenceDependentSlot,
    Aets,
    AplotBoundedLoss,
}

impl HandwrittenPlan {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ImmediateRelease => "ImmediateRelease",
            Self::FixedSizeOnly => "FixedSizeOnly",
            Self::CoarseBucket => "CoarseBucket",
            Self::EvidenceDependentSlot => "EvidenceDependentSlot",
            Self::Aets => "AETS",
            Self::AplotBoundedLoss => "APLOT-bounded-loss",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdapterVerdict {
    Valid(VerifiedReport),
    Counterexample(Box<Counterexample>),
    Inconclusive,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterEvaluation {
    pub plan: HandwrittenPlan,
    pub verdict: AdapterVerdict,
}

pub fn run_handwritten_benchmark(plan: HandwrittenPlan) -> Result<AdapterEvaluation, ModelError> {
    let model = benchmark_model(plan);
    let verdict = match check(
        &model,
        CheckLimits {
            max_nodes: 10_000,
            max_depth: 16,
            time_limit: Duration::from_secs(5),
        },
    )? {
        CheckOutcome::Verified(report) => AdapterVerdict::Valid(report),
        CheckOutcome::Counterexample(counterexample) => {
            AdapterVerdict::Counterexample(counterexample)
        }
        CheckOutcome::Inconclusive(_) => AdapterVerdict::Inconclusive,
    };
    Ok(AdapterEvaluation { plan, verdict })
}

fn benchmark_model(plan: HandwrittenPlan) -> CheckerModel {
    let left = StateId::from("left");
    let right = StateId::from("right");
    let semantic = SemanticId::from("same-authorized-action");
    let delivered = InputId::from("delivered");
    let lost = InputId::from("public-loss");
    let mut inputs = vec![EnvironmentInput {
        id: delivered.clone(),
        public_symbol: "delivered".to_owned(),
        fault: None,
    }];
    let mut faults = Vec::new();
    if plan == HandwrittenPlan::AplotBoundedLoss {
        let fault = FaultInputId::from("bounded-public-loss");
        faults.push(FaultInput {
            id: fault.clone(),
            recovery: None,
        });
        inputs.push(EnvironmentInput {
            id: lost.clone(),
            public_symbol: "lost".to_owned(),
            fault: Some(fault),
        });
    }

    let mut transitions = Vec::new();
    for state in [&left, &right] {
        for input in &inputs {
            transitions.push(Transition {
                from: state.clone(),
                input: input.id.clone(),
                to: state.clone(),
                release: release_for(plan, state == &left, input.id == lost),
            });
        }
    }
    let visible_fields = match plan {
        HandwrittenPlan::FixedSizeOnly => {
            BTreeSet::from([FieldId::from("size"), FieldId::from("payload")])
        }
        HandwrittenPlan::CoarseBucket => BTreeSet::from([FieldId::from("bucket")]),
        HandwrittenPlan::Aets | HandwrittenPlan::AplotBoundedLoss => {
            BTreeSet::from([FieldId::from("public-status")])
        }
        HandwrittenPlan::ImmediateRelease | HandwrittenPlan::EvidenceDependentSlot => {
            BTreeSet::new()
        }
    };
    CheckerModel {
        horizon: if plan == HandwrittenPlan::EvidenceDependentSlot {
            2
        } else {
            1
        },
        states: vec![
            State {
                id: left.clone(),
                action_semantics: semantic.clone(),
                private_history: PrivateHistoryId::from("private-left"),
            },
            State {
                id: right.clone(),
                action_semantics: semantic.clone(),
                private_history: PrivateHistoryId::from("private-right"),
            },
        ],
        semantics: vec![SemanticContract {
            id: semantic,
            obligations: Vec::new(),
        }],
        faults,
        inputs,
        transitions,
        observers: vec![Observer {
            id: ObserverId::from("network"),
            visible_fields,
            observes_actions: true,
        }],
        initial_pairs: vec![InitialPair { left, right }],
    }
}

fn release_for(plan: HandwrittenPlan, left: bool, public_loss: bool) -> Release {
    match plan {
        HandwrittenPlan::ImmediateRelease | HandwrittenPlan::EvidenceDependentSlot => {
            if left {
                Release::emitted()
            } else {
                Release::silent()
            }
        }
        HandwrittenPlan::FixedSizeOnly => Release {
            emitted: true,
            fields: BTreeMap::from([
                (FieldId::from("size"), "236".to_owned()),
                (
                    FieldId::from("payload"),
                    if left { "identity-a" } else { "identity-b" }.to_owned(),
                ),
            ]),
            actions: Vec::new(),
        },
        HandwrittenPlan::CoarseBucket => Release {
            emitted: true,
            fields: BTreeMap::from([(
                FieldId::from("bucket"),
                if left { "low" } else { "high" }.to_owned(),
            )]),
            actions: Vec::new(),
        },
        HandwrittenPlan::Aets => public_release("fixed-slot"),
        HandwrittenPlan::AplotBoundedLoss => public_release(if public_loss {
            "public-loss"
        } else {
            "delivered"
        }),
    }
}

fn public_release(status: &str) -> Release {
    Release {
        emitted: true,
        fields: BTreeMap::from([(FieldId::from("public-status"), status.to_owned())]),
        actions: Vec::new(),
    }
}
