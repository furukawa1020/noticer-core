#![forbid(unsafe_code)]

//! Canonical finite-state IR for Action-Quotient Release Synthesis.

mod automata;
mod canonical;
mod ids;
mod model;
mod observer;
mod plant;
mod quotient;
mod transducer;

pub use automata::{
    FaultAutomaton, FaultState, FaultTransition, UtilityAutomaton, UtilityState, UtilityTransition,
};
pub use ids::{FaultStateId, PlantStateId, QuotientStateId, ReleaseStateId, UtilityStateId};
pub use model::CompiledModel;
pub use observer::{ObservableField, Observer, ObserverModel};
pub use plant::{PlantState, PlantTransition, PrivatePlant};
pub use quotient::{
    ActionSemanticsLabel, PlantQuotientProjection, QuotientLabel, QuotientMonitor, QuotientState,
    QuotientTransition,
};
pub use transducer::{
    CostVector, ReleaseInput, ReleaseOutput, ReleaseState, ReleaseTransducer, ReleaseTransition,
};

use thiserror::Error;

pub const DOMAIN_IR: &[u8] = b"QUOTIENT_FORGE_IR_V1";
pub const DOMAIN_PLANT: &[u8] = b"QUOTIENT_FORGE_PLANT_V1";
pub const DOMAIN_QUOTIENT: &[u8] = b"QUOTIENT_FORGE_QUOTIENT_V1";
pub const DOMAIN_OBSERVER: &[u8] = b"QUOTIENT_FORGE_OBSERVER_V1";
pub const DOMAIN_UTILITY: &[u8] = b"QUOTIENT_FORGE_UTILITY_V1";
pub const DOMAIN_FAULT: &[u8] = b"QUOTIENT_FORGE_FAULT_V1";
pub const DOMAIN_TRANSDUCER: &[u8] = b"QUOTIENT_FORGE_TRANSDUCER_V1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IrLimits {
    pub max_states: usize,
    pub max_transitions: usize,
    pub max_horizon: u16,
    pub max_observers: usize,
    pub max_label_bytes: usize,
}

impl Default for IrLimits {
    fn default() -> Self {
        Self {
            max_states: 256,
            max_transitions: 100_000,
            max_horizon: 512,
            max_observers: 16,
            max_label_bytes: 256,
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum IrError {
    #[error("{component} has no states")]
    EmptyStates { component: &'static str },
    #[error("{component} exceeds a declared resource limit")]
    LimitExceeded { component: &'static str },
    #[error("{component} has an invalid initial state")]
    InvalidInitial { component: &'static str },
    #[error("{component} contains a duplicate state or transition")]
    Duplicate { component: &'static str },
    #[error("{component} contains an invalid state, symbol, or output reference")]
    InvalidReference { component: &'static str },
    #[error("{component} transition relation is not total")]
    NonTotal { component: &'static str },
    #[error("action quotient merges or mislabels different action semantics")]
    QuotientMismatch,
    #[error("action semantics are invalid")]
    InvalidActionSemantics,
    #[error("observer model is empty, cyclic, or references an unknown observer")]
    InvalidObserver,
    #[error("utility state is both accepting and rejecting")]
    InvalidUtility,
    #[error("component `{component}` must be canonical before model assembly")]
    NonCanonical { component: &'static str },
    #[error("compiled model and release transducer dimensions do not match")]
    DimensionMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use quotient_forge_types::ObserverId;
    use std::cmp::Ordering;
    use std::collections::BTreeSet;

    fn canonical_plant() -> PrivatePlant {
        PrivatePlant {
            states: vec![
                PlantState {
                    id: PlantStateId(0),
                    label: "waiting".to_owned(),
                },
                PlantState {
                    id: PlantStateId(1),
                    label: "ready".to_owned(),
                },
            ],
            initial: PlantStateId(0),
            private_input_count: 1,
            public_input_count: 1,
            transitions: vec![
                PlantTransition {
                    from: PlantStateId(0),
                    private_input: 0,
                    public_input: 0,
                    to: PlantStateId(1),
                    emitted_private_events: BTreeSet::from([1]),
                },
                PlantTransition {
                    from: PlantStateId(1),
                    private_input: 0,
                    public_input: 0,
                    to: PlantStateId(1),
                    emitted_private_events: BTreeSet::new(),
                },
            ],
        }
    }

    fn semantics() -> QuotientLabel {
        QuotientLabel::Action(ActionSemanticsLabel {
            service: "menfugu".to_owned(),
            action: "soft_inflate".to_owned(),
            public_bucket: 0,
            release_window_start: 1,
            release_deadline: 3,
        })
    }

    fn quotient() -> QuotientMonitor {
        QuotientMonitor {
            states: vec![QuotientState {
                id: QuotientStateId(0),
                semantics: semantics(),
            }],
            initial: QuotientStateId(0),
            alphabet_size: 1,
            transitions: vec![QuotientTransition {
                from: QuotientStateId(0),
                symbol: 0,
                to: QuotientStateId(0),
            }],
            plant_state_count: 2,
            projection: vec![
                PlantQuotientProjection {
                    plant: PlantStateId(0),
                    quotient: QuotientStateId(0),
                    semantics: semantics(),
                },
                PlantQuotientProjection {
                    plant: PlantStateId(1),
                    quotient: QuotientStateId(0),
                    semantics: semantics(),
                },
            ],
        }
    }

    fn utility() -> UtilityAutomaton {
        UtilityAutomaton {
            states: vec![UtilityState {
                id: UtilityStateId(0),
                accepting: true,
                rejecting: false,
            }],
            initial: UtilityStateId(0),
            alphabet_size: 1,
            transitions: vec![UtilityTransition {
                from: UtilityStateId(0),
                symbol: 0,
                to: UtilityStateId(0),
            }],
        }
    }

    fn fault() -> FaultAutomaton {
        FaultAutomaton {
            states: vec![FaultState {
                id: FaultStateId(0),
                recoverable: true,
            }],
            initial: FaultStateId(0),
            alphabet_size: 1,
            transitions: vec![FaultTransition {
                from: FaultStateId(0),
                symbol: 0,
                to: FaultStateId(0),
            }],
        }
    }

    fn observers() -> ObserverModel {
        ObserverModel {
            observers: vec![Observer {
                id: ObserverId("network".to_owned()),
                sees: BTreeSet::from([ObservableField::FrameKind, ObservableField::SendSlot]),
                combines: BTreeSet::new(),
            }],
        }
    }

    fn transducer() -> ReleaseTransducer {
        ReleaseTransducer {
            states: vec![ReleaseState {
                id: ReleaseStateId(0),
            }],
            initial: ReleaseStateId(0),
            quotient_state_count: 1,
            public_input_count: 1,
            fault_state_count: 1,
            horizon: 4,
            transitions: vec![ReleaseTransition {
                from: ReleaseStateId(0),
                input: ReleaseInput {
                    quotient: QuotientStateId(0),
                    public_input: 0,
                    fault: FaultStateId(0),
                },
                to: ReleaseStateId(0),
                output: ReleaseOutput::Action {
                    action_class: QuotientStateId(0),
                    release_slot: 2,
                },
            }],
        }
    }

    #[test]
    fn plant_hash_is_stable_under_state_rename_and_transition_order() {
        let left = canonical_plant();
        let right = PrivatePlant {
            states: vec![
                PlantState {
                    id: PlantStateId(20),
                    label: "ready".to_owned(),
                },
                PlantState {
                    id: PlantStateId(10),
                    label: "waiting".to_owned(),
                },
            ],
            initial: PlantStateId(10),
            private_input_count: 1,
            public_input_count: 1,
            transitions: vec![
                PlantTransition {
                    from: PlantStateId(20),
                    private_input: 0,
                    public_input: 0,
                    to: PlantStateId(20),
                    emitted_private_events: BTreeSet::new(),
                },
                PlantTransition {
                    from: PlantStateId(10),
                    private_input: 0,
                    public_input: 0,
                    to: PlantStateId(20),
                    emitted_private_events: BTreeSet::from([1]),
                },
            ],
        };
        assert_eq!(
            left.canonical_hash(IrLimits::default()).unwrap(),
            right.canonical_hash(IrLimits::default()).unwrap()
        );
    }

    #[test]
    fn unreachable_plant_state_is_removed() {
        let mut plant = canonical_plant();
        plant.states.push(PlantState {
            id: PlantStateId(2),
            label: "unreachable".to_owned(),
        });
        plant.transitions.push(PlantTransition {
            from: PlantStateId(2),
            private_input: 0,
            public_input: 0,
            to: PlantStateId(2),
            emitted_private_events: BTreeSet::new(),
        });
        let canonical = plant.canonicalized(IrLimits::default()).unwrap();
        assert_eq!(canonical.states.len(), 2);
        assert_eq!(canonical.transitions.len(), 2);
    }

    #[test]
    fn quotient_cannot_merge_different_action_semantics() {
        let mut monitor = quotient();
        monitor.projection[1].semantics = QuotientLabel::NoAction;
        assert_eq!(
            monitor.validate(IrLimits::default()),
            Err(IrError::QuotientMismatch)
        );
    }

    #[test]
    fn observer_hash_ignores_declaration_order() {
        let first = Observer {
            id: ObserverId("network".to_owned()),
            sees: BTreeSet::from([ObservableField::SendSlot]),
            combines: BTreeSet::new(),
        };
        let second = Observer {
            id: ObserverId("service(menfugu)".to_owned()),
            sees: BTreeSet::from([ObservableField::ActionSlot]),
            combines: BTreeSet::new(),
        };
        let left = ObserverModel {
            observers: vec![first.clone(), second.clone()],
        };
        let right = ObserverModel {
            observers: vec![second, first],
        };
        assert_eq!(
            left.canonical_hash(IrLimits::default()).unwrap(),
            right.canonical_hash(IrLimits::default()).unwrap()
        );
    }

    #[test]
    fn observer_combination_cycle_is_rejected() {
        let model = ObserverModel {
            observers: vec![
                Observer {
                    id: ObserverId("left".to_owned()),
                    sees: BTreeSet::new(),
                    combines: BTreeSet::from([ObserverId("right".to_owned())]),
                },
                Observer {
                    id: ObserverId("right".to_owned()),
                    sees: BTreeSet::new(),
                    combines: BTreeSet::from([ObserverId("left".to_owned())]),
                },
            ],
        };
        assert_eq!(
            model.validate(IrLimits::default()),
            Err(IrError::InvalidObserver)
        );
    }

    #[test]
    fn release_transition_function_must_be_total() {
        let mut machine = transducer();
        machine.public_input_count = 2;
        assert_eq!(
            machine.validate(IrLimits::default()),
            Err(IrError::NonTotal {
                component: "release transducer"
            })
        );
    }

    #[test]
    fn compiled_model_and_release_dimensions_match() {
        let model = CompiledModel {
            plant: canonical_plant(),
            quotient: quotient(),
            observers: observers(),
            utility: utility(),
            fault: fault(),
            horizon: 4,
        };
        model.validate(IrLimits::default()).unwrap();
        model
            .validate_transducer(&transducer(), IrLimits::default())
            .unwrap();
        assert_ne!(model.canonical_hash(IrLimits::default()).unwrap(), [0; 32]);
    }

    #[test]
    fn release_input_has_only_quotient_public_and_fault_axes() {
        let input = ReleaseInput {
            quotient: QuotientStateId(0),
            public_input: 0,
            fault: FaultStateId(0),
        };
        assert_eq!(input.quotient, QuotientStateId(0));
    }

    #[test]
    fn cost_comparison_uses_declared_lexicographic_order() {
        let low_dummy = CostVector {
            dummy_frames: 1,
            worst_latency: 100,
            ..CostVector::default()
        };
        let low_latency = CostVector {
            dummy_frames: 2,
            worst_latency: 1,
            ..CostVector::default()
        };
        assert_eq!(low_dummy.lexicographic_cmp(&low_latency), Ordering::Less);
    }

    #[test]
    fn canonical_domains_are_pairwise_distinct() {
        let domains = [
            DOMAIN_IR,
            DOMAIN_PLANT,
            DOMAIN_QUOTIENT,
            DOMAIN_OBSERVER,
            DOMAIN_UTILITY,
            DOMAIN_FAULT,
            DOMAIN_TRANSDUCER,
        ];
        let unique: BTreeSet<&[u8]> = domains.into_iter().collect();
        assert_eq!(unique.len(), domains.len());
    }
}
