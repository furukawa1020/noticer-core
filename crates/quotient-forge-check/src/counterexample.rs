use std::collections::BTreeMap;

use crate::model::{
    ActionEmission, ActionId, EnvironmentInput, FieldId, ObligationRef, ObserverId, Release,
    StateId,
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Side {
    Left,
    Right,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Observation {
    pub emitted: bool,
    pub fields: BTreeMap<FieldId, String>,
    pub actions: Vec<ActionEmission>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum CausalField {
    ReleasePresence,
    Field(FieldId),
    Actions,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum CounterexampleKind {
    SecurityDivergence,
    UnauthorizedAction {
        side: Side,
        action: ActionId,
        obligation: ObligationRef,
    },
    DuplicateAction {
        side: Side,
        action: ActionId,
        obligation: ObligationRef,
    },
    MissedDeadline {
        side: Side,
        action: ActionId,
        obligation: ObligationRef,
    },
    RecoverableFaultViolation {
        side: Side,
        action: ActionId,
        obligation: ObligationRef,
    },
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum RepairCandidate {
    EqualizeReleasePresence,
    NormalizeField(FieldId),
    HideField {
        observer: ObserverId,
        field: FieldId,
    },
    NormalizeObservedActions,
    BindAuthorizedAction(ObligationRef),
    SuppressDuplicateAction(ObligationRef),
    ScheduleBeforeDeadline(ObligationRef),
    AddRecoveryTransition(ObligationRef),
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TraceStep {
    pub slot: u32,
    pub input: EnvironmentInput,
    pub left_state: StateId,
    pub right_state: StateId,
    pub left_release: Release,
    pub right_release: Release,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Counterexample {
    pub kind: CounterexampleKind,
    pub slot: u32,
    pub observer: Option<ObserverId>,
    pub left_observation: Option<Observation>,
    pub right_observation: Option<Observation>,
    pub causal_field: Option<CausalField>,
    pub trace: Vec<TraceStep>,
    pub repair_candidates: Vec<RepairCandidate>,
}
