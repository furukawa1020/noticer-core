use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

macro_rules! text_id {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            #[must_use]
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            fn is_empty(&self) -> bool {
                self.0.is_empty()
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self::new(value)
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self::new(value)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

text_id!(StateId);
text_id!(SemanticId);
text_id!(PrivateHistoryId);
text_id!(InputId);
text_id!(FaultInputId);
text_id!(ObserverId);
text_id!(FieldId);
text_id!(ActionId);
text_id!(ObligationId);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct State {
    pub id: StateId,
    pub action_semantics: SemanticId,
    pub private_history: PrivateHistoryId,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ObligationRef {
    Authorized(ObligationId),
    Recovery {
        fault: FaultInputId,
        triggered_at: u32,
    },
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ActionObligation {
    pub id: ObligationId,
    pub action: ActionId,
    pub trigger_slot: u32,
    pub deadline_slot: u32,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SemanticContract {
    pub id: SemanticId,
    pub obligations: Vec<ActionObligation>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RecoveryRequirement {
    pub action: ActionId,
    pub deadline_after_slots: u32,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct FaultInput {
    pub id: FaultInputId,
    pub recovery: Option<RecoveryRequirement>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct EnvironmentInput {
    pub id: InputId,
    pub public_symbol: String,
    pub fault: Option<FaultInputId>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ActionEmission {
    pub obligation: ObligationRef,
    pub action: ActionId,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Release {
    pub emitted: bool,
    pub fields: BTreeMap<FieldId, String>,
    pub actions: Vec<ActionEmission>,
}

impl Release {
    #[must_use]
    pub fn silent() -> Self {
        Self {
            emitted: false,
            fields: BTreeMap::new(),
            actions: Vec::new(),
        }
    }

    #[must_use]
    pub fn emitted() -> Self {
        Self {
            emitted: true,
            fields: BTreeMap::new(),
            actions: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Transition {
    pub from: StateId,
    pub input: InputId,
    pub to: StateId,
    pub release: Release,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Observer {
    pub id: ObserverId,
    pub visible_fields: BTreeSet<FieldId>,
    pub observes_actions: bool,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct InitialPair {
    pub left: StateId,
    pub right: StateId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckerModel {
    pub horizon: u32,
    pub states: Vec<State>,
    pub semantics: Vec<SemanticContract>,
    pub faults: Vec<FaultInput>,
    pub inputs: Vec<EnvironmentInput>,
    pub transitions: Vec<Transition>,
    pub observers: Vec<Observer>,
    pub initial_pairs: Vec<InitialPair>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelError {
    EmptyDomain(&'static str),
    EmptyIdentifier(&'static str),
    DuplicateIdentifier {
        domain: &'static str,
        id: String,
    },
    UnknownReference {
        domain: &'static str,
        id: String,
    },
    InvalidInitialPair {
        left: StateId,
        right: StateId,
        reason: &'static str,
    },
    InvalidObligation {
        id: ObligationId,
        reason: &'static str,
    },
    InvalidRelease {
        state: StateId,
        reason: &'static str,
    },
    DuplicateTransition {
        state: StateId,
        input: InputId,
    },
    MissingTransition {
        state: StateId,
        input: InputId,
    },
}

impl fmt::Display for ModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyDomain(domain) => write!(formatter, "{domain} must not be empty"),
            Self::EmptyIdentifier(domain) => {
                write!(formatter, "{domain} contains an empty identifier")
            }
            Self::DuplicateIdentifier { domain, id } => {
                write!(formatter, "{domain} contains duplicate identifier {id}")
            }
            Self::UnknownReference { domain, id } => {
                write!(formatter, "{domain} references unknown identifier {id}")
            }
            Self::InvalidInitialPair {
                left,
                right,
                reason,
            } => {
                write!(
                    formatter,
                    "invalid initial pair ({left}, {right}): {reason}"
                )
            }
            Self::InvalidObligation { id, reason } => {
                write!(formatter, "invalid obligation {id}: {reason}")
            }
            Self::InvalidRelease { state, reason } => {
                write!(formatter, "invalid release from state {state}: {reason}")
            }
            Self::DuplicateTransition { state, input } => {
                write!(formatter, "duplicate transition for ({state}, {input})")
            }
            Self::MissingTransition { state, input } => {
                write!(formatter, "missing transition for ({state}, {input})")
            }
        }
    }
}

impl std::error::Error for ModelError {}

impl CheckerModel {
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.horizon == 0 {
            return Err(ModelError::EmptyDomain("horizon"));
        }
        require_non_empty(&self.states, "states")?;
        require_non_empty(&self.semantics, "semantics")?;
        require_non_empty(&self.inputs, "inputs")?;
        require_non_empty(&self.observers, "observers")?;
        require_non_empty(&self.initial_pairs, "initial_pairs")?;

        let state_by_id = unique_map(
            &self.states,
            |state| &state.id,
            |id| id.is_empty(),
            "states",
        )?;
        let semantic_by_id = unique_map(
            &self.semantics,
            |semantic| &semantic.id,
            |id| id.is_empty(),
            "semantics",
        )?;
        let fault_by_id = unique_map(
            &self.faults,
            |fault| &fault.id,
            |id| id.is_empty(),
            "faults",
        )?;
        let input_by_id = unique_map(
            &self.inputs,
            |input| &input.id,
            |id| id.is_empty(),
            "inputs",
        )?;
        let _observer_by_id = unique_map(
            &self.observers,
            |observer| &observer.id,
            |id| id.is_empty(),
            "observers",
        )?;

        for state in &self.states {
            if state.private_history.is_empty() {
                return Err(ModelError::EmptyIdentifier("private_histories"));
            }
            if !semantic_by_id.contains_key(&state.action_semantics) {
                return Err(ModelError::UnknownReference {
                    domain: "state.action_semantics",
                    id: state.action_semantics.to_string(),
                });
            }
        }

        for semantic in &self.semantics {
            let mut obligation_ids = BTreeSet::new();
            for obligation in &semantic.obligations {
                if obligation.id.is_empty() || obligation.action.is_empty() {
                    return Err(ModelError::EmptyIdentifier("obligations"));
                }
                if !obligation_ids.insert(obligation.id.clone()) {
                    return Err(ModelError::DuplicateIdentifier {
                        domain: "obligations",
                        id: obligation.id.to_string(),
                    });
                }
                if obligation.trigger_slot > obligation.deadline_slot {
                    return Err(ModelError::InvalidObligation {
                        id: obligation.id.clone(),
                        reason: "trigger must not follow deadline",
                    });
                }
                if obligation.deadline_slot >= self.horizon {
                    return Err(ModelError::InvalidObligation {
                        id: obligation.id.clone(),
                        reason: "deadline must be inside the bounded horizon",
                    });
                }
            }
        }

        for input in &self.inputs {
            if input.public_symbol.is_empty() {
                return Err(ModelError::EmptyIdentifier("public_symbols"));
            }
            if let Some(fault) = &input.fault {
                if !fault_by_id.contains_key(fault) {
                    return Err(ModelError::UnknownReference {
                        domain: "input.fault",
                        id: fault.to_string(),
                    });
                }
            }
        }

        for pair in &self.initial_pairs {
            let left = state_by_id
                .get(&pair.left)
                .ok_or_else(|| ModelError::UnknownReference {
                    domain: "initial_pair.left",
                    id: pair.left.to_string(),
                })?;
            let right =
                state_by_id
                    .get(&pair.right)
                    .ok_or_else(|| ModelError::UnknownReference {
                        domain: "initial_pair.right",
                        id: pair.right.to_string(),
                    })?;
            if left.action_semantics != right.action_semantics {
                return Err(ModelError::InvalidInitialPair {
                    left: pair.left.clone(),
                    right: pair.right.clone(),
                    reason: "runs are not action-equivalent",
                });
            }
            if left.private_history == right.private_history {
                return Err(ModelError::InvalidInitialPair {
                    left: pair.left.clone(),
                    right: pair.right.clone(),
                    reason: "runs are not private-distinct",
                });
            }
        }

        let mut transition_keys = BTreeSet::new();
        for transition in &self.transitions {
            if !state_by_id.contains_key(&transition.from) {
                return Err(ModelError::UnknownReference {
                    domain: "transition.from",
                    id: transition.from.to_string(),
                });
            }
            if !state_by_id.contains_key(&transition.to) {
                return Err(ModelError::UnknownReference {
                    domain: "transition.to",
                    id: transition.to.to_string(),
                });
            }
            if !input_by_id.contains_key(&transition.input) {
                return Err(ModelError::UnknownReference {
                    domain: "transition.input",
                    id: transition.input.to_string(),
                });
            }
            if !transition_keys.insert((transition.from.clone(), transition.input.clone())) {
                return Err(ModelError::DuplicateTransition {
                    state: transition.from.clone(),
                    input: transition.input.clone(),
                });
            }
            if !transition.release.emitted
                && (!transition.release.fields.is_empty() || !transition.release.actions.is_empty())
            {
                return Err(ModelError::InvalidRelease {
                    state: transition.from.clone(),
                    reason: "silent release carries observable content",
                });
            }
            if transition.release.fields.keys().any(FieldId::is_empty) {
                return Err(ModelError::EmptyIdentifier("release_fields"));
            }
        }

        for state in state_by_id.keys() {
            for input in input_by_id.keys() {
                if !transition_keys.contains(&(state.clone(), input.clone())) {
                    return Err(ModelError::MissingTransition {
                        state: state.clone(),
                        input: input.clone(),
                    });
                }
            }
        }

        Ok(())
    }

    pub(crate) fn state_index(&self) -> BTreeMap<StateId, &State> {
        self.states
            .iter()
            .map(|state| (state.id.clone(), state))
            .collect()
    }

    pub(crate) fn semantic_index(&self) -> BTreeMap<SemanticId, &SemanticContract> {
        self.semantics
            .iter()
            .map(|semantic| (semantic.id.clone(), semantic))
            .collect()
    }

    pub(crate) fn fault_index(&self) -> BTreeMap<FaultInputId, &FaultInput> {
        self.faults
            .iter()
            .map(|fault| (fault.id.clone(), fault))
            .collect()
    }

    pub(crate) fn transition_index(&self) -> BTreeMap<(StateId, InputId), &Transition> {
        self.transitions
            .iter()
            .map(|transition| {
                (
                    (transition.from.clone(), transition.input.clone()),
                    transition,
                )
            })
            .collect()
    }
}

fn require_non_empty<T>(values: &[T], domain: &'static str) -> Result<(), ModelError> {
    if values.is_empty() {
        Err(ModelError::EmptyDomain(domain))
    } else {
        Ok(())
    }
}

fn unique_map<'a, T, I, F, E>(
    values: &'a [T],
    id_of: F,
    is_empty: E,
    domain: &'static str,
) -> Result<BTreeMap<I, &'a T>, ModelError>
where
    I: Clone + fmt::Display + Ord,
    F: Fn(&T) -> &I,
    E: Fn(&I) -> bool,
{
    let mut by_id = BTreeMap::new();
    for value in values {
        let id = id_of(value);
        if is_empty(id) {
            return Err(ModelError::EmptyIdentifier(domain));
        }
        if by_id.insert(id.clone(), value).is_some() {
            return Err(ModelError::DuplicateIdentifier {
                domain,
                id: id.to_string(),
            });
        }
    }
    Ok(by_id)
}
