#![forbid(unsafe_code)]

//! Canonical finite causal model for the Action-Quotient Release Polytope.

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const DOMAIN_MODEL: &[u8] = b"QUOTIENT_LIMIT_MODEL_V1";

macro_rules! id_type {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(pub u16);
    };
}

id_type!(PrivateHistoryId);
id_type!(ActionQuotientClassId);
id_type!(InformationSetId);
id_type!(PublicPrefixId);
id_type!(QuotientPrefixId);
id_type!(FaultPrefixId);
id_type!(ObserverId);
id_type!(ServiceId);
id_type!(PolicyId);
id_type!(ActionCode);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelLimits {
    pub max_histories: usize,
    pub max_quotient_classes: usize,
    pub max_horizon: u16,
    pub max_services: usize,
    pub max_observers: usize,
}

impl Default for ModelLimits {
    fn default() -> Self {
        Self {
            max_histories: 256,
            max_quotient_classes: 64,
            max_horizon: 256,
            max_services: 16,
            max_observers: 16,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedActionSemantics {
    pub action_sequence: Vec<ActionCode>,
    pub service: ServiceId,
    pub policy: PolicyId,
    pub admission_cutoff: u16,
    pub release_window_start: u16,
    pub release_deadline: u16,
    pub public_fault_contract: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionQuotientClass {
    pub id: ActionQuotientClassId,
    pub semantics: AuthorizedActionSemantics,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoryClass {
    pub history: PrivateHistoryId,
    pub class: ActionQuotientClassId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionQuotient {
    pub classes: Vec<ActionQuotientClass>,
    pub class_of_history: Vec<HistoryClass>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InformationSet {
    pub id: InformationSetId,
    pub time: u16,
    pub public_prefix: PublicPrefixId,
    pub admitted_quotient_prefix: QuotientPrefixId,
    pub fault_prefix: FaultPrefixId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InformationTree {
    pub information_sets: Vec<InformationSet>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadinessEntry {
    pub history: PrivateHistoryId,
    pub ready_slot: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadinessModel {
    pub entries: Vec<ReadinessEntry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicInputModel {
    pub horizon: u16,
    pub public_prefix_count: u16,
    pub quotient_prefix_count: u16,
    pub fault_prefix_count: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObserverProjection {
    Presence,
    Timing,
    Size,
    Service,
    Failure,
    Collusion { services: Vec<ServiceId> },
    Longitudinal { buckets: u16 },
    FullDeclaredTrace,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Observer {
    pub id: ObserverId,
    pub projection: ObserverProjection,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObserverFamily {
    pub observers: Vec<Observer>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateHistoryModel {
    pub histories: Vec<PrivateHistoryId>,
    pub action_quotient: ActionQuotient,
    pub information_tree: InformationTree,
    pub readiness: ReadinessModel,
    pub public_inputs: PublicInputModel,
    pub observers: ObserverFamily,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("{component} is empty")]
    Empty { component: &'static str },
    #[error("{component} exceeds a frozen resource limit")]
    ResourceLimit { component: &'static str },
    #[error("{component} is not canonical")]
    NonCanonical { component: &'static str },
    #[error("every history must have exactly one class and readiness entry")]
    IncompleteHistoryPartition,
    #[error("a quotient class is unknown or unused")]
    InvalidQuotientClass,
    #[error("readiness/admission/window/deadline order is invalid")]
    InvalidAdmissionOrder,
    #[error("an information set is outside the public information tree")]
    InvalidInformationSet,
    #[error("an observer projection is invalid")]
    InvalidObserver,
}

impl PrivateHistoryModel {
    pub fn validate(&self, limits: ModelLimits) -> Result<(), ModelError> {
        ordered_nonempty(&self.histories, "private histories")?;
        if self.histories.len() > limits.max_histories {
            return Err(ModelError::ResourceLimit {
                component: "private histories",
            });
        }
        let inputs = self.public_inputs;
        if inputs.horizon == 0 || inputs.horizon > limits.max_horizon {
            return Err(ModelError::ResourceLimit {
                component: "horizon",
            });
        }
        if inputs.public_prefix_count == 0
            || inputs.quotient_prefix_count == 0
            || inputs.fault_prefix_count == 0
        {
            return Err(ModelError::InvalidInformationSet);
        }
        self.validate_quotient(limits)?;
        self.validate_readiness()?;
        self.validate_information_tree()?;
        self.validate_observers(limits)
    }

    fn validate_quotient(&self, limits: ModelLimits) -> Result<(), ModelError> {
        let quotient = &self.action_quotient;
        if quotient.classes.is_empty() {
            return Err(ModelError::Empty {
                component: "action quotient",
            });
        }
        if quotient.classes.len() > limits.max_quotient_classes {
            return Err(ModelError::ResourceLimit {
                component: "action quotient",
            });
        }
        if !ordered(quotient.classes.iter().map(|item| item.id))
            || !ordered(quotient.class_of_history.iter().map(|item| item.history))
        {
            return Err(ModelError::NonCanonical {
                component: "action quotient",
            });
        }
        let class_ids: BTreeSet<_> = quotient.classes.iter().map(|item| item.id).collect();
        let services: BTreeSet<_> = quotient
            .classes
            .iter()
            .map(|item| item.semantics.service)
            .collect();
        if services.len() > limits.max_services {
            return Err(ModelError::ResourceLimit {
                component: "services",
            });
        }
        for class in &quotient.classes {
            let semantics = &class.semantics;
            if semantics.action_sequence.is_empty()
                || semantics.admission_cutoff >= semantics.release_window_start
                || semantics.release_window_start > semantics.release_deadline
                || semantics.release_deadline > self.public_inputs.horizon
            {
                return Err(ModelError::InvalidAdmissionOrder);
            }
        }
        if quotient.class_of_history.len() != self.histories.len()
            || quotient
                .class_of_history
                .iter()
                .map(|item| item.history)
                .ne(self.histories.iter().copied())
        {
            return Err(ModelError::IncompleteHistoryPartition);
        }
        let used: BTreeSet<_> = quotient
            .class_of_history
            .iter()
            .map(|item| item.class)
            .collect();
        if used != class_ids {
            return Err(ModelError::InvalidQuotientClass);
        }
        Ok(())
    }

    fn validate_readiness(&self) -> Result<(), ModelError> {
        if self.readiness.entries.len() != self.histories.len()
            || !ordered(self.readiness.entries.iter().map(|item| item.history))
            || self
                .readiness
                .entries
                .iter()
                .map(|item| item.history)
                .ne(self.histories.iter().copied())
        {
            return Err(ModelError::IncompleteHistoryPartition);
        }
        let partition: BTreeMap<_, _> = self
            .action_quotient
            .class_of_history
            .iter()
            .map(|item| (item.history, item.class))
            .collect();
        let classes: BTreeMap<_, _> = self
            .action_quotient
            .classes
            .iter()
            .map(|item| (item.id, &item.semantics))
            .collect();
        for entry in &self.readiness.entries {
            let cutoff = partition
                .get(&entry.history)
                .and_then(|id| classes.get(id))
                .map(|item| item.admission_cutoff)
                .ok_or(ModelError::InvalidQuotientClass)?;
            if entry.ready_slot > cutoff {
                return Err(ModelError::InvalidAdmissionOrder);
            }
        }
        Ok(())
    }

    fn validate_information_tree(&self) -> Result<(), ModelError> {
        let sets = &self.information_tree.information_sets;
        if sets.is_empty() {
            return Err(ModelError::Empty {
                component: "information tree",
            });
        }
        if !ordered(sets.iter().map(|item| item.id)) {
            return Err(ModelError::NonCanonical {
                component: "information tree",
            });
        }
        for set in sets {
            if set.time > self.public_inputs.horizon
                || set.public_prefix.0 >= self.public_inputs.public_prefix_count
                || set.admitted_quotient_prefix.0 >= self.public_inputs.quotient_prefix_count
                || set.fault_prefix.0 >= self.public_inputs.fault_prefix_count
            {
                return Err(ModelError::InvalidInformationSet);
            }
        }
        Ok(())
    }

    fn validate_observers(&self, limits: ModelLimits) -> Result<(), ModelError> {
        let observers = &self.observers.observers;
        if observers.is_empty() {
            return Err(ModelError::Empty {
                component: "observers",
            });
        }
        if observers.len() > limits.max_observers {
            return Err(ModelError::ResourceLimit {
                component: "observers",
            });
        }
        if !ordered(observers.iter().map(|item| item.id)) {
            return Err(ModelError::NonCanonical {
                component: "observers",
            });
        }
        let declared: BTreeSet<_> = self
            .action_quotient
            .classes
            .iter()
            .map(|item| item.semantics.service)
            .collect();
        for observer in observers {
            match &observer.projection {
                ObserverProjection::Collusion { services }
                    if services.len() < 2
                        || !ordered(services.iter().copied())
                        || services.iter().any(|service| !declared.contains(service)) =>
                {
                    return Err(ModelError::InvalidObserver)
                }
                ObserverProjection::Longitudinal { buckets: 0 } => {
                    return Err(ModelError::InvalidObserver)
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub fn canonical_hash(&self, limits: ModelLimits) -> Result<[u8; 32], ModelError> {
        self.validate(limits)?;
        let mut e = Encoder::default();
        e.u16(self.public_inputs.horizon);
        e.u16(self.public_inputs.public_prefix_count);
        e.u16(self.public_inputs.quotient_prefix_count);
        e.u16(self.public_inputs.fault_prefix_count);
        e.len(self.histories.len());
        for id in &self.histories {
            e.u16(id.0);
        }
        e.len(self.action_quotient.classes.len());
        for class in &self.action_quotient.classes {
            e.u16(class.id.0);
            e.len(class.semantics.action_sequence.len());
            for action in &class.semantics.action_sequence {
                e.u16(action.0);
            }
            e.u16(class.semantics.service.0);
            e.u16(class.semantics.policy.0);
            e.u16(class.semantics.admission_cutoff);
            e.u16(class.semantics.release_window_start);
            e.u16(class.semantics.release_deadline);
            e.u16(class.semantics.public_fault_contract);
        }
        for item in &self.action_quotient.class_of_history {
            e.u16(item.history.0);
            e.u16(item.class.0);
        }
        e.len(self.information_tree.information_sets.len());
        for set in &self.information_tree.information_sets {
            e.u16(set.id.0);
            e.u16(set.time);
            e.u16(set.public_prefix.0);
            e.u16(set.admitted_quotient_prefix.0);
            e.u16(set.fault_prefix.0);
        }
        for item in &self.readiness.entries {
            e.u16(item.history.0);
            e.u16(item.ready_slot);
        }
        e.len(self.observers.observers.len());
        for observer in &self.observers.observers {
            e.u16(observer.id.0);
            observer.projection.encode(&mut e);
        }
        let mut digest = Sha256::new();
        digest.update(DOMAIN_MODEL);
        digest.update([0]);
        digest.update(e.bytes);
        Ok(digest.finalize().into())
    }
}

impl ObserverProjection {
    fn encode(&self, e: &mut Encoder) {
        match self {
            Self::Presence => e.u8(0),
            Self::Timing => e.u8(1),
            Self::Size => e.u8(2),
            Self::Service => e.u8(3),
            Self::Failure => e.u8(4),
            Self::Collusion { services } => {
                e.u8(5);
                e.len(services.len());
                for service in services {
                    e.u16(service.0);
                }
            }
            Self::Longitudinal { buckets } => {
                e.u8(6);
                e.u16(*buckets);
            }
            Self::FullDeclaredTrace => e.u8(7),
        }
    }
}

fn ordered_nonempty<T: Ord>(values: &[T], component: &'static str) -> Result<(), ModelError> {
    if values.is_empty() {
        return Err(ModelError::Empty { component });
    }
    if !values.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(ModelError::NonCanonical { component });
    }
    Ok(())
}

fn ordered<T: Ord>(values: impl IntoIterator<Item = T>) -> bool {
    let mut values = values.into_iter();
    let Some(mut previous) = values.next() else {
        return true;
    };
    for value in values {
        if previous >= value {
            return false;
        }
        previous = value;
    }
    true
}

#[derive(Default)]
struct Encoder {
    bytes: Vec<u8>,
}
impl Encoder {
    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }
    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }
    fn len(&mut self, value: usize) {
        self.bytes.extend_from_slice(&(value as u64).to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model() -> PrivateHistoryModel {
        PrivateHistoryModel {
            histories: vec![PrivateHistoryId(0), PrivateHistoryId(1)],
            action_quotient: ActionQuotient {
                classes: vec![ActionQuotientClass {
                    id: ActionQuotientClassId(0),
                    semantics: AuthorizedActionSemantics {
                        action_sequence: vec![ActionCode(7)],
                        service: ServiceId(0),
                        policy: PolicyId(0),
                        admission_cutoff: 3,
                        release_window_start: 4,
                        release_deadline: 8,
                        public_fault_contract: 0,
                    },
                }],
                class_of_history: vec![
                    HistoryClass {
                        history: PrivateHistoryId(0),
                        class: ActionQuotientClassId(0),
                    },
                    HistoryClass {
                        history: PrivateHistoryId(1),
                        class: ActionQuotientClassId(0),
                    },
                ],
            },
            information_tree: InformationTree {
                information_sets: vec![InformationSet {
                    id: InformationSetId(0),
                    time: 0,
                    public_prefix: PublicPrefixId(0),
                    admitted_quotient_prefix: QuotientPrefixId(0),
                    fault_prefix: FaultPrefixId(0),
                }],
            },
            readiness: ReadinessModel {
                entries: vec![
                    ReadinessEntry {
                        history: PrivateHistoryId(0),
                        ready_slot: 1,
                    },
                    ReadinessEntry {
                        history: PrivateHistoryId(1),
                        ready_slot: 3,
                    },
                ],
            },
            public_inputs: PublicInputModel {
                horizon: 8,
                public_prefix_count: 1,
                quotient_prefix_count: 1,
                fault_prefix_count: 1,
            },
            observers: ObserverFamily {
                observers: vec![Observer {
                    id: ObserverId(0),
                    projection: ObserverProjection::Timing,
                }],
            },
        }
    }

    #[test]
    fn canonical_model_validates_and_hashes() {
        let model = model();
        model.validate(ModelLimits::default()).unwrap();
        assert_ne!(
            model.canonical_hash(ModelLimits::default()).unwrap(),
            [0; 32]
        );
    }

    #[test]
    fn partition_must_be_total() {
        let mut model = model();
        model.action_quotient.class_of_history.pop();
        assert_eq!(
            model.validate(ModelLimits::default()),
            Err(ModelError::IncompleteHistoryPartition)
        );
    }

    #[test]
    fn readiness_must_precede_admission() {
        let mut model = model();
        model.readiness.entries[1].ready_slot = 4;
        assert_eq!(
            model.validate(ModelLimits::default()),
            Err(ModelError::InvalidAdmissionOrder)
        );
    }

    #[test]
    fn information_set_rejects_unknown_prefix() {
        let mut model = model();
        model.information_tree.information_sets[0].public_prefix = PublicPrefixId(1);
        assert_eq!(
            model.validate(ModelLimits::default()),
            Err(ModelError::InvalidInformationSet)
        );
    }

    #[test]
    fn canonical_order_is_required() {
        let mut model = model();
        model.histories.reverse();
        assert_eq!(
            model.validate(ModelLimits::default()),
            Err(ModelError::NonCanonical {
                component: "private histories"
            })
        );
    }
}
