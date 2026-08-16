use crate::canonical::{canonical_hash, CanonicalEncode, Encoder};
use crate::{IrError, IrLimits, DOMAIN_OBSERVER};
use quotient_forge_types::ObserverId;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ObservableField {
    Bytes = 0,
    PacketSize = 1,
    SendSlot = 2,
    FrameCount = 3,
    Silence = 4,
    Connection = 5,
    Failure = 6,
    FrameKind = 7,
    ActionSlot = 8,
    ServiceAlias = 9,
    Retry = 10,
    Reconnect = 11,
    Cost = 12,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Observer {
    pub id: ObserverId,
    pub sees: BTreeSet<ObservableField>,
    pub combines: BTreeSet<ObserverId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObserverModel {
    pub observers: Vec<Observer>,
}

impl ObserverModel {
    pub fn validate(&self, limits: IrLimits) -> Result<(), IrError> {
        if self.observers.is_empty() || self.observers.len() > limits.max_observers {
            return Err(IrError::InvalidObserver);
        }
        let by_id: BTreeMap<_, _> = self
            .observers
            .iter()
            .map(|observer| (&observer.id, observer))
            .collect();
        if by_id.len() != self.observers.len() {
            return Err(IrError::InvalidObserver);
        }
        for observer in &self.observers {
            if observer.id.0.is_empty()
                || observer.id.0.len() > limits.max_label_bytes
                || observer.sees.is_empty() && observer.combines.is_empty()
            {
                return Err(IrError::InvalidObserver);
            }
            for combined in &observer.combines {
                if combined == &observer.id || !by_id.contains_key(combined) {
                    return Err(IrError::InvalidObserver);
                }
            }
        }
        if observer_graph_has_cycle(&self.observers) {
            return Err(IrError::InvalidObserver);
        }
        Ok(())
    }

    pub fn canonicalized(&self, limits: IrLimits) -> Result<Self, IrError> {
        self.validate(limits)?;
        let mut observers = self.observers.clone();
        observers.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(Self { observers })
    }

    pub fn is_canonical(&self, limits: IrLimits) -> Result<bool, IrError> {
        Ok(self == &self.canonicalized(limits)?)
    }

    pub fn canonical_hash(&self, limits: IrLimits) -> Result<[u8; 32], IrError> {
        let canonical = self.canonicalized(limits)?;
        Ok(canonical_hash(DOMAIN_OBSERVER, &canonical))
    }
}

fn observer_graph_has_cycle(observers: &[Observer]) -> bool {
    let by_id: BTreeMap<_, _> = observers
        .iter()
        .map(|observer| (observer.id.clone(), observer))
        .collect();
    let mut visiting = BTreeSet::new();
    let mut complete = BTreeSet::new();
    observers
        .iter()
        .any(|observer| visit_observer(&observer.id, &by_id, &mut visiting, &mut complete))
}

fn visit_observer(
    id: &ObserverId,
    by_id: &BTreeMap<ObserverId, &Observer>,
    visiting: &mut BTreeSet<ObserverId>,
    complete: &mut BTreeSet<ObserverId>,
) -> bool {
    if complete.contains(id) {
        return false;
    }
    if !visiting.insert(id.clone()) {
        return true;
    }
    let cyclic = by_id.get(id).is_some_and(|observer| {
        observer
            .combines
            .iter()
            .any(|combined| visit_observer(combined, by_id, visiting, complete))
    });
    visiting.remove(id);
    complete.insert(id.clone());
    cyclic
}

impl CanonicalEncode for ObserverModel {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.usize(self.observers.len());
        for observer in &self.observers {
            encoder.string(&observer.id.0);
            encoder.usize(observer.sees.len());
            for field in &observer.sees {
                encoder.u8(*field as u8);
            }
            encoder.usize(observer.combines.len());
            for combined in &observer.combines {
                encoder.string(&combined.0);
            }
        }
    }
}
