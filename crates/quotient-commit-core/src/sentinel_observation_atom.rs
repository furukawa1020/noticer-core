//! Public-safe runtime events; raw biosignals are unrepresentable.

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PublicRuntimeEvent {
    Release,
    Suppress,
    Delay,
    Padding,
    Transition,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RuntimeObservationAtom {
    pub slot: u32,
    pub event: PublicRuntimeEvent,
    pub action_class: u16,
    pub public_state: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationAtomError {
    ZeroActionClass,
}

impl RuntimeObservationAtom {
    pub fn new(
        slot: u32,
        event: PublicRuntimeEvent,
        action_class: u16,
        public_state: u32,
    ) -> Result<Self, ObservationAtomError> {
        if action_class == 0 {
            return Err(ObservationAtomError::ZeroActionClass);
        }
        Ok(Self {
            slot,
            event,
            action_class,
            public_state,
        })
    }

    #[must_use]
    pub fn digest(self) -> [u8; 32] {
        let mut bytes = b"noticer.quotient-sentinel.observation.v1\0".to_vec();
        bytes.extend_from_slice(&self.slot.to_be_bytes());
        bytes.push(self.event as u8);
        bytes.extend_from_slice(&self.action_class.to_be_bytes());
        bytes.extend_from_slice(&self.public_state.to_be_bytes());
        crate::sha256::sha256(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atom_contains_only_public_release_semantics() {
        let atom = RuntimeObservationAtom::new(7, PublicRuntimeEvent::Release, 2, 9).unwrap();
        assert_eq!(atom.action_class, 2);
        assert_ne!(atom.digest(), [0; 32]);
    }
}
