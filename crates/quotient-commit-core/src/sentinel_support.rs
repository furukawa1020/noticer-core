//! Membership checker for the public support certified at repair time.

use std::collections::BTreeSet;

use crate::sentinel_observation_atom::RuntimeObservationAtom;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeSupportChecker {
    supported_observation_digests: BTreeSet<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupportError {
    EmptySupport,
    OutsideSupport([u8; 32]),
}

impl RuntimeSupportChecker {
    pub fn new(digests: BTreeSet<[u8; 32]>) -> Result<Self, SupportError> {
        if digests.is_empty() || digests.contains(&[0; 32]) {
            return Err(SupportError::EmptySupport);
        }
        Ok(Self {
            supported_observation_digests: digests,
        })
    }

    pub fn verify(&self, atom: RuntimeObservationAtom) -> Result<(), SupportError> {
        let digest = atom.digest();
        if self.supported_observation_digests.contains(&digest) {
            Ok(())
        } else {
            Err(SupportError::OutsideSupport(digest))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sentinel_observation_atom::PublicRuntimeEvent;

    #[test]
    fn out_of_support_observation_fails_closed() {
        let known = RuntimeObservationAtom::new(1, PublicRuntimeEvent::Release, 1, 0).unwrap();
        let unknown = RuntimeObservationAtom::new(2, PublicRuntimeEvent::Release, 1, 0).unwrap();
        let checker = RuntimeSupportChecker::new(BTreeSet::from([known.digest()])).unwrap();
        assert!(matches!(
            checker.verify(unknown),
            Err(SupportError::OutsideSupport(_))
        ));
    }
}
