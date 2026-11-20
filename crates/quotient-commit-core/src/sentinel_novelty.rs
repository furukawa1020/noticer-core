//! Bounded public novelty detector with no raw or private features.

use std::collections::BTreeSet;

use crate::sentinel_observation_atom::RuntimeObservationAtom;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicNoveltyDetector {
    known: BTreeSet<[u8; 32]>,
    maximum_known: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NoveltyResult {
    Known,
    Novel([u8; 32]),
    CapacityReached,
}

impl PublicNoveltyDetector {
    pub fn new(maximum_known: usize) -> Option<Self> {
        (maximum_known > 0).then_some(Self {
            known: BTreeSet::new(),
            maximum_known,
        })
    }

    pub fn observe(&mut self, atom: RuntimeObservationAtom) -> NoveltyResult {
        let digest = atom.digest();
        if self.known.contains(&digest) {
            return NoveltyResult::Known;
        }
        if self.known.len() >= self.maximum_known {
            return NoveltyResult::CapacityReached;
        }
        self.known.insert(digest);
        NoveltyResult::Novel(digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sentinel_observation_atom::PublicRuntimeEvent;

    #[test]
    fn first_observation_is_novel_then_known() {
        let atom = RuntimeObservationAtom::new(1, PublicRuntimeEvent::Padding, 1, 0).unwrap();
        let mut detector = PublicNoveltyDetector::new(1).unwrap();
        assert!(matches!(detector.observe(atom), NoveltyResult::Novel(_)));
        assert_eq!(detector.observe(atom), NoveltyResult::Known);
    }
}
