//! Deterministic visited-state tracking for oracle exploration.

use std::collections::BTreeSet;

use crate::{oracle_state_digest::digest, oracle_state_pair::StatePair};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VisitedStateSet {
    digests: BTreeSet<[u8; 32]>,
}

impl VisitedStateSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` only for the first visit to the ordered state pair.
    pub fn visit(&mut self, state: &StatePair) -> bool {
        self.digests.insert(digest(state))
    }

    pub fn contains(&self, state: &StatePair) -> bool {
        self.digests.contains(&digest(state))
    }

    pub fn len(&self) -> usize {
        self.digests.len()
    }

    pub fn is_empty(&self) -> bool {
        self.digests.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(left: &[u8], right: &[u8]) -> StatePair {
        StatePair {
            slot: 1,
            left: left.to_vec(),
            right: right.to_vec(),
        }
    }

    #[test]
    fn duplicate_is_visited_once() {
        let state = pair(b"a", b"b");
        let mut visited = VisitedStateSet::new();
        assert!(visited.visit(&state));
        assert!(!visited.visit(&state));
        assert_eq!(visited.len(), 1);
    }

    #[test]
    fn swapped_pair_remains_distinct() {
        let mut visited = VisitedStateSet::new();
        assert!(visited.visit(&pair(b"a", b"b")));
        assert!(visited.visit(&pair(b"b", b"a")));
        assert_eq!(visited.len(), 2);
    }
}
