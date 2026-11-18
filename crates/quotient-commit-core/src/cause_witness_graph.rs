//! First-predecessor graph for shortest causal witness reconstruction.

use std::collections::{BTreeMap, BTreeSet};

use crate::{cause_intervention::Intervention, cause_verdict::CausalInvalidReason};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Edge {
    parent: [u8; 32],
    intervention: Intervention,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessGraph {
    root: [u8; 32],
    predecessors: BTreeMap<[u8; 32], Edge>,
}

impl WitnessGraph {
    pub fn new(root: [u8; 32]) -> Self {
        Self {
            root,
            predecessors: BTreeMap::new(),
        }
    }

    pub fn record_first(
        &mut self,
        child: [u8; 32],
        parent: [u8; 32],
        intervention: Intervention,
    ) -> bool {
        if child == self.root || self.predecessors.contains_key(&child) {
            return false;
        }
        self.predecessors.insert(
            child,
            Edge {
                parent,
                intervention,
            },
        );
        true
    }

    pub fn reconstruct(&self, target: [u8; 32]) -> Result<Vec<Intervention>, CausalInvalidReason> {
        let mut current = target;
        let mut seen = BTreeSet::new();
        let mut reversed = Vec::new();
        while current != self.root {
            if !seen.insert(current) {
                return Err(CausalInvalidReason::NonCanonical);
            }
            let edge = self
                .predecessors
                .get(&current)
                .ok_or(CausalInvalidReason::Domain)?;
            reversed.push(edge.intervention);
            current = edge.parent;
        }
        reversed.reverse();
        Ok(reversed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cause_atom::{create as atom, AtomKind},
        cause_intervention::{create as intervention, InterventionValue},
    };

    fn change(field: u16) -> Intervention {
        intervention(
            atom(1, AtomKind::Transition, field, 0).unwrap(),
            InterventionValue::SetPublicBranch(1),
        )
        .unwrap()
    }

    #[test]
    fn reconstructs_root_to_target_order() {
        let mut graph = WitnessGraph::new([0; 32]);
        assert!(graph.record_first([1; 32], [0; 32], change(1)));
        assert!(graph.record_first([2; 32], [1; 32], change(2)));
        assert_eq!(graph.reconstruct([2; 32]), Ok(vec![change(1), change(2)]));
    }

    #[test]
    fn later_predecessor_cannot_replace_shortest_parent() {
        let mut graph = WitnessGraph::new([0; 32]);
        assert!(graph.record_first([2; 32], [0; 32], change(1)));
        assert!(!graph.record_first([2; 32], [1; 32], change(2)));
        assert_eq!(graph.reconstruct([2; 32]), Ok(vec![change(1)]));
    }

    #[test]
    fn missing_predecessor_is_invalid() {
        let graph = WitnessGraph::new([0; 32]);
        assert_eq!(graph.reconstruct([9; 32]), Err(CausalInvalidReason::Domain));
    }
}
