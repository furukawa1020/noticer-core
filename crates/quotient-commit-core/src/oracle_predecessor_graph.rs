use crate::oracle_state_pair::StatePair;
use std::collections::BTreeMap;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Predecessor {
    pub parent: StatePair,
    pub input: u16,
}
pub struct PredecessorGraph {
    root: StatePair,
    edges: BTreeMap<StatePair, Predecessor>,
}
impl PredecessorGraph {
    pub fn new(root: StatePair) -> Self {
        Self {
            root,
            edges: BTreeMap::new(),
        }
    }
    pub fn record_first(&mut self, node: StatePair, parent: StatePair, input: u16) -> bool {
        if node == self.root || self.edges.contains_key(&node) {
            return false;
        }
        self.edges.insert(node, Predecessor { parent, input });
        true
    }
    pub fn predecessor(&self, node: &StatePair) -> Option<&Predecessor> {
        self.edges.get(node)
    }
    pub fn root(&self) -> &StatePair {
        &self.root
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::oracle_state_pair::create;
    fn s(slot: u64, v: u8) -> StatePair {
        create(slot, &[v], &[v + 1], 4).unwrap()
    }
    #[test]
    fn keeps_first_predecessor() {
        let root = s(0, 1);
        let node = s(1, 2);
        let mut g = PredecessorGraph::new(root.clone());
        assert!(g.record_first(node.clone(), root, 3));
        assert!(!g.record_first(node.clone(), s(0, 9), 4));
        assert_eq!(g.predecessor(&node).unwrap().input, 3)
    }
    #[test]
    fn root_has_no_predecessor() {
        let root = s(0, 1);
        let mut g = PredecessorGraph::new(root.clone());
        assert!(!g.record_first(root.clone(), root.clone(), 1));
        assert_eq!(g.predecessor(&root), None);
    }
}
