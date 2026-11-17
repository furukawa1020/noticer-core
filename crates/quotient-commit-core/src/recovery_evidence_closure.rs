use crate::recovery_evidence_graph::EvidenceGraph;
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClosureError {
    UnknownRoot,
    MissingEvidence,
}

pub fn verify(
    graph: &EvidenceGraph,
    root: u32,
    presented: &BTreeSet<u32>,
) -> Result<BTreeSet<u32>, ClosureError> {
    if graph.dependencies(root).is_none() {
        return Err(ClosureError::UnknownRoot);
    }
    let mut required = BTreeSet::new();
    let mut pending = vec![root];
    while let Some(id) = pending.pop() {
        if required.insert(id) {
            let dependencies = graph.dependencies(id).ok_or(ClosureError::UnknownRoot)?;
            pending.extend(dependencies.iter().copied());
        }
    }
    if !required.is_subset(presented) {
        return Err(ClosureError::MissingEvidence);
    }
    Ok(required)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery_evidence_graph::{EvidenceGraph, EvidenceNode};
    fn graph() -> EvidenceGraph {
        EvidenceGraph::compile(&[
            EvidenceNode {
                id: 1,
                dependencies: vec![],
            },
            EvidenceNode {
                id: 2,
                dependencies: vec![1],
            },
            EvidenceNode {
                id: 3,
                dependencies: vec![2],
            },
        ])
        .unwrap()
    }
    #[test]
    fn accepts_transitive_closure() {
        assert_eq!(
            verify(&graph(), 3, &BTreeSet::from([1, 2, 3])),
            Ok(BTreeSet::from([1, 2, 3]))
        )
    }
    #[test]
    fn rejects_missing_transitive_evidence() {
        assert_eq!(
            verify(&graph(), 3, &BTreeSet::from([2, 3])),
            Err(ClosureError::MissingEvidence)
        )
    }
}
