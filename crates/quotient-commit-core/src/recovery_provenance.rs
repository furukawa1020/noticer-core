//! Deterministic provenance DAG validation for recovery artifacts.
use crate::sha256::sha256;
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvenanceNode {
    pub digest: [u8; 32],
    pub parents: Vec<[u8; 32]>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvenanceGraph {
    pub ordered: Vec<[u8; 32]>,
    pub root_digest: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProvenanceError {
    Empty,
    InvalidDigest,
    Duplicate,
    MissingParent,
    Cycle,
    TooManyParents,
}
pub fn verify(nodes: &[ProvenanceNode]) -> Result<ProvenanceGraph, ProvenanceError> {
    if nodes.is_empty() {
        return Err(ProvenanceError::Empty);
    }
    let mut map = BTreeMap::new();
    for n in nodes {
        if n.digest == [0; 32] || n.parents.contains(&[0; 32]) {
            return Err(ProvenanceError::InvalidDigest);
        }
        if n.parents.len() > 16 {
            return Err(ProvenanceError::TooManyParents);
        }
        let mut p = n.parents.clone();
        p.sort();
        p.dedup();
        if p.len() != n.parents.len() {
            return Err(ProvenanceError::Duplicate);
        }
        if map.insert(n.digest, p).is_some() {
            return Err(ProvenanceError::Duplicate);
        }
    }
    if map.values().flatten().any(|p| !map.contains_key(p)) {
        return Err(ProvenanceError::MissingParent);
    }
    let mut emitted = BTreeSet::new();
    let mut ordered = Vec::new();
    while ordered.len() < map.len() {
        let next = map
            .iter()
            .find(|(id, p)| !emitted.contains(*id) && p.iter().all(|x| emitted.contains(x)))
            .map(|(id, _)| *id);
        let Some(next) = next else {
            return Err(ProvenanceError::Cycle);
        };
        emitted.insert(next);
        ordered.push(next)
    }
    let mut b = Vec::new();
    for id in &ordered {
        b.extend_from_slice(id)
    }
    Ok(ProvenanceGraph {
        ordered,
        root_digest: sha256(&b),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn graph_is_order_independent() {
        let a = ProvenanceNode {
            digest: [1; 32],
            parents: vec![],
        };
        let b = ProvenanceNode {
            digest: [2; 32],
            parents: vec![[1; 32]],
        };
        assert_eq!(verify(&[a.clone(), b.clone()]), verify(&[b, a]));
    }
    #[test]
    fn missing_and_cycle_fail() {
        assert_eq!(
            verify(&[ProvenanceNode {
                digest: [2; 32],
                parents: vec![[1; 32]]
            }]),
            Err(ProvenanceError::MissingParent)
        );
        let a = ProvenanceNode {
            digest: [1; 32],
            parents: vec![[2; 32]],
        };
        let b = ProvenanceNode {
            digest: [2; 32],
            parents: vec![[1; 32]],
        };
        assert_eq!(verify(&[a, b]), Err(ProvenanceError::Cycle));
    }
}
