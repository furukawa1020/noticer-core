use crate::{
    oracle_predecessor_graph::PredecessorGraph,
    oracle_state_pair::StatePair,
    oracle_trace_step::{create, TraceStep},
};
use std::collections::BTreeSet;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconstructionError {
    MissingPredecessor,
    Cycle,
    InvalidStep,
}
pub fn reconstruct(
    graph: &PredecessorGraph,
    target: &StatePair,
) -> Result<Vec<TraceStep>, ReconstructionError> {
    let mut current = target.clone();
    let mut reverse = Vec::new();
    let mut seen = BTreeSet::new();
    while &current != graph.root() {
        if !seen.insert(current.clone()) {
            return Err(ReconstructionError::Cycle);
        }
        let p = graph
            .predecessor(&current)
            .ok_or(ReconstructionError::MissingPredecessor)?;
        let step = create(p.parent.slot, p.input, p.parent.clone(), current.clone())
            .map_err(|_| ReconstructionError::InvalidStep)?;
        reverse.push(step);
        current = p.parent.clone()
    }
    reverse.reverse();
    Ok(reverse)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{oracle_predecessor_graph::PredecessorGraph, oracle_state_pair::create as state};
    fn s(slot: u64) -> StatePair {
        state(slot, &[slot as u8], &[0], 8).unwrap()
    }
    #[test]
    fn reconstructs_complete_trace() {
        let mut g = PredecessorGraph::new(s(0));
        g.record_first(s(1), s(0), 4);
        g.record_first(s(2), s(1), 5);
        let t = reconstruct(&g, &s(2)).unwrap();
        assert_eq!(
            t.iter().map(|x| (x.slot, x.input)).collect::<Vec<_>>(),
            vec![(0, 4), (1, 5)]
        )
    }
    #[test]
    fn rejects_missing() {
        let g = PredecessorGraph::new(s(0));
        assert_eq!(
            reconstruct(&g, &s(1)),
            Err(ReconstructionError::MissingPredecessor)
        );
    }
}
