use crate::{
    oracle_predecessor_graph::PredecessorGraph, oracle_state_pair::StatePair,
    oracle_verdict::InconclusiveReason,
};
use std::collections::{BTreeSet, VecDeque};
pub enum SearchResult {
    Counterexample {
        target: StatePair,
        graph: PredecessorGraph,
        explored: u64,
    },
    NoCounterexample {
        explored: u64,
    },
    Inconclusive(InconclusiveReason),
}
pub fn search<T, V>(
    initial: StatePair,
    inputs: &[u16],
    maximum_nodes: usize,
    transition: T,
    violates: V,
) -> SearchResult
where
    T: Fn(&StatePair, u16) -> StatePair,
    V: Fn(&StatePair) -> bool,
{
    if maximum_nodes == 0 {
        return SearchResult::Inconclusive(InconclusiveReason::NodeLimit);
    }
    let mut ordered = inputs.to_vec();
    ordered.sort();
    ordered.dedup();
    let mut graph = PredecessorGraph::new(initial.clone());
    let mut seen = BTreeSet::from([initial.clone()]);
    let mut queue = VecDeque::from([initial.clone()]);
    while let Some(state) = queue.pop_front() {
        if violates(&state) {
            return SearchResult::Counterexample {
                target: state,
                graph,
                explored: seen.len() as u64,
            };
        }
        for input in &ordered {
            let next = transition(&state, *input);
            if seen.contains(&next) {
                continue;
            }
            if seen.len() >= maximum_nodes {
                return SearchResult::Inconclusive(InconclusiveReason::NodeLimit);
            }
            seen.insert(next.clone());
            graph.record_first(next.clone(), state.clone(), *input);
            queue.push_back(next)
        }
    }
    SearchResult::NoCounterexample {
        explored: seen.len() as u64,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::oracle_state_pair::create;
    fn state(slot: u64) -> StatePair {
        create(slot, &[slot as u8], &[0], 16).unwrap()
    }
    #[test]
    fn finds_shortest_depth() {
        let r = search(
            state(0),
            &[2, 1],
            10,
            |s, _| state(s.slot + 1),
            |s| s.slot == 2,
        );
        match r {
            SearchResult::Counterexample { target, .. } => assert_eq!(target.slot, 2),
            _ => panic!("expected counterexample"),
        }
    }
    #[test]
    fn limit_is_inconclusive() {
        let r = search(state(0), &[1], 1, |s, _| state(s.slot + 1), |_| false);
        assert!(matches!(
            r,
            SearchResult::Inconclusive(InconclusiveReason::NodeLimit)
        ));
    }
}
