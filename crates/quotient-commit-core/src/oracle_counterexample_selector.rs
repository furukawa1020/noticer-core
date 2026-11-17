use crate::oracle_state_pair::StatePair;
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CounterexampleCandidate {
    pub state: StatePair,
    pub input: u16,
}
pub fn select(candidates: &[CounterexampleCandidate]) -> Option<CounterexampleCandidate> {
    candidates
        .iter()
        .cloned()
        .min_by_key(|c| (c.state.slot, c.state.clone(), c.input))
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::oracle_state_pair::create;
    fn c(slot: u64, left: u8, input: u16) -> CounterexampleCandidate {
        CounterexampleCandidate {
            state: create(slot, &[left], &[0], 4).unwrap(),
            input,
        }
    }
    #[test]
    fn shortest_slot_wins() {
        assert_eq!(select(&[c(2, 0, 0), c(1, 9, 9)]).unwrap().state.slot, 1)
    }
    #[test]
    fn canonical_tie_break() {
        assert_eq!(
            select(&[c(1, 2, 1), c(1, 1, 9)]).unwrap().state.left,
            vec![1]
        )
    }
}
