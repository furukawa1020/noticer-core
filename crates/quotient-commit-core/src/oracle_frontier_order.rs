use crate::oracle_state_pair::StatePair;
use std::collections::BTreeSet;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrontierItem {
    pub state: StatePair,
    pub input: u16,
}
pub fn canonical(states: &[StatePair], inputs: &[u16]) -> Vec<FrontierItem> {
    let states = states.iter().cloned().collect::<BTreeSet<_>>();
    let inputs = inputs.iter().copied().collect::<BTreeSet<_>>();
    let mut out = Vec::new();
    for state in states {
        for input in &inputs {
            out.push(FrontierItem {
                state: state.clone(),
                input: *input,
            })
        }
    }
    out
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::oracle_state_pair::create;
    fn s(v: u8) -> StatePair {
        create(0, &[v], &[0], 4).unwrap()
    }
    #[test]
    fn permutation_independent() {
        assert_eq!(
            canonical(&[s(2), s(1)], &[2, 1]),
            canonical(&[s(1), s(2)], &[1, 2])
        )
    }
    #[test]
    fn removes_duplicates() {
        assert_eq!(canonical(&[s(1), s(1)], &[1, 1]).len(), 1)
    }
}
