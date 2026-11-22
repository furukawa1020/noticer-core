//! Within-workload and seed paired differences.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairedObservation {
    pub pair_id: u64,
    pub baseline: i64,
    pub candidate: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairedDifference {
    pub pair_id: u64,
    pub difference: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairedDesignError {
    Empty,
    DuplicatePair,
    Overflow,
}

pub fn differences(
    mut observations: Vec<PairedObservation>,
) -> Result<Vec<PairedDifference>, PairedDesignError> {
    if observations.is_empty() {
        return Err(PairedDesignError::Empty);
    }
    observations.sort_by_key(|v| v.pair_id);
    if observations
        .windows(2)
        .any(|p| p[0].pair_id == p[1].pair_id)
    {
        return Err(PairedDesignError::DuplicatePair);
    }
    observations
        .into_iter()
        .map(|v| {
            v.candidate
                .checked_sub(v.baseline)
                .map(|difference| PairedDifference {
                    pair_id: v.pair_id,
                    difference,
                })
                .ok_or(PairedDesignError::Overflow)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pairing_removes_shared_offset() {
        let result = differences(vec![
            PairedObservation {
                pair_id: 1,
                baseline: 100,
                candidate: 90,
            },
            PairedObservation {
                pair_id: 2,
                baseline: 1000,
                candidate: 990,
            },
        ])
        .unwrap();
        assert_eq!(
            result.iter().map(|v| v.difference).collect::<Vec<_>>(),
            vec![-10, -10]
        );
    }
}
