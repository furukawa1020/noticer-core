//! Deterministic first-counterexample oracle over known-good public traces.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegressionCase {
    pub trace_id: u64,
    pub expected_action: u16,
    pub repaired_action: u16,
    pub semantics_preserved: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegressionWitness {
    pub index: usize,
    pub trace_id: u64,
    pub expected_action: u16,
    pub repaired_action: u16,
}

pub fn first_regression(cases: &[RegressionCase]) -> Option<RegressionWitness> {
    cases.iter().enumerate().find_map(|(index, case)| {
        (!case.semantics_preserved || case.expected_action != case.repaired_action).then_some(
            RegressionWitness {
                index,
                trace_id: case.trace_id,
                expected_action: case.expected_action,
                repaired_action: case.repaired_action,
            },
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn earliest_counterexample_is_stable() {
        let cases = [
            RegressionCase {
                trace_id: 7,
                expected_action: 1,
                repaired_action: 2,
                semantics_preserved: false,
            },
            RegressionCase {
                trace_id: 8,
                expected_action: 1,
                repaired_action: 3,
                semantics_preserved: false,
            },
        ];
        assert_eq!(first_regression(&cases).unwrap().trace_id, 7);
    }

    #[test]
    fn clean_suite_has_no_witness() {
        assert_eq!(
            first_regression(&[RegressionCase {
                trace_id: 1,
                expected_action: 2,
                repaired_action: 2,
                semantics_preserved: true
            }]),
            None
        );
    }
}
