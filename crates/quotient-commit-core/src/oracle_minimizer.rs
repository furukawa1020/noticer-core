//! Deterministic deletion-based counterexample minimization.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MinimizationError {
    NotCounterexample,
}

/// Repeatedly removes the first element whose deletion preserves violation.
///
/// The ascending index order and restart after each accepted deletion make the
/// result reproducible for a deterministic predicate.
pub fn minimize<T: Clone>(
    trace: &[T],
    preserves_violation: impl Fn(&[T]) -> bool,
) -> Result<Vec<T>, MinimizationError> {
    if !preserves_violation(trace) {
        return Err(MinimizationError::NotCounterexample);
    }
    let mut candidate = trace.to_vec();
    loop {
        let removable = (0..candidate.len()).find(|&index| {
            let mut trial = candidate.clone();
            trial.remove(index);
            preserves_violation(&trial)
        });
        match removable {
            Some(index) => {
                candidate.remove(index);
            }
            None => return Ok(candidate),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_in_ascending_deterministic_order() {
        let predicate = |trace: &[u8]| trace.contains(&3) && trace.contains(&5);
        let trace = [1, 3, 2, 5, 4];
        assert_eq!(minimize(&trace, predicate), Ok(vec![3, 5]));
        assert_eq!(minimize(&trace, predicate), Ok(vec![3, 5]));
    }

    #[test]
    fn rejects_input_that_is_not_a_counterexample() {
        assert_eq!(
            minimize(&[1, 2], |trace| trace.contains(&9)),
            Err(MinimizationError::NotCounterexample)
        );
    }

    #[test]
    fn empty_counterexample_is_supported() {
        assert_eq!(minimize::<u8>(&[], |_| true), Ok(Vec::new()));
    }
}
