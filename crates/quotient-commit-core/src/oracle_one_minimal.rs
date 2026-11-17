//! Independent one-minimality verification for counterexample traces.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OneMinimalError {
    NotCounterexample,
    RemovableElement { index: usize },
}

/// Verifies that the trace violates the property and no single deletion does.
pub fn verify<T: Clone>(
    trace: &[T],
    preserves_violation: impl Fn(&[T]) -> bool,
) -> Result<(), OneMinimalError> {
    if !preserves_violation(trace) {
        return Err(OneMinimalError::NotCounterexample);
    }
    for index in 0..trace.len() {
        let mut trial = trace.to_vec();
        trial.remove(index);
        if preserves_violation(&trial) {
            return Err(OneMinimalError::RemovableElement { index });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_one_minimal_trace() {
        let predicate = |trace: &[u8]| trace.contains(&3) && trace.contains(&5);
        assert_eq!(verify(&[3, 5], predicate), Ok(()));
    }

    #[test]
    fn reports_first_removable_element() {
        let predicate = |trace: &[u8]| trace.contains(&3) && trace.contains(&5);
        assert_eq!(
            verify(&[9, 3, 5], predicate),
            Err(OneMinimalError::RemovableElement { index: 0 })
        );
    }

    #[test]
    fn non_counterexample_is_rejected() {
        assert_eq!(
            verify(&[3], |trace| trace.contains(&3) && trace.contains(&5)),
            Err(OneMinimalError::NotCounterexample)
        );
    }
}
