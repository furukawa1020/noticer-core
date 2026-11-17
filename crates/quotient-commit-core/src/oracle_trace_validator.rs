use crate::oracle_trace_step::TraceStep;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceError {
    Empty,
    SlotGap,
    StateDiscontinuity,
    EarlyViolation,
    TerminalNotViolation,
}
pub fn validate<V>(trace: &[TraceStep], violates: V) -> Result<(), TraceError>
where
    V: Fn(&crate::oracle_state_pair::StatePair) -> bool,
{
    if trace.is_empty() {
        return Err(TraceError::Empty);
    }
    for (i, s) in trace.iter().enumerate() {
        if i > 0 {
            let p = &trace[i - 1];
            if s.slot != p.slot + 1 {
                return Err(TraceError::SlotGap);
            }
            if s.before != p.after {
                return Err(TraceError::StateDiscontinuity);
            }
        }
        if violates(&s.before) {
            return Err(TraceError::EarlyViolation);
        }
    }
    if !violates(&trace.last().expect("nonempty").after) {
        return Err(TraceError::TerminalNotViolation);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{oracle_state_pair::create as state, oracle_trace_step::create};
    fn s(n: u64) -> crate::oracle_state_pair::StatePair {
        state(n, &[n as u8], &[0], 8).unwrap()
    }
    #[test]
    fn validates_first_violation() {
        let t = [
            create(0, 1, s(0), s(1)).unwrap(),
            create(1, 2, s(1), s(2)).unwrap(),
        ];
        assert_eq!(validate(&t, |x| x.slot == 2), Ok(()))
    }
    #[test]
    fn rejects_nonviolating_terminal() {
        let t = [create(0, 1, s(0), s(1)).unwrap()];
        assert_eq!(
            validate(&t, |_| false),
            Err(TraceError::TerminalNotViolation)
        );
    }
}
