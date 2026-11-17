use crate::{oracle_state_pair::StatePair, oracle_verdict::InvalidReason};
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceStep {
    pub slot: u64,
    pub input: u16,
    pub before: StatePair,
    pub after: StatePair,
}
pub fn create(
    slot: u64,
    input: u16,
    before: StatePair,
    after: StatePair,
) -> Result<TraceStep, InvalidReason> {
    if before.slot != slot || after.slot != slot.checked_add(1).ok_or(InvalidReason::Domain)? {
        return Err(InvalidReason::NonCanonical);
    }
    Ok(TraceStep {
        slot,
        input,
        before,
        after,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::oracle_state_pair::create as state;
    #[test]
    fn binds_complete_step() {
        let b = state(2, &[1], &[2], 4).unwrap();
        let a = state(3, &[3], &[4], 4).unwrap();
        let s = create(2, 7, b, a).unwrap();
        assert_eq!((s.slot, s.input), (2, 7))
    }
    #[test]
    fn rejects_slot_gap() {
        let b = state(2, &[1], &[2], 4).unwrap();
        let a = state(4, &[3], &[4], 4).unwrap();
        assert_eq!(create(2, 7, b, a), Err(InvalidReason::NonCanonical));
    }
}
