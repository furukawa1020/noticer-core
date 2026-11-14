//! Bounded deterministic fault schedules for recovery campaigns.
use std::collections::BTreeSet;
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum FaultPoint {
    BeforeProof = 1,
    AfterQuorum = 2,
    DuringLease = 3,
    BeforeHandoff = 4,
    DuringAudit = 5,
    BeforeAttestation = 6,
}
const POINTS: [FaultPoint; 6] = [
    FaultPoint::BeforeProof,
    FaultPoint::AfterQuorum,
    FaultPoint::DuringLease,
    FaultPoint::BeforeHandoff,
    FaultPoint::DuringAudit,
    FaultPoint::BeforeAttestation,
];
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ScheduledFault {
    pub step: u32,
    pub point: FaultPoint,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FaultSchedule {
    pub seed: u64,
    pub total_steps: u32,
    pub faults: Vec<ScheduledFault>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScheduleError {
    InvalidSeed,
    InvalidSteps,
    TooManyFaults,
}
pub fn generate(
    seed: u64,
    total_steps: u32,
    fault_count: u8,
) -> Result<FaultSchedule, ScheduleError> {
    if seed == 0 {
        return Err(ScheduleError::InvalidSeed);
    }
    if total_steps == 0 || total_steps > 10_000 {
        return Err(ScheduleError::InvalidSteps);
    }
    if fault_count as u32 > total_steps || fault_count > 64 {
        return Err(ScheduleError::TooManyFaults);
    }
    let mut state = seed;
    let mut unique = BTreeSet::new();
    while unique.len() < usize::from(fault_count) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let step = (state % u64::from(total_steps)) as u32;
        let point = POINTS[((state >> 32) as usize) % POINTS.len()];
        unique.insert(ScheduledFault { step, point });
    }
    Ok(FaultSchedule {
        seed,
        total_steps,
        faults: unique.into_iter().collect(),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn schedule_is_bounded_unique_and_reproducible() {
        let a = generate(42, 100, 12).unwrap();
        let b = generate(42, 100, 12).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.faults.len(), 12);
        assert!(a.faults.windows(2).all(|w| w[0] != w[1]));
    }
    #[test]
    fn invalid_bounds_fail() {
        assert_eq!(generate(0, 10, 1), Err(ScheduleError::InvalidSeed));
        assert_eq!(generate(1, 2, 3), Err(ScheduleError::TooManyFaults));
    }
}
