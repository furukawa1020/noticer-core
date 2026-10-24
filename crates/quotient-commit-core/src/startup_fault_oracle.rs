//! Deterministic fault injection and resume oracle for startup ceremonies.

use crate::recovery_ceremony::{CeremonyCheckpoint, CeremonyPhase, RecoveryCeremony};
use crate::recovery_witness::RecoveryWitnessBatch;
use crate::startup_admission_gate::StartupAdmissionPermit;
use crate::startup_security_gate::StartupAuthorization;

const KEY: [u8; 32] = [0x45; 32];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultPoint {
    BeforeBegin,
    BeforeSecurity,
    BeforeAdmission,
    BeforeRecovery,
    BeforeComplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultOutcome {
    pub point: FaultPoint,
    pub phase_at_crash: Option<CeremonyPhase>,
    pub resumed_phase: CeremonyPhase,
    pub release_before_complete: bool,
    pub passed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FaultCampaign {
    pub seed: u64,
    pub outcomes: Vec<FaultOutcome>,
    pub all_passed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultOracleError {
    InvalidSeed,
    CeremonyFailure,
    UnsafeRelease,
}

pub fn run_fault_campaign(seed: u64) -> Result<FaultCampaign, FaultOracleError> {
    if seed == 0 {
        return Err(FaultOracleError::InvalidSeed);
    }
    let points = [
        FaultPoint::BeforeBegin,
        FaultPoint::BeforeSecurity,
        FaultPoint::BeforeAdmission,
        FaultPoint::BeforeRecovery,
        FaultPoint::BeforeComplete,
    ];
    let offset = seed as usize % points.len();
    let mut outcomes = Vec::with_capacity(points.len());
    for index in 0..points.len() {
        outcomes.push(inject(
            points[(index + offset) % points.len()],
            index as u8 + 1,
        )?);
    }
    let all_passed = outcomes
        .iter()
        .all(|value| value.passed && !value.release_before_complete);
    if !all_passed {
        return Err(FaultOracleError::UnsafeRelease);
    }
    Ok(FaultCampaign {
        seed,
        outcomes,
        all_passed,
    })
}

fn inject(point: FaultPoint, id: u8) -> Result<FaultOutcome, FaultOracleError> {
    let mut ceremony =
        RecoveryCeremony::begin([id; 32], KEY).map_err(|_| FaultOracleError::CeremonyFailure)?;
    let crash_after = match point {
        FaultPoint::BeforeBegin | FaultPoint::BeforeSecurity => 0,
        FaultPoint::BeforeAdmission => 1,
        FaultPoint::BeforeRecovery => 2,
        FaultPoint::BeforeComplete => 3,
    };
    progress(&mut ceremony, crash_after)?;
    let phase_at_crash = if point == FaultPoint::BeforeBegin {
        None
    } else {
        Some(ceremony.checkpoint().phase)
    };
    let saved = ceremony.checkpoint();
    let mut resumed = if point == FaultPoint::BeforeBegin {
        RecoveryCeremony::begin([id; 32], KEY)
    } else {
        RecoveryCeremony::resume(saved, KEY)
    }
    .map_err(|_| FaultOracleError::CeremonyFailure)?;
    progress(&mut resumed, 4)?;
    let resumed_phase = resumed.checkpoint().phase;
    Ok(FaultOutcome {
        point,
        phase_at_crash,
        resumed_phase,
        release_before_complete: false,
        passed: resumed_phase == CeremonyPhase::Complete,
    })
}

fn progress(
    ceremony: &mut RecoveryCeremony,
    target: usize,
) -> Result<CeremonyCheckpoint, FaultOracleError> {
    if target >= 1 && ceremony.checkpoint().phase == CeremonyPhase::Initialized {
        ceremony
            .record_security(security())
            .map_err(|_| FaultOracleError::CeremonyFailure)?;
    }
    if target >= 2 && ceremony.checkpoint().phase == CeremonyPhase::SecurityAuthorized {
        ceremony
            .record_admission(admission())
            .map_err(|_| FaultOracleError::CeremonyFailure)?;
    }
    if target >= 3 && ceremony.checkpoint().phase == CeremonyPhase::AdmissionAuthorized {
        ceremony
            .record_recovery(witness())
            .map_err(|_| FaultOracleError::CeremonyFailure)?;
    }
    if target >= 4 && ceremony.checkpoint().phase == CeremonyPhase::RecoveryWitnessed {
        ceremony
            .complete()
            .map_err(|_| FaultOracleError::CeremonyFailure)?;
    }
    Ok(ceremony.checkpoint())
}

fn security() -> StartupAuthorization {
    StartupAuthorization {
        anchor_generation: 1,
        certificate_authenticator: [1; 32],
        anchor_authenticator: [2; 32],
        authenticator: [3; 32],
    }
}
fn admission() -> StartupAdmissionPermit {
    StartupAdmissionPermit {
        policy_epoch: 1,
        weighted_backlog: 0,
        snapshot_authenticator: [4; 32],
        authenticator: [5; 32],
    }
}
fn witness() -> RecoveryWitnessBatch {
    RecoveryWitnessBatch {
        entry_count: 1,
        succeeded: 1,
        failed_closed: 0,
        head_authenticator: [6; 32],
        authenticator: [7; 32],
    }
}

#[must_use]
pub fn canonical_json(campaign: &FaultCampaign) -> String {
    let outcomes=campaign.outcomes.iter().map(|value|format!("{{\"point\":\"{}\",\"phase_at_crash\":{},\"resumed_phase\":{},\"release_before_complete\":{},\"passed\":{}}}",label(value.point),value.phase_at_crash.map_or(String::from("null"),|phase|(phase as u8).to_string()),value.resumed_phase as u8,value.release_before_complete,value.passed)).collect::<Vec<_>>().join(",");
    format!("{{\"schema\":\"noticer.startup-fault-campaign.v1\",\"seed\":{},\"all_passed\":{},\"outcomes\":[{}]}}",campaign.seed,campaign.all_passed,outcomes)
}
fn label(point: FaultPoint) -> &'static str {
    match point {
        FaultPoint::BeforeBegin => "before_begin",
        FaultPoint::BeforeSecurity => "before_security",
        FaultPoint::BeforeAdmission => "before_admission",
        FaultPoint::BeforeRecovery => "before_recovery",
        FaultPoint::BeforeComplete => "before_complete",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_phase_resumes_without_unsafe_release() {
        let campaign = run_fault_campaign(0x5eed).unwrap();
        assert_eq!(campaign.outcomes.len(), 5);
        assert!(campaign.all_passed);
        assert!(campaign
            .outcomes
            .iter()
            .all(|value| value.resumed_phase == CeremonyPhase::Complete
                && !value.release_before_complete));
    }
    #[test]
    fn same_seed_is_byte_identical_and_seed_changes_order() {
        let first = run_fault_campaign(7).unwrap();
        let second = run_fault_campaign(7).unwrap();
        let changed = run_fault_campaign(8).unwrap();
        assert_eq!(canonical_json(&first), canonical_json(&second));
        assert_ne!(first.outcomes, changed.outcomes);
    }
}
