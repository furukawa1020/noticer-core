//! Authenticated, resumable ordering for the startup recovery ceremony.

use crate::receipt::hmac_sha256;
use crate::recovery_witness::RecoveryWitnessBatch;
use crate::startup_admission_gate::StartupAdmissionPermit;
use crate::startup_security_gate::StartupAuthorization;

const DOMAIN: &[u8] = b"noticer.quotient-commit.recovery-ceremony.v1\0";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CeremonyPhase {
    Initialized = 1,
    SecurityAuthorized = 2,
    AdmissionAuthorized = 3,
    RecoveryWitnessed = 4,
    Complete = 5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CeremonyCheckpoint {
    pub ceremony_id: [u8; 32],
    pub phase: CeremonyPhase,
    pub certificate_authenticator: [u8; 32],
    pub anchor_authenticator: [u8; 32],
    pub admission_authenticator: [u8; 32],
    pub witness_authenticator: [u8; 32],
    pub authenticator: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CeremonyAbort {
    InvalidKey,
    InvalidCeremonyId,
    AuthenticationFailed,
    PhaseOrder {
        required: CeremonyPhase,
        actual: CeremonyPhase,
    },
    ComponentSubstitution,
}

#[derive(Debug)]
pub struct RecoveryCeremony {
    checkpoint: CeremonyCheckpoint,
    key: [u8; 32],
}

impl RecoveryCeremony {
    pub fn begin(ceremony_id: [u8; 32], key: [u8; 32]) -> Result<Self, CeremonyAbort> {
        if key == [0; 32] {
            return Err(CeremonyAbort::InvalidKey);
        }
        if ceremony_id == [0; 32] {
            return Err(CeremonyAbort::InvalidCeremonyId);
        }
        let mut checkpoint = CeremonyCheckpoint {
            ceremony_id,
            phase: CeremonyPhase::Initialized,
            certificate_authenticator: [0; 32],
            anchor_authenticator: [0; 32],
            admission_authenticator: [0; 32],
            witness_authenticator: [0; 32],
            authenticator: [0; 32],
        };
        checkpoint.authenticator = authenticate(checkpoint, key);
        Ok(Self { checkpoint, key })
    }

    pub fn resume(checkpoint: CeremonyCheckpoint, key: [u8; 32]) -> Result<Self, CeremonyAbort> {
        if key == [0; 32] {
            return Err(CeremonyAbort::InvalidKey);
        }
        if checkpoint.ceremony_id == [0; 32] {
            return Err(CeremonyAbort::InvalidCeremonyId);
        }
        if checkpoint.authenticator != authenticate(checkpoint, key) {
            return Err(CeremonyAbort::AuthenticationFailed);
        }
        Ok(Self { checkpoint, key })
    }

    pub fn record_security(
        &mut self,
        authorization: StartupAuthorization,
    ) -> Result<CeremonyCheckpoint, CeremonyAbort> {
        let supplied = (
            authorization.certificate_authenticator,
            authorization.anchor_authenticator,
        );
        if self.checkpoint.phase > CeremonyPhase::Initialized {
            let recorded = (
                self.checkpoint.certificate_authenticator,
                self.checkpoint.anchor_authenticator,
            );
            return self.idempotent(supplied == recorded);
        }
        self.require(CeremonyPhase::Initialized)?;
        if authorization.authenticator == [0; 32] || supplied.0 == [0; 32] || supplied.1 == [0; 32]
        {
            return Err(CeremonyAbort::ComponentSubstitution);
        }
        self.checkpoint.certificate_authenticator = supplied.0;
        self.checkpoint.anchor_authenticator = supplied.1;
        self.advance(CeremonyPhase::SecurityAuthorized)
    }

    pub fn record_admission(
        &mut self,
        permit: StartupAdmissionPermit,
    ) -> Result<CeremonyCheckpoint, CeremonyAbort> {
        if self.checkpoint.phase > CeremonyPhase::SecurityAuthorized {
            return self
                .idempotent(self.checkpoint.admission_authenticator == permit.authenticator);
        }
        self.require(CeremonyPhase::SecurityAuthorized)?;
        if permit.authenticator == [0; 32] {
            return Err(CeremonyAbort::ComponentSubstitution);
        }
        self.checkpoint.admission_authenticator = permit.authenticator;
        self.advance(CeremonyPhase::AdmissionAuthorized)
    }

    pub fn record_recovery(
        &mut self,
        batch: RecoveryWitnessBatch,
    ) -> Result<CeremonyCheckpoint, CeremonyAbort> {
        if self.checkpoint.phase > CeremonyPhase::AdmissionAuthorized {
            return self.idempotent(self.checkpoint.witness_authenticator == batch.authenticator);
        }
        self.require(CeremonyPhase::AdmissionAuthorized)?;
        if batch.authenticator == [0; 32] {
            return Err(CeremonyAbort::ComponentSubstitution);
        }
        self.checkpoint.witness_authenticator = batch.authenticator;
        self.advance(CeremonyPhase::RecoveryWitnessed)
    }

    pub fn complete(&mut self) -> Result<CeremonyCheckpoint, CeremonyAbort> {
        if self.checkpoint.phase == CeremonyPhase::Complete {
            return Ok(self.checkpoint);
        }
        self.require(CeremonyPhase::RecoveryWitnessed)?;
        self.advance(CeremonyPhase::Complete)
    }

    #[must_use]
    pub const fn checkpoint(&self) -> CeremonyCheckpoint {
        self.checkpoint
    }

    fn require(&self, required: CeremonyPhase) -> Result<(), CeremonyAbort> {
        if self.checkpoint.phase != required {
            return Err(CeremonyAbort::PhaseOrder {
                required,
                actual: self.checkpoint.phase,
            });
        }
        Ok(())
    }

    fn idempotent(&self, matches: bool) -> Result<CeremonyCheckpoint, CeremonyAbort> {
        if matches {
            Ok(self.checkpoint)
        } else {
            Err(CeremonyAbort::ComponentSubstitution)
        }
    }

    fn advance(&mut self, phase: CeremonyPhase) -> Result<CeremonyCheckpoint, CeremonyAbort> {
        self.checkpoint.phase = phase;
        self.checkpoint.authenticator = authenticate(self.checkpoint, self.key);
        Ok(self.checkpoint)
    }
}

fn authenticate(mut checkpoint: CeremonyCheckpoint, key: [u8; 32]) -> [u8; 32] {
    checkpoint.authenticator = [0; 32];
    let mut bytes = Vec::with_capacity(DOMAIN.len() + 161);
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&checkpoint.ceremony_id);
    bytes.push(checkpoint.phase as u8);
    bytes.extend_from_slice(&checkpoint.certificate_authenticator);
    bytes.extend_from_slice(&checkpoint.anchor_authenticator);
    bytes.extend_from_slice(&checkpoint.admission_authenticator);
    bytes.extend_from_slice(&checkpoint.witness_authenticator);
    hmac_sha256(key, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    const KEY: [u8; 32] = [7; 32];

    fn security() -> StartupAuthorization {
        StartupAuthorization {
            anchor_generation: 1,
            certificate_authenticator: [2; 32],
            anchor_authenticator: [3; 32],
            authenticator: [4; 32],
        }
    }
    fn admission() -> StartupAdmissionPermit {
        StartupAdmissionPermit {
            policy_epoch: 1,
            weighted_backlog: 0,
            snapshot_authenticator: [5; 32],
            authenticator: [6; 32],
        }
    }
    fn recovery() -> RecoveryWitnessBatch {
        RecoveryWitnessBatch {
            entry_count: 1,
            succeeded: 1,
            failed_closed: 0,
            head_authenticator: [7; 32],
            authenticator: [8; 32],
        }
    }

    #[test]
    fn phase_skip_is_rejected_and_full_ceremony_completes() {
        let mut ceremony = RecoveryCeremony::begin([1; 32], KEY).unwrap();
        assert!(matches!(
            ceremony.record_admission(admission()),
            Err(CeremonyAbort::PhaseOrder { .. })
        ));
        ceremony.record_security(security()).unwrap();
        ceremony.record_admission(admission()).unwrap();
        ceremony.record_recovery(recovery()).unwrap();
        assert_eq!(ceremony.complete().unwrap().phase, CeremonyPhase::Complete);
    }

    #[test]
    fn crash_resume_and_repeated_component_are_idempotent() {
        let mut first = RecoveryCeremony::begin([1; 32], KEY).unwrap();
        let saved = first.record_security(security()).unwrap();
        let mut resumed = RecoveryCeremony::resume(saved, KEY).unwrap();
        assert_eq!(resumed.record_security(security()), Ok(saved));
        resumed.record_admission(admission()).unwrap();
        let saved = resumed.record_recovery(recovery()).unwrap();
        let mut resumed = RecoveryCeremony::resume(saved, KEY).unwrap();
        assert_eq!(resumed.record_recovery(recovery()), Ok(saved));
        assert_eq!(resumed.complete().unwrap().phase, CeremonyPhase::Complete);
    }

    #[test]
    fn component_substitution_and_checkpoint_tampering_fail_closed() {
        let mut ceremony = RecoveryCeremony::begin([1; 32], KEY).unwrap();
        let saved = ceremony.record_security(security()).unwrap();
        let mut changed = security();
        changed.anchor_authenticator = [9; 32];
        assert_eq!(
            ceremony.record_security(changed),
            Err(CeremonyAbort::ComponentSubstitution)
        );
        let mut tampered = saved;
        tampered.phase = CeremonyPhase::Complete;
        assert!(matches!(
            RecoveryCeremony::resume(tampered, KEY),
            Err(CeremonyAbort::AuthenticationFailed)
        ));
    }
}
