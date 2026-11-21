//! Irreversible runtime quarantine for violated or unavailable assurance.

use crate::sentinel_verdict::AssuranceVerdict;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuarantineState {
    Active,
    Quarantined { evidence_digest: [u8; 32] },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuarantineError {
    ZeroEvidence,
    AlreadyQuarantined,
    AssuranceUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeQuarantineController {
    state: QuarantineState,
}

impl RuntimeQuarantineController {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: QuarantineState::Active,
        }
    }

    pub fn observe(
        &mut self,
        verdict: AssuranceVerdict,
        evidence_digest: [u8; 32],
    ) -> Result<(), QuarantineError> {
        if matches!(self.state, QuarantineState::Quarantined { .. }) {
            return Err(QuarantineError::AlreadyQuarantined);
        }
        if verdict.permit_remains_valid() {
            return Ok(());
        }
        if evidence_digest == [0; 32] {
            return Err(QuarantineError::ZeroEvidence);
        }
        self.state = QuarantineState::Quarantined { evidence_digest };
        Err(QuarantineError::AssuranceUnavailable)
    }

    #[must_use]
    pub const fn release_allowed(self) -> bool {
        matches!(self.state, QuarantineState::Active)
    }
}

impl Default for RuntimeQuarantineController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inconclusive_assurance_quarantines_release() {
        let mut controller = RuntimeQuarantineController::new();
        assert_eq!(
            controller.observe(
                AssuranceVerdict::Inconclusive(
                    crate::sentinel_verdict::AssuranceInconclusive::EvidenceGap
                ),
                [1; 32]
            ),
            Err(QuarantineError::AssuranceUnavailable)
        );
        assert!(!controller.release_allowed());
        assert_eq!(
            controller.observe(AssuranceVerdict::Healthy, [1; 32]),
            Err(QuarantineError::AlreadyQuarantined)
        );
    }
}
