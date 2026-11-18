//! Verdict promotion gate for the minimal counterexample oracle.

use crate::oracle_verdict::OracleVerdict;

/// Errors returned when a candidate verdict cannot be certified as verified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PromotionError {
    InvalidCannotVerify,
    InconclusiveCannotVerify,
    EvidenceIncomplete,
}

/// Allows only an already verified candidate with complete evidence to pass.
///
/// In particular, this API deliberately provides no conversion from an
/// `Invalid` or `Inconclusive` verdict into `Verified`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromotionGate {
    candidate: OracleVerdict,
}

impl PromotionGate {
    pub fn new(candidate: OracleVerdict) -> Self {
        Self { candidate }
    }

    pub fn confirm(self, evidence_complete: bool) -> Result<OracleVerdict, PromotionError> {
        match self.candidate {
            OracleVerdict::Invalid(_) => Err(PromotionError::InvalidCannotVerify),
            OracleVerdict::Inconclusive(_) => Err(PromotionError::InconclusiveCannotVerify),
            OracleVerdict::Verified { .. } if !evidence_complete => {
                Err(PromotionError::EvidenceIncomplete)
            }
            verified @ OracleVerdict::Verified { .. } => Ok(verified),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oracle_verdict::{InconclusiveReason, InvalidReason};

    #[test]
    fn invalid_never_promotes_to_verified() {
        let result =
            PromotionGate::new(OracleVerdict::Invalid(InvalidReason::Counterexample)).confirm(true);
        assert_eq!(result, Err(PromotionError::InvalidCannotVerify));
    }

    #[test]
    fn inconclusive_never_promotes_to_verified() {
        let result = PromotionGate::new(OracleVerdict::Inconclusive(InconclusiveReason::NodeLimit))
            .confirm(true);
        assert_eq!(result, Err(PromotionError::InconclusiveCannotVerify));
    }

    #[test]
    fn verified_requires_complete_evidence() {
        let candidate = OracleVerdict::Verified { explored: 7 };
        assert_eq!(
            PromotionGate::new(candidate).confirm(false),
            Err(PromotionError::EvidenceIncomplete)
        );
        assert_eq!(PromotionGate::new(candidate).confirm(true), Ok(candidate));
    }
}
