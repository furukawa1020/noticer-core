//! Minimal public artifact for a proof-carrying repair decision.

use crate::remedy_redaction::PublicRepairExplanation;
use crate::remedy_verdict::RepairVerdict;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicRepairCapsule {
    pub verdict: RepairVerdict,
    pub patch_label: String,
    pub reason_code: String,
    pub certificate_digest: [u8; 32],
    pub model_digest: [u8; 32],
    pub verification_summary: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapsuleError {
    ZeroDigest,
    EmptyVerificationSummary,
    DeployableWithoutAllChecks,
}

impl PublicRepairCapsule {
    pub fn new(
        verdict: RepairVerdict,
        explanation: PublicRepairExplanation,
        model_digest: [u8; 32],
        verification_summary: u16,
    ) -> Result<Self, CapsuleError> {
        if explanation.certificate_digest == [0; 32] || model_digest == [0; 32] {
            return Err(CapsuleError::ZeroDigest);
        }
        if verification_summary == 0 {
            return Err(CapsuleError::EmptyVerificationSummary);
        }
        const ALL_REQUIRED: u16 = 0b1_1111;
        if verdict.deployment_allowed() && verification_summary & ALL_REQUIRED != ALL_REQUIRED {
            return Err(CapsuleError::DeployableWithoutAllChecks);
        }
        Ok(Self {
            verdict,
            patch_label: explanation.patch_label,
            reason_code: explanation.reason_code,
            certificate_digest: explanation.certificate_digest,
            model_digest,
            verification_summary,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn explanation() -> PublicRepairExplanation {
        PublicRepairExplanation {
            patch_label: "delay_gate".into(),
            reason_code: "cause_blocked".into(),
            certificate_digest: [1; 32],
        }
    }

    #[test]
    fn repaired_capsule_requires_every_public_check() {
        assert_eq!(
            PublicRepairCapsule::new(RepairVerdict::Repaired, explanation(), [2; 32], 0b0_1111),
            Err(CapsuleError::DeployableWithoutAllChecks)
        );
        assert!(PublicRepairCapsule::new(
            RepairVerdict::Repaired,
            explanation(),
            [2; 32],
            0b1_1111
        )
        .is_ok());
    }
}
