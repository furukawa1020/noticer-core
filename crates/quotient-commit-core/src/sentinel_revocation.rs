//! Evidence-bound revocation of a deployed repair permit.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationReason {
    SafetyViolation,
    SemanticsDrift,
    LivenessViolation,
    PrivacyViolation,
    EvidenceExpired,
    MonitorFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepairRevocationCertificate {
    pub deployment_identity_digest: [u8; 32],
    pub evidence_digest: [u8; 32],
    pub sequence: u64,
    pub reason: RevocationReason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationError {
    ZeroBinding,
    ZeroSequence,
}

impl RepairRevocationCertificate {
    pub fn new(
        deployment_identity_digest: [u8; 32],
        evidence_digest: [u8; 32],
        sequence: u64,
        reason: RevocationReason,
    ) -> Result<Self, RevocationError> {
        if deployment_identity_digest == [0; 32] || evidence_digest == [0; 32] {
            return Err(RevocationError::ZeroBinding);
        }
        if sequence == 0 {
            return Err(RevocationError::ZeroSequence);
        }
        Ok(Self {
            deployment_identity_digest,
            evidence_digest,
            sequence,
            reason,
        })
    }

    #[must_use]
    pub fn digest(self) -> [u8; 32] {
        let mut bytes = b"noticer.quotient-sentinel.revocation.v1\0".to_vec();
        bytes.extend_from_slice(&self.deployment_identity_digest);
        bytes.extend_from_slice(&self.evidence_digest);
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.push(self.reason as u8);
        crate::sha256::sha256(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reason_is_committed() {
        let a = RepairRevocationCertificate::new(
            [1; 32],
            [2; 32],
            3,
            RevocationReason::SafetyViolation,
        )
        .unwrap();
        let b = RepairRevocationCertificate::new(
            [1; 32],
            [2; 32],
            3,
            RevocationReason::PrivacyViolation,
        )
        .unwrap();
        assert_ne!(a.digest(), b.digest());
    }
}
