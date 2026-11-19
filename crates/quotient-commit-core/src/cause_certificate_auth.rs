//! Authentication envelope for causality soundness certificates.

use crate::{cause_certificate::CausalityCertificate, receipt::hmac_sha256};

const DOMAIN: &[u8] = b"noticer.quotient-cause.authenticated-certificate.v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedCertificate {
    pub certificate: CausalityCertificate,
    authenticator: [u8; 32],
}

impl AuthenticatedCertificate {
    pub fn issue(key: [u8; 32], certificate: CausalityCertificate) -> Self {
        let authenticator = authenticate(key, &certificate);
        Self {
            certificate,
            authenticator,
        }
    }

    pub fn verify(&self, key: [u8; 32]) -> bool {
        self.authenticator == authenticate(key, &self.certificate)
    }

    pub fn authenticator(&self) -> [u8; 32] {
        self.authenticator
    }
}

fn authenticate(key: [u8; 32], certificate: &CausalityCertificate) -> [u8; 32] {
    let canonical = certificate.canonical_bytes();
    let mut bytes = Vec::with_capacity(DOMAIN.len() + canonical.len());
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&canonical);
    hmac_sha256(key, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cause_verdict::CausalityVerdict;

    fn certificate() -> CausalityCertificate {
        CausalityCertificate::create(
            [1; 32],
            [2; 32],
            [3; 32],
            1,
            7,
            [[4; 32], [4; 32]],
            CausalityVerdict::Causal {
                cause_size: 1,
                contingency_size: 0,
            },
        )
        .unwrap()
    }

    #[test]
    fn issued_certificate_verifies() {
        assert!(AuthenticatedCertificate::issue([8; 32], certificate()).verify([8; 32]));
    }

    #[test]
    fn changed_verdict_is_rejected() {
        let mut envelope = AuthenticatedCertificate::issue([8; 32], certificate());
        envelope.certificate.verdict = CausalityVerdict::NonCausal {
            examined_interventions: 7,
        };
        assert!(!envelope.verify([8; 32]));
    }

    #[test]
    fn changed_witness_digest_is_rejected() {
        let mut envelope = AuthenticatedCertificate::issue([8; 32], certificate());
        envelope.certificate.witness_digest[0] ^= 1;
        assert!(!envelope.verify([8; 32]));
    }
}
