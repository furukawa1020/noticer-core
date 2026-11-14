//! Authenticated release-candidate attestation over all recovery gates.
use crate::receipt::hmac_sha256;
const DOMAIN: &[u8] = b"noticer.recovery-release-attestation.v1\0";
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleaseCandidate {
    pub policy_epoch: u64,
    pub build_digest: [u8; 32],
    pub readiness_digest: [u8; 32],
    pub slo_digest: [u8; 32],
    pub transition_digest: [u8; 32],
    pub incident_clear_digest: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleaseAttestation {
    pub version: u8,
    pub candidate: ReleaseCandidate,
    pub authenticator: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttestationError {
    InvalidKey,
    InvalidEpoch,
    MissingEvidence,
    AuthenticationFailed,
}
pub fn attest(
    candidate: ReleaseCandidate,
    key: [u8; 32],
) -> Result<ReleaseAttestation, AttestationError> {
    validate(candidate, key)?;
    let mut v = ReleaseAttestation {
        version: 1,
        candidate,
        authenticator: [0; 32],
    };
    v.authenticator = authenticate(v, key);
    Ok(v)
}
pub fn verify(v: ReleaseAttestation, key: [u8; 32]) -> Result<(), AttestationError> {
    validate(v.candidate, key)?;
    if v.version != 1 || v.authenticator != authenticate(v, key) {
        Err(AttestationError::AuthenticationFailed)
    } else {
        Ok(())
    }
}
#[must_use]
pub fn canonical_json(v: ReleaseAttestation) -> String {
    format!("{{\"schema\":\"noticer.recovery-release-attestation.v1\",\"policy_epoch\":{},\"build\":\"{}\",\"readiness\":\"{}\",\"slo\":\"{}\",\"transition\":\"{}\",\"incident_clear\":\"{}\",\"authenticator\":\"{}\"}}",v.candidate.policy_epoch,hex(v.candidate.build_digest),hex(v.candidate.readiness_digest),hex(v.candidate.slo_digest),hex(v.candidate.transition_digest),hex(v.candidate.incident_clear_digest),hex(v.authenticator))
}
fn validate(c: ReleaseCandidate, key: [u8; 32]) -> Result<(), AttestationError> {
    if key == [0; 32] {
        return Err(AttestationError::InvalidKey);
    }
    if c.policy_epoch == 0 {
        return Err(AttestationError::InvalidEpoch);
    }
    if [
        c.build_digest,
        c.readiness_digest,
        c.slo_digest,
        c.transition_digest,
        c.incident_clear_digest,
    ]
    .contains(&[0; 32])
    {
        return Err(AttestationError::MissingEvidence);
    }
    Ok(())
}
fn authenticate(mut v: ReleaseAttestation, key: [u8; 32]) -> [u8; 32] {
    v.authenticator = [0; 32];
    let mut b = Vec::with_capacity(DOMAIN.len() + 169);
    b.extend_from_slice(DOMAIN);
    b.push(v.version);
    b.extend_from_slice(&v.candidate.policy_epoch.to_be_bytes());
    for d in [
        v.candidate.build_digest,
        v.candidate.readiness_digest,
        v.candidate.slo_digest,
        v.candidate.transition_digest,
        v.candidate.incident_clear_digest,
    ] {
        b.extend_from_slice(&d)
    }
    hmac_sha256(key, &b)
}
fn hex(v: [u8; 32]) -> String {
    v.iter().map(|b| format!("{b:02x}")).collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    const K: [u8; 32] = [6; 32];
    fn c() -> ReleaseCandidate {
        ReleaseCandidate {
            policy_epoch: 3,
            build_digest: [1; 32],
            readiness_digest: [2; 32],
            slo_digest: [3; 32],
            transition_digest: [4; 32],
            incident_clear_digest: [5; 32],
        }
    }
    #[test]
    fn complete_candidate_is_verifiable() {
        let a = attest(c(), K).unwrap();
        assert_eq!(verify(a, K), Ok(()));
        assert!(canonical_json(a).contains("release-attestation"))
    }
    #[test]
    fn missing_and_substituted_evidence_fail() {
        let mut x = c();
        x.slo_digest = [0; 32];
        assert_eq!(attest(x, K), Err(AttestationError::MissingEvidence));
        let mut a = attest(c(), K).unwrap();
        a.candidate.build_digest = [9; 32];
        assert_eq!(verify(a, K), Err(AttestationError::AuthenticationFailed));
    }
}
