use crate::receipt::hmac_sha256;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ClockSource {
    Monotonic = 1,
    Network = 2,
    Hardware = 3,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimestampEnvelope {
    pub observed_at: u64,
    pub uncertainty: u64,
    pub source: ClockSource,
    pub evidence_digest: [u8; 32],
    pub authenticator: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimestampError {
    EmptyEvidence,
    UncertaintyExceeded,
    Authentication,
}
pub fn issue(
    observed_at: u64,
    uncertainty: u64,
    source: ClockSource,
    evidence_digest: [u8; 32],
    key: [u8; 32],
) -> Result<TimestampEnvelope, TimestampError> {
    if evidence_digest == [0; 32] {
        return Err(TimestampError::EmptyEvidence);
    }
    let mut v = TimestampEnvelope {
        observed_at,
        uncertainty,
        source,
        evidence_digest,
        authenticator: [0; 32],
    };
    v.authenticator = auth(v, key);
    Ok(v)
}
pub fn verify(
    v: TimestampEnvelope,
    max_uncertainty: u64,
    key: [u8; 32],
) -> Result<(), TimestampError> {
    if v.uncertainty > max_uncertainty {
        return Err(TimestampError::UncertaintyExceeded);
    }
    if v.authenticator != auth(v, key) {
        return Err(TimestampError::Authentication);
    }
    Ok(())
}
fn auth(mut v: TimestampEnvelope, key: [u8; 32]) -> [u8; 32] {
    v.authenticator = [0; 32];
    let mut b = Vec::new();
    b.extend_from_slice(b"noticer.timestamp-envelope.v1");
    b.extend_from_slice(&v.observed_at.to_be_bytes());
    b.extend_from_slice(&v.uncertainty.to_be_bytes());
    b.push(v.source as u8);
    b.extend_from_slice(&v.evidence_digest);
    hmac_sha256(key, &b)
}
#[cfg(test)]
mod tests {
    use super::*;
    const K: [u8; 32] = [3; 32];
    #[test]
    fn verifies_timestamp() {
        let v = issue(100, 5, ClockSource::Hardware, [1; 32], K).unwrap();
        assert_eq!(verify(v, 5, K), Ok(()))
    }
    #[test]
    fn rejects_tamper() {
        let mut v = issue(100, 5, ClockSource::Hardware, [1; 32], K).unwrap();
        v.source = ClockSource::Network;
        assert_eq!(verify(v, 5, K), Err(TimestampError::Authentication));
    }
}
