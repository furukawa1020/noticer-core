//! Size-bounded incident evidence containing no free text or private identifiers.
use crate::receipt::hmac_sha256;
const DOMAIN: &[u8] = b"noticer.recovery-incident-capsule.v1\0";
const MAX_EVENTS: usize = 32;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum IncidentReason {
    ProofRejected = 1,
    ReplayDetected = 2,
    LeaseFenced = 3,
    PrivacyBreach = 4,
    SloBreach = 5,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IncidentEvent {
    pub reason: IncidentReason,
    pub public_digest: [u8; 32],
    pub time_bucket: u32,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncidentCapsule {
    pub version: u8,
    pub policy_epoch: u64,
    pub events: Vec<IncidentEvent>,
    pub authenticator: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapsuleError {
    InvalidKey,
    InvalidEpoch,
    Empty,
    TooManyEvents,
    InvalidEvent,
    AuthenticationFailed,
}
pub fn seal(
    policy_epoch: u64,
    events: Vec<IncidentEvent>,
    key: [u8; 32],
) -> Result<IncidentCapsule, CapsuleError> {
    validate(policy_epoch, &events, key)?;
    let mut v = IncidentCapsule {
        version: 1,
        policy_epoch,
        events,
        authenticator: [0; 32],
    };
    v.authenticator = authenticate(&v, key);
    Ok(v)
}
pub fn verify(v: &IncidentCapsule, key: [u8; 32]) -> Result<(), CapsuleError> {
    validate(v.policy_epoch, &v.events, key)?;
    if v.version != 1 || v.authenticator != authenticate(v, key) {
        Err(CapsuleError::AuthenticationFailed)
    } else {
        Ok(())
    }
}
#[must_use]
pub fn canonical_json(v: &IncidentCapsule) -> String {
    let events = v
        .events
        .iter()
        .map(|e| {
            format!(
                "{{\"reason\":{},\"digest\":\"{}\",\"time_bucket\":{}}}",
                e.reason as u8,
                hex(e.public_digest),
                e.time_bucket
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("{{\"schema\":\"noticer.recovery-incident.v1\",\"policy_epoch\":{},\"events\":[{}],\"authenticator\":\"{}\"}}",v.policy_epoch,events,hex(v.authenticator))
}
fn validate(epoch: u64, events: &[IncidentEvent], key: [u8; 32]) -> Result<(), CapsuleError> {
    if key == [0; 32] {
        return Err(CapsuleError::InvalidKey);
    }
    if epoch == 0 {
        return Err(CapsuleError::InvalidEpoch);
    }
    if events.is_empty() {
        return Err(CapsuleError::Empty);
    }
    if events.len() > MAX_EVENTS {
        return Err(CapsuleError::TooManyEvents);
    }
    if events.iter().any(|e| e.public_digest == [0; 32]) {
        return Err(CapsuleError::InvalidEvent);
    }
    Ok(())
}
fn authenticate(v: &IncidentCapsule, key: [u8; 32]) -> [u8; 32] {
    let mut b = Vec::with_capacity(DOMAIN.len() + 17 + v.events.len() * 37);
    b.extend_from_slice(DOMAIN);
    b.push(v.version);
    b.extend_from_slice(&v.policy_epoch.to_be_bytes());
    b.extend_from_slice(&(v.events.len() as u64).to_be_bytes());
    for e in &v.events {
        b.push(e.reason as u8);
        b.extend_from_slice(&e.public_digest);
        b.extend_from_slice(&e.time_bucket.to_be_bytes())
    }
    hmac_sha256(key, &b)
}
fn hex(v: [u8; 32]) -> String {
    v.iter().map(|b| format!("{b:02x}")).collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    const K: [u8; 32] = [5; 32];
    fn event() -> IncidentEvent {
        IncidentEvent {
            reason: IncidentReason::ReplayDetected,
            public_digest: [1; 32],
            time_bucket: 7,
        }
    }
    #[test]
    fn capsule_is_bounded_authenticated_and_private_safe() {
        let c = seal(2, vec![event()], K).unwrap();
        assert_eq!(verify(&c, K), Ok(()));
        let j = canonical_json(&c);
        for word in ["subject", "biosignal", "identity", "free_text"] {
            assert!(!j.contains(word))
        }
    }
    #[test]
    fn tampering_and_oversize_fail() {
        let mut c = seal(2, vec![event()], K).unwrap();
        c.events[0].time_bucket = 8;
        assert_eq!(verify(&c, K), Err(CapsuleError::AuthenticationFailed));
        assert_eq!(
            seal(2, vec![event(); 33], K),
            Err(CapsuleError::TooManyEvents)
        );
    }
}
