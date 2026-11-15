use crate::receipt::hmac_sha256;
const D: &[u8] = b"noticer.recovery-break-glass.v1\0";
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EmergencyScope {
    ReadEvidence = 1,
    RestoreCheckpoint = 2,
    FenceRegion = 3,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BreakGlassPermit {
    pub id: [u8; 16],
    pub scope: EmergencyScope,
    pub epoch: u64,
    pub expires_at: u64,
    pub maximum_operations: u16,
    pub used: u16,
    pub authenticator: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BreakGlassError {
    Invalid,
    Expired,
    Exhausted,
    AuthenticationFailed,
}
pub fn issue(
    id: [u8; 16],
    scope: EmergencyScope,
    epoch: u64,
    expires: u64,
    max: u16,
    key: [u8; 32],
) -> Result<BreakGlassPermit, BreakGlassError> {
    if id == [0; 16] || epoch == 0 || expires == 0 || max == 0 || key == [0; 32] {
        return Err(BreakGlassError::Invalid);
    }
    let mut p = BreakGlassPermit {
        id,
        scope,
        epoch,
        expires_at: expires,
        maximum_operations: max,
        used: 0,
        authenticator: [0; 32],
    };
    p.authenticator = auth(&p, key);
    Ok(p)
}
impl BreakGlassPermit {
    pub fn consume(&mut self, now: u64, key: [u8; 32]) -> Result<u16, BreakGlassError> {
        if self.authenticator != auth(self, key) {
            return Err(BreakGlassError::AuthenticationFailed);
        }
        if now > self.expires_at {
            return Err(BreakGlassError::Expired);
        }
        if self.used >= self.maximum_operations {
            return Err(BreakGlassError::Exhausted);
        }
        self.used += 1;
        Ok(self.used)
    }
}
fn auth(p: &BreakGlassPermit, k: [u8; 32]) -> [u8; 32] {
    let mut b = Vec::from(D);
    b.extend_from_slice(&p.id);
    b.push(p.scope as u8);
    b.extend_from_slice(&p.epoch.to_be_bytes());
    b.extend_from_slice(&p.expires_at.to_be_bytes());
    b.extend_from_slice(&p.maximum_operations.to_be_bytes());
    hmac_sha256(k, &b)
}
#[cfg(test)]
mod tests {
    use super::*;
    const K: [u8; 32] = [2; 32];
    #[test]
    fn operation_count_is_bounded() {
        let mut p = issue([1; 16], EmergencyScope::FenceRegion, 2, 100, 2, K).unwrap();
        assert_eq!(p.consume(50, K), Ok(1));
        assert_eq!(p.consume(50, K), Ok(2));
        assert_eq!(p.consume(50, K), Err(BreakGlassError::Exhausted))
    }
    #[test]
    fn expiry_and_tamper_fail() {
        let mut p = issue([1; 16], EmergencyScope::ReadEvidence, 2, 10, 1, K).unwrap();
        assert_eq!(p.consume(11, K), Err(BreakGlassError::Expired));
        p.epoch = 3;
        assert_eq!(p.consume(1, K), Err(BreakGlassError::AuthenticationFailed));
    }
}
