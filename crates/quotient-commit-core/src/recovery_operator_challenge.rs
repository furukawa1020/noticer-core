use crate::receipt::hmac_sha256;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperatorChallenge {
    pub session: [u8; 16],
    pub nonce: [u8; 16],
    pub action_digest: [u8; 32],
    pub epoch: u64,
    pub expires_at: u64,
    pub authenticator: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChallengeResponse {
    pub challenge_authenticator: [u8; 32],
    pub proof: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChallengeError {
    Expired,
    ChallengeInvalid,
    ResponseInvalid,
}
pub fn issue(
    session: [u8; 16],
    nonce: [u8; 16],
    action_digest: [u8; 32],
    epoch: u64,
    expires_at: u64,
    key: [u8; 32],
) -> OperatorChallenge {
    let mut v = OperatorChallenge {
        session,
        nonce,
        action_digest,
        epoch,
        expires_at,
        authenticator: [0; 32],
    };
    v.authenticator = auth(v, key);
    v
}
pub fn respond(v: OperatorChallenge, operator_key: [u8; 32]) -> ChallengeResponse {
    ChallengeResponse {
        challenge_authenticator: v.authenticator,
        proof: hmac_sha256(operator_key, &v.authenticator),
    }
}
pub fn verify(
    v: OperatorChallenge,
    r: ChallengeResponse,
    now: u64,
    issuer_key: [u8; 32],
    operator_key: [u8; 32],
) -> Result<(), ChallengeError> {
    if now > v.expires_at {
        return Err(ChallengeError::Expired);
    }
    if v.authenticator != auth(v, issuer_key) {
        return Err(ChallengeError::ChallengeInvalid);
    }
    if r.challenge_authenticator != v.authenticator
        || r.proof != hmac_sha256(operator_key, &v.authenticator)
    {
        return Err(ChallengeError::ResponseInvalid);
    }
    Ok(())
}
fn auth(mut v: OperatorChallenge, key: [u8; 32]) -> [u8; 32] {
    v.authenticator = [0; 32];
    let mut b = Vec::new();
    b.extend_from_slice(b"noticer.operator-challenge.v1");
    b.extend_from_slice(&v.session);
    b.extend_from_slice(&v.nonce);
    b.extend_from_slice(&v.action_digest);
    b.extend_from_slice(&v.epoch.to_be_bytes());
    b.extend_from_slice(&v.expires_at.to_be_bytes());
    hmac_sha256(key, &b)
}
#[cfg(test)]
mod tests {
    use super::*;
    const I: [u8; 32] = [1; 32];
    const O: [u8; 32] = [2; 32];
    #[test]
    fn verifies_response() {
        let c = issue([1; 16], [2; 16], [3; 32], 4, 100, I);
        assert_eq!(verify(c, respond(c, O), 90, I, O), Ok(()))
    }
    #[test]
    fn rejects_action_tamper() {
        let mut c = issue([1; 16], [2; 16], [3; 32], 4, 100, I);
        let r = respond(c, O);
        c.action_digest = [9; 32];
        assert_eq!(
            verify(c, r, 90, I, O),
            Err(ChallengeError::ChallengeInvalid)
        );
    }
}
