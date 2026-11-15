use crate::receipt::hmac_sha256;
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OperatorRole {
    Observer = 1,
    Restorer = 2,
    Commander = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperatorSession {
    pub operator: [u8; 16],
    pub role: OperatorRole,
    pub device_digest: [u8; 32],
    pub nonce: [u8; 16],
    pub epoch: u64,
    pub expires_at: u64,
    pub authenticator: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionError {
    AuthenticationFailed,
    RoleMismatch,
    DeviceMismatch,
    EpochMismatch,
    Expired,
    Replay,
}

pub fn issue(
    operator: [u8; 16],
    role: OperatorRole,
    device_digest: [u8; 32],
    nonce: [u8; 16],
    epoch: u64,
    expires_at: u64,
    key: [u8; 32],
) -> OperatorSession {
    let mut session = OperatorSession {
        operator,
        role,
        device_digest,
        nonce,
        epoch,
        expires_at,
        authenticator: [0; 32],
    };
    session.authenticator = authenticate(session, key);
    session
}

pub struct SessionAcceptor {
    seen: BTreeSet<[u8; 16]>,
}

impl SessionAcceptor {
    pub fn new() -> Self {
        Self {
            seen: BTreeSet::new(),
        }
    }
    pub fn accept(
        &mut self,
        session: OperatorSession,
        role: OperatorRole,
        device: [u8; 32],
        epoch: u64,
        now: u64,
        key: [u8; 32],
    ) -> Result<(), SessionError> {
        if session.authenticator != authenticate(session, key) {
            return Err(SessionError::AuthenticationFailed);
        }
        if session.role != role {
            return Err(SessionError::RoleMismatch);
        }
        if session.device_digest != device {
            return Err(SessionError::DeviceMismatch);
        }
        if session.epoch != epoch {
            return Err(SessionError::EpochMismatch);
        }
        if now > session.expires_at {
            return Err(SessionError::Expired);
        }
        if !self.seen.insert(session.nonce) {
            return Err(SessionError::Replay);
        }
        Ok(())
    }
}

impl Default for SessionAcceptor {
    fn default() -> Self {
        Self::new()
    }
}

fn authenticate(mut session: OperatorSession, key: [u8; 32]) -> [u8; 32] {
    session.authenticator = [0; 32];
    let mut bytes = Vec::with_capacity(104);
    bytes.extend_from_slice(b"noticer.operator-session.v1");
    bytes.extend_from_slice(&session.operator);
    bytes.push(session.role as u8);
    bytes.extend_from_slice(&session.device_digest);
    bytes.extend_from_slice(&session.nonce);
    bytes.extend_from_slice(&session.epoch.to_be_bytes());
    bytes.extend_from_slice(&session.expires_at.to_be_bytes());
    hmac_sha256(key, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    const KEY: [u8; 32] = [3; 32];
    #[test]
    fn binds_session_and_rejects_replay() {
        let session = issue(
            [1; 16],
            OperatorRole::Restorer,
            [2; 32],
            [3; 16],
            4,
            100,
            KEY,
        );
        let mut acceptor = SessionAcceptor::new();
        assert_eq!(
            acceptor.accept(session, OperatorRole::Restorer, [2; 32], 4, 90, KEY),
            Ok(())
        );
        assert_eq!(
            acceptor.accept(session, OperatorRole::Restorer, [2; 32], 4, 90, KEY),
            Err(SessionError::Replay)
        );
    }
    #[test]
    fn rejects_wrong_device_and_expiry() {
        let session = issue(
            [1; 16],
            OperatorRole::Commander,
            [2; 32],
            [3; 16],
            4,
            100,
            KEY,
        );
        assert_eq!(
            SessionAcceptor::new().accept(session, OperatorRole::Commander, [9; 32], 4, 90, KEY),
            Err(SessionError::DeviceMismatch)
        );
        assert_eq!(
            SessionAcceptor::new().accept(session, OperatorRole::Commander, [2; 32], 4, 101, KEY),
            Err(SessionError::Expired)
        );
    }
}
