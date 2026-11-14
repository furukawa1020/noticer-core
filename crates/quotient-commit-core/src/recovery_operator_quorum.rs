//! Role-separated operator quorum for recovery authorization.
use crate::receipt::hmac_sha256;
use std::collections::BTreeSet;
const DOMAIN: &[u8] = b"noticer.recovery-operator-approval.v1\0";
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum OperatorRole {
    Security = 1,
    Privacy = 2,
    Operations = 3,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperatorKey {
    pub id: [u8; 16],
    pub role: OperatorRole,
    pub key: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperatorApproval {
    pub id: [u8; 16],
    pub role: OperatorRole,
    pub candidate: [u8; 32],
    pub expires_at: u64,
    pub authenticator: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuorumError {
    InvalidKey,
    InvalidCandidate,
    Expired,
    UnknownOperator,
    RoleMismatch,
    DuplicateOperator,
    MissingRole,
    InsufficientQuorum,
    InvalidApproval,
}
pub fn approve(
    operator: OperatorKey,
    candidate: [u8; 32],
    expires_at: u64,
) -> Result<OperatorApproval, QuorumError> {
    if operator.id == [0; 16] || operator.key == [0; 32] {
        return Err(QuorumError::InvalidKey);
    }
    if candidate == [0; 32] {
        return Err(QuorumError::InvalidCandidate);
    }
    let mut a = OperatorApproval {
        id: operator.id,
        role: operator.role,
        candidate,
        expires_at,
        authenticator: [0; 32],
    };
    a.authenticator = auth(a, operator.key);
    Ok(a)
}
pub fn verify_quorum(
    approvals: &[OperatorApproval],
    operators: &[OperatorKey],
    candidate: [u8; 32],
    now: u64,
) -> Result<(), QuorumError> {
    if approvals.len() < 3 {
        return Err(QuorumError::InsufficientQuorum);
    }
    let mut ids = BTreeSet::new();
    let mut roles = BTreeSet::new();
    for a in approvals {
        if !ids.insert(a.id) {
            return Err(QuorumError::DuplicateOperator);
        }
        if a.candidate != candidate {
            return Err(QuorumError::InvalidCandidate);
        }
        if a.expires_at < now {
            return Err(QuorumError::Expired);
        }
        let op = operators
            .iter()
            .find(|o| o.id == a.id)
            .ok_or(QuorumError::UnknownOperator)?;
        if op.role != a.role {
            return Err(QuorumError::RoleMismatch);
        }
        if a.authenticator != auth(*a, op.key) {
            return Err(QuorumError::InvalidApproval);
        }
        roles.insert(a.role);
    }
    if ![
        OperatorRole::Security,
        OperatorRole::Privacy,
        OperatorRole::Operations,
    ]
    .iter()
    .all(|r| roles.contains(r))
    {
        return Err(QuorumError::MissingRole);
    }
    Ok(())
}
fn auth(mut a: OperatorApproval, key: [u8; 32]) -> [u8; 32] {
    a.authenticator = [0; 32];
    let mut b = Vec::new();
    b.extend_from_slice(DOMAIN);
    b.extend_from_slice(&a.id);
    b.push(a.role as u8);
    b.extend_from_slice(&a.candidate);
    b.extend_from_slice(&a.expires_at.to_be_bytes());
    hmac_sha256(key, &b)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn ops() -> Vec<OperatorKey> {
        vec![
            OperatorKey {
                id: [1; 16],
                role: OperatorRole::Security,
                key: [1; 32],
            },
            OperatorKey {
                id: [2; 16],
                role: OperatorRole::Privacy,
                key: [2; 32],
            },
            OperatorKey {
                id: [3; 16],
                role: OperatorRole::Operations,
                key: [3; 32],
            },
        ]
    }
    #[test]
    fn separated_roles_form_quorum() {
        let o = ops();
        let a = o
            .iter()
            .map(|x| approve(*x, [9; 32], 100).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(verify_quorum(&a, &o, [9; 32], 50), Ok(()))
    }
    #[test]
    fn duplicates_and_expiry_fail() {
        let o = ops();
        let a = approve(o[0], [9; 32], 10).unwrap();
        assert_eq!(
            verify_quorum(&[a, a, a], &o, [9; 32], 1),
            Err(QuorumError::DuplicateOperator)
        );
        let all = o
            .iter()
            .map(|x| approve(*x, [9; 32], 10).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            verify_quorum(&all, &o, [9; 32], 11),
            Err(QuorumError::Expired)
        );
    }
}
