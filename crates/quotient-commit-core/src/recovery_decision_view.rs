use crate::{
    receipt::hmac_sha256,
    recovery_decision_capsule::{DecisionCapsule, RecoveryDecision},
};
pub const FIELD_DECISION: u8 = 1;
pub const FIELD_EPOCH: u8 = 2;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecisionView {
    pub decision: Option<RecoveryDecision>,
    pub epoch: Option<u64>,
    pub commitment: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ViewError {
    EmptySelection,
    UnknownField,
}
pub fn project(c: DecisionCapsule, fields: u8, key: [u8; 32]) -> Result<DecisionView, ViewError> {
    if fields == 0 {
        return Err(ViewError::EmptySelection);
    }
    if fields & !(FIELD_DECISION | FIELD_EPOCH) != 0 {
        return Err(ViewError::UnknownField);
    }
    let decision = (fields & FIELD_DECISION != 0).then_some(c.decision);
    let epoch = (fields & FIELD_EPOCH != 0).then_some(c.epoch);
    let mut b = Vec::new();
    b.extend_from_slice(b"noticer.decision-view.v1");
    b.push(fields);
    if let Some(v) = decision {
        b.push(v as u8)
    }
    if let Some(v) = epoch {
        b.extend_from_slice(&v.to_be_bytes())
    }
    Ok(DecisionView {
        decision,
        epoch,
        commitment: hmac_sha256(key, &b),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{recovery_authority_lattice::RecoveryCapability, recovery_decision_capsule::issue};
    const K: [u8; 32] = [1; 32];
    fn c() -> DecisionCapsule {
        issue(
            RecoveryCapability::Release,
            [1; 32],
            [2; 32],
            [3; 32],
            7,
            RecoveryDecision::Release,
            K,
        )
    }
    #[test]
    fn projects_allowlist() {
        let v = project(c(), FIELD_DECISION, K).unwrap();
        assert_eq!(v.decision, Some(RecoveryDecision::Release));
        assert_eq!(v.epoch, None)
    }
    #[test]
    fn rejects_unknown() {
        assert_eq!(project(c(), 4, K), Err(ViewError::UnknownField))
    }
}
