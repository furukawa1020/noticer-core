//! Authenticated continuity proof between adjacent recovery epochs.

use crate::receipt::hmac_sha256;
const DOMAIN: &[u8] = b"noticer.recovery-epoch-transition.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EpochTransitionCertificate {
    pub version: u8,
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub old_audit_head: [u8; 32],
    pub new_checkpoint: [u8; 32],
    pub new_key_binding: [u8; 32],
    pub authenticator: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionError {
    InvalidKey,
    InvalidEpoch,
    NonAdjacentEpoch,
    MissingBinding,
    AuthenticationFailed,
}

pub fn certify(
    old_epoch: u64,
    new_epoch: u64,
    old_audit_head: [u8; 32],
    new_checkpoint: [u8; 32],
    new_key_binding: [u8; 32],
    key: [u8; 32],
) -> Result<EpochTransitionCertificate, TransitionError> {
    validate(
        old_epoch,
        new_epoch,
        old_audit_head,
        new_checkpoint,
        new_key_binding,
        key,
    )?;
    let mut value = EpochTransitionCertificate {
        version: 1,
        old_epoch,
        new_epoch,
        old_audit_head,
        new_checkpoint,
        new_key_binding,
        authenticator: [0; 32],
    };
    value.authenticator = authenticate(value, key);
    Ok(value)
}
pub fn verify(value: EpochTransitionCertificate, key: [u8; 32]) -> Result<(), TransitionError> {
    validate(
        value.old_epoch,
        value.new_epoch,
        value.old_audit_head,
        value.new_checkpoint,
        value.new_key_binding,
        key,
    )?;
    if value.version != 1 || value.authenticator != authenticate(value, key) {
        Err(TransitionError::AuthenticationFailed)
    } else {
        Ok(())
    }
}
#[must_use]
pub fn canonical_json(value: EpochTransitionCertificate) -> String {
    format!("{{\"schema\":\"noticer.recovery-epoch-transition.v1\",\"old_epoch\":{},\"new_epoch\":{},\"old_audit_head\":\"{}\",\"new_checkpoint\":\"{}\",\"new_key_binding\":\"{}\",\"authenticator\":\"{}\"}}", value.old_epoch, value.new_epoch, hex(value.old_audit_head), hex(value.new_checkpoint), hex(value.new_key_binding), hex(value.authenticator))
}
fn validate(
    old_epoch: u64,
    new_epoch: u64,
    audit: [u8; 32],
    checkpoint: [u8; 32],
    binding: [u8; 32],
    key: [u8; 32],
) -> Result<(), TransitionError> {
    if key == [0; 32] {
        return Err(TransitionError::InvalidKey);
    }
    if old_epoch == 0 || new_epoch == 0 {
        return Err(TransitionError::InvalidEpoch);
    }
    if old_epoch.checked_add(1) != Some(new_epoch) {
        return Err(TransitionError::NonAdjacentEpoch);
    }
    if audit == [0; 32] || checkpoint == [0; 32] || binding == [0; 32] {
        return Err(TransitionError::MissingBinding);
    }
    Ok(())
}
fn authenticate(mut value: EpochTransitionCertificate, key: [u8; 32]) -> [u8; 32] {
    value.authenticator = [0; 32];
    let mut bytes = Vec::with_capacity(DOMAIN.len() + 113);
    bytes.extend_from_slice(DOMAIN);
    bytes.push(value.version);
    bytes.extend_from_slice(&value.old_epoch.to_be_bytes());
    bytes.extend_from_slice(&value.new_epoch.to_be_bytes());
    bytes.extend_from_slice(&value.old_audit_head);
    bytes.extend_from_slice(&value.new_checkpoint);
    bytes.extend_from_slice(&value.new_key_binding);
    hmac_sha256(key, &bytes)
}
fn hex(value: [u8; 32]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    const KEY: [u8; 32] = [7; 32];
    #[test]
    fn adjacent_transition_is_deterministic_and_verifiable() {
        let first = certify(4, 5, [1; 32], [2; 32], [3; 32], KEY).unwrap();
        let second = certify(4, 5, [1; 32], [2; 32], [3; 32], KEY).unwrap();
        assert_eq!(first, second);
        assert_eq!(verify(first, KEY), Ok(()));
        assert!(canonical_json(first).contains("\"new_epoch\":5"));
    }
    #[test]
    fn skipped_epoch_and_substitution_fail() {
        assert_eq!(
            certify(4, 6, [1; 32], [2; 32], [3; 32], KEY),
            Err(TransitionError::NonAdjacentEpoch)
        );
        let mut value = certify(4, 5, [1; 32], [2; 32], [3; 32], KEY).unwrap();
        value.new_checkpoint = [9; 32];
        assert_eq!(
            verify(value, KEY),
            Err(TransitionError::AuthenticationFailed)
        );
    }
}
