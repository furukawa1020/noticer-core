//! Domain-separated authentication for repair certificates.

use crate::remedy_certificate::RepairCertificate;

const DOMAIN: &[u8] = b"noticer.quotient-remedy.certificate-auth.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepairCertificateTag(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthError {
    ZeroKey,
    TagMismatch,
}

pub fn authenticate(
    certificate: RepairCertificate,
    key: [u8; 32],
) -> Result<RepairCertificateTag, AuthError> {
    if key == [0; 32] {
        return Err(AuthError::ZeroKey);
    }
    let mut bytes = Vec::with_capacity(DOMAIN.len() + 32 + 200);
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&key);
    bytes.extend_from_slice(&certificate.canonical_bytes());
    Ok(RepairCertificateTag(crate::sha256::sha256(&bytes)))
}

pub fn verify(
    certificate: RepairCertificate,
    key: [u8; 32],
    tag: RepairCertificateTag,
) -> Result<(), AuthError> {
    if authenticate(certificate, key)? == tag {
        Ok(())
    } else {
        Err(AuthError::TagMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remedy_certificate::{RepairCertificateBindings, RepairSearchEvidence};

    fn certificate() -> RepairCertificate {
        RepairCertificate::new(
            RepairCertificateBindings {
                cause_digest: [1; 32],
                patch_digest: [2; 32],
                objective_digest: [3; 32],
                constraint_digest: [4; 32],
                model_digest: [5; 32],
                verification_digest: [6; 32],
            },
            RepairSearchEvidence {
                explored_nodes: 7,
                explored_worlds: 8,
            },
        )
        .unwrap()
    }

    #[test]
    fn substitution_changes_the_tag() {
        let tag = authenticate(certificate(), [9; 32]).unwrap();
        let mut changed = certificate();
        changed.patch_digest = [8; 32];
        assert_eq!(verify(changed, [9; 32], tag), Err(AuthError::TagMismatch));
    }
}
