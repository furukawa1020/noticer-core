//! Detects mutations across certificate, model, manifest, and authentication tag.

use crate::remedy_certificate::RepairCertificate;
use crate::remedy_certificate_auth::{verify, AuthError, RepairCertificateTag};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpectedRepairBindings {
    pub patch_digest: [u8; 32],
    pub model_digest: [u8; 32],
    pub manifest_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationError {
    PatchChanged,
    ModelChanged,
    ManifestChanged,
    Authentication(AuthError),
}

pub fn detect(
    certificate: RepairCertificate,
    observed_manifest_digest: [u8; 32],
    expected: ExpectedRepairBindings,
    key: [u8; 32],
    tag: RepairCertificateTag,
) -> Result<(), MutationError> {
    if certificate.patch_digest != expected.patch_digest {
        return Err(MutationError::PatchChanged);
    }
    if certificate.model_digest != expected.model_digest {
        return Err(MutationError::ModelChanged);
    }
    if observed_manifest_digest != expected.manifest_digest {
        return Err(MutationError::ManifestChanged);
    }
    verify(certificate, key, tag).map_err(MutationError::Authentication)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remedy_certificate::{RepairCertificateBindings, RepairSearchEvidence};
    use crate::remedy_certificate_auth::authenticate;

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
                explored_nodes: 1,
                explored_worlds: 1,
            },
        )
        .unwrap()
    }

    #[test]
    fn one_bit_patch_mutation_is_detected() {
        let original = certificate();
        let tag = authenticate(original, [9; 32]).unwrap();
        let mut changed = original;
        changed.patch_digest[0] ^= 1;
        assert_eq!(
            detect(
                changed,
                [7; 32],
                ExpectedRepairBindings {
                    patch_digest: [2; 32],
                    model_digest: [5; 32],
                    manifest_digest: [7; 32]
                },
                [9; 32],
                tag
            ),
            Err(MutationError::PatchChanged)
        );
    }
}
