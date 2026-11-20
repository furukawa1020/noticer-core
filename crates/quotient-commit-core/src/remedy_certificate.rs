//! Proof-carrying binding for a selected counterfactual repair.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepairCertificate {
    pub cause_digest: [u8; 32],
    pub patch_digest: [u8; 32],
    pub objective_digest: [u8; 32],
    pub constraint_digest: [u8; 32],
    pub model_digest: [u8; 32],
    pub verification_digest: [u8; 32],
    pub explored_nodes: u32,
    pub explored_worlds: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepairCertificateBindings {
    pub cause_digest: [u8; 32],
    pub patch_digest: [u8; 32],
    pub objective_digest: [u8; 32],
    pub constraint_digest: [u8; 32],
    pub model_digest: [u8; 32],
    pub verification_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepairSearchEvidence {
    pub explored_nodes: u32,
    pub explored_worlds: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateError {
    ZeroBinding,
    NoExplorationEvidence,
}

impl RepairCertificate {
    pub fn new(
        bindings: RepairCertificateBindings,
        search: RepairSearchEvidence,
    ) -> Result<Self, CertificateError> {
        if [
            bindings.cause_digest,
            bindings.patch_digest,
            bindings.objective_digest,
            bindings.constraint_digest,
            bindings.model_digest,
            bindings.verification_digest,
        ]
        .contains(&[0; 32])
        {
            return Err(CertificateError::ZeroBinding);
        }
        if search.explored_nodes == 0 || search.explored_worlds == 0 {
            return Err(CertificateError::NoExplorationEvidence);
        }
        Ok(Self {
            cause_digest: bindings.cause_digest,
            patch_digest: bindings.patch_digest,
            objective_digest: bindings.objective_digest,
            constraint_digest: bindings.constraint_digest,
            model_digest: bindings.model_digest,
            verification_digest: bindings.verification_digest,
            explored_nodes: search.explored_nodes,
            explored_worlds: search.explored_worlds,
        })
    }

    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 * 6 + 8);
        for digest in [
            self.cause_digest,
            self.patch_digest,
            self.objective_digest,
            self.constraint_digest,
            self.model_digest,
            self.verification_digest,
        ] {
            bytes.extend_from_slice(&digest);
        }
        bytes.extend_from_slice(&self.explored_nodes.to_be_bytes());
        bytes.extend_from_slice(&self.explored_worlds.to_be_bytes());
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bindings() -> RepairCertificateBindings {
        RepairCertificateBindings {
            cause_digest: [1; 32],
            patch_digest: [2; 32],
            objective_digest: [3; 32],
            constraint_digest: [4; 32],
            model_digest: [5; 32],
            verification_digest: [6; 32],
        }
    }

    #[test]
    fn every_security_binding_is_required() {
        let mut invalid = bindings();
        invalid.cause_digest = [0; 32];
        assert_eq!(
            RepairCertificate::new(
                invalid,
                RepairSearchEvidence {
                    explored_nodes: 1,
                    explored_worlds: 1
                },
            ),
            Err(CertificateError::ZeroBinding)
        );
    }

    #[test]
    fn canonical_encoding_is_fixed_width() {
        let certificate = RepairCertificate::new(
            bindings(),
            RepairSearchEvidence {
                explored_nodes: 7,
                explored_worlds: 8,
            },
        )
        .unwrap();
        assert_eq!(certificate.canonical_bytes().len(), 200);
    }
}
