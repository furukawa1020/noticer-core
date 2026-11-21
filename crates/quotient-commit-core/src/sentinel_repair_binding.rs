//! Cryptographic binding from a K17 repair certificate to its runtime monitors.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepairAssuranceBinding {
    pub repair_certificate_digest: [u8; 32],
    pub deployment_identity_digest: [u8; 32],
    pub invariant_spec_digest: [u8; 32],
    pub monitor_configuration_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairAssuranceBindingError {
    ZeroBinding,
    DigestMismatch,
}

impl RepairAssuranceBinding {
    pub fn new(
        repair_certificate_digest: [u8; 32],
        deployment_identity_digest: [u8; 32],
        invariant_spec_digest: [u8; 32],
        monitor_configuration_digest: [u8; 32],
    ) -> Result<Self, RepairAssuranceBindingError> {
        if [
            repair_certificate_digest,
            deployment_identity_digest,
            invariant_spec_digest,
            monitor_configuration_digest,
        ]
        .contains(&[0; 32])
        {
            return Err(RepairAssuranceBindingError::ZeroBinding);
        }
        Ok(Self {
            repair_certificate_digest,
            deployment_identity_digest,
            invariant_spec_digest,
            monitor_configuration_digest,
        })
    }

    #[must_use]
    pub fn digest(self) -> [u8; 32] {
        let mut bytes = b"noticer.quotient-sentinel.repair-binding.v1\0".to_vec();
        for digest in [
            self.repair_certificate_digest,
            self.deployment_identity_digest,
            self.invariant_spec_digest,
            self.monitor_configuration_digest,
        ] {
            bytes.extend_from_slice(&digest);
        }
        crate::sha256::sha256(&bytes)
    }

    pub fn verify(self, expected: [u8; 32]) -> Result<(), RepairAssuranceBindingError> {
        if self.digest() == expected {
            Ok(())
        } else {
            Err(RepairAssuranceBindingError::DigestMismatch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monitor_substitution_changes_binding() {
        let a = RepairAssuranceBinding::new([1; 32], [2; 32], [3; 32], [4; 32]).unwrap();
        let b = RepairAssuranceBinding::new([1; 32], [2; 32], [3; 32], [5; 32]).unwrap();
        assert_ne!(a.digest(), b.digest());
    }
}
