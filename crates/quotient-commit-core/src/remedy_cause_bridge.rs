//! Digest-bound bridge from a K16 cause proof to repairable public atoms.

use crate::remedy_atom::RepairAtom;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CauseRepairBinding {
    pub cause_certificate_digest: [u8; 32],
    pub model_digest: [u8; 32],
    pub atoms: Vec<RepairAtom>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CauseBridgeError {
    ZeroCertificateDigest,
    ZeroModelDigest,
    EmptyCause,
    ModelMismatch,
}

impl CauseRepairBinding {
    pub fn new(
        cause_certificate_digest: [u8; 32],
        model_digest: [u8; 32],
        mut atoms: Vec<RepairAtom>,
    ) -> Result<Self, CauseBridgeError> {
        if cause_certificate_digest == [0; 32] {
            return Err(CauseBridgeError::ZeroCertificateDigest);
        }
        if model_digest == [0; 32] {
            return Err(CauseBridgeError::ZeroModelDigest);
        }
        atoms.sort();
        atoms.dedup();
        if atoms.is_empty() {
            return Err(CauseBridgeError::EmptyCause);
        }
        Ok(Self {
            cause_certificate_digest,
            model_digest,
            atoms,
        })
    }

    pub fn verify_model(&self, expected: [u8; 32]) -> Result<(), CauseBridgeError> {
        if self.model_digest == expected {
            Ok(())
        } else {
            Err(CauseBridgeError::ModelMismatch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_is_canonical_and_model_bound() {
        let atom = RepairAtom::new(1, "gate").unwrap();
        let binding = CauseRepairBinding::new([1; 32], [2; 32], vec![atom.clone(), atom]).unwrap();
        assert_eq!(binding.atoms.len(), 1);
        assert_eq!(
            binding.verify_model([3; 32]),
            Err(CauseBridgeError::ModelMismatch)
        );
    }
}
