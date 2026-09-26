#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;

pub const AQPC_MAGIC: [u8; 4] = *b"AQPC";
pub const AQPC_VERSION: u16 = 1;
pub const MAX_ORDERS: usize = 64;
const FLAG_UNBOUNDED: u16 = 1;
const FLAG_LAB_ONLY: u16 = 1 << 1;
const FLAG_DIRECTED_UPPER: u16 = 1 << 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Hash32([u8; 32]);

impl Hash32 {
    pub const fn new(bytes: [u8; 32]) -> Result<Self, ProfileError> {
        if all_zero(&bytes) {
            Err(ProfileError::ZeroHash)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileDerivation {
    ExactFinite { source_certificate_hash: Hash32 },
    Analytic { proof_contract_hash: Hash32 },
    EmpiricalLabOnly { experiment_hash: Hash32 },
}

impl ProfileDerivation {
    const fn source_hash(self) -> Hash32 {
        match self {
            Self::ExactFinite {
                source_certificate_hash,
            } => source_certificate_hash,
            Self::Analytic {
                proof_contract_hash,
            } => proof_contract_hash,
            Self::EmpiricalLabOnly { experiment_hash } => experiment_hash,
        }
    }

    const fn lab_only(self) -> bool {
        matches!(self, Self::EmpiricalLabOnly { .. })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConservativeMomentBound {
    pub alpha: u16,
    pub forward_q64_64_upper: u128,
    pub reverse_q64_64_upper: u128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionQuotientPrivacyProfile {
    pub mechanism_hash: Hash32,
    pub action_quotient_hash: Hash32,
    pub secret_family_hash: Hash32,
    pub observer_coalition_hash: Hash32,
    pub public_context_hash: Hash32,
    pub model_version: u64,
    pub validity_epoch: u64,
    pub moments: Vec<ConservativeMomentBound>,
    pub derivation: ProfileDerivation,
    pub checker_contract_hash: Hash32,
    pub support_complete: bool,
}

impl ActionQuotientPrivacyProfile {
    pub fn encode_aqpc(&self) -> Result<Vec<u8>, ProfileError> {
        validate_orders(&self.moments)?;
        let mut flags = FLAG_DIRECTED_UPPER;
        if !self.support_complete {
            flags |= FLAG_UNBOUNDED;
        }
        if self.derivation.lab_only() {
            flags |= FLAG_LAB_ONLY;
        }

        let mut output = Vec::with_capacity(250 + 34 * self.moments.len());
        output.extend_from_slice(&AQPC_MAGIC);
        output.extend_from_slice(&AQPC_VERSION.to_le_bytes());
        output.extend_from_slice(&flags.to_le_bytes());
        for hash in [
            self.mechanism_hash,
            self.action_quotient_hash,
            self.secret_family_hash,
            self.observer_coalition_hash,
            self.public_context_hash,
        ] {
            output.extend_from_slice(&hash.as_bytes());
        }
        output.extend_from_slice(&self.model_version.to_le_bytes());
        output.extend_from_slice(&self.validity_epoch.to_le_bytes());
        output.extend_from_slice(&self.derivation.source_hash().as_bytes());
        output.extend_from_slice(&self.checker_contract_hash.as_bytes());
        output.extend_from_slice(&(self.moments.len() as u16).to_le_bytes());
        for moment in &self.moments {
            output.extend_from_slice(&moment.alpha.to_le_bytes());
            output.extend_from_slice(&moment.forward_q64_64_upper.to_le_bytes());
            output.extend_from_slice(&moment.reverse_q64_64_upper.to_le_bytes());
        }
        Ok(output)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileError {
    ZeroHash,
    EmptyProfile,
    ResourceLimit,
    InvalidOrder,
    NonCanonicalOrder,
}

fn validate_orders(moments: &[ConservativeMomentBound]) -> Result<(), ProfileError> {
    if moments.is_empty() {
        return Err(ProfileError::EmptyProfile);
    }
    if moments.len() > MAX_ORDERS {
        return Err(ProfileError::ResourceLimit);
    }
    let mut previous = 1;
    for moment in moments {
        if moment.alpha <= 1 {
            return Err(ProfileError::InvalidOrder);
        }
        if moment.alpha <= previous {
            return Err(ProfileError::NonCanonicalOrder);
        }
        previous = moment.alpha;
    }
    Ok(())
}

const fn all_zero(bytes: &[u8; 32]) -> bool {
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn hash(value: u8) -> Hash32 {
        Hash32::new([value; 32]).unwrap()
    }

    fn profile() -> ActionQuotientPrivacyProfile {
        ActionQuotientPrivacyProfile {
            mechanism_hash: hash(1),
            action_quotient_hash: hash(2),
            secret_family_hash: hash(3),
            observer_coalition_hash: hash(4),
            public_context_hash: hash(5),
            model_version: 6,
            validity_epoch: 7,
            moments: vec![
                ConservativeMomentBound {
                    alpha: 2,
                    forward_q64_64_upper: 8,
                    reverse_q64_64_upper: 9,
                },
                ConservativeMomentBound {
                    alpha: 4,
                    forward_q64_64_upper: 10,
                    reverse_q64_64_upper: 11,
                },
            ],
            derivation: ProfileDerivation::ExactFinite {
                source_certificate_hash: hash(12),
            },
            checker_contract_hash: hash(13),
            support_complete: true,
        }
    }

    #[test]
    fn canonical_profile_has_fixed_layout() {
        let bytes = profile().encode_aqpc().unwrap();
        assert_eq!(&bytes[..4], b"AQPC");
        assert_eq!(bytes.len(), 250 + 34 * 2);
    }

    #[test]
    fn noncanonical_orders_are_rejected() {
        let mut profile = profile();
        profile.moments[1].alpha = 2;
        assert_eq!(profile.encode_aqpc(), Err(ProfileError::NonCanonicalOrder));
    }

    #[test]
    fn zero_hash_is_rejected() {
        assert_eq!(Hash32::new([0; 32]), Err(ProfileError::ZeroHash));
    }
}
