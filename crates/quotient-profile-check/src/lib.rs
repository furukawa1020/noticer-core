#![forbid(unsafe_code)]

pub const HEADER_BYTES: usize = 250;
pub const RECORD_BYTES: usize = 34;
pub const MAX_ORDERS: usize = 64;
const FLAG_UNBOUNDED: u16 = 1;
const FLAG_LAB_ONLY: u16 = 1 << 1;
const FLAG_DIRECTED_UPPER: u16 = 1 << 2;
const KNOWN_FLAGS: u16 = FLAG_UNBOUNDED | FLAG_LAB_ONLY | FLAG_DIRECTED_UPPER;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckVerdict {
    ValidProfile,
    InvalidProfile,
    IncompatibleProfile,
    UnboundedProfile,
    ResourceLimit,
}

impl CheckVerdict {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ValidProfile => "VALID_PROFILE",
            Self::InvalidProfile => "INVALID_PROFILE",
            Self::IncompatibleProfile => "INCOMPATIBLE_PROFILE",
            Self::UnboundedProfile => "UNBOUNDED_PROFILE",
            Self::ResourceLimit => "RESOURCE_LIMIT",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckerMode {
    Production,
    Lab,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpectedBindings {
    pub mechanism_hash: [u8; 32],
    pub action_quotient_hash: [u8; 32],
    pub secret_family_hash: [u8; 32],
    pub observer_coalition_hash: [u8; 32],
    pub public_context_hash: [u8; 32],
    pub model_version: u64,
    pub validity_epoch: u64,
}

pub fn check_aqpc(
    bytes: &[u8],
    mode: CheckerMode,
    expected: Option<ExpectedBindings>,
) -> CheckVerdict {
    if bytes.len() < HEADER_BYTES {
        return CheckVerdict::InvalidProfile;
    }
    if &bytes[..4] != b"AQPC" || read_u16(bytes, 4) != Some(1) {
        return CheckVerdict::InvalidProfile;
    }
    let Some(flags) = read_u16(bytes, 6) else {
        return CheckVerdict::InvalidProfile;
    };
    if flags & !KNOWN_FLAGS != 0 || flags & FLAG_DIRECTED_UPPER == 0 {
        return CheckVerdict::InvalidProfile;
    }
    if flags & FLAG_UNBOUNDED != 0 {
        return CheckVerdict::UnboundedProfile;
    }
    if mode == CheckerMode::Production && flags & FLAG_LAB_ONLY != 0 {
        return CheckVerdict::InvalidProfile;
    }

    let hashes = [
        slice_hash(bytes, 8),
        slice_hash(bytes, 40),
        slice_hash(bytes, 72),
        slice_hash(bytes, 104),
        slice_hash(bytes, 136),
        slice_hash(bytes, 184),
        slice_hash(bytes, 216),
    ];
    if hashes.iter().any(|hash| hash.is_none_or(all_zero)) {
        return CheckVerdict::InvalidProfile;
    }

    let Some(count) = read_u16(bytes, 248).map(usize::from) else {
        return CheckVerdict::InvalidProfile;
    };
    if count == 0 {
        return CheckVerdict::InvalidProfile;
    }
    if count > MAX_ORDERS {
        return CheckVerdict::ResourceLimit;
    }
    let Some(expected_len) = HEADER_BYTES.checked_add(RECORD_BYTES.saturating_mul(count)) else {
        return CheckVerdict::ResourceLimit;
    };
    if bytes.len() != expected_len {
        return CheckVerdict::InvalidProfile;
    }

    let mut previous_alpha = 1;
    for index in 0..count {
        let offset = HEADER_BYTES + index * RECORD_BYTES;
        let Some(alpha) = read_u16(bytes, offset) else {
            return CheckVerdict::InvalidProfile;
        };
        if alpha <= 1 || alpha <= previous_alpha {
            return CheckVerdict::InvalidProfile;
        }
        previous_alpha = alpha;
    }

    if let Some(expected) = expected {
        let actual = ExpectedBindings {
            mechanism_hash: hashes[0].unwrap(),
            action_quotient_hash: hashes[1].unwrap(),
            secret_family_hash: hashes[2].unwrap(),
            observer_coalition_hash: hashes[3].unwrap(),
            public_context_hash: hashes[4].unwrap(),
            model_version: read_u64(bytes, 168).unwrap(),
            validity_epoch: read_u64(bytes, 176).unwrap(),
        };
        if actual != expected {
            return CheckVerdict::IncompatibleProfile;
        }
    }
    CheckVerdict::ValidProfile
}

fn slice_hash(bytes: &[u8], offset: usize) -> Option<[u8; 32]> {
    bytes.get(offset..offset + 32)?.try_into().ok()
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn all_zero(hash: [u8; 32]) -> bool {
    hash == [0; 32]
}

#[cfg(test)]
mod tests {
    use super::*;
    use quotient_profile_certificate::{
        ActionQuotientPrivacyProfile, ConservativeMomentBound, Hash32, ProfileDerivation,
    };

    fn hash(value: u8) -> Hash32 {
        Hash32::new([value; 32]).unwrap()
    }

    fn encoded(support_complete: bool, lab: bool) -> Vec<u8> {
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
            derivation: if lab {
                ProfileDerivation::EmpiricalLabOnly {
                    experiment_hash: hash(12),
                }
            } else {
                ProfileDerivation::ExactFinite {
                    source_certificate_hash: hash(12),
                }
            },
            checker_contract_hash: hash(13),
            support_complete,
        }
        .encode_aqpc()
        .unwrap()
    }

    fn bindings() -> ExpectedBindings {
        ExpectedBindings {
            mechanism_hash: [1; 32],
            action_quotient_hash: [2; 32],
            secret_family_hash: [3; 32],
            observer_coalition_hash: [4; 32],
            public_context_hash: [5; 32],
            model_version: 6,
            validity_epoch: 7,
        }
    }

    #[test]
    fn independently_accepts_canonical_profile() {
        assert_eq!(
            check_aqpc(
                &encoded(true, false),
                CheckerMode::Production,
                Some(bindings())
            ),
            CheckVerdict::ValidProfile
        );
    }

    #[test]
    fn binding_mismatch_is_incompatible() {
        let mut expected = bindings();
        expected.model_version = 99;
        assert_eq!(
            check_aqpc(
                &encoded(true, false),
                CheckerMode::Production,
                Some(expected)
            ),
            CheckVerdict::IncompatibleProfile
        );
    }

    #[test]
    fn support_mismatch_is_unbounded() {
        assert_eq!(
            check_aqpc(&encoded(false, false), CheckerMode::Production, None),
            CheckVerdict::UnboundedProfile
        );
    }

    #[test]
    fn empirical_profile_is_lab_only() {
        let bytes = encoded(true, true);
        assert_eq!(
            check_aqpc(&bytes, CheckerMode::Production, None),
            CheckVerdict::InvalidProfile
        );
        assert_eq!(
            check_aqpc(&bytes, CheckerMode::Lab, None),
            CheckVerdict::ValidProfile
        );
    }

    #[test]
    fn truncation_unknown_flags_and_mutation_are_invalid() {
        let bytes = encoded(true, false);
        assert_eq!(
            check_aqpc(&bytes[..bytes.len() - 1], CheckerMode::Production, None),
            CheckVerdict::InvalidProfile
        );
        let mut flags = bytes.clone();
        flags[7] |= 0x80;
        assert_eq!(
            check_aqpc(&flags, CheckerMode::Production, None),
            CheckVerdict::InvalidProfile
        );
        let mut order = bytes;
        order[250..252].copy_from_slice(&1_u16.to_le_bytes());
        assert_eq!(
            check_aqpc(&order, CheckerMode::Production, None),
            CheckVerdict::InvalidProfile
        );
    }

    #[test]
    fn excessive_order_count_is_resource_limit() {
        let mut bytes = encoded(true, false);
        bytes[248..250].copy_from_slice(&65_u16.to_le_bytes());
        assert_eq!(
            check_aqpc(&bytes, CheckerMode::Production, None),
            CheckVerdict::ResourceLimit
        );
    }
}
