#![no_std]
#![forbid(unsafe_code)]

//! Canonical, fixed-width Atypicality Token v2 wire format.

use core::fmt;
use noticer_aetp::{AudienceLevel, ClaimBound, ImpactLevel, SemanticLevel};
use noticer_types::{ActionCode, PolicyHash};

pub const MAGIC: [u8; 4] = *b"NAT2";
pub const VERSION: u8 = 2;
pub const OUTER_HEADER_SIZE: usize = 60;
pub const INNER_BODY_SIZE: usize = 96;
pub const SIGNATURE_SIZE: usize = 64;
pub const SIGNED_PLAINTEXT_SIZE: usize = INNER_BODY_SIZE + SIGNATURE_SIZE;
pub const CIPHERTEXT_SIZE: usize = SIGNED_PLAINTEXT_SIZE + 16;
pub const ENVELOPE_SIZE: usize = OUTER_HEADER_SIZE + CIPHERTEXT_SIZE;
const _: [(); 236] = [(); ENVELOPE_SIZE];

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KeyId(pub [u8; 8]);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WireServiceAlias(pub [u8; 8]);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TokenId(pub [u8; 16]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameKind {
    Cover = 0,
    Action = 1,
}

impl FrameKind {
    fn parse(value: u8) -> Result<Self, ProtocolError> {
        match value {
            0 => Ok(Self::Cover),
            1 => Ok(Self::Action),
            _ => Err(ProtocolError::InvalidFrameKind),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OuterHeader {
    pub kind: FrameKind,
    pub service_alias: WireServiceAlias,
    pub key_id: KeyId,
    pub public_epoch: u32,
    pub public_bucket: u32,
    pub sequence: u32,
    pub nonce: [u8; 24],
}

impl OuterHeader {
    pub fn encode(self) -> [u8; OUTER_HEADER_SIZE] {
        let mut out = [0_u8; OUTER_HEADER_SIZE];
        out[..4].copy_from_slice(&MAGIC);
        out[4] = VERSION;
        out[5] = self.kind as u8;
        out[8..16].copy_from_slice(&self.service_alias.0);
        out[16..24].copy_from_slice(&self.key_id.0);
        out[24..28].copy_from_slice(&self.public_epoch.to_le_bytes());
        out[28..32].copy_from_slice(&self.public_bucket.to_le_bytes());
        out[32..36].copy_from_slice(&self.sequence.to_le_bytes());
        out[36..60].copy_from_slice(&self.nonce);
        out
    }
}

pub fn parse_outer(bytes: &[u8]) -> Result<OuterHeader, ProtocolError> {
    if bytes.len() != OUTER_HEADER_SIZE {
        return Err(ProtocolError::WrongLength);
    }
    if bytes[..4] != MAGIC || bytes[4] != VERSION {
        return Err(ProtocolError::InvalidFraming);
    }
    if bytes[6] != 0 || bytes[7] != 0 {
        return Err(ProtocolError::NonCanonicalEncoding);
    }
    Ok(OuterHeader {
        kind: FrameKind::parse(bytes[5])?,
        service_alias: WireServiceAlias(copy_array(&bytes[8..16])),
        key_id: KeyId(copy_array(&bytes[16..24])),
        public_epoch: u32::from_le_bytes(copy_array(&bytes[24..28])),
        public_bucket: u32::from_le_bytes(copy_array(&bytes[28..32])),
        sequence: u32::from_le_bytes(copy_array(&bytes[32..36])),
        nonce: copy_array(&bytes[36..60]),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InnerBody {
    pub token_id: TokenId,
    pub action: ActionCode,
    pub claim_bound: ClaimBound,
    pub valid_from: u32,
    pub valid_until: u32,
    pub max_uses: u16,
    pub policy_hash: PolicyHash,
    pub semantics_tag: [u8; 16],
}

impl InnerBody {
    pub const fn cover(token_id: TokenId) -> Self {
        Self {
            token_id,
            action: ActionCode::NoAction,
            claim_bound: ClaimBound::NONE,
            valid_from: 0,
            valid_until: 0,
            max_uses: 0,
            policy_hash: PolicyHash([0; 32]),
            semantics_tag: [0; 16],
        }
    }

    pub fn encode(self) -> [u8; INNER_BODY_SIZE] {
        let mut out = [0_u8; INNER_BODY_SIZE];
        out[..16].copy_from_slice(&self.token_id.0);
        out[16..18].copy_from_slice(&(self.action as u16).to_le_bytes());
        out[18] = self.claim_bound.semantic as u8;
        out[19] = self.claim_bound.audience as u8;
        out[20] = self.claim_bound.impact as u8;
        out[24..28].copy_from_slice(&self.valid_from.to_le_bytes());
        out[28..32].copy_from_slice(&self.valid_until.to_le_bytes());
        out[32..34].copy_from_slice(&self.max_uses.to_le_bytes());
        out[36..68].copy_from_slice(&self.policy_hash.0);
        out[68..84].copy_from_slice(&self.semantics_tag);
        out
    }
}

pub fn parse_inner(bytes: &[u8], kind: FrameKind) -> Result<InnerBody, ProtocolError> {
    if bytes.len() != INNER_BODY_SIZE {
        return Err(ProtocolError::WrongLength);
    }
    if bytes[21..24].iter().any(|value| *value != 0)
        || bytes[34..36].iter().any(|value| *value != 0)
        || bytes[84..96].iter().any(|value| *value != 0)
    {
        return Err(ProtocolError::NonCanonicalEncoding);
    }
    let action_raw = u16::from_le_bytes(copy_array(&bytes[16..18]));
    let action = ActionCode::from_u16(action_raw).ok_or(ProtocolError::InvalidAction)?;
    let body = InnerBody {
        token_id: TokenId(copy_array(&bytes[..16])),
        action,
        claim_bound: ClaimBound {
            semantic: SemanticLevel::from_u8(bytes[18]).ok_or(ProtocolError::InvalidClaim)?,
            audience: AudienceLevel::from_u8(bytes[19]).ok_or(ProtocolError::InvalidClaim)?,
            impact: ImpactLevel::from_u8(bytes[20]).ok_or(ProtocolError::InvalidClaim)?,
        },
        valid_from: u32::from_le_bytes(copy_array(&bytes[24..28])),
        valid_until: u32::from_le_bytes(copy_array(&bytes[28..32])),
        max_uses: u16::from_le_bytes(copy_array(&bytes[32..34])),
        policy_hash: PolicyHash(copy_array(&bytes[36..68])),
        semantics_tag: copy_array(&bytes[68..84]),
    };
    match kind {
        FrameKind::Cover if body != InnerBody::cover(body.token_id) => {
            Err(ProtocolError::InvalidCoverBody)
        }
        FrameKind::Action
            if body.action == ActionCode::NoAction
                || body.max_uses != 1
                || body.valid_until < body.valid_from =>
        {
            Err(ProtocolError::InvalidActionBody)
        }
        _ => Ok(body),
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AtypicalityTokenEnvelope(pub [u8; ENVELOPE_SIZE]);

impl fmt::Debug for AtypicalityTokenEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AtypicalityTokenEnvelope(<236 bytes>)")
    }
}

impl AtypicalityTokenEnvelope {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != ENVELOPE_SIZE {
            return Err(ProtocolError::WrongLength);
        }
        Ok(Self(copy_array(bytes)))
    }

    pub const fn as_bytes(&self) -> &[u8; ENVELOPE_SIZE] {
        &self.0
    }

    pub fn outer(&self) -> Result<OuterHeader, ProtocolError> {
        parse_outer(&self.0[..OUTER_HEADER_SIZE])
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.0[OUTER_HEADER_SIZE..]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    WrongLength,
    InvalidFraming,
    InvalidFrameKind,
    NonCanonicalEncoding,
    InvalidAction,
    InvalidClaim,
    InvalidCoverBody,
    InvalidActionBody,
}

fn copy_array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut out = [0_u8; N];
    out.copy_from_slice(bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn envelope_is_ble_att_compatible_and_fixed() {
        assert_eq!(ENVELOPE_SIZE, 236);
        assert!(ENVELOPE_SIZE <= 244);
    }

    proptest! {
        #[test]
        fn arbitrary_outer_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
            let _ = parse_outer(&bytes);
        }

        #[test]
        fn arbitrary_inner_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..150)) {
            let _ = parse_inner(&bytes, FrameKind::Action);
        }
    }
}
