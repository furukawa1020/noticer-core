#![no_std]
#![forbid(unsafe_code)]

//! Allocation-free ATv2 verification sequence shared by host and firmware.

use noticer_aetp::{ClaimBound, ServiceBinding};
use noticer_crypto::VerifierKeyMaterial;
use noticer_protocol::{
    parse_inner, AtypicalityTokenEnvelope, FrameKind, InnerBody, KeyId, TokenId, WireServiceAlias,
    INNER_BODY_SIZE, OUTER_HEADER_SIZE, SIGNATURE_SIZE,
};
use noticer_types::{ActionCode, PolicyHash};

pub trait KeySource {
    fn get(
        &self,
        alias: WireServiceAlias,
        key_id: KeyId,
        epoch: u32,
    ) -> Option<&VerifierKeyMaterial>;
}

pub trait PolicySource {
    fn permits(&self, body: &InnerBody) -> bool;
}

pub trait RevocationSource {
    fn key_is_revoked(&self, key_id: KeyId) -> bool;
    fn policy_is_revoked(&self, policy_hash: PolicyHash) -> bool;
}

pub trait ReplayGuard {
    fn accept_once(&self, epoch: u32, token_id: TokenId) -> bool;
}

#[derive(Clone, Copy, Debug)]
pub struct VerifierContext {
    pub expected_service: ServiceBinding,
    pub expected_epoch: u32,
    pub now_slot: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuthorizationSeal;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizedAction {
    pub action: ActionCode,
    pub token_id: TokenId,
    _seal: AuthorizationSeal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationResult {
    Cover,
    Authorized(AuthorizedAction),
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationError {
    Framing,
    UnknownKey,
    Binding,
    Nonce,
    Authentication,
    Signature,
    Body,
    Freshness,
    Revoked,
    ClaimOrPolicy,
    Replay,
}

pub fn verify(
    bytes: &[u8],
    context: VerifierContext,
    keys: &dyn KeySource,
    policies: &dyn PolicySource,
    revocations: &dyn RevocationSource,
    replay: &dyn ReplayGuard,
) -> Result<VerificationResult, VerificationError> {
    let envelope =
        AtypicalityTokenEnvelope::from_slice(bytes).map_err(|_| VerificationError::Framing)?;
    let outer = envelope.outer().map_err(|_| VerificationError::Framing)?;
    if outer.public_epoch != context.expected_epoch {
        return Err(VerificationError::Binding);
    }
    let material = keys
        .get(outer.service_alias, outer.key_id, outer.public_epoch)
        .ok_or(VerificationError::UnknownKey)?;
    if material.service() != context.expected_service || material.epoch() != context.expected_epoch
    {
        return Err(VerificationError::Binding);
    }
    if material.expected_nonce(outer.public_bucket, outer.sequence) != outer.nonce {
        return Err(VerificationError::Nonce);
    }

    let outer_bytes = outer.encode();
    let plaintext = material
        .open(&outer.nonce, &outer_bytes, envelope.ciphertext())
        .map_err(|_| VerificationError::Authentication)?;
    let inner_bytes: [u8; INNER_BODY_SIZE] = plaintext[..INNER_BODY_SIZE]
        .try_into()
        .map_err(|_| VerificationError::Framing)?;
    let signature: [u8; SIGNATURE_SIZE] = plaintext[INNER_BODY_SIZE..]
        .try_into()
        .map_err(|_| VerificationError::Framing)?;
    let mut signed_message = [0_u8; OUTER_HEADER_SIZE + INNER_BODY_SIZE];
    signed_message[..OUTER_HEADER_SIZE].copy_from_slice(&outer_bytes);
    signed_message[OUTER_HEADER_SIZE..].copy_from_slice(&inner_bytes);
    material
        .verify(&signed_message, &signature)
        .map_err(|_| VerificationError::Signature)?;
    let body = parse_inner(&inner_bytes, outer.kind).map_err(|_| VerificationError::Body)?;

    if revocations.key_is_revoked(outer.key_id) {
        return Err(VerificationError::Revoked);
    }
    if outer.kind == FrameKind::Cover {
        return Ok(VerificationResult::Cover);
    }
    if context.now_slot < body.valid_from || context.now_slot > body.valid_until {
        return Err(VerificationError::Freshness);
    }
    if revocations.policy_is_revoked(body.policy_hash) {
        return Err(VerificationError::Revoked);
    }
    if !policies.permits(&body) {
        return Err(VerificationError::ClaimOrPolicy);
    }
    if !replay.accept_once(outer.public_epoch, body.token_id) {
        return Err(VerificationError::Replay);
    }
    Ok(VerificationResult::Authorized(AuthorizedAction {
        action: body.action,
        token_id: body.token_id,
        _seal: AuthorizationSeal,
    }))
}

#[derive(Clone, Copy)]
pub struct FixedPolicyEntry {
    pub policy_hash: PolicyHash,
    pub action: ActionCode,
    pub maximum_claim: ClaimBound,
    pub semantics_tag: [u8; 16],
}

pub struct FixedPolicySource<'a> {
    pub entries: &'a [FixedPolicyEntry],
}

impl PolicySource for FixedPolicySource<'_> {
    fn permits(&self, body: &InnerBody) -> bool {
        self.entries.iter().any(|entry| {
            entry.policy_hash == body.policy_hash
                && entry.action == body.action
                && entry.maximum_claim.permits(body.claim_bound)
                && entry.semantics_tag == body.semantics_tag
        })
    }
}
