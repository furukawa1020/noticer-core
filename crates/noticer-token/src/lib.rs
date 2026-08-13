#![forbid(unsafe_code)]

//! Fixed-size, signed, encrypted ATv2 frame issuance.
//!
//! The issuer accepts only low-side public frame identities and admitted action
//! obligations. Biosignal histories and `EvidencePermit` are not dependencies.
//!
//! Schedule randomness cannot be substituted for cryptographic root material:
//!
//! ```compile_fail
//! use noticer_aetp::{ScheduleRandomTape, ServiceBinding};
//! use noticer_token::TokenIssuer;
//!
//! let schedule = ScheduleRandomTape([7; 32]);
//! let _ = TokenIssuer::new(schedule, 1, &[ServiceBinding([1; 16])]);
//! ```
//!
//! An evidence permit cannot bypass the admission and planning boundary:
//!
//! ```compile_fail
//! use noticer_evidence::{EvidencePermit, GuaranteeMarker};
//! use noticer_token::TokenIssuer;
//!
//! fn bypass<G: GuaranteeMarker>(issuer: &TokenIssuer, permit: EvidencePermit<G>) {
//!     let _ = issuer.issue_action_frame(permit);
//! }
//! ```

use noticer_aetp::{ActionObligation, ClaimBound, ServiceBinding};
use noticer_crypto::{
    derive_issuer_keys, CryptoError, CryptographicRootSecret, IssuerKeyMaterial,
    VerifierKeyMaterial,
};
use noticer_protocol::{
    AtypicalityTokenEnvelope, FrameKind, InnerBody, OuterHeader, CIPHERTEXT_SIZE, ENVELOPE_SIZE,
    INNER_BODY_SIZE, OUTER_HEADER_SIZE, SIGNATURE_SIZE, SIGNED_PLAINTEXT_SIZE,
};
use noticer_trace_shaper::{FrameIssueError, FrameIssuer, PublicFrameIdentity};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Mutex,
};
use thiserror::Error;

type NonceIdentity = (ServiceBinding, u32, u32, [u8; 24]);

pub struct TokenIssuer {
    epoch: u32,
    keys: BTreeMap<ServiceBinding, IssuerKeyMaterial>,
    used_nonces: Mutex<BTreeSet<NonceIdentity>>,
}

impl TokenIssuer {
    pub fn new(
        root: CryptographicRootSecret,
        epoch: u32,
        services: &[ServiceBinding],
    ) -> Result<Self, TokenIssueError> {
        let mut keys = BTreeMap::new();
        for service in services {
            if keys
                .insert(*service, derive_issuer_keys(&root, *service, epoch)?)
                .is_some()
            {
                return Err(TokenIssueError::InvalidPublicInput);
            }
        }
        if keys.is_empty() {
            return Err(TokenIssueError::InvalidPublicInput);
        }
        Ok(Self {
            epoch,
            keys,
            used_nonces: Mutex::new(BTreeSet::new()),
        })
    }

    pub fn verifier_material(&self, service: ServiceBinding) -> Option<VerifierKeyMaterial> {
        self.keys
            .get(&service)
            .map(IssuerKeyMaterial::verifier_material)
    }

    pub fn issue_cover_frame(
        &self,
        identity: PublicFrameIdentity,
    ) -> Result<AtypicalityTokenEnvelope, TokenIssueError> {
        self.issue(identity, None)
    }

    pub fn issue_action_frame(
        &self,
        identity: PublicFrameIdentity,
        obligation: &ActionObligation,
        claim_bound: ClaimBound,
    ) -> Result<AtypicalityTokenEnvelope, TokenIssueError> {
        if identity.service != obligation.service
            || identity.public_bucket
                != u32::try_from(obligation.public_bucket.0)
                    .map_err(|_| TokenIssueError::InvalidPublicInput)?
            || identity.absolute_slot < obligation.release_window_start
            || identity.absolute_slot > obligation.release_deadline
        {
            return Err(TokenIssueError::InvalidPublicInput);
        }
        self.issue(identity, Some((obligation, claim_bound)))
    }

    fn issue(
        &self,
        identity: PublicFrameIdentity,
        action: Option<(&ActionObligation, ClaimBound)>,
    ) -> Result<AtypicalityTokenEnvelope, TokenIssueError> {
        if identity.public_epoch != self.epoch {
            return Err(TokenIssueError::InvalidPublicInput);
        }
        let keys = self
            .keys
            .get(&identity.service)
            .ok_or(TokenIssueError::InvalidPublicInput)?;
        let nonce = keys.nonce(identity.public_bucket, identity.sequence);
        let nonce_identity = (
            identity.service,
            identity.public_epoch,
            identity.sequence,
            nonce,
        );
        let mut used = self
            .used_nonces
            .lock()
            .map_err(|_| TokenIssueError::StateFailure)?;
        if !used.insert(nonce_identity) {
            return Err(TokenIssueError::NonceReuse);
        }
        drop(used);

        let kind = if action.is_some() {
            FrameKind::Action
        } else {
            FrameKind::Cover
        };
        let outer = OuterHeader {
            kind,
            service_alias: keys.wire_alias(),
            key_id: keys.key_id(),
            public_epoch: identity.public_epoch,
            public_bucket: identity.public_bucket,
            sequence: identity.sequence,
            nonce,
        };
        let token_id = keys.token_id(identity.public_bucket, identity.sequence);
        let inner = match action {
            None => InnerBody::cover(token_id),
            Some((obligation, claim_bound)) => InnerBody {
                token_id,
                action: obligation.action,
                claim_bound,
                valid_from: u32::try_from(obligation.release_window_start.0)
                    .map_err(|_| TokenIssueError::InvalidPublicInput)?,
                valid_until: u32::try_from(obligation.release_deadline.0)
                    .map_err(|_| TokenIssueError::InvalidPublicInput)?,
                max_uses: obligation.max_uses,
                policy_hash: obligation.policy_hash,
                semantics_tag: semantics_tag(obligation, claim_bound),
            },
        };
        let outer_bytes = outer.encode();
        let inner_bytes = inner.encode();
        let mut signed_message = [0_u8; OUTER_HEADER_SIZE + INNER_BODY_SIZE];
        signed_message[..OUTER_HEADER_SIZE].copy_from_slice(&outer_bytes);
        signed_message[OUTER_HEADER_SIZE..].copy_from_slice(&inner_bytes);
        let signature = keys.sign(&signed_message);
        let mut plaintext = [0_u8; SIGNED_PLAINTEXT_SIZE];
        plaintext[..INNER_BODY_SIZE].copy_from_slice(&inner_bytes);
        plaintext[INNER_BODY_SIZE..INNER_BODY_SIZE + SIGNATURE_SIZE].copy_from_slice(&signature);
        let ciphertext = keys.seal(&nonce, &outer_bytes, &plaintext)?;
        let mut envelope = [0_u8; ENVELOPE_SIZE];
        envelope[..OUTER_HEADER_SIZE].copy_from_slice(&outer_bytes);
        envelope[OUTER_HEADER_SIZE..OUTER_HEADER_SIZE + CIPHERTEXT_SIZE]
            .copy_from_slice(&ciphertext);
        Ok(AtypicalityTokenEnvelope(envelope))
    }
}

impl FrameIssuer for TokenIssuer {
    fn frame_length(&self) -> usize {
        ENVELOPE_SIZE
    }

    fn issue_cover(&self, identity: PublicFrameIdentity) -> Result<Vec<u8>, FrameIssueError> {
        self.issue_cover_frame(identity)
            .map(|token| token.0.to_vec())
            .map_err(|_| FrameIssueError)
    }

    fn issue_action(
        &self,
        identity: PublicFrameIdentity,
        obligation: &ActionObligation,
        claim_bound: ClaimBound,
    ) -> Result<Vec<u8>, FrameIssueError> {
        self.issue_action_frame(identity, obligation, claim_bound)
            .map(|token| token.0.to_vec())
            .map_err(|_| FrameIssueError)
    }
}

pub fn semantics_tag(obligation: &ActionObligation, claim_bound: ClaimBound) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(b"NOTICER_AT_V2_ACTION_SEMANTICS_TAG");
    digest.update(obligation.service.0);
    digest.update((obligation.action as u16).to_le_bytes());
    digest.update(obligation.public_bucket.0.to_le_bytes());
    digest.update(obligation.admission_cutoff.0.to_le_bytes());
    digest.update(obligation.release_window_start.0.to_le_bytes());
    digest.update(obligation.release_deadline.0.to_le_bytes());
    digest.update(obligation.max_uses.to_le_bytes());
    digest.update(obligation.policy_hash.0);
    digest.update([
        claim_bound.semantic as u8,
        claim_bound.audience as u8,
        claim_bound.impact as u8,
    ]);
    let output: [u8; 32] = digest.finalize().into();
    output[..16].try_into().expect("fixed digest prefix")
}

#[derive(Debug, Error)]
pub enum TokenIssueError {
    #[error("invalid public token input")]
    InvalidPublicInput,
    #[error("nonce/sequence reuse was rejected")]
    NonceReuse,
    #[error("issuer state is unavailable")]
    StateFailure,
    #[error("cryptographic operation failed")]
    Crypto(#[from] CryptoError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use noticer_aetp::{required_claim, BucketId};
    use noticer_types::{ActionCode, LogicalSlot, PolicyHash};

    fn identity(service: ServiceBinding, sequence: u32) -> PublicFrameIdentity {
        PublicFrameIdentity {
            service,
            public_epoch: 3,
            public_bucket: 1,
            slot_in_bucket: 0,
            sequence,
            absolute_slot: LogicalSlot(10),
        }
    }

    #[test]
    fn cover_and_action_are_exactly_the_same_length() {
        let service = ServiceBinding([1; 16]);
        let issuer =
            TokenIssuer::new(CryptographicRootSecret::new([7; 32]), 3, &[service]).unwrap();
        let cover = issuer.issue_cover_frame(identity(service, 1)).unwrap();
        let obligation = ActionObligation {
            service,
            action: ActionCode::RenderAmbientPulse,
            public_bucket: BucketId(1),
            admission_cutoff: LogicalSlot(8),
            release_window_start: LogicalSlot(9),
            release_deadline: LogicalSlot(12),
            max_uses: 1,
            policy_hash: PolicyHash([4; 32]),
        };
        let action = issuer
            .issue_action_frame(
                identity(service, 2),
                &obligation,
                required_claim(obligation.action),
            )
            .unwrap();
        assert_eq!(cover.0.len(), 236);
        assert_eq!(cover.0.len(), action.0.len());
    }

    #[test]
    fn nonce_reuse_is_rejected() {
        let service = ServiceBinding([1; 16]);
        let issuer =
            TokenIssuer::new(CryptographicRootSecret::new([7; 32]), 3, &[service]).unwrap();
        issuer.issue_cover_frame(identity(service, 1)).unwrap();
        assert!(matches!(
            issuer.issue_cover_frame(identity(service, 1)),
            Err(TokenIssueError::NonceReuse)
        ));
    }
}
