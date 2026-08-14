#![forbid(unsafe_code)]

//! Fixed-size, signed, encrypted ATv2 frame issuance.
//!
//! `ProductionTokenIssuer` is the production entry point. It emits an action
//! only after consuming the opaque conjunction of a K1 evidence permit and a
//! validated NPL1 lease. The low-level `TokenIssuer` can issue actions only
//! when the explicit `lab-unattested` feature is enabled.
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
//!
//! A production caller cannot directly issue an action without first arming
//! the issuer with a sealed production admission:
//!
//! ```compile_fail
//! use noticer_token::ProductionTokenIssuer;
//!
//! fn bypass(issuer: &ProductionTokenIssuer) {
//!     let _ = issuer.issue_action_frame();
//! }
//! ```

use noticer_aetp::{ActionObligation, ClaimBound, ServiceBinding};
use noticer_crypto::{
    derive_issuer_keys, CryptoError, CryptographicRootSecret, IssuerKeyMaterial,
    VerifierKeyMaterial,
};
use noticer_evidence_bridge::ProductionAdmission;
use noticer_nepp::PairwiseServiceAlias;
use noticer_protocol::{
    AtypicalityTokenEnvelope, FrameKind, InnerBody, OuterHeader, CIPHERTEXT_SIZE, ENVELOPE_SIZE,
    INNER_BODY_SIZE, OUTER_HEADER_SIZE, SIGNATURE_SIZE, SIGNED_PLAINTEXT_SIZE,
};
use noticer_provenance::{dominates, AssuranceProfile, PipelineMeasurementHash, ProvenanceMode};
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

    fn issue_action_frame_authorized(
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

    /// Research-only action issuance. Enabling this feature must be recorded
    /// as `LAB_UNATTESTED` in every generated artifact.
    #[cfg(feature = "lab-unattested")]
    pub fn issue_action_frame(
        &self,
        identity: PublicFrameIdentity,
        obligation: &ActionObligation,
        claim_bound: ClaimBound,
    ) -> Result<AtypicalityTokenEnvelope, TokenIssueError> {
        self.issue_action_frame_authorized(identity, obligation, claim_bound)
    }

    #[cfg(feature = "lab-unattested")]
    pub const fn provenance_artifact_label(&self) -> &'static str {
        "LAB_UNATTESTED"
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductionBindings {
    pub service: ServiceBinding,
    pub lease_service_alias: PairwiseServiceAlias,
    pub public_epoch: u32,
    pub pipeline: PipelineMeasurementHash,
    pub policy_hash: noticer_types::PolicyHash,
    pub minimum_assurance: AssuranceProfile,
}

pub struct ProductionTokenIssuer {
    inner: TokenIssuer,
    bindings: ProductionBindings,
    atv2_issuer_key_id: [u8; 8],
    pending: Mutex<Option<ArmedAdmission>>,
}

impl ProductionTokenIssuer {
    pub fn new(
        root: CryptographicRootSecret,
        bindings: ProductionBindings,
    ) -> Result<Self, TokenIssueError> {
        let inner = TokenIssuer::new(root, bindings.public_epoch, &[bindings.service])?;
        let atv2_issuer_key_id = inner
            .verifier_material(bindings.service)
            .ok_or(TokenIssueError::InvalidPublicInput)?
            .key_id()
            .0;
        Ok(Self {
            inner,
            bindings,
            atv2_issuer_key_id,
            pending: Mutex::new(None),
        })
    }

    pub const fn mode(&self) -> ProvenanceMode {
        ProvenanceMode::ProductionRequired
    }

    pub const fn provenance_artifact_label(&self) -> &'static str {
        "PRODUCTION_REQUIRED"
    }

    pub fn verifier_material(&self) -> Option<VerifierKeyMaterial> {
        self.inner.verifier_material(self.bindings.service)
    }

    pub fn issue_cover_frame(
        &self,
        identity: PublicFrameIdentity,
    ) -> Result<AtypicalityTokenEnvelope, TokenIssueError> {
        self.inner.issue_cover_frame(identity)
    }

    pub fn arm(&self, admission: ProductionAdmission) -> Result<(), ProductionGuardError> {
        let claims = admission.lease_claims();
        if claims.service_alias != self.bindings.lease_service_alias {
            return Err(ProductionGuardError::WrongService);
        }
        if claims.public_epoch != self.bindings.public_epoch {
            return Err(ProductionGuardError::WrongEpoch);
        }
        if claims.atv2_issuer_key_id != self.atv2_issuer_key_id {
            return Err(ProductionGuardError::WrongAtv2Key);
        }
        if claims.pipeline != self.bindings.pipeline {
            return Err(ProductionGuardError::WrongPipeline);
        }
        if claims.policy_hash != self.bindings.policy_hash.0
            || admission.policy_hash() != self.bindings.policy_hash
        {
            return Err(ProductionGuardError::WrongPolicy);
        }
        if claims.assurance != admission.actual_assurance().digest()
            || !dominates(
                &admission.actual_assurance(),
                &self.bindings.minimum_assurance,
            )
        {
            return Err(ProductionGuardError::AssuranceBelowMinimum);
        }
        let armed = ArmedAdmission {
            action: admission.action(),
            policy_hash: admission.policy_hash(),
            evidence_issued_slot: admission.issued_slot(),
            evidence_expires_slot: admission.expires_slot(),
            lease_issued_slot: claims.issued_public_slot,
            lease_expires_slot: claims.expires_public_slot,
        };
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if pending.is_some() {
            return Err(ProductionGuardError::AdmissionAlreadyArmed);
        }
        *pending = Some(armed);
        Ok(())
    }

    pub fn has_pending_admission(&self) -> bool {
        self.pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_some()
    }
}

#[derive(Clone, Copy)]
struct ArmedAdmission {
    action: noticer_types::ActionCode,
    policy_hash: noticer_types::PolicyHash,
    evidence_issued_slot: noticer_types::LogicalSlot,
    evidence_expires_slot: noticer_types::LogicalSlot,
    lease_issued_slot: u32,
    lease_expires_slot: u32,
}

impl ArmedAdmission {
    fn permits(self, identity: PublicFrameIdentity, obligation: &ActionObligation) -> bool {
        let Ok(public_bucket) = u32::try_from(obligation.public_bucket.0) else {
            return false;
        };
        let Ok(public_slot) = u32::try_from(identity.absolute_slot.0) else {
            return false;
        };
        identity.service == obligation.service
            && identity.public_epoch > 0
            && identity.public_bucket == public_bucket
            && identity.absolute_slot >= obligation.release_window_start
            && identity.absolute_slot <= obligation.release_deadline
            && obligation.max_uses == 1
            && obligation.action == self.action
            && obligation.policy_hash == self.policy_hash
            && identity.absolute_slot >= self.evidence_issued_slot
            && identity.absolute_slot <= self.evidence_expires_slot
            && public_slot >= self.lease_issued_slot
            && public_slot < self.lease_expires_slot
    }
}

impl FrameIssuer for ProductionTokenIssuer {
    fn frame_length(&self) -> usize {
        ENVELOPE_SIZE
    }

    fn issue_cover(&self, identity: PublicFrameIdentity) -> Result<Vec<u8>, FrameIssueError> {
        self.inner
            .issue_cover_frame(identity)
            .map(|token| token.0.to_vec())
            .map_err(|_| FrameIssueError)
    }

    fn issue_action(
        &self,
        identity: PublicFrameIdentity,
        obligation: &ActionObligation,
        claim_bound: ClaimBound,
    ) -> Result<Vec<u8>, FrameIssueError> {
        let admission = self
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if admission.is_none_or(|armed| !armed.permits(identity, obligation)) {
            return self.issue_cover(identity);
        }
        self.inner
            .issue_action_frame_authorized(identity, obligation, claim_bound)
            .map(|token| token.0.to_vec())
            .map_err(|_| FrameIssueError)
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProductionGuardError {
    #[error("NPL1 service binding does not match the production issuer")]
    WrongService,
    #[error("NPL1 epoch does not match the production issuer")]
    WrongEpoch,
    #[error("NPL1 ATv2 key does not match the production issuer")]
    WrongAtv2Key,
    #[error("NPL1 pipeline does not match production policy")]
    WrongPipeline,
    #[error("K1/NPL1 policy does not match production policy")]
    WrongPolicy,
    #[error("appraised assurance is below production policy")]
    AssuranceBelowMinimum,
    #[error("an unconsumed production admission is already armed")]
    AdmissionAlreadyArmed,
}

#[cfg(feature = "lab-unattested")]
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
            .issue_action_frame_authorized(
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
