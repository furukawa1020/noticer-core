#![forbid(unsafe_code)]

//! The high-to-low admission boundary.
//!
//! `EvidencePermit` is consumed here. Private readiness, expiry, epoch, score,
//! and evidence provenance are checked and then irreversibly erased before an
//! `AdmittedAction` can cross into release planning.
//!
//! Private readiness is intentionally not a field on the low-side value:
//!
//! ```compile_fail
//! use noticer_claim::AdmittedAction;
//!
//! fn leak_private_readiness(action: &AdmittedAction) {
//!     let _ = action.evidence_ready_slot;
//! }
//! ```

use noticer_aetp::{
    required_claim, validate_obligation, ActionObligation, ClaimBound, ServiceBinding,
};
use noticer_evidence::{EvidenceEpochId, EvidencePermit, GuaranteeMarker};
use noticer_types::{ActionCode, LogicalSlot, PolicyHash};
use std::fmt;
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionTemplate {
    pub service: ServiceBinding,
    pub action: ActionCode,
    pub public_bucket: noticer_aetp::BucketId,
    pub admission_cutoff: LogicalSlot,
    pub release_window_start: LogicalSlot,
    pub release_deadline: LogicalSlot,
    pub max_uses: u16,
    pub policy_hash: PolicyHash,
    pub claim_bound: ClaimBound,
    pub local_policy_ceiling: ClaimBound,
}

struct PrivateAdmissionCandidate {
    action: ActionCode,
    policy_hash: PolicyHash,
    evidence_ready_slot: LogicalSlot,
    evidence_expiry_slot: LogicalSlot,
    evidence_epoch: EvidenceEpochId,
    provenance: &'static str,
}

impl fmt::Debug for PrivateAdmissionCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateAdmissionCandidate(<redacted>)")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedAction {
    obligation: ActionObligation,
    claim_bound: ClaimBound,
}

impl AdmittedAction {
    pub const fn obligation(&self) -> &ActionObligation {
        &self.obligation
    }

    pub const fn claim_bound(&self) -> ClaimBound {
        self.claim_bound
    }

    pub fn into_public_parts(self) -> (ActionObligation, ClaimBound) {
        (self.obligation, self.claim_bound)
    }
}

pub fn admit<G: GuaranteeMarker>(
    permit: EvidencePermit<G>,
    template: ActionTemplate,
) -> Result<AdmittedAction, AdmissionError> {
    let (action, policy_hash, ready, expiry, epoch, provenance) =
        permit.consume().into_admission_parts();
    let private = PrivateAdmissionCandidate {
        action,
        policy_hash,
        evidence_ready_slot: ready,
        evidence_expiry_slot: expiry,
        evidence_epoch: epoch,
        provenance,
    };
    let required = required_claim(template.action);
    if private.action != template.action
        || private.policy_hash != template.policy_hash
        || private.evidence_ready_slot > template.admission_cutoff
        || private.evidence_expiry_slot < template.admission_cutoff
        || !template.claim_bound.permits(required)
        || !template.local_policy_ceiling.permits(template.claim_bound)
    {
        return Err(AdmissionError::Rejected);
    }
    let obligation = ActionObligation {
        service: template.service,
        action: template.action,
        public_bucket: template.public_bucket,
        admission_cutoff: template.admission_cutoff,
        release_window_start: template.release_window_start,
        release_deadline: template.release_deadline,
        max_uses: template.max_uses,
        policy_hash: template.policy_hash,
    };
    validate_obligation(&obligation).map_err(|_| AdmissionError::Rejected)?;
    // These reads make the deliberate erasure point explicit without exposing
    // any of the values in the low-side type or its Debug representation.
    let _erased = (private.evidence_epoch, private.provenance);
    Ok(AdmittedAction {
        obligation,
        claim_bound: template.claim_bound,
    })
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AdmissionError {
    #[error("evidence was not admissible for the public action template")]
    Rejected,
}
