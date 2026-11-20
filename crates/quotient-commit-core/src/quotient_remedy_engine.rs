//! End-to-end fail-closed orchestration for proof-carrying remediation.

use crate::remedy_certificate::{
    CertificateError, RepairCertificate, RepairCertificateBindings, RepairSearchEvidence,
};
use crate::remedy_certificate_auth::{authenticate, RepairCertificateTag};
use crate::remedy_deployment_gate::{authorize, RepairDeploymentEvidence, RepairDeploymentPermit};
use crate::remedy_input_classifier::{classify, InvalidInput, RepairInputFacts};
use crate::remedy_replay::{replay, RepairReplayInput};
use crate::remedy_replay_disagreement::classify as classify_disagreement;
use crate::remedy_verdict::{InconclusiveRepair, InvalidRepair, RepairVerdict};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemedyVerificationFacts {
    pub safety: bool,
    pub action_equivalence: bool,
    pub liveness: bool,
    pub privacy: bool,
    pub minimality: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotientRemedyInput {
    pub admission: RepairInputFacts,
    pub bindings: RepairCertificateBindings,
    pub search: RepairSearchEvidence,
    pub key: [u8; 32],
    pub verification: RemedyVerificationFacts,
    pub exhausted: Option<InconclusiveRepair>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotientRemedyResult {
    pub verdict: RepairVerdict,
    pub certificate: Option<RepairCertificate>,
    pub tag: Option<RepairCertificateTag>,
    pub permit: Option<RepairDeploymentPermit>,
}

fn invalid_result(reason: InvalidRepair) -> QuotientRemedyResult {
    QuotientRemedyResult {
        verdict: RepairVerdict::Invalid(reason),
        certificate: None,
        tag: None,
        permit: None,
    }
}

pub fn run(input: QuotientRemedyInput) -> QuotientRemedyResult {
    if let Some(limit) = input.exhausted {
        return QuotientRemedyResult {
            verdict: RepairVerdict::Inconclusive(limit),
            certificate: None,
            tag: None,
            permit: None,
        };
    }
    if let Err(reason) = classify(input.admission) {
        let mapped = match reason {
            InvalidInput::BoundaryViolation => InvalidRepair::BoundaryViolation,
            InvalidInput::ContradictoryConstraints => InvalidRepair::ContradictoryConstraint,
            _ => InvalidRepair::MalformedInput,
        };
        return invalid_result(mapped);
    }
    let certificate = match RepairCertificate::new(input.bindings, input.search) {
        Ok(certificate) => certificate,
        Err(CertificateError::ZeroBinding | CertificateError::NoExplorationEvidence) => {
            return invalid_result(InvalidRepair::MalformedInput);
        }
    };
    let tag = match authenticate(certificate, input.key) {
        Ok(tag) => tag,
        Err(_) => return invalid_result(InvalidRepair::MalformedInput),
    };
    let facts = input.verification;
    let primary = facts.safety
        && facts.action_equivalence
        && facts.liveness
        && facts.privacy
        && facts.minimality;
    if !primary {
        return QuotientRemedyResult {
            verdict: RepairVerdict::Unrepairable,
            certificate: Some(certificate),
            tag: Some(tag),
            permit: None,
        };
    }
    let replay_verdict = replay(RepairReplayInput {
        certificate_digest: crate::sha256::sha256(&certificate.canonical_bytes()),
        patch_digest: certificate.patch_digest,
        model_digest: certificate.model_digest,
        safety: facts.safety,
        action_equivalence: facts.action_equivalence,
        liveness: facts.liveness,
        privacy: facts.privacy,
        minimality: facts.minimality,
    });
    let disagreement = classify_disagreement(primary, replay_verdict);
    let verdict = RepairVerdict::Repaired;
    let permit = authorize(RepairDeploymentEvidence {
        verdict,
        certificate_digest: crate::sha256::sha256(&certificate.canonical_bytes()),
        authenticated: true,
        replay: replay_verdict,
        disagreement,
        safety: facts.safety,
        action_equivalence: facts.action_equivalence,
        liveness: facts.liveness,
        privacy: facts.privacy,
        minimality: facts.minimality,
    })
    .ok();
    QuotientRemedyResult {
        verdict: if permit.is_some() {
            verdict
        } else {
            RepairVerdict::Unrepairable
        },
        certificate: Some(certificate),
        tag: Some(tag),
        permit,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> QuotientRemedyInput {
        QuotientRemedyInput {
            admission: RepairInputFacts {
                certificate_authenticated: true,
                model_bound: true,
                constraints_satisfiable: true,
                targets_inside_boundary: true,
                cause_nonempty: true,
            },
            bindings: RepairCertificateBindings {
                cause_digest: [1; 32],
                patch_digest: [2; 32],
                objective_digest: [3; 32],
                constraint_digest: [4; 32],
                model_digest: [5; 32],
                verification_digest: [6; 32],
            },
            search: RepairSearchEvidence {
                explored_nodes: 7,
                explored_worlds: 8,
            },
            key: [9; 32],
            verification: RemedyVerificationFacts {
                safety: true,
                action_equivalence: true,
                liveness: true,
                privacy: true,
                minimality: true,
            },
            exhausted: None,
        }
    }

    #[test]
    fn verified_pipeline_issues_deployment_permit() {
        let result = run(valid());
        assert_eq!(result.verdict, RepairVerdict::Repaired);
        assert!(result.certificate.is_some());
        assert!(result.permit.is_some());
    }

    #[test]
    fn exhausted_and_invalid_inputs_never_deploy() {
        let mut exhausted = valid();
        exhausted.exhausted = Some(InconclusiveRepair::NodeLimit);
        assert!(matches!(
            run(exhausted).verdict,
            RepairVerdict::Inconclusive(_)
        ));
        let mut invalid = valid();
        invalid.admission.targets_inside_boundary = false;
        let result = run(invalid);
        assert_eq!(
            result.verdict,
            RepairVerdict::Invalid(InvalidRepair::BoundaryViolation)
        );
        assert!(result.permit.is_none());
    }

    #[test]
    fn failed_verifier_is_unrepairable_without_permit() {
        let mut input = valid();
        input.verification.privacy = false;
        let result = run(input);
        assert_eq!(result.verdict, RepairVerdict::Unrepairable);
        assert!(result.permit.is_none());
    }
}
