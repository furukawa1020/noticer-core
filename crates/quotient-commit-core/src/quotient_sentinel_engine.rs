//! End-to-end runtime assurance, revocation, quarantine, and response engine.

use crate::sentinel_escalation::{AssuranceEscalationPolicy, AssuranceResponse};
use crate::sentinel_quarantine::RuntimeQuarantineController;
use crate::sentinel_revocation::{RepairRevocationCertificate, RevocationReason};
use crate::sentinel_sample::MonitorSample;
use crate::sentinel_verdict::{AssuranceInconclusive, AssuranceInvalid, AssuranceVerdict};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SentinelMonitorFacts {
    pub semantics_preserved: bool,
    pub safety_preserved: bool,
    pub liveness_preserved: bool,
    pub privacy_preserved: bool,
    pub inside_support: bool,
    pub evidence_fresh: bool,
    pub artifact_authenticated: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotientSentinelInput {
    pub deployment_identity_digest: [u8; 32],
    pub sample: MonitorSample,
    pub facts: SentinelMonitorFacts,
    pub evidence_digest: [u8; 32],
    pub confidence_ppm: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotientSentinelResult {
    pub verdict: AssuranceVerdict,
    pub response: AssuranceResponse,
    pub revocation: Option<RepairRevocationCertificate>,
    pub release_allowed: bool,
}

fn reason(facts: SentinelMonitorFacts) -> RevocationReason {
    if !facts.safety_preserved {
        RevocationReason::SafetyViolation
    } else if !facts.semantics_preserved {
        RevocationReason::SemanticsDrift
    } else if !facts.liveness_preserved {
        RevocationReason::LivenessViolation
    } else if !facts.privacy_preserved {
        RevocationReason::PrivacyViolation
    } else if !facts.evidence_fresh {
        RevocationReason::EvidenceExpired
    } else {
        RevocationReason::MonitorFailure
    }
}

pub fn run(
    input: QuotientSentinelInput,
    policy: AssuranceEscalationPolicy,
) -> QuotientSentinelResult {
    let verdict = if input.deployment_identity_digest == [0; 32] || input.evidence_digest == [0; 32]
    {
        AssuranceVerdict::Invalid(AssuranceInvalid::DeploymentMismatch)
    } else if !input.facts.artifact_authenticated {
        AssuranceVerdict::Invalid(AssuranceInvalid::StaleEvidence)
    } else if !input.facts.evidence_fresh {
        AssuranceVerdict::Inconclusive(AssuranceInconclusive::EvidenceGap)
    } else if input.facts.semantics_preserved
        && input.facts.safety_preserved
        && input.facts.liveness_preserved
        && input.facts.privacy_preserved
        && input.facts.inside_support
    {
        AssuranceVerdict::Healthy
    } else {
        AssuranceVerdict::Violated
    };

    if verdict == AssuranceVerdict::Healthy {
        return QuotientSentinelResult {
            verdict,
            response: AssuranceResponse::ContinueMonitoring,
            revocation: None,
            release_allowed: true,
        };
    }

    let severity = if matches!(verdict, AssuranceVerdict::Violated) {
        crate::sentinel_alarm_fusion::AlarmSeverity::Critical
    } else {
        crate::sentinel_alarm_fusion::AlarmSeverity::Elevated
    };
    let response = policy.decide(severity, input.confidence_ppm);
    let revocation = RepairRevocationCertificate::new(
        input.deployment_identity_digest,
        input.evidence_digest,
        input.sample.sequence,
        reason(input.facts),
    )
    .ok();
    let mut quarantine = RuntimeQuarantineController::new();
    let _ = quarantine.observe(verdict, input.evidence_digest);
    QuotientSentinelResult {
        verdict,
        response,
        revocation,
        release_allowed: quarantine.release_allowed(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sentinel_observation_atom::{PublicRuntimeEvent, RuntimeObservationAtom};

    fn input() -> QuotientSentinelInput {
        QuotientSentinelInput {
            deployment_identity_digest: [1; 32],
            sample: MonitorSample::new(
                7,
                70,
                RuntimeObservationAtom::new(3, PublicRuntimeEvent::Release, 1, 0).unwrap(),
            )
            .unwrap(),
            facts: SentinelMonitorFacts {
                semantics_preserved: true,
                safety_preserved: true,
                liveness_preserved: true,
                privacy_preserved: true,
                inside_support: true,
                evidence_fresh: true,
                artifact_authenticated: true,
            },
            evidence_digest: [2; 32],
            confidence_ppm: 950_000,
        }
    }

    #[test]
    fn healthy_evidence_keeps_release_active() {
        let result = run(input(), AssuranceEscalationPolicy::new(900_000).unwrap());
        assert_eq!(result.verdict, AssuranceVerdict::Healthy);
        assert!(result.release_allowed);
        assert!(result.revocation.is_none());
    }

    #[test]
    fn privacy_drift_revokes_and_rolls_back() {
        let mut changed = input();
        changed.facts.privacy_preserved = false;
        let result = run(changed, AssuranceEscalationPolicy::new(900_000).unwrap());
        assert_eq!(result.verdict, AssuranceVerdict::Violated);
        assert_eq!(result.response, AssuranceResponse::Rollback);
        assert!(!result.release_allowed);
        assert_eq!(
            result.revocation.unwrap().reason,
            RevocationReason::PrivacyViolation
        );
    }

    #[test]
    fn stale_evidence_never_remains_healthy() {
        let mut changed = input();
        changed.facts.evidence_fresh = false;
        let result = run(changed, AssuranceEscalationPolicy::new(900_000).unwrap());
        assert!(matches!(result.verdict, AssuranceVerdict::Inconclusive(_)));
        assert!(!result.release_allowed);
    }
}
