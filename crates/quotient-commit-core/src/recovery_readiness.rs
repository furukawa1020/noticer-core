//! Deployment readiness manifest binding all mandatory recovery gates.

use crate::sha256::sha256;
use std::collections::BTreeSet;

const DOMAIN: &[u8] = b"noticer.recovery-readiness.v1\0";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum GateKind {
    Proof = 1,
    Quorum = 2,
    Lease = 3,
    ReplayDefense = 4,
    Privacy = 5,
    Audit = 6,
}
const REQUIRED: [GateKind; 6] = [
    GateKind::Proof,
    GateKind::Quorum,
    GateKind::Lease,
    GateKind::ReplayDefense,
    GateKind::Privacy,
    GateKind::Audit,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GateEvidence {
    pub kind: GateKind,
    pub policy_epoch: u64,
    pub valid_until: u64,
    pub digest: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ReadinessReason {
    DuplicateGate,
    EpochMismatch,
    Expired,
    InvalidDigest,
    MissingGate,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadinessManifest {
    pub ready: bool,
    pub policy_epoch: u64,
    pub evaluated_at: u64,
    pub evidence_digest: [u8; 32],
    pub reasons: Vec<(GateKind, ReadinessReason)>,
}

#[must_use]
pub fn evaluate(policy_epoch: u64, now: u64, evidence: &[GateEvidence]) -> ReadinessManifest {
    let mut reasons = Vec::new();
    let mut seen = BTreeSet::new();
    for item in evidence {
        if !seen.insert(item.kind) {
            reasons.push((item.kind, ReadinessReason::DuplicateGate));
        }
        if item.policy_epoch != policy_epoch || policy_epoch == 0 {
            reasons.push((item.kind, ReadinessReason::EpochMismatch));
        }
        if item.valid_until < now {
            reasons.push((item.kind, ReadinessReason::Expired));
        }
        if item.digest == [0; 32] {
            reasons.push((item.kind, ReadinessReason::InvalidDigest));
        }
    }
    for kind in REQUIRED {
        if !seen.contains(&kind) {
            reasons.push((kind, ReadinessReason::MissingGate));
        }
    }
    reasons.sort();
    reasons.dedup();
    ReadinessManifest {
        ready: reasons.is_empty(),
        policy_epoch,
        evaluated_at: now,
        evidence_digest: evidence_digest(evidence),
        reasons,
    }
}

#[must_use]
pub fn canonical_json(value: &ReadinessManifest) -> String {
    let reasons = value
        .reasons
        .iter()
        .map(|(gate, reason)| {
            format!(
                "{{\"gate\":\"{}\",\"reason\":\"{}\"}}",
                gate_name(*gate),
                reason_name(*reason)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("{{\"schema\":\"noticer.recovery-readiness.v1\",\"ready\":{},\"policy_epoch\":{},\"evaluated_at\":{},\"evidence_digest\":\"{}\",\"reasons\":[{}]}}", value.ready, value.policy_epoch, value.evaluated_at, hex(value.evidence_digest), reasons)
}
fn evidence_digest(evidence: &[GateEvidence]) -> [u8; 32] {
    let mut sorted = evidence.to_vec();
    sorted.sort_by_key(|item| item.kind);
    let mut bytes = Vec::with_capacity(DOMAIN.len() + sorted.len() * 49);
    bytes.extend_from_slice(DOMAIN);
    for item in sorted {
        bytes.push(item.kind as u8);
        bytes.extend_from_slice(&item.policy_epoch.to_be_bytes());
        bytes.extend_from_slice(&item.valid_until.to_be_bytes());
        bytes.extend_from_slice(&item.digest);
    }
    sha256(&bytes)
}
fn gate_name(value: GateKind) -> &'static str {
    match value {
        GateKind::Proof => "proof",
        GateKind::Quorum => "quorum",
        GateKind::Lease => "lease",
        GateKind::ReplayDefense => "replay_defense",
        GateKind::Privacy => "privacy",
        GateKind::Audit => "audit",
    }
}
fn reason_name(value: ReadinessReason) -> &'static str {
    match value {
        ReadinessReason::DuplicateGate => "duplicate_gate",
        ReadinessReason::EpochMismatch => "epoch_mismatch",
        ReadinessReason::Expired => "expired",
        ReadinessReason::InvalidDigest => "invalid_digest",
        ReadinessReason::MissingGate => "missing_gate",
    }
}
fn hex(value: [u8; 32]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn all() -> Vec<GateEvidence> {
        REQUIRED
            .iter()
            .enumerate()
            .map(|(index, kind)| GateEvidence {
                kind: *kind,
                policy_epoch: 3,
                valid_until: 100,
                digest: [(index + 1) as u8; 32],
            })
            .collect()
    }
    #[test]
    fn all_valid_gates_are_ready_and_order_independent() {
        let evidence = all();
        let first = evaluate(3, 50, &evidence);
        let mut reversed = evidence;
        reversed.reverse();
        let second = evaluate(3, 50, &reversed);
        assert!(first.ready);
        assert_eq!(first.evidence_digest, second.evidence_digest);
    }
    #[test]
    fn missing_expired_and_wrong_epoch_report_reasons() {
        let mut evidence = all();
        evidence.pop();
        evidence[0].valid_until = 49;
        evidence[1].policy_epoch = 4;
        let report = evaluate(3, 50, &evidence);
        assert!(!report.ready);
        assert_eq!(report.reasons.len(), 3);
        let json = canonical_json(&report);
        assert!(json.contains("missing_gate"));
        assert!(json.contains("expired"));
    }
}
