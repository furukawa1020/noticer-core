//! Deterministic end-to-end recovery deployment drill.

use crate::recovery_readiness::{evaluate, GateEvidence, GateKind};
use crate::sha256::sha256;

const DOMAIN: &[u8] = b"noticer.recovery-drill.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DrillScenario {
    Normal,
    TamperedProof,
    ReplayedHandoff,
    SplitBrain,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScenarioResult {
    pub scenario: DrillScenario,
    pub expected_ready: bool,
    pub actual_ready: bool,
    pub passed: bool,
    pub reason_count: u16,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DrillReport {
    pub seed: u64,
    pub all_passed: bool,
    pub scenarios: Vec<ScenarioResult>,
}

pub fn run(seed: u64) -> Result<DrillReport, &'static str> {
    if seed == 0 {
        return Err("seed must be nonzero");
    }
    let scenarios = [
        DrillScenario::Normal,
        DrillScenario::TamperedProof,
        DrillScenario::ReplayedHandoff,
        DrillScenario::SplitBrain,
    ]
    .into_iter()
    .map(|scenario| execute(seed, scenario))
    .collect::<Vec<_>>();
    Ok(DrillReport {
        seed,
        all_passed: scenarios.iter().all(|result| result.passed),
        scenarios,
    })
}

#[must_use]
pub fn canonical_json(report: &DrillReport) -> String {
    let scenarios = report.scenarios.iter().map(|result| format!("{{\"scenario\":\"{}\",\"expected_ready\":{},\"actual_ready\":{},\"passed\":{},\"reason_count\":{}}}", name(result.scenario), result.expected_ready, result.actual_ready, result.passed, result.reason_count)).collect::<Vec<_>>().join(",");
    format!("{{\"schema\":\"noticer.recovery-drill.v1\",\"seed\":{},\"all_passed\":{},\"scenarios\":[{}]}}", report.seed, report.all_passed, scenarios)
}

fn execute(seed: u64, scenario: DrillScenario) -> ScenarioResult {
    let now = 1_000;
    let epoch = 7;
    let kinds = [
        GateKind::Proof,
        GateKind::Quorum,
        GateKind::Lease,
        GateKind::ReplayDefense,
        GateKind::Privacy,
        GateKind::Audit,
    ];
    let mut evidence = kinds
        .into_iter()
        .map(|kind| GateEvidence {
            kind,
            policy_epoch: epoch,
            valid_until: now + 100,
            digest: digest(seed, kind),
        })
        .collect::<Vec<_>>();
    match scenario {
        DrillScenario::Normal => {}
        DrillScenario::TamperedProof => {
            evidence
                .iter_mut()
                .find(|item| item.kind == GateKind::Proof)
                .unwrap()
                .digest = [0; 32]
        }
        DrillScenario::ReplayedHandoff => {
            evidence.retain(|item| item.kind != GateKind::ReplayDefense)
        }
        DrillScenario::SplitBrain => {
            evidence
                .iter_mut()
                .find(|item| item.kind == GateKind::Lease)
                .unwrap()
                .valid_until = now - 1
        }
    }
    let manifest = evaluate(epoch, now, &evidence);
    let expected_ready = scenario == DrillScenario::Normal;
    ScenarioResult {
        scenario,
        expected_ready,
        actual_ready: manifest.ready,
        passed: expected_ready == manifest.ready,
        reason_count: manifest.reasons.len() as u16,
    }
}
fn digest(seed: u64, kind: GateKind) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(DOMAIN.len() + 9);
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&seed.to_be_bytes());
    bytes.push(kind as u8);
    sha256(&bytes)
}
fn name(value: DrillScenario) -> &'static str {
    match value {
        DrillScenario::Normal => "normal",
        DrillScenario::TamperedProof => "tampered_proof",
        DrillScenario::ReplayedHandoff => "replayed_handoff",
        DrillScenario::SplitBrain => "split_brain",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn drill_is_deterministic_and_detects_all_attacks() {
        let first = run(42).unwrap();
        let second = run(42).unwrap();
        assert_eq!(first, second);
        assert!(first.all_passed);
        assert!(first.scenarios[0].actual_ready);
        assert!(first.scenarios[1..]
            .iter()
            .all(|result| !result.actual_ready && result.reason_count > 0));
        assert_eq!(canonical_json(&first), canonical_json(&second));
    }
    #[test]
    fn zero_seed_is_rejected() {
        assert_eq!(run(0), Err("seed must be nonzero"));
    }
}
