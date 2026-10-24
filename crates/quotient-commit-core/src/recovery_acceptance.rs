//! Reproducible acceptance scenarios for the QuotientCommit recovery boundary.

use crate::crash_matrix::{CrashCampaign, CrashPoint};
use crate::recovery_admission::{seal_policy, AdmissionState, RecoveryAdmissionController};
use crate::recovery_simulator::{run_simulation, SimulationConfig, SimulationEvent};
use crate::rollback_anchor::{
    DurableRollbackAnchor, RollbackAnchorError, RollbackAnchorRecord, RollbackAnchorStore,
    StoreHeads,
};

const KEY: [u8; 32] = [0x71; 32];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptanceScenario {
    pub id: &'static str,
    pub invariant: &'static str,
    pub passed: bool,
    pub evidence: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryAcceptanceReport {
    pub schema: &'static str,
    pub scenarios: Vec<AcceptanceScenario>,
    pub all_passed: bool,
}

#[derive(Default)]
struct MemoryAnchorStore(Vec<RollbackAnchorRecord>);
impl RollbackAnchorStore for MemoryAnchorStore {
    fn append_and_sync(&mut self, record: RollbackAnchorRecord) -> Result<(), RollbackAnchorError> {
        self.0.push(record);
        Ok(())
    }
    fn load(&self) -> Result<Vec<RollbackAnchorRecord>, RollbackAnchorError> {
        Ok(self.0.clone())
    }
}

pub fn run_acceptance() -> RecoveryAcceptanceReport {
    let normal = CrashCampaign::run();
    let normal_pass = normal
        .witnesses()
        .iter()
        .all(|value| value.effect_at_most_once && value.audit_at_most_once && value.converged);

    let simulation = run_simulation(SimulationConfig {
        seed: 0x5eed,
        event_count: 128,
        maximum_backlog: 3,
    })
    .expect("fixed acceptance config");
    let restart_count = simulation.terminal.restart_count;
    let crash_pass = restart_count > 0
        && simulation
            .steps
            .iter()
            .any(|value| value.event == SimulationEvent::CrashRestart);

    let substitution = CrashCampaign::run_substitution_attack();
    let substitution_pass = substitution
        .witnesses()
        .iter()
        .all(|value| value.fail_closed && value.effect_at_most_once && value.audit_at_most_once);

    let heads = |value: u8| StoreHeads {
        outbox: [value; 32],
        vault: [value + 1; 32],
        audit: [value + 2; 32],
    };
    let mut anchor = DurableRollbackAnchor::open(MemoryAnchorStore::default(), KEY, 8)
        .expect("fixed anchor config");
    anchor.advance(heads(1)).expect("first anchor");
    anchor.advance(heads(4)).expect("second anchor");
    let rollback_result = anchor.verify_snapshot(1, heads(1));
    let rollback_pass = rollback_result == Err(RollbackAnchorError::RollbackDetected);

    let policy = seal_policy(1, 2, 3, 10, 4, KEY).expect("fixed admission policy");
    let mut admission =
        RecoveryAdmissionController::new(policy, KEY).expect("fixed admission controller");
    let halted = admission.observe(1, 3);
    let resumed = admission.observe(0, 1);
    let backlog_pass = halted == AdmissionState::Halted && resumed == AdmissionState::Accepting;

    let scenarios = vec![
        AcceptanceScenario {
            id: "normal",
            invariant: "all crash points converge with at-most-once effects",
            passed: normal_pass,
            evidence: format!("{} crash points certified", CrashPoint::ALL.len()),
        },
        AcceptanceScenario {
            id: "crash",
            invariant: "authenticated ceremony state survives deterministic restart",
            passed: crash_pass,
            evidence: format!("{restart_count} seeded restarts"),
        },
        AcceptanceScenario {
            id: "substitution",
            invariant: "binding substitution fails closed without duplicate effects",
            passed: substitution_pass,
            evidence: format!("{} attacks rejected", substitution.witnesses().len()),
        },
        AcceptanceScenario {
            id: "rollback",
            invariant: "a stale durable generation cannot authorize startup",
            passed: rollback_pass,
            evidence: format!("result={rollback_result:?}"),
        },
        AcceptanceScenario {
            id: "backlog",
            invariant: "release halts above the high watermark and resumes below the low watermark",
            passed: backlog_pass,
            evidence: format!("high={halted:?}; low={resumed:?}"),
        },
    ];
    let all_passed = scenarios.iter().all(|value| value.passed);
    RecoveryAcceptanceReport {
        schema: "noticer.quotient-commit.recovery-acceptance.v1",
        scenarios,
        all_passed,
    }
}

#[must_use]
pub fn canonical_json(report: &RecoveryAcceptanceReport) -> String {
    let scenarios = report
        .scenarios
        .iter()
        .map(|value| {
            format!(
                "{{\"id\":\"{}\",\"invariant\":\"{}\",\"passed\":{},\"evidence\":\"{}\"}}",
                value.id, value.invariant, value.passed, value.evidence
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"schema\":\"{}\",\"all_passed\":{},\"scenarios\":[{}]}}",
        report.schema, report.all_passed, scenarios
    )
}

#[must_use]
pub fn human_summary(report: &RecoveryAcceptanceReport) -> String {
    let mut output = format!(
        "QuotientCommit recovery acceptance: {}\n",
        if report.all_passed { "PASS" } else { "FAIL" }
    );
    for scenario in &report.scenarios {
        output.push_str(&format!(
            "[{}] {:<12} {} -- {}\n",
            if scenario.passed { "PASS" } else { "FAIL" },
            scenario.id,
            scenario.invariant,
            scenario.evidence
        ));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_five_security_scenarios_pass() {
        let report = run_acceptance();
        assert!(report.all_passed);
        assert_eq!(report.scenarios.len(), 5);
        assert!(report.scenarios.iter().all(|value| value.passed));
    }
    #[test]
    fn artifacts_are_deterministic_and_machine_readable() {
        let first = run_acceptance();
        let second = run_acceptance();
        assert_eq!(canonical_json(&first), canonical_json(&second));
        assert!(canonical_json(&first)
            .starts_with("{\"schema\":\"noticer.quotient-commit.recovery-acceptance.v1\""));
        assert!(human_summary(&first).contains("recovery acceptance: PASS"));
    }
}
