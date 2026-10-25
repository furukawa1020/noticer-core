//! Three-act deterministic security showcase composed from native recovery evaluators.
use crate::recovery_acceptance::run_acceptance;
use crate::recovery_telemetry_budget::{
    canonical_json as telemetry_json, RecoveryTelemetryBudget, TelemetryEvent, TelemetryPolicy,
};
use crate::startup_fault_oracle::run_fault_campaign;
const KEY: [u8; 32] = [0x50; 32];
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShowcaseAct {
    pub id: &'static str,
    pub headline: &'static str,
    pub invariant: &'static str,
    pub passed: bool,
    pub evidence: String,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryShowcase {
    pub schema: &'static str,
    pub seed: u64,
    pub acts: Vec<ShowcaseAct>,
    pub telemetry: String,
    pub all_passed: bool,
}
pub fn run_showcase(seed: u64) -> RecoveryShowcase {
    let acceptance = run_acceptance();
    let faults = run_fault_campaign(seed).expect("nonzero showcase seed");
    let normal = acceptance
        .scenarios
        .iter()
        .find(|v| v.id == "normal")
        .expect("normal");
    let substitution = acceptance
        .scenarios
        .iter()
        .find(|v| v.id == "substitution")
        .expect("substitution");
    let rollback = acceptance
        .scenarios
        .iter()
        .find(|v| v.id == "rollback")
        .expect("rollback");
    let acts = vec![
        ShowcaseAct {
            id: "normal",
            headline: "Seal and release",
            invariant: "all crash points converge with at-most-once effects",
            passed: normal.passed,
            evidence: normal.evidence.clone(),
        },
        ShowcaseAct {
            id: "crash",
            headline: "Cut power, keep truth",
            invariant: "every ceremony phase resumes without premature release",
            passed: faults.all_passed,
            evidence: format!("{} injected phase faults", faults.outcomes.len()),
        },
        ShowcaseAct {
            id: "attack",
            headline: "Substitute and rewind",
            invariant: "binding substitution and rollback both fail closed",
            passed: substitution.passed && rollback.passed,
            evidence: String::from("substitution=REJECTED; rollback=BLOCKED"),
        },
    ];
    let mut budget = RecoveryTelemetryBudget::new(
        TelemetryPolicy {
            epoch: 1,
            maximum_releases: 1,
        },
        KEY,
    )
    .expect("policy");
    budget.observe(TelemetryEvent::CeremonyCompleted);
    for _ in &faults.outcomes {
        budget.observe(TelemetryEvent::CrashRestart)
    }
    let telemetry = telemetry_json(budget.release().expect("single release"));
    let all_passed = acts.iter().all(|v| v.passed);
    RecoveryShowcase {
        schema: "noticer.recovery-showcase.v1",
        seed,
        acts,
        telemetry,
        all_passed,
    }
}
#[must_use]
pub fn canonical_json(v: &RecoveryShowcase) -> String {
    let acts=v.acts.iter().map(|a|format!("{{\"id\":\"{}\",\"headline\":\"{}\",\"invariant\":\"{}\",\"passed\":{},\"evidence\":\"{}\"}}",a.id,a.headline,a.invariant,a.passed,a.evidence)).collect::<Vec<_>>().join(",");
    format!(
        "{{\"schema\":\"{}\",\"seed\":{},\"all_passed\":{},\"acts\":[{}],\"telemetry\":{}}}",
        v.schema, v.seed, v.all_passed, acts, v.telemetry
    )
}
#[must_use]
pub fn summary(v: &RecoveryShowcase) -> String {
    let mut s = format!(
        "QuotientCommit Recovery Showcase -- {}\n",
        if v.all_passed { "PASS" } else { "FAIL" }
    );
    for (index, act) in v.acts.iter().enumerate() {
        s.push_str(&format!(
            "ACT {} / {} / {} / {}\n",
            index + 1,
            act.headline,
            if act.passed { "PASS" } else { "FAIL" },
            act.invariant
        ));
    }
    s
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn three_acts_pass_and_are_deterministic() {
        let a = run_showcase(0x5eed);
        let b = run_showcase(0x5eed);
        assert!(a.all_passed);
        assert_eq!(a.acts.len(), 3);
        assert_eq!(canonical_json(&a), canonical_json(&b));
        assert!(summary(&a).contains("ACT 3"));
    }
    #[test]
    fn artifact_has_no_private_identifiers() {
        let j = canonical_json(&run_showcase(0x5eed));
        for x in [
            "subject",
            "biosignal",
            "identity",
            "transaction_id",
            "device_id",
        ] {
            assert!(!j.contains(x));
        }
    }
}
