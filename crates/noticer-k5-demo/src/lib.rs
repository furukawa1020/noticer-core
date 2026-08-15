use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PUBLIC_ARTIFACT_SCHEMA: &str = "noticer-k5-tier-a-public-v1";

#[derive(Debug, Clone, Deserialize)]
pub struct ProvenanceSummary {
    pub schema: String,
    pub seed: u64,
    pub case_count: usize,
    pub all_private_inputs_distinct: bool,
    pub all_congruent: bool,
    pub rates: CongruenceRates,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CongruenceRates {
    pub pointwise_provenance: f64,
    pub lease: f64,
    pub atv2_trace: f64,
    pub k4_trace: f64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct K4Summary {
    pub schema_version: u32,
    pub observer_trace_equal: bool,
    pub both_reassembled: bool,
    pub both_authorized: bool,
    pub execution_trace_equal: bool,
    pub replay_rejected_without_actuation: bool,
    pub provenance_mode: String,
    pub tier_a: String,
    pub tier_b: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SoftwareGateSummary {
    pub schema: String,
    pub all_passed: bool,
    pub gates: Vec<SoftwareGate>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SoftwareGate {
    pub id: String,
    pub status: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Decision {
    GoTierA,
    Pivot,
    Kill,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScenarioOutcome {
    AuthorizedAction,
    RejectedCover,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScenarioResult {
    pub id: String,
    pub expected: ScenarioOutcome,
    pub observed: ScenarioOutcome,
    pub reason_code: String,
    pub authorized_action_count: u32,
    pub unauthorized_action_count: u32,
    pub cover_behavior: bool,
    pub passed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PipelineStage {
    pub id: String,
    pub status: String,
    pub evidence_kind: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LeaseInspection {
    pub authorized_scenario_count: usize,
    pub rejected_scenario_count: usize,
    pub all_rejections_used_cover: bool,
    pub unauthorized_action_count: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct PipelineInspection {
    pub counterfactual_case_count: usize,
    pub all_private_inputs_distinct: bool,
    pub pointwise_provenance_congruent: bool,
    pub lease_congruent: bool,
    pub atv2_trace_congruent: bool,
    pub k4_trace_congruent: bool,
    pub observer_trace_equal: bool,
    pub execution_trace_equal: bool,
    pub replay_rejected_without_actuation: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct HardwareTier {
    pub tier: String,
    pub status: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicArtifact {
    pub schema: String,
    pub seed: u64,
    pub tier_a: String,
    pub decision: Decision,
    pub source_profile: String,
    pub private_field_count: usize,
    pub all_software_gates_passed: bool,
    pub all_scenarios_passed: bool,
    pub pipeline: Vec<PipelineStage>,
    pub scenarios: Vec<ScenarioResult>,
    pub lease_inspection: LeaseInspection,
    pub pipeline_inspection: PipelineInspection,
    pub hardware_tiers: Vec<HardwareTier>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactValidation {
    pub private_field_count: usize,
    pub forbidden_paths: Vec<String>,
}

pub struct LeaseInspector;

impl LeaseInspector {
    pub fn inspect(scenarios: &[ScenarioResult]) -> LeaseInspection {
        let authorized_scenario_count = scenarios
            .iter()
            .filter(|scenario| scenario.observed == ScenarioOutcome::AuthorizedAction)
            .count();
        let rejected: Vec<_> = scenarios
            .iter()
            .filter(|scenario| scenario.observed == ScenarioOutcome::RejectedCover)
            .collect();
        LeaseInspection {
            authorized_scenario_count,
            rejected_scenario_count: rejected.len(),
            all_rejections_used_cover: rejected.iter().all(|scenario| scenario.cover_behavior),
            unauthorized_action_count: scenarios
                .iter()
                .map(|scenario| scenario.unauthorized_action_count)
                .sum(),
        }
    }
}

pub struct PipelineInspector;

impl PipelineInspector {
    pub fn inspect(provenance: &ProvenanceSummary, k4: &K4Summary) -> PipelineInspection {
        PipelineInspection {
            counterfactual_case_count: provenance.case_count,
            all_private_inputs_distinct: provenance.all_private_inputs_distinct,
            pointwise_provenance_congruent: rate_is_one(provenance.rates.pointwise_provenance),
            lease_congruent: rate_is_one(provenance.rates.lease),
            atv2_trace_congruent: rate_is_one(provenance.rates.atv2_trace),
            k4_trace_congruent: rate_is_one(provenance.rates.k4_trace),
            observer_trace_equal: k4.observer_trace_equal,
            execution_trace_equal: k4.execution_trace_equal,
            replay_rejected_without_actuation: k4.replay_rejected_without_actuation,
        }
    }
}

pub struct PublicArtifactValidator;

impl PublicArtifactValidator {
    pub fn validate(value: &Value) -> ArtifactValidation {
        let forbidden: BTreeSet<&str> = [
            "raw_ppg",
            "ppg_samples",
            "raw_acc",
            "acc_samples",
            "baseline_values",
            "private_history",
            "device_id",
            "attestation_chain",
            "permit_signature",
            "lease_bytes",
            "token_bytes",
            "key_material",
        ]
        .into_iter()
        .collect();
        let mut paths = Vec::new();
        visit_value(value, "$", &forbidden, &mut paths);
        ArtifactValidation {
            private_field_count: paths.len(),
            forbidden_paths: paths,
        }
    }
}

pub fn build_public_artifact(
    provenance: &ProvenanceSummary,
    k4: &K4Summary,
    gates: &SoftwareGateSummary,
) -> PublicArtifact {
    let pipeline_inspection = PipelineInspector::inspect(provenance, k4);
    let pipeline_ok = provenance.schema == "noticer-aepa-counterfactual-v1"
        && provenance.all_congruent
        && k4.schema_version == 1
        && k4.tier_a == "VERIFIED"
        && k4.both_reassembled
        && k4.both_authorized
        && gates.schema == "noticer-k5-software-gates-v1"
        && gates.all_passed
        && pipeline_inspection.pointwise_provenance_congruent
        && pipeline_inspection.lease_congruent
        && pipeline_inspection.atv2_trace_congruent
        && pipeline_inspection.k4_trace_congruent
        && pipeline_inspection.observer_trace_equal
        && pipeline_inspection.execution_trace_equal
        && pipeline_inspection.replay_rejected_without_actuation;

    let scenarios = scenario_contracts()
        .into_iter()
        .map(|contract| evaluate_scenario(contract, pipeline_ok, k4))
        .collect::<Vec<_>>();
    let lease_inspection = LeaseInspector::inspect(&scenarios);
    let pipeline = pipeline_stages(gates, provenance, k4);
    let all_scenarios_passed = scenarios.iter().all(|scenario| scenario.passed);

    let mut artifact = PublicArtifact {
        schema: PUBLIC_ARTIFACT_SCHEMA.to_owned(),
        seed: provenance.seed,
        tier_a: if pipeline_ok { "VERIFIED" } else { "FAILED" }.to_owned(),
        decision: Decision::Pivot,
        source_profile: "synthetic-paired-commercial-sensor-v1".to_owned(),
        private_field_count: 0,
        all_software_gates_passed: gates.all_passed,
        all_scenarios_passed,
        pipeline,
        scenarios,
        lease_inspection,
        pipeline_inspection,
        hardware_tiers: vec![
            unverified_hardware_tier("B", "physical sensor and Android collector"),
            unverified_hardware_tier("C", "hardware-backed attestation and appraiser"),
            unverified_hardware_tier("D", "sustained field and adversarial measurements"),
        ],
    };

    let value = serde_json::to_value(&artifact).expect("public artifact is serializable");
    artifact.private_field_count = PublicArtifactValidator::validate(&value).private_field_count;
    artifact.decision = decide(&artifact, pipeline_ok);
    artifact
}

pub fn write_public_artifacts(
    artifact: &PublicArtifact,
    output: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(output)?;
    let summary = serde_json::to_value(artifact)?;
    let validation = PublicArtifactValidator::validate(&summary);
    if validation.private_field_count != 0 {
        return Err(format!(
            "private fields in public artifact: {:?}",
            validation.forbidden_paths
        )
        .into());
    }
    fs::write(
        output.join("summary.json"),
        format!("{}\n", serde_json::to_string_pretty(&summary)?),
    )?;
    fs::write(
        output.join("scenarios.csv"),
        scenarios_csv(&artifact.scenarios),
    )?;
    fs::write(
        output.join("manifest.json"),
        "{\n  \"schema\": \"noticer-k5-public-manifest-v1\",\n  \"files\": [\"summary.json\", \"scenarios.csv\"]\n}\n",
    )?;
    Ok(())
}

fn decide(artifact: &PublicArtifact, pipeline_ok: bool) -> Decision {
    let valid_failed = artifact.scenarios.iter().any(|scenario| {
        scenario.id == "valid" && scenario.observed != ScenarioOutcome::AuthorizedAction
    });
    if artifact.private_field_count > 0 || artifact.lease_inspection.unauthorized_action_count > 0 {
        Decision::Kill
    } else if !artifact.all_software_gates_passed {
        Decision::Pivot
    } else if valid_failed || !artifact.all_scenarios_passed {
        Decision::Kill
    } else if pipeline_ok && artifact.all_scenarios_passed {
        Decision::GoTierA
    } else {
        Decision::Kill
    }
}

#[derive(Debug, Clone, Copy)]
struct ScenarioContract {
    id: &'static str,
    has_lease: bool,
    expired: bool,
    downgrade: bool,
    key_matches: bool,
    replay: bool,
    lab_unattested: bool,
}

fn scenario_contracts() -> [ScenarioContract; 7] {
    [
        ScenarioContract {
            id: "valid",
            has_lease: true,
            expired: false,
            downgrade: false,
            key_matches: true,
            replay: false,
            lab_unattested: false,
        },
        ScenarioContract {
            id: "no_lease",
            has_lease: false,
            expired: false,
            downgrade: false,
            key_matches: true,
            replay: false,
            lab_unattested: false,
        },
        ScenarioContract {
            id: "expired",
            has_lease: true,
            expired: true,
            downgrade: false,
            key_matches: true,
            replay: false,
            lab_unattested: false,
        },
        ScenarioContract {
            id: "downgrade",
            has_lease: true,
            expired: false,
            downgrade: true,
            key_matches: true,
            replay: false,
            lab_unattested: false,
        },
        ScenarioContract {
            id: "wrong_key",
            has_lease: true,
            expired: false,
            downgrade: false,
            key_matches: false,
            replay: false,
            lab_unattested: false,
        },
        ScenarioContract {
            id: "replay",
            has_lease: true,
            expired: false,
            downgrade: false,
            key_matches: true,
            replay: true,
            lab_unattested: false,
        },
        ScenarioContract {
            id: "lab_unattested",
            has_lease: true,
            expired: false,
            downgrade: false,
            key_matches: true,
            replay: false,
            lab_unattested: true,
        },
    ]
}

fn evaluate_scenario(
    contract: ScenarioContract,
    pipeline_ok: bool,
    k4: &K4Summary,
) -> ScenarioResult {
    let (observed, reason_code) = if contract.lab_unattested {
        (ScenarioOutcome::RejectedCover, "LAB_UNATTESTED")
    } else if !contract.has_lease {
        (ScenarioOutcome::RejectedCover, "LEASE_MISSING")
    } else if contract.expired {
        (ScenarioOutcome::RejectedCover, "LEASE_EXPIRED")
    } else if contract.downgrade {
        (ScenarioOutcome::RejectedCover, "PROFILE_DOWNGRADE")
    } else if !contract.key_matches {
        (ScenarioOutcome::RejectedCover, "KEY_BINDING_MISMATCH")
    } else if contract.replay {
        if k4.replay_rejected_without_actuation {
            (ScenarioOutcome::RejectedCover, "REPLAY_REJECTED")
        } else {
            (ScenarioOutcome::AuthorizedAction, "REPLAY_NOT_REJECTED")
        }
    } else if pipeline_ok {
        (ScenarioOutcome::AuthorizedAction, "ADMITTED_ONCE")
    } else {
        (ScenarioOutcome::RejectedCover, "PIPELINE_GATE_FAILED")
    };
    let expected = if contract.id == "valid" {
        ScenarioOutcome::AuthorizedAction
    } else {
        ScenarioOutcome::RejectedCover
    };
    ScenarioResult {
        id: contract.id.to_owned(),
        expected,
        observed,
        reason_code: reason_code.to_owned(),
        authorized_action_count: u32::from(observed == ScenarioOutcome::AuthorizedAction),
        unauthorized_action_count: u32::from(
            contract.id != "valid" && observed == ScenarioOutcome::AuthorizedAction,
        ),
        cover_behavior: observed == ScenarioOutcome::RejectedCover,
        passed: observed == expected,
    }
}

fn pipeline_stages(
    gates: &SoftwareGateSummary,
    provenance: &ProvenanceSummary,
    k4: &K4Summary,
) -> Vec<PipelineStage> {
    let gate_passed = |id: &str| {
        gates
            .gates
            .iter()
            .any(|gate| gate.id == id && gate.status == "PASSED")
    };
    vec![
        stage(
            "acquisition",
            gate_passed("synthetic_acquisition"),
            "cargo-test",
        ),
        stage(
            "k1_evidence_permit",
            gate_passed("k1_evidence_bridge"),
            "cargo-test",
        ),
        stage(
            "npl1_appraisal",
            gate_passed("npl1_appraiser"),
            "cargo-test",
        ),
        stage(
            "production_lease",
            gate_passed("production_lease_guard"),
            "cargo-test",
        ),
        stage(
            "atv2",
            provenance.rates.atv2_trace == 1.0,
            "counterfactual-sim",
        ),
        stage("k4_transport", k4.observer_trace_equal, "transport-sim"),
        stage(
            "virtual_menfugu",
            k4.both_authorized && k4.execution_trace_equal,
            "virtual-execution",
        ),
    ]
}

fn stage(id: &str, passed: bool, evidence_kind: &str) -> PipelineStage {
    PipelineStage {
        id: id.to_owned(),
        status: if passed { "VERIFIED" } else { "FAILED" }.to_owned(),
        evidence_kind: evidence_kind.to_owned(),
    }
}

fn unverified_hardware_tier(tier: &str, evidence: &str) -> HardwareTier {
    HardwareTier {
        tier: tier.to_owned(),
        status: "NOT_VERIFIED".to_owned(),
        evidence: evidence.to_owned(),
    }
}

fn rate_is_one(rate: f64) -> bool {
    (rate - 1.0).abs() <= f64::EPSILON
}

fn visit_value(value: &Value, path: &str, forbidden: &BTreeSet<&str>, found: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if forbidden.contains(key.as_str()) {
                    found.push(child_path.clone());
                }
                visit_value(child, &child_path, forbidden, found);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                visit_value(child, &format!("{path}[{index}]"), forbidden, found);
            }
        }
        _ => {}
    }
}

fn scenarios_csv(scenarios: &[ScenarioResult]) -> String {
    let mut csv = String::from(
        "id,expected,observed,reason_code,authorized_action_count,unauthorized_action_count,cover_behavior,passed\n",
    );
    for scenario in scenarios {
        writeln!(
            csv,
            "{},{:?},{:?},{},{},{},{},{}",
            scenario.id,
            scenario.expected,
            scenario.observed,
            scenario.reason_code,
            scenario.authorized_action_count,
            scenario.unauthorized_action_count,
            scenario.cover_behavior,
            scenario.passed,
        )
        .expect("writing to String cannot fail");
    }
    csv
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn tier_a_contract_authorizes_only_valid_once() {
        let artifact = build_public_artifact(&provenance(), &k4(), &gates());
        assert_eq!(artifact.decision, Decision::GoTierA);
        assert_eq!(artifact.lease_inspection.authorized_scenario_count, 1);
        assert_eq!(artifact.lease_inspection.rejected_scenario_count, 6);
        assert_eq!(artifact.lease_inspection.unauthorized_action_count, 0);
        assert!(artifact.all_scenarios_passed);
        assert_eq!(artifact.private_field_count, 0);
    }

    #[test]
    fn replay_failure_kills_the_validity_claim() {
        let mut k4 = k4();
        k4.replay_rejected_without_actuation = false;
        let artifact = build_public_artifact(&provenance(), &k4, &gates());
        assert_eq!(artifact.decision, Decision::Kill);
        assert_eq!(artifact.lease_inspection.unauthorized_action_count, 1);
    }

    #[test]
    fn failed_software_gate_pivots_without_false_action() {
        let mut gates = gates();
        gates.all_passed = false;
        let artifact = build_public_artifact(&provenance(), &k4(), &gates);
        assert_eq!(artifact.decision, Decision::Pivot);
        assert_eq!(artifact.lease_inspection.unauthorized_action_count, 0);
    }

    #[test]
    fn public_validator_finds_exact_private_keys() {
        let validation = PublicArtifactValidator::validate(&json!({
            "schema": PUBLIC_ARTIFACT_SCHEMA,
            "nested": {"device_id": "must-not-appear"},
            "private_field_count": 0
        }));
        assert_eq!(validation.private_field_count, 1);
        assert_eq!(validation.forbidden_paths, vec!["$.nested.device_id"]);
    }

    #[test]
    fn hardware_tiers_never_inherit_tier_a_verification() {
        let artifact = build_public_artifact(&provenance(), &k4(), &gates());
        assert!(artifact
            .hardware_tiers
            .iter()
            .all(|tier| tier.status == "NOT_VERIFIED"));
    }

    fn provenance() -> ProvenanceSummary {
        ProvenanceSummary {
            schema: "noticer-aepa-counterfactual-v1".to_owned(),
            seed: 20_260_814,
            case_count: 24,
            all_private_inputs_distinct: true,
            all_congruent: true,
            rates: CongruenceRates {
                pointwise_provenance: 1.0,
                lease: 1.0,
                atv2_trace: 1.0,
                k4_trace: 1.0,
            },
        }
    }

    fn k4() -> K4Summary {
        K4Summary {
            schema_version: 1,
            observer_trace_equal: true,
            both_reassembled: true,
            both_authorized: true,
            execution_trace_equal: true,
            replay_rejected_without_actuation: true,
            provenance_mode: "LAB_UNATTESTED".to_owned(),
            tier_a: "VERIFIED".to_owned(),
            tier_b: "NOT_VERIFIED".to_owned(),
        }
    }

    fn gates() -> SoftwareGateSummary {
        SoftwareGateSummary {
            schema: "noticer-k5-software-gates-v1".to_owned(),
            all_passed: true,
            gates: [
                "synthetic_acquisition",
                "k1_evidence_bridge",
                "npl1_appraiser",
                "production_lease_guard",
            ]
            .into_iter()
            .map(|id| SoftwareGate {
                id: id.to_owned(),
                status: "PASSED".to_owned(),
            })
            .collect(),
        }
    }
}
