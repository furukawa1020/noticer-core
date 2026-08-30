use crate::{
    FixtureRunArtifact, FixtureRunSummary, FixtureRunnerError, GateInconclusiveReason,
    GateRuleOutcome, HardwareStatus, MeasurementProvenance, PerformanceGateArtifact,
    PerformanceGateError, PerformanceGateVerdict, StatisticsArtifact, StatisticsError,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use thiserror::Error;

pub const PERFORMANCE_BUNDLE_SCHEMA: &str = "quotient-seal.performance-reproduction-bundle.v1";

const BUNDLE_DOMAIN: &[u8] = b"QUOTIENT_SEAL_PERFORMANCE_REPRODUCTION_BUNDLE_V1";
const EVIDENCE_ORIGIN: &str = "SOFTWARE_FIXTURE";
const SECURITY_INTERPRETATION: &str = "NOT_A_SECURITY_VERDICT";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateOutcomeCounts {
    pub pass: u32,
    pub fail: u32,
    pub inconclusive: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformanceBundleSummary {
    pub baseline_fixture_sha256: [u8; 32],
    pub candidate_fixture_sha256: [u8; 32],
    pub baseline_statistics_sha256: [u8; 32],
    pub candidate_statistics_sha256: [u8; 32],
    pub gate_sha256: [u8; 32],
    pub baseline_outcomes: FixtureRunSummary,
    pub candidate_outcomes: FixtureRunSummary,
    pub gate_verdict: PerformanceGateVerdict,
    pub gate_outcomes: GateOutcomeCounts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformanceReproductionBundle {
    pub schema: String,
    pub baseline_fixture: FixtureRunArtifact,
    pub candidate_fixture: FixtureRunArtifact,
    pub baseline_statistics: StatisticsArtifact,
    pub candidate_statistics: StatisticsArtifact,
    pub gate: PerformanceGateArtifact,
    pub summary: PerformanceBundleSummary,
    pub evidence_origin: String,
    pub security_interpretation: String,
    pub hardware_status: HardwareStatus,
    pub artifact_sha256: [u8; 32],
}

impl PerformanceReproductionBundle {
    pub fn build(
        baseline_fixture: FixtureRunArtifact,
        candidate_fixture: FixtureRunArtifact,
        baseline_statistics: StatisticsArtifact,
        candidate_statistics: StatisticsArtifact,
        gate: PerformanceGateArtifact,
    ) -> Result<Self, PerformanceBundleError> {
        let summary = derive_summary(
            &baseline_fixture,
            &candidate_fixture,
            &baseline_statistics,
            &candidate_statistics,
            &gate,
        )?;
        let mut bundle = Self {
            schema: PERFORMANCE_BUNDLE_SCHEMA.to_owned(),
            baseline_fixture,
            candidate_fixture,
            baseline_statistics,
            candidate_statistics,
            gate,
            summary,
            evidence_origin: EVIDENCE_ORIGIN.to_owned(),
            security_interpretation: SECURITY_INTERPRETATION.to_owned(),
            hardware_status: HardwareStatus::NotVerified,
            artifact_sha256: [0; 32],
        };
        bundle.validate_components()?;
        bundle.artifact_sha256 = bundle.recomputed_sha256()?;
        Ok(bundle)
    }

    pub fn validate(&self) -> Result<(), PerformanceBundleError> {
        self.validate_components()?;
        if self.artifact_sha256 != self.recomputed_sha256()? {
            return Err(PerformanceBundleError::ArtifactMismatch);
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, PerformanceBundleError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| PerformanceBundleError::Json)
    }

    pub fn markdown_report(&self) -> Result<String, PerformanceBundleError> {
        self.validate()?;
        let mut report = String::new();
        writeln!(report, "# QuotientSeal Performance Reproduction Report")?;
        writeln!(report)?;
        writeln!(report, "- Evidence origin: `{}`", self.evidence_origin)?;
        writeln!(report, "- Hardware status: `NOT_VERIFIED`")?;
        writeln!(
            report,
            "- Security interpretation: `{}`",
            self.security_interpretation
        )?;
        writeln!(
            report,
            "- Performance gate verdict: `{}`",
            verdict_label(self.summary.gate_verdict)
        )?;
        writeln!(report)?;
        writeln!(
            report,
            "Performance `PASS` is not a security proof or a hardware claim."
        )?;
        writeln!(report)?;
        writeln!(report, "## Reproduction links")?;
        writeln!(report)?;
        writeln!(report, "| Artifact | SHA-256 |")?;
        writeln!(report, "|---|---|")?;
        writeln!(
            report,
            "| Baseline fixture | `{}` |",
            digest_hex(self.summary.baseline_fixture_sha256)
        )?;
        writeln!(
            report,
            "| Candidate fixture | `{}` |",
            digest_hex(self.summary.candidate_fixture_sha256)
        )?;
        writeln!(
            report,
            "| Baseline statistics | `{}` |",
            digest_hex(self.summary.baseline_statistics_sha256)
        )?;
        writeln!(
            report,
            "| Candidate statistics | `{}` |",
            digest_hex(self.summary.candidate_statistics_sha256)
        )?;
        writeln!(
            report,
            "| Budget gate | `{}` |",
            digest_hex(self.summary.gate_sha256)
        )?;
        writeln!(report)?;
        writeln!(report, "## Censored outcomes")?;
        writeln!(report)?;
        writeln!(
            report,
            "| Side | Measured success | Measured failure | Measured inconclusive |"
        )?;
        writeln!(report, "|---|---:|---:|---:|")?;
        writeln!(
            report,
            "| Baseline | {} | {} | {} |",
            self.summary.baseline_outcomes.measured_success,
            self.summary.baseline_outcomes.measured_failure,
            self.summary.baseline_outcomes.measured_inconclusive
        )?;
        writeln!(
            report,
            "| Candidate | {} | {} | {} |",
            self.summary.candidate_outcomes.measured_success,
            self.summary.candidate_outcomes.measured_failure,
            self.summary.candidate_outcomes.measured_inconclusive
        )?;
        writeln!(report)?;
        writeln!(report, "## Budget evaluations")?;
        writeln!(report)?;
        writeln!(
            report,
            "| Rule | Statistic | Candidate | Baseline | Increase | Ratio (millionths) | Outcome |"
        )?;
        writeln!(report, "|---:|---|---:|---:|---:|---:|---|")?;
        for (rule, evaluation) in self.gate.plan.rules.iter().zip(&self.gate.evaluations) {
            writeln!(
                report,
                "| {} | {} | {} | {} | {} | {} | {} |",
                rule.rule_id,
                statistic_label(rule.statistic),
                optional_number(evaluation.candidate_value),
                optional_number(evaluation.baseline_value),
                optional_number(evaluation.observed_increase),
                optional_number(evaluation.observed_ratio_millionths),
                outcome_label(evaluation.outcome)
            )?;
        }
        writeln!(report)?;
        writeln!(
            report,
            "Gate counts: PASS={}, FAIL={}, INCONCLUSIVE={}",
            self.summary.gate_outcomes.pass,
            self.summary.gate_outcomes.fail,
            self.summary.gate_outcomes.inconclusive
        )?;
        Ok(report)
    }

    fn validate_components(&self) -> Result<(), PerformanceBundleError> {
        self.baseline_fixture.validate()?;
        self.candidate_fixture.validate()?;
        self.baseline_statistics.validate()?;
        self.candidate_statistics.validate()?;
        self.gate.validate()?;

        let baseline_campaign = self.baseline_fixture.campaign.artifact_sha256;
        let candidate_campaign = self.candidate_fixture.campaign.artifact_sha256;
        let expected_summary = derive_summary(
            &self.baseline_fixture,
            &self.candidate_fixture,
            &self.baseline_statistics,
            &self.candidate_statistics,
            &self.gate,
        )?;
        if self.schema != PERFORMANCE_BUNDLE_SCHEMA
            || self.baseline_fixture.config.provenance != MeasurementProvenance::SoftwareFixture
            || self.candidate_fixture.config.provenance != MeasurementProvenance::SoftwareFixture
            || self.baseline_fixture.plan != self.candidate_fixture.plan
            || self.baseline_fixture.campaign.machine != self.candidate_fixture.campaign.machine
            || self.baseline_statistics.source_campaign_sha256 != vec![baseline_campaign]
            || self.candidate_statistics.source_campaign_sha256 != vec![candidate_campaign]
            || self.gate.baseline != self.baseline_statistics
            || self.gate.candidate != self.candidate_statistics
            || self.summary != expected_summary
            || self.evidence_origin != EVIDENCE_ORIGIN
            || self.security_interpretation != SECURITY_INTERPRETATION
            || self.hardware_status != HardwareStatus::NotVerified
        {
            return Err(PerformanceBundleError::ArtifactMismatch);
        }
        Ok(())
    }

    fn recomputed_sha256(&self) -> Result<[u8; 32], PerformanceBundleError> {
        let mut value = self.clone();
        value.artifact_sha256 = [0; 32];
        let encoded = serde_json::to_vec(&value).map_err(|_| PerformanceBundleError::Json)?;
        Ok(domain_hash(BUNDLE_DOMAIN, &encoded))
    }
}

pub fn write_reproduction_artifacts(
    bundle: &PerformanceReproductionBundle,
    json_path: impl AsRef<Path>,
    report_path: impl AsRef<Path>,
) -> Result<(), PerformanceBundleError> {
    bundle.validate()?;
    let json_path = json_path.as_ref();
    let report_path = report_path.as_ref();
    if json_path == report_path {
        return Err(PerformanceBundleError::ArtifactMismatch);
    }
    create_parent(json_path)?;
    create_parent(report_path)?;
    fs::write(json_path, bundle.canonical_json()?)?;
    fs::write(report_path, bundle.markdown_report()?.as_bytes())?;
    Ok(())
}

fn derive_summary(
    baseline_fixture: &FixtureRunArtifact,
    candidate_fixture: &FixtureRunArtifact,
    baseline_statistics: &StatisticsArtifact,
    candidate_statistics: &StatisticsArtifact,
    gate: &PerformanceGateArtifact,
) -> Result<PerformanceBundleSummary, PerformanceBundleError> {
    let mut gate_outcomes = GateOutcomeCounts {
        pass: 0,
        fail: 0,
        inconclusive: 0,
    };
    for evaluation in &gate.evaluations {
        let count = match evaluation.outcome {
            GateRuleOutcome::Pass => &mut gate_outcomes.pass,
            GateRuleOutcome::Fail => &mut gate_outcomes.fail,
            GateRuleOutcome::Inconclusive { .. } => &mut gate_outcomes.inconclusive,
        };
        *count = count
            .checked_add(1)
            .ok_or(PerformanceBundleError::ArtifactMismatch)?;
    }
    Ok(PerformanceBundleSummary {
        baseline_fixture_sha256: baseline_fixture.artifact_sha256,
        candidate_fixture_sha256: candidate_fixture.artifact_sha256,
        baseline_statistics_sha256: baseline_statistics.artifact_sha256,
        candidate_statistics_sha256: candidate_statistics.artifact_sha256,
        gate_sha256: gate.artifact_sha256,
        baseline_outcomes: baseline_fixture.summary,
        candidate_outcomes: candidate_fixture.summary,
        gate_verdict: gate.verdict,
        gate_outcomes,
    })
}

fn create_parent(path: &Path) -> Result<(), PerformanceBundleError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn optional_number(value: Option<u64>) -> String {
    value.map_or_else(|| "-".to_owned(), |value| value.to_string())
}

fn verdict_label(verdict: PerformanceGateVerdict) -> &'static str {
    match verdict {
        PerformanceGateVerdict::Pass => "PASS",
        PerformanceGateVerdict::Fail => "FAIL",
        PerformanceGateVerdict::Inconclusive => "INCONCLUSIVE",
    }
}

fn outcome_label(outcome: GateRuleOutcome) -> &'static str {
    match outcome {
        GateRuleOutcome::Pass => "PASS",
        GateRuleOutcome::Fail => "FAIL",
        GateRuleOutcome::Inconclusive { reason } => inconclusive_label(reason),
    }
}

fn inconclusive_label(reason: GateInconclusiveReason) -> &'static str {
    match reason {
        GateInconclusiveReason::MissingCandidateGroup => "INCONCLUSIVE:MISSING_CANDIDATE_GROUP",
        GateInconclusiveReason::MissingBaselineGroup => "INCONCLUSIVE:MISSING_BASELINE_GROUP",
        GateInconclusiveReason::UnitMismatch => "INCONCLUSIVE:UNIT_MISMATCH",
        GateInconclusiveReason::InsufficientSuccessSamples => {
            "INCONCLUSIVE:INSUFFICIENT_SUCCESS_SAMPLES"
        }
        GateInconclusiveReason::ZeroBaseline => "INCONCLUSIVE:ZERO_BASELINE",
        GateInconclusiveReason::ArithmeticOverflow => "INCONCLUSIVE:ARITHMETIC_OVERFLOW",
    }
}

fn statistic_label(statistic: crate::BudgetStatistic) -> &'static str {
    match statistic {
        crate::BudgetStatistic::Median => "MEDIAN",
        crate::BudgetStatistic::P95 => "P95",
        crate::BudgetStatistic::P99 => "P99",
        crate::BudgetStatistic::MedianAbsoluteDeviation => "MEDIAN_ABSOLUTE_DEVIATION",
        crate::BudgetStatistic::FailureRateMillionths => "FAILURE_RATE_MILLIONTHS",
        crate::BudgetStatistic::InconclusiveRateMillionths => "INCONCLUSIVE_RATE_MILLIONTHS",
    }
}

fn digest_hex(digest: [u8; 32]) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}

#[derive(Debug, Error)]
pub enum PerformanceBundleError {
    #[error("performance reproduction bundle failed full recomputation")]
    ArtifactMismatch,
    #[error("performance reproduction bundle JSON serialization failed")]
    Json,
    #[error("performance reproduction report formatting failed")]
    Formatting(#[from] std::fmt::Error),
    #[error("performance reproduction artifact I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("software fixture artifact was rejected: {0}")]
    Fixture(#[from] FixtureRunnerError),
    #[error("statistics artifact was rejected: {0}")]
    Statistics(#[from] StatisticsError),
    #[error("performance gate artifact was rejected: {0}")]
    Gate(#[from] PerformanceGateError),
}
