use quotient_seal_performance::{
    aggregate_campaigns, evaluate_budget, run_software_fixture, write_reproduction_artifacts,
    BenchmarkCase, BenchmarkRunConfig, BudgetConstraint, BudgetPlan, BudgetRule, BudgetStatistic,
    DeterministicFixturePlan, FixtureInvocation, FixtureInvocationPhase, FixtureRunArtifact,
    FixtureRunnerConfig, FixtureTask, GateOutcomeCounts, MeasurementFailureReason,
    MeasurementMetric, MeasurementOutcome, MeasurementProvenance, MeasurementStage,
    PerformanceBundleError, PerformanceGateVerdict, PerformanceReproductionBundle,
    SanitizedMachineMetadata, SoftwareFixtureBenchmark, StatisticsArtifact, StatisticsPlan,
};

const CASE: BenchmarkCase = BenchmarkCase {
    module_family_alias: 101,
    compiler_config_alias: 202,
    engine_alias: 303,
};

struct LogicalFixture {
    offset: u64,
    fail_iteration: Option<u32>,
}

impl SoftwareFixtureBenchmark for LogicalFixture {
    fn measure(&mut self, invocation: FixtureInvocation) -> MeasurementOutcome {
        if invocation.phase == FixtureInvocationPhase::Measured
            && self.fail_iteration == Some(invocation.iteration)
        {
            MeasurementOutcome::Failure {
                reason: MeasurementFailureReason::RuntimeTrap,
            }
        } else {
            MeasurementOutcome::Success {
                value: 100 + self.offset + u64::from(invocation.iteration),
            }
        }
    }
}

fn fixture_plan() -> DeterministicFixturePlan {
    DeterministicFixturePlan::build(vec![FixtureTask {
        stage: MeasurementStage::Runtime,
        metric: MeasurementMetric::LogicalFuel,
        case: CASE,
    }])
    .expect("fixture plan must be valid")
}

fn run_fixture(
    plan: DeterministicFixturePlan,
    seed: u64,
    offset: u64,
    fail_iteration: Option<u32>,
) -> FixtureRunArtifact {
    let config = FixtureRunnerConfig {
        measurement: BenchmarkRunConfig {
            seed,
            warmup_iterations: 1,
            measured_iterations: 3,
            max_samples: 3,
            wall_clock_opt_in: false,
            benchmark_plan_sha256: plan.artifact_sha256,
        },
        provenance: MeasurementProvenance::SoftwareFixture,
        max_tasks: 1,
        max_invocations: 4,
    };
    let machine = SanitizedMachineMetadata::injected_fixture([77; 32])
        .expect("fixture machine metadata must be valid");
    run_software_fixture(
        config,
        plan,
        machine,
        &mut LogicalFixture {
            offset,
            fail_iteration,
        },
    )
    .expect("software fixture run must succeed")
}

fn statistics(run: &FixtureRunArtifact) -> StatisticsArtifact {
    let plan =
        StatisticsPlan::build(1, 1, 16, vec![], vec![]).expect("statistics plan must be valid");
    aggregate_campaigns(plan, std::slice::from_ref(&run.campaign))
        .expect("statistics aggregation must succeed")
}

fn bundle(candidate_failure: Option<u32>) -> PerformanceReproductionBundle {
    let plan = fixture_plan();
    let baseline_fixture = run_fixture(plan.clone(), 41, 0, None);
    let candidate_fixture = run_fixture(plan, 42, 10, candidate_failure);
    let baseline_statistics = statistics(&baseline_fixture);
    let candidate_statistics = statistics(&candidate_fixture);
    let budget = BudgetPlan::build(vec![BudgetRule {
        rule_id: 1,
        key: quotient_seal_performance::MetricGroupKey {
            stage: MeasurementStage::Runtime,
            metric: MeasurementMetric::LogicalFuel,
            unit: MeasurementMetric::LogicalFuel.expected_unit(),
            case: CASE,
            provenance: MeasurementProvenance::SoftwareFixture,
        },
        statistic: BudgetStatistic::Median,
        constraint: BudgetConstraint::RelativeMaximum {
            ratio_millionths: 1_200_000,
        },
    }])
    .expect("budget plan must be valid");
    let gate = evaluate_budget(
        budget,
        baseline_statistics.clone(),
        candidate_statistics.clone(),
    )
    .expect("performance gate must evaluate");
    PerformanceReproductionBundle::build(
        baseline_fixture,
        candidate_fixture,
        baseline_statistics,
        candidate_statistics,
        gate,
    )
    .expect("performance bundle must build")
}

#[test]
fn bundle_cross_links_every_typed_artifact_and_keeps_claim_boundaries() {
    let bundle = bundle(None);

    bundle.validate().expect("bundle must validate");
    assert_eq!(bundle.evidence_origin, "SOFTWARE_FIXTURE");
    assert_eq!(bundle.security_interpretation, "NOT_A_SECURITY_VERDICT");
    assert_eq!(bundle.gate.verdict, PerformanceGateVerdict::Pass);
    assert_eq!(
        bundle.summary.gate_outcomes,
        GateOutcomeCounts {
            pass: 1,
            fail: 0,
            inconclusive: 0,
        }
    );
    assert_eq!(
        bundle.baseline_statistics.source_campaign_sha256,
        vec![bundle.baseline_fixture.campaign.artifact_sha256]
    );
}

#[test]
fn report_preserves_censored_outcomes_and_fixture_provenance() {
    let bundle = bundle(Some(1));

    let report = bundle.markdown_report().expect("report must render");

    assert_eq!(bundle.summary.candidate_outcomes.measured_failure, 1);
    assert!(report.contains("`SOFTWARE_FIXTURE`"));
    assert!(report.contains("`NOT_VERIFIED`"));
    assert!(report.contains("`NOT_A_SECURITY_VERDICT`"));
    assert!(report.contains("| Candidate | 2 | 1 | 0 |"));
}

#[test]
fn valid_but_unlinked_statistics_are_rejected() {
    let mut bundle = bundle(None);
    bundle.baseline_statistics = bundle.candidate_statistics.clone();

    assert!(matches!(
        bundle.validate(),
        Err(PerformanceBundleError::ArtifactMismatch)
    ));
}

#[test]
fn canonical_bundle_and_report_files_are_reproducible() {
    let first = bundle(None);
    let second = bundle(None);
    assert_eq!(
        first.canonical_json().expect("bundle must encode"),
        second.canonical_json().expect("bundle must encode")
    );
    assert_eq!(
        first.markdown_report().expect("report must render"),
        second.markdown_report().expect("report must render")
    );

    let root = std::env::temp_dir().join(format!(
        "quotient-seal-performance-bundle-{}-{}",
        std::process::id(),
        first.artifact_sha256[0]
    ));
    let json_path = root.join("bundle.json");
    let report_path = root.join("report.md");
    write_reproduction_artifacts(&first, &json_path, &report_path)
        .expect("artifact files must be written");
    assert_eq!(
        std::fs::read(&json_path).expect("JSON must be readable"),
        first.canonical_json().expect("bundle must encode")
    );
    assert_eq!(
        std::fs::read_to_string(&report_path).expect("report must be readable"),
        first.markdown_report().expect("report must render")
    );
    std::fs::remove_file(json_path).expect("temporary JSON must be removable");
    std::fs::remove_file(report_path).expect("temporary report must be removable");
    std::fs::remove_dir(root).expect("temporary directory must be removable");
}

#[test]
fn digest_tampering_and_ambiguous_output_paths_are_rejected() {
    let mut tampered = bundle(None);
    tampered.artifact_sha256[0] ^= 0xff;
    assert!(matches!(
        tampered.validate(),
        Err(PerformanceBundleError::ArtifactMismatch)
    ));

    let valid = bundle(None);
    let path = std::env::temp_dir().join("quotient-seal-same-output");
    assert!(matches!(
        write_reproduction_artifacts(&valid, &path, &path),
        Err(PerformanceBundleError::ArtifactMismatch)
    ));
}
