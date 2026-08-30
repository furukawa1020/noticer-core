use quotient_seal_performance::{
    aggregate_campaigns, evaluate_budget, run_software_fixture, write_reproduction_artifacts,
    BenchmarkCase, BenchmarkRunConfig, BudgetConstraint, BudgetPlan, BudgetRule, BudgetStatistic,
    DeterministicFixturePlan, FixtureInvocation, FixtureRunArtifact, FixtureRunnerConfig,
    FixtureTask, MeasurementMetric, MeasurementOutcome, MeasurementProvenance, MeasurementStage,
    PerformanceReproductionBundle, SanitizedMachineMetadata, SoftwareFixtureBenchmark,
    StatisticsArtifact, StatisticsPlan,
};
use std::path::PathBuf;

const CASE: BenchmarkCase = BenchmarkCase {
    module_family_alias: 101,
    compiler_config_alias: 202,
    engine_alias: 303,
};

struct LogicalFixture {
    offset: u64,
}

impl SoftwareFixtureBenchmark for LogicalFixture {
    fn measure(&mut self, invocation: FixtureInvocation) -> MeasurementOutcome {
        MeasurementOutcome::Success {
            value: 100 + self.offset + u64::from(invocation.iteration),
        }
    }
}

fn run_fixture(
    plan: DeterministicFixturePlan,
    seed: u64,
    offset: u64,
) -> Result<FixtureRunArtifact, Box<dyn std::error::Error>> {
    let config = FixtureRunnerConfig {
        measurement: BenchmarkRunConfig {
            seed,
            warmup_iterations: 1,
            measured_iterations: 5,
            max_samples: 5,
            wall_clock_opt_in: false,
            benchmark_plan_sha256: plan.artifact_sha256,
        },
        provenance: MeasurementProvenance::SoftwareFixture,
        max_tasks: 1,
        max_invocations: 6,
    };
    let machine = SanitizedMachineMetadata::injected_fixture([77; 32])?;
    Ok(run_software_fixture(
        config,
        plan,
        machine,
        &mut LogicalFixture { offset },
    )?)
}

fn statistics(run: &FixtureRunArtifact) -> Result<StatisticsArtifact, Box<dyn std::error::Error>> {
    let plan = StatisticsPlan::build(3, 1, 16, vec![], vec![])?;
    Ok(aggregate_campaigns(
        plan,
        std::slice::from_ref(&run.campaign),
    )?)
}

fn output_paths() -> (PathBuf, PathBuf) {
    let requested = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("artifacts/quotient_seal/performance"));
    if requested
        .extension()
        .is_some_and(|extension| extension == "json")
    {
        let report = requested.with_extension("md");
        (requested, report)
    } else {
        (
            requested.join("performance_bundle.json"),
            requested.join("performance_report.md"),
        )
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fixture_plan = DeterministicFixturePlan::build(vec![FixtureTask {
        stage: MeasurementStage::Runtime,
        metric: MeasurementMetric::LogicalFuel,
        case: CASE,
    }])?;
    let baseline_fixture = run_fixture(fixture_plan.clone(), 41, 0)?;
    let candidate_fixture = run_fixture(fixture_plan, 42, 10)?;
    let baseline_statistics = statistics(&baseline_fixture)?;
    let candidate_statistics = statistics(&candidate_fixture)?;
    let budget = BudgetPlan::build(vec![BudgetRule {
        rule_id: 1,
        key: quotient_seal_performance::MetricGroupKey {
            stage: MeasurementStage::Runtime,
            metric: MeasurementMetric::LogicalFuel,
            unit: MeasurementMetric::LogicalFuel.expected_unit(),
            case: CASE,
            provenance: MeasurementProvenance::SoftwareFixture,
        },
        statistic: BudgetStatistic::P95,
        constraint: BudgetConstraint::RelativeMaximum {
            ratio_millionths: 1_200_000,
        },
    }])?;
    let gate = evaluate_budget(
        budget,
        baseline_statistics.clone(),
        candidate_statistics.clone(),
    )?;
    let bundle = PerformanceReproductionBundle::build(
        baseline_fixture,
        candidate_fixture,
        baseline_statistics,
        candidate_statistics,
        gate,
    )?;
    let (json_path, report_path) = output_paths();
    write_reproduction_artifacts(&bundle, &json_path, &report_path)?;

    println!("evidence_origin=SOFTWARE_FIXTURE");
    println!("hardware_status=NOT_VERIFIED");
    println!("security_interpretation=NOT_A_SECURITY_VERDICT");
    println!("performance_verdict={:?}", bundle.gate.verdict);
    println!("json={}", json_path.display());
    println!("report={}", report_path.display());
    Ok(())
}
