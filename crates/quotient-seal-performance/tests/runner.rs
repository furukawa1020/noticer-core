use quotient_seal_performance::{
    run_software_fixture, BenchmarkCase, BenchmarkRunConfig, DeterministicFixturePlan,
    FixtureInvocation, FixtureInvocationPhase, FixtureRunnerConfig, FixtureRunnerError,
    FixtureTask, MeasurementFailureReason, MeasurementInconclusiveReason, MeasurementMetric,
    MeasurementOutcome, MeasurementProvenance, MeasurementStage, SanitizedMachineMetadata,
    SoftwareFixtureBenchmark,
};

struct FormulaFixture;

impl SoftwareFixtureBenchmark for FormulaFixture {
    fn measure(&mut self, invocation: FixtureInvocation) -> MeasurementOutcome {
        MeasurementOutcome::Success {
            value: u64::from(invocation.task_index) * 100
                + u64::from(invocation.iteration)
                + invocation.public_randomness_word % 17,
        }
    }
}

struct CensoredFixture;

impl SoftwareFixtureBenchmark for CensoredFixture {
    fn measure(&mut self, invocation: FixtureInvocation) -> MeasurementOutcome {
        match invocation.task.case.module_family_alias {
            1 => panic!("injected fixture panic"),
            2 => MeasurementOutcome::Failure {
                reason: MeasurementFailureReason::ParseError,
            },
            3 => MeasurementOutcome::Inconclusive {
                reason: MeasurementInconclusiveReason::ResourceBound,
            },
            _ => MeasurementOutcome::Success { value: 7 },
        }
    }
}

fn case(alias: u32) -> BenchmarkCase {
    BenchmarkCase {
        module_family_alias: alias,
        compiler_config_alias: 1,
        engine_alias: 1,
    }
}

fn task(stage: MeasurementStage, metric: MeasurementMetric, alias: u32) -> FixtureTask {
    FixtureTask {
        stage,
        metric,
        case: case(alias),
    }
}

fn plan() -> DeterministicFixturePlan {
    DeterministicFixturePlan::build(vec![
        task(
            MeasurementStage::Validate,
            MeasurementMetric::LogicalFuel,
            1,
        ),
        task(
            MeasurementStage::Runtime,
            MeasurementMetric::HostCallCount,
            2,
        ),
        task(
            MeasurementStage::CapsuleEncode,
            MeasurementMetric::ArtifactSize,
            3,
        ),
    ])
    .unwrap()
}

fn config(plan: &DeterministicFixturePlan, warmup: u32, measured: u32) -> FixtureRunnerConfig {
    FixtureRunnerConfig {
        measurement: BenchmarkRunConfig {
            seed: 0x5eed,
            warmup_iterations: warmup,
            measured_iterations: measured,
            max_samples: 128,
            wall_clock_opt_in: false,
            benchmark_plan_sha256: plan.artifact_sha256,
        },
        provenance: MeasurementProvenance::SoftwareFixture,
        max_tasks: 16,
        max_invocations: 256,
    }
}

fn machine() -> SanitizedMachineMetadata {
    SanitizedMachineMetadata::injected_fixture([0x33; 32]).unwrap()
}

#[test]
fn same_seed_and_plan_produce_byte_identical_fixture_artifact() {
    let plan = plan();
    let mut left_fixture = FormulaFixture;
    let mut right_fixture = FormulaFixture;
    let left = run_software_fixture(
        config(&plan, 2, 3),
        plan.clone(),
        machine(),
        &mut left_fixture,
    )
    .unwrap();
    let right =
        run_software_fixture(config(&plan, 2, 3), plan, machine(), &mut right_fixture).unwrap();
    assert_eq!(
        left.canonical_json().unwrap(),
        right.canonical_json().unwrap()
    );
    assert_eq!(left.invocations.len(), 15);
    assert_eq!(left.campaign.samples.len(), 9);
    assert_eq!(left.summary.warmup_success, 6);
    assert_eq!(left.summary.measured_success, 9);
    assert!(left.invocations.iter().all(|record| {
        record.phase != FixtureInvocationPhase::Warmup || record.sample_sha256.is_none()
    }));
}

#[test]
fn panic_failure_and_resource_bound_remain_typed() {
    let plan = DeterministicFixturePlan::build(vec![
        task(MeasurementStage::Parse, MeasurementMetric::LogicalFuel, 1),
        task(MeasurementStage::Parse, MeasurementMetric::LogicalFuel, 2),
        task(
            MeasurementStage::ContextCheck,
            MeasurementMetric::LogicalFuel,
            3,
        ),
        task(MeasurementStage::Runtime, MeasurementMetric::LogicalFuel, 4),
    ])
    .unwrap();
    let mut fixture = CensoredFixture;
    let artifact =
        run_software_fixture(config(&plan, 0, 1), plan, machine(), &mut fixture).unwrap();
    assert_eq!(artifact.summary.measured_success, 1);
    assert_eq!(artifact.summary.measured_failure, 2);
    assert_eq!(artifact.summary.measured_inconclusive, 1);
    assert!(artifact.campaign.samples.iter().any(|sample| matches!(
        sample.outcome,
        MeasurementOutcome::Failure {
            reason: MeasurementFailureReason::ToolError
        }
    )));
    assert!(artifact.campaign.samples.iter().any(|sample| matches!(
        sample.outcome,
        MeasurementOutcome::Inconclusive {
            reason: MeasurementInconclusiveReason::ResourceBound
        }
    )));
}

#[test]
fn wall_clock_is_forbidden_in_deterministic_fixture_runner() {
    assert_eq!(
        DeterministicFixturePlan::build(vec![task(
            MeasurementStage::Runtime,
            MeasurementMetric::WallClockTime,
            1,
        )])
        .unwrap_err(),
        FixtureRunnerError::InvalidTask
    );
    let plan = plan();
    let mut invalid = config(&plan, 0, 1);
    invalid.measurement.wall_clock_opt_in = true;
    let mut fixture = FormulaFixture;
    assert_eq!(
        run_software_fixture(invalid, plan, machine(), &mut fixture).unwrap_err(),
        FixtureRunnerError::InvalidConfig
    );
}

#[test]
fn plan_and_invocation_bounds_fail_closed() {
    let duplicate = task(
        MeasurementStage::Validate,
        MeasurementMetric::LogicalFuel,
        1,
    );
    assert_eq!(
        DeterministicFixturePlan::build(vec![duplicate, duplicate]).unwrap_err(),
        FixtureRunnerError::DuplicateTask
    );
    let plan = plan();
    let mut bounded = config(&plan, 2, 3);
    bounded.max_invocations = 14;
    let mut fixture = FormulaFixture;
    assert_eq!(
        run_software_fixture(bounded, plan.clone(), machine(), &mut fixture).unwrap_err(),
        FixtureRunnerError::InvocationBound
    );
    let mut mismatch = config(&plan, 0, 1);
    mismatch.measurement.benchmark_plan_sha256 = [0x99; 32];
    assert_eq!(
        run_software_fixture(mismatch, plan, machine(), &mut fixture).unwrap_err(),
        FixtureRunnerError::PlanMismatch
    );
}

#[test]
fn invocation_trace_tamper_fails_full_recomputation() {
    let plan = plan();
    let mut fixture = FormulaFixture;
    let mut artifact =
        run_software_fixture(config(&plan, 1, 1), plan, machine(), &mut fixture).unwrap();
    artifact.invocations[0].public_randomness_word ^= 1;
    assert_eq!(
        artifact.validate().unwrap_err(),
        FixtureRunnerError::ArtifactMismatch
    );
}
