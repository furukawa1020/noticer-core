use quotient_seal_performance::{
    aggregate_campaigns, evaluate_budget, BenchmarkCase, BenchmarkRunConfig, BudgetConstraint,
    BudgetPlan, BudgetRule, BudgetStatistic, GateInconclusiveReason, GateRuleOutcome,
    MeasurementCampaign, MeasurementFailureReason, MeasurementMetric, MeasurementOutcome,
    MeasurementProvenance, MeasurementSample, MeasurementStage, MeasurementUnit,
    PerformanceGateError, PerformanceGateVerdict, SanitizedMachineMetadata, StatisticsArtifact,
    StatisticsPlan,
};

const CASE: BenchmarkCase = BenchmarkCase {
    module_family_alias: 11,
    compiler_config_alias: 22,
    engine_alias: 33,
};

fn statistics(
    case: BenchmarkCase,
    metric: MeasurementMetric,
    outcomes: &[MeasurementOutcome],
    min_success_samples: u32,
    seed: u64,
) -> StatisticsArtifact {
    let samples = outcomes
        .iter()
        .copied()
        .enumerate()
        .map(|(iteration, outcome)| {
            MeasurementSample::build(
                MeasurementStage::Runtime,
                metric,
                case,
                iteration as u32,
                MeasurementProvenance::SoftwareFixture,
                outcome,
            )
            .expect("sample contract must be valid")
        })
        .collect::<Vec<_>>();
    let measured_iterations = samples.len() as u32;
    let config = BenchmarkRunConfig {
        seed,
        warmup_iterations: 0,
        measured_iterations,
        max_samples: measured_iterations,
        wall_clock_opt_in: false,
        benchmark_plan_sha256: [seed as u8; 32],
    };
    let machine = SanitizedMachineMetadata::injected_fixture([(seed as u8) + 32; 32])
        .expect("fixture metadata must be valid");
    let campaign = MeasurementCampaign::build(config, machine, samples)
        .expect("campaign contract must be valid");
    let plan = StatisticsPlan::build(min_success_samples, 1, 64, vec![], vec![])
        .expect("statistics plan must be valid");
    aggregate_campaigns(plan, &[campaign]).expect("statistics aggregation must succeed")
}

fn success(value: u64) -> MeasurementOutcome {
    MeasurementOutcome::Success { value }
}

fn rule(
    rule_id: u32,
    metric: MeasurementMetric,
    unit: MeasurementUnit,
    statistic: BudgetStatistic,
    constraint: BudgetConstraint,
) -> BudgetRule {
    BudgetRule {
        rule_id,
        key: quotient_seal_performance::MetricGroupKey {
            stage: MeasurementStage::Runtime,
            metric,
            unit,
            case: CASE,
            provenance: MeasurementProvenance::SoftwareFixture,
        },
        statistic,
        constraint,
    }
}

#[test]
fn inclusive_absolute_threshold_passes_and_any_overrun_fails_the_gate() {
    let baseline = statistics(CASE, MeasurementMetric::LogicalFuel, &[success(100)], 1, 1);
    let candidate = statistics(CASE, MeasurementMetric::LogicalFuel, &[success(110)], 1, 2);
    let plan = BudgetPlan::build(vec![
        rule(
            2,
            MeasurementMetric::LogicalFuel,
            MeasurementUnit::FuelUnits,
            BudgetStatistic::P95,
            BudgetConstraint::AbsoluteMaximum { limit: 109 },
        ),
        rule(
            1,
            MeasurementMetric::LogicalFuel,
            MeasurementUnit::FuelUnits,
            BudgetStatistic::Median,
            BudgetConstraint::AbsoluteMaximum { limit: 110 },
        ),
    ])
    .expect("budget plan must be valid");

    let artifact = evaluate_budget(plan, baseline, candidate).expect("gate must evaluate");

    assert_eq!(artifact.verdict, PerformanceGateVerdict::Fail);
    assert_eq!(artifact.evaluations[0].rule_id, 1);
    assert_eq!(artifact.evaluations[0].outcome, GateRuleOutcome::Pass);
    assert_eq!(artifact.evaluations[1].outcome, GateRuleOutcome::Fail);
    assert_eq!(artifact.security_interpretation, "NOT_A_SECURITY_VERDICT");
}

#[test]
fn relative_and_absolute_increase_use_inclusive_integer_budgets() {
    let baseline = statistics(CASE, MeasurementMetric::LogicalFuel, &[success(100)], 1, 3);
    let candidate = statistics(CASE, MeasurementMetric::LogicalFuel, &[success(110)], 1, 4);
    let passing = BudgetPlan::build(vec![
        rule(
            1,
            MeasurementMetric::LogicalFuel,
            MeasurementUnit::FuelUnits,
            BudgetStatistic::Median,
            BudgetConstraint::RelativeMaximum {
                ratio_millionths: 1_100_000,
            },
        ),
        rule(
            2,
            MeasurementMetric::LogicalFuel,
            MeasurementUnit::FuelUnits,
            BudgetStatistic::P95,
            BudgetConstraint::AbsoluteIncreaseMaximum { limit: 10 },
        ),
    ])
    .expect("budget plan must be valid");
    let pass =
        evaluate_budget(passing, baseline.clone(), candidate.clone()).expect("gate must evaluate");
    assert_eq!(pass.verdict, PerformanceGateVerdict::Pass);
    assert_eq!(
        pass.evaluations[0].observed_ratio_millionths,
        Some(1_100_000)
    );
    assert_eq!(pass.evaluations[1].observed_increase, Some(10));

    let failing = BudgetPlan::build(vec![rule(
        3,
        MeasurementMetric::LogicalFuel,
        MeasurementUnit::FuelUnits,
        BudgetStatistic::Median,
        BudgetConstraint::RelativeMaximum {
            ratio_millionths: 1_099_999,
        },
    )])
    .expect("budget plan must be valid");
    let fail = evaluate_budget(failing, baseline, candidate).expect("gate must evaluate");
    assert_eq!(fail.verdict, PerformanceGateVerdict::Fail);
}

#[test]
fn censored_failure_rate_remains_visible_and_can_fail_a_budget() {
    let baseline = statistics(CASE, MeasurementMetric::LogicalFuel, &[success(10)], 1, 5);
    let candidate = statistics(
        CASE,
        MeasurementMetric::LogicalFuel,
        &[
            success(10),
            MeasurementOutcome::Failure {
                reason: MeasurementFailureReason::RuntimeTrap,
            },
        ],
        1,
        6,
    );
    let plan = BudgetPlan::build(vec![rule(
        1,
        MeasurementMetric::LogicalFuel,
        MeasurementUnit::FuelUnits,
        BudgetStatistic::FailureRateMillionths,
        BudgetConstraint::AbsoluteMaximum { limit: 400_000 },
    )])
    .expect("budget plan must be valid");

    let artifact = evaluate_budget(plan, baseline, candidate).expect("gate must evaluate");

    assert_eq!(artifact.verdict, PerformanceGateVerdict::Fail);
    assert_eq!(artifact.evaluations[0].candidate_value, Some(500_000));
    assert_eq!(artifact.candidate.groups[0].counts.failure, 1);
    assert_eq!(artifact.candidate.groups[0].counts.success, 1);
}

#[test]
fn incomparable_inputs_are_explicitly_inconclusive() {
    let candidate = statistics(CASE, MeasurementMetric::LogicalFuel, &[success(1)], 1, 7);
    let other_case = BenchmarkCase {
        module_family_alias: 99,
        ..CASE
    };
    let missing_baseline = statistics(
        other_case,
        MeasurementMetric::LogicalFuel,
        &[success(1)],
        1,
        8,
    );
    let median_rule = || {
        BudgetPlan::build(vec![rule(
            1,
            MeasurementMetric::LogicalFuel,
            MeasurementUnit::FuelUnits,
            BudgetStatistic::Median,
            BudgetConstraint::AbsoluteIncreaseMaximum { limit: 1 },
        )])
        .expect("budget plan must be valid")
    };
    let missing = evaluate_budget(median_rule(), missing_baseline, candidate.clone())
        .expect("gate must evaluate");
    assert_eq!(
        missing.evaluations[0].outcome,
        GateRuleOutcome::Inconclusive {
            reason: GateInconclusiveReason::MissingBaselineGroup,
        }
    );

    let bytes_baseline = statistics(CASE, MeasurementMetric::ArtifactSize, &[success(1)], 1, 9);
    let bytes_candidate = statistics(CASE, MeasurementMetric::ArtifactSize, &[success(1)], 1, 10);
    let wrong_unit = BudgetPlan::build(vec![rule(
        2,
        MeasurementMetric::ArtifactSize,
        MeasurementUnit::FuelUnits,
        BudgetStatistic::Median,
        BudgetConstraint::AbsoluteMaximum { limit: 1 },
    )])
    .expect("budget plan must be valid");
    let mismatch =
        evaluate_budget(wrong_unit, bytes_baseline, bytes_candidate).expect("gate must evaluate");
    assert_eq!(
        mismatch.evaluations[0].outcome,
        GateRuleOutcome::Inconclusive {
            reason: GateInconclusiveReason::UnitMismatch,
        }
    );

    let zero = statistics(CASE, MeasurementMetric::LogicalFuel, &[success(0)], 1, 11);
    let relative = BudgetPlan::build(vec![rule(
        3,
        MeasurementMetric::LogicalFuel,
        MeasurementUnit::FuelUnits,
        BudgetStatistic::Median,
        BudgetConstraint::RelativeMaximum {
            ratio_millionths: 2_000_000,
        },
    )])
    .expect("budget plan must be valid");
    let zero_baseline =
        evaluate_budget(relative, zero, candidate.clone()).expect("gate must evaluate");
    assert_eq!(
        zero_baseline.evaluations[0].outcome,
        GateRuleOutcome::Inconclusive {
            reason: GateInconclusiveReason::ZeroBaseline,
        }
    );

    let insufficient = statistics(CASE, MeasurementMetric::LogicalFuel, &[success(1)], 2, 12);
    let insufficient =
        evaluate_budget(median_rule(), insufficient, candidate).expect("gate must evaluate");
    assert_eq!(insufficient.verdict, PerformanceGateVerdict::Inconclusive);
    assert_eq!(
        insufficient.evaluations[0].outcome,
        GateRuleOutcome::Inconclusive {
            reason: GateInconclusiveReason::InsufficientSuccessSamples,
        }
    );
}

#[test]
fn plan_duplicates_tampering_and_reproducibility_are_enforced() {
    let duplicate = rule(
        1,
        MeasurementMetric::LogicalFuel,
        MeasurementUnit::FuelUnits,
        BudgetStatistic::Median,
        BudgetConstraint::AbsoluteMaximum { limit: 10 },
    );
    assert!(matches!(
        BudgetPlan::build(vec![duplicate, duplicate]),
        Err(PerformanceGateError::DuplicateRule)
    ));

    let baseline = statistics(CASE, MeasurementMetric::LogicalFuel, &[success(9)], 1, 13);
    let candidate = statistics(CASE, MeasurementMetric::LogicalFuel, &[success(10)], 1, 14);
    let plan = BudgetPlan::build(vec![duplicate]).expect("budget plan must be valid");
    let first = evaluate_budget(plan.clone(), baseline.clone(), candidate.clone())
        .expect("gate must evaluate");
    let second = evaluate_budget(plan, baseline, candidate).expect("gate must evaluate");
    assert_eq!(
        first.canonical_json().expect("canonical JSON must encode"),
        second.canonical_json().expect("canonical JSON must encode")
    );

    let mut tampered = first;
    tampered.evaluations[0].candidate_value = Some(999);
    assert!(matches!(
        tampered.validate(),
        Err(PerformanceGateError::ArtifactMismatch)
    ));
}
