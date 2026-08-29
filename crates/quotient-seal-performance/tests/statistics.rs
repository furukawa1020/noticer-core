use quotient_seal_performance::{
    aggregate_campaigns, AttackAucStatus, AttackClass, AttackLabelBinding, BenchmarkCase,
    BenchmarkRunConfig, EffectSizePair, EffectSizeStatus, MeasurementCampaign,
    MeasurementFailureReason, MeasurementInconclusiveReason, MeasurementMetric, MeasurementOutcome,
    MeasurementProvenance, MeasurementSample, MeasurementStage, MetricStatisticsStatus,
    SanitizedMachineMetadata, StatisticsError, StatisticsInconclusiveReason, StatisticsPlan,
};

fn case(module: u32, compiler: u32, engine: u32) -> BenchmarkCase {
    BenchmarkCase {
        module_family_alias: module,
        compiler_config_alias: compiler,
        engine_alias: engine,
    }
}

fn sample(
    stage: MeasurementStage,
    metric: MeasurementMetric,
    case: BenchmarkCase,
    iteration: u32,
    outcome: MeasurementOutcome,
) -> MeasurementSample {
    MeasurementSample::build(
        stage,
        metric,
        case,
        iteration,
        MeasurementProvenance::InjectedTestFixture,
        outcome,
    )
    .unwrap()
}

fn campaign(samples: Vec<MeasurementSample>, marker: u8) -> MeasurementCampaign {
    MeasurementCampaign::build(
        BenchmarkRunConfig {
            seed: u64::from(marker),
            warmup_iterations: 0,
            measured_iterations: 16,
            max_samples: 128,
            wall_clock_opt_in: false,
            benchmark_plan_sha256: [marker; 32],
        },
        SanitizedMachineMetadata::injected_fixture([marker.wrapping_add(1); 32]).unwrap(),
        samples,
    )
    .unwrap()
}

fn plan(
    minimum: u32,
    pairs: Vec<EffectSizePair>,
    labels: Vec<AttackLabelBinding>,
) -> StatisticsPlan {
    StatisticsPlan::build(minimum, 16, 1024, pairs, labels).unwrap()
}

#[test]
fn nearest_rank_percentiles_and_mad_are_deterministic() {
    let benchmark_case = case(1, 1, 1);
    let samples = [10, 20, 30, 40, 50]
        .into_iter()
        .enumerate()
        .map(|(iteration, value)| {
            sample(
                MeasurementStage::Validate,
                MeasurementMetric::LogicalFuel,
                benchmark_case,
                iteration as u32,
                MeasurementOutcome::Success { value },
            )
        })
        .collect();
    let artifact = aggregate_campaigns(plan(3, vec![], vec![]), &[campaign(samples, 1)]).unwrap();
    assert_eq!(artifact.groups.len(), 1);
    assert_eq!(
        artifact.groups[0].statistics,
        MetricStatisticsStatus::Ready {
            median: 30,
            p95: 50,
            p99: 50,
            median_absolute_deviation: 10,
        }
    );
    assert_eq!(artifact.groups[0].counts.success, 5);
}

#[test]
fn censored_outcomes_are_counted_but_not_used_as_values() {
    let benchmark_case = case(1, 1, 1);
    let samples = vec![
        sample(
            MeasurementStage::Parse,
            MeasurementMetric::LogicalFuel,
            benchmark_case,
            0,
            MeasurementOutcome::Success { value: 10 },
        ),
        sample(
            MeasurementStage::Parse,
            MeasurementMetric::LogicalFuel,
            benchmark_case,
            1,
            MeasurementOutcome::Success { value: 30 },
        ),
        sample(
            MeasurementStage::Parse,
            MeasurementMetric::LogicalFuel,
            benchmark_case,
            2,
            MeasurementOutcome::Failure {
                reason: MeasurementFailureReason::ParseError,
            },
        ),
        sample(
            MeasurementStage::Parse,
            MeasurementMetric::LogicalFuel,
            benchmark_case,
            3,
            MeasurementOutcome::Inconclusive {
                reason: MeasurementInconclusiveReason::ResourceBound,
            },
        ),
    ];
    let artifact = aggregate_campaigns(plan(2, vec![], vec![]), &[campaign(samples, 2)]).unwrap();
    let group = &artifact.groups[0];
    assert_eq!(group.counts.total, 4);
    assert_eq!(group.counts.success, 2);
    assert_eq!(group.counts.failure, 1);
    assert_eq!(group.counts.inconclusive, 1);
    assert_eq!(
        group.statistics,
        MetricStatisticsStatus::Ready {
            median: 10,
            p95: 30,
            p99: 30,
            median_absolute_deviation: 0,
        }
    );
}

#[test]
fn cliffs_delta_uses_explicit_baseline_and_candidate_groups() {
    let baseline = case(1, 1, 1);
    let candidate = case(2, 1, 1);
    let mut samples = Vec::new();
    for (iteration, value) in [1, 2].into_iter().enumerate() {
        samples.push(sample(
            MeasurementStage::Runtime,
            MeasurementMetric::LogicalFuel,
            baseline,
            iteration as u32,
            MeasurementOutcome::Success { value },
        ));
    }
    for (iteration, value) in [3, 4].into_iter().enumerate() {
        samples.push(sample(
            MeasurementStage::Runtime,
            MeasurementMetric::LogicalFuel,
            candidate,
            iteration as u32,
            MeasurementOutcome::Success { value },
        ));
    }
    let pair = EffectSizePair {
        stage: MeasurementStage::Runtime,
        metric: MeasurementMetric::LogicalFuel,
        provenance: MeasurementProvenance::InjectedTestFixture,
        baseline_case: baseline,
        candidate_case: candidate,
    };
    let artifact =
        aggregate_campaigns(plan(2, vec![pair], vec![]), &[campaign(samples, 3)]).unwrap();
    assert_eq!(
        artifact.effect_sizes[0].status,
        EffectSizeStatus::Ready {
            cliffs_delta_millionths: 1_000_000
        }
    );
}

#[test]
fn attack_auc_is_scaled_and_single_class_is_inconclusive() {
    let mut samples = Vec::new();
    for (iteration, value) in [900_000, 800_000].into_iter().enumerate() {
        samples.push(sample(
            MeasurementStage::AttackEvaluation,
            MeasurementMetric::AttackScore,
            case(10, 1, 1),
            iteration as u32,
            MeasurementOutcome::Success { value },
        ));
    }
    for (iteration, value) in [100_000, 200_000].into_iter().enumerate() {
        samples.push(sample(
            MeasurementStage::AttackEvaluation,
            MeasurementMetric::AttackScore,
            case(20, 1, 1),
            iteration as u32,
            MeasurementOutcome::Success { value },
        ));
    }
    let labels = vec![
        AttackLabelBinding {
            module_family_alias: 10,
            class: AttackClass::Positive,
        },
        AttackLabelBinding {
            module_family_alias: 20,
            class: AttackClass::Negative,
        },
    ];
    let artifact =
        aggregate_campaigns(plan(1, vec![], labels), &[campaign(samples.clone(), 4)]).unwrap();
    assert_eq!(
        artifact.attack_auc[0].status,
        AttackAucStatus::Ready {
            auc_millionths: 1_000_000
        }
    );

    let positive_only: Vec<_> = samples
        .into_iter()
        .filter(|sample| sample.case.module_family_alias == 10)
        .collect();
    let single = aggregate_campaigns(
        plan(
            1,
            vec![],
            vec![AttackLabelBinding {
                module_family_alias: 10,
                class: AttackClass::Positive,
            }],
        ),
        &[campaign(positive_only, 5)],
    )
    .unwrap();
    assert_eq!(
        single.attack_auc[0].status,
        AttackAucStatus::Inconclusive {
            reason: StatisticsInconclusiveReason::SingleAttackClass
        }
    );
}

#[test]
fn insufficient_duplicate_and_tampered_inputs_fail_closed() {
    let benchmark_case = case(1, 1, 1);
    let source = campaign(
        vec![sample(
            MeasurementStage::Validate,
            MeasurementMetric::LogicalFuel,
            benchmark_case,
            0,
            MeasurementOutcome::Success { value: 10 },
        )],
        6,
    );
    let mut artifact =
        aggregate_campaigns(plan(2, vec![], vec![]), std::slice::from_ref(&source)).unwrap();
    assert_eq!(
        artifact.groups[0].statistics,
        MetricStatisticsStatus::Inconclusive {
            reason: StatisticsInconclusiveReason::InsufficientSuccessSamples
        }
    );
    assert_eq!(
        aggregate_campaigns(plan(1, vec![], vec![]), &[source.clone(), source]).unwrap_err(),
        StatisticsError::DuplicateCampaign
    );
    artifact.artifact_sha256[0] ^= 0xff;
    assert_eq!(
        artifact.validate().unwrap_err(),
        StatisticsError::ArtifactMismatch
    );
}
