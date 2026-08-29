use quotient_seal_performance::{
    BenchmarkCase, BenchmarkRunConfig, HardwareStatus, MachineArchitecture, MeasurementCampaign,
    MeasurementContractError, MeasurementEvidenceOrigin, MeasurementFailureReason,
    MeasurementInconclusiveReason, MeasurementMetric, MeasurementOutcome, MeasurementProvenance,
    MeasurementSample, MeasurementStage, MeasurementUnit, OsFamily, SanitizedMachineMetadata,
    TimerKind,
};

fn config(wall_clock_opt_in: bool) -> BenchmarkRunConfig {
    BenchmarkRunConfig {
        seed: 0x5eed,
        warmup_iterations: 2,
        measured_iterations: 4,
        max_samples: 32,
        wall_clock_opt_in,
        benchmark_plan_sha256: [0x11; 32],
    }
}

fn case() -> BenchmarkCase {
    BenchmarkCase {
        module_family_alias: 1,
        compiler_config_alias: 2,
        engine_alias: 3,
    }
}

fn fixture_metadata() -> SanitizedMachineMetadata {
    SanitizedMachineMetadata::injected_fixture([0x22; 32]).unwrap()
}

#[test]
fn typed_fixture_campaign_is_canonical_and_reproducible() {
    let samples = vec![
        MeasurementSample::build(
            MeasurementStage::Validate,
            MeasurementMetric::LogicalFuel,
            case(),
            1,
            MeasurementProvenance::InjectedTestFixture,
            MeasurementOutcome::Success { value: 120 },
        )
        .unwrap(),
        MeasurementSample::build(
            MeasurementStage::Validate,
            MeasurementMetric::LogicalFuel,
            case(),
            0,
            MeasurementProvenance::InjectedTestFixture,
            MeasurementOutcome::Success { value: 100 },
        )
        .unwrap(),
    ];
    let first =
        MeasurementCampaign::build(config(false), fixture_metadata(), samples.clone()).unwrap();
    let second = MeasurementCampaign::build(config(false), fixture_metadata(), samples).unwrap();
    assert_eq!(
        first.canonical_json().unwrap(),
        second.canonical_json().unwrap()
    );
    assert_eq!(
        first.evidence_origin,
        MeasurementEvidenceOrigin::InjectedTestFixture
    );
    assert_eq!(first.hardware_status, HardwareStatus::NotVerified);
    assert_eq!(first.samples[0].iteration, 0);
    let decoded = MeasurementCampaign::decode_json(&first.canonical_json().unwrap()).unwrap();
    assert_eq!(decoded, first);
}

#[test]
fn failure_and_inconclusive_have_no_numeric_value() {
    let samples = vec![
        MeasurementSample::build(
            MeasurementStage::Parse,
            MeasurementMetric::LogicalFuel,
            case(),
            0,
            MeasurementProvenance::SoftwareFixture,
            MeasurementOutcome::Failure {
                reason: MeasurementFailureReason::ParseError,
            },
        )
        .unwrap(),
        MeasurementSample::build(
            MeasurementStage::ContextCheck,
            MeasurementMetric::LogicalFuel,
            case(),
            1,
            MeasurementProvenance::SoftwareFixture,
            MeasurementOutcome::Inconclusive {
                reason: MeasurementInconclusiveReason::ResourceBound,
            },
        )
        .unwrap(),
    ];
    let campaign = MeasurementCampaign::build(config(false), fixture_metadata(), samples).unwrap();
    let json = String::from_utf8(campaign.canonical_json().unwrap()).unwrap();
    assert!(json.contains("FAILURE"));
    assert!(json.contains("INCONCLUSIVE"));
    assert_eq!(
        campaign.evidence_origin,
        MeasurementEvidenceOrigin::SoftwareFixture
    );
}

#[test]
fn wall_clock_requires_explicit_opt_in_and_monotonic_timer() {
    let sample = MeasurementSample::build(
        MeasurementStage::Runtime,
        MeasurementMetric::WallClockTime,
        case(),
        0,
        MeasurementProvenance::OptInLocalWallClock,
        MeasurementOutcome::Success { value: 10 },
    )
    .unwrap();
    assert_eq!(
        MeasurementCampaign::build(config(false), fixture_metadata(), vec![sample.clone()])
            .unwrap_err(),
        MeasurementContractError::WallClockNotOptedIn
    );
    assert_eq!(
        MeasurementCampaign::build(config(true), fixture_metadata(), vec![sample.clone()])
            .unwrap_err(),
        MeasurementContractError::WallClockNotOptedIn
    );
    let machine = SanitizedMachineMetadata {
        os_family: OsFamily::Linux,
        architecture: MachineArchitecture::X86_64,
        logical_cpu_bucket: quotient_seal_performance::CpuCountBucket::Eight,
        memory_bucket: quotient_seal_performance::MemoryBucket::UpToSixteenGib,
        timer_kind: TimerKind::MonotonicWallClock,
        software_profile_sha256: [0x33; 32],
    };
    let campaign = MeasurementCampaign::build(config(true), machine, vec![sample]).unwrap();
    assert_eq!(
        campaign.evidence_origin,
        MeasurementEvidenceOrigin::OptInLocalMeasurement
    );
    assert_eq!(campaign.hardware_status, HardwareStatus::NotVerified);
}

#[test]
fn invalid_score_duplicate_key_and_tamper_fail_closed() {
    assert_eq!(
        MeasurementSample::build(
            MeasurementStage::AttackEvaluation,
            MeasurementMetric::AttackScore,
            case(),
            0,
            MeasurementProvenance::InjectedTestFixture,
            MeasurementOutcome::Success { value: 1_000_001 },
        )
        .unwrap_err(),
        MeasurementContractError::InvalidOutcome
    );
    let sample = MeasurementSample::build(
        MeasurementStage::CapsuleCheck,
        MeasurementMetric::ArtifactSize,
        case(),
        0,
        MeasurementProvenance::InjectedTestFixture,
        MeasurementOutcome::Success { value: 512 },
    )
    .unwrap();
    assert_eq!(sample.unit, MeasurementUnit::Bytes);
    assert_eq!(
        MeasurementCampaign::build(
            config(false),
            fixture_metadata(),
            vec![sample.clone(), sample.clone()],
        )
        .unwrap_err(),
        MeasurementContractError::DuplicateSampleKey
    );
    let mut campaign =
        MeasurementCampaign::build(config(false), fixture_metadata(), vec![sample]).unwrap();
    campaign.artifact_sha256[0] ^= 0xff;
    assert_eq!(
        campaign.validate().unwrap_err(),
        MeasurementContractError::ArtifactMismatch
    );
}

#[test]
fn sanitized_artifact_has_no_identity_or_private_signal_fields() {
    let sample = MeasurementSample::build(
        MeasurementStage::Runtime,
        MeasurementMetric::HostCallCount,
        case(),
        0,
        MeasurementProvenance::InjectedTestFixture,
        MeasurementOutcome::Success { value: 4 },
    )
    .unwrap();
    let campaign =
        MeasurementCampaign::build(config(false), fixture_metadata(), vec![sample]).unwrap();
    let json = String::from_utf8(campaign.canonical_json().unwrap()).unwrap();
    for forbidden in [
        "hostname",
        "username",
        "serial_number",
        "user_path",
        "private_biosignal",
        "stable_subject_identifier",
    ] {
        assert!(!json.contains(forbidden));
    }
    assert!(json.contains("INJECTED_TEST_FIXTURE"));
    assert!(json.contains("NOT_VERIFIED"));
}
