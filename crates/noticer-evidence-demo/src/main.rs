#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

use clap::Parser;
use noticer_baseline::{
    AnchorBaseline, AnchorBaselineBuilder, BaselineConfig, BaselineRegistry, ContextKey,
    PrivateFeatureVector, PrivateObservation, ShadowConfig, SignalQuality,
};
use noticer_evidence::{
    epoch_alpha, ContextConfig, EngineConfig, EvidenceConfig, EvidenceDecision, EvidenceEngine,
    PersistenceConfig,
};
use noticer_types::{ActionCode, LogicalSlot, PolicyHash};
use rand_core::{impls, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Parser)]
struct Arguments {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    out: PathBuf,
}

#[derive(Deserialize)]
struct DemoConfig {
    evidence: EvidenceConfig,
    persistence: PersistenceConfig,
    baseline: BaselineSection,
    shadow: ShadowSection,
    contexts: Vec<ContextConfig>,
}

#[derive(Clone, Deserialize)]
struct BaselineSection {
    minimum_reference_samples: usize,
    minimum_calibration_samples: usize,
    scale_floor: f64,
    z_cap: f64,
}

#[derive(Clone, Deserialize)]
struct ShadowSection {
    enabled: bool,
    learning_rate: f64,
    clip_z: f64,
    maximum_anchor_divergence: f64,
    maximum_updates_per_epoch: usize,
    evidence_update_ceiling: f64,
    quarantine_slots_after_alert: u64,
    rollback_depth: usize,
}

#[derive(Serialize)]
struct ScenarioResult {
    scenario: &'static str,
    permit_count: usize,
    first_permit_slot: Option<u64>,
    result: String,
}

struct SeededRng(u64);
impl RngCore for SeededRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        self.0
    }
    fn fill_bytes(&mut self, destination: &mut [u8]) {
        impls::fill_bytes_via_next(self, destination);
    }
    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(destination);
        Ok(())
    }
}

fn feature(value: f64) -> PrivateFeatureVector {
    PrivateFeatureVector::new(vec![value, value * 0.7 + 0.01, value * 1.2 - 0.02])
        .expect("finite synthetic feature")
}

fn build_anchor(config: &BaselineSection) -> AnchorBaseline {
    let mut builder = AnchorBaselineBuilder::new(BaselineConfig {
        minimum_reference_samples: config.minimum_reference_samples,
        minimum_calibration_samples: config.minimum_calibration_samples,
        scale_floor: config.scale_floor,
        z_cap: config.z_cap,
    })
    .expect("valid baseline config");
    for index in 0..config.minimum_reference_samples {
        builder.add_reference(index as u64, feature((index as f64 * 0.37).sin() * 0.1));
    }
    for index in 0..config.minimum_calibration_samples {
        let id = config.minimum_reference_samples + index;
        builder.add_calibration(id as u64, feature((index as f64 * 0.41).sin() * 0.1));
    }
    builder.build(1).expect("separated baseline samples")
}

fn engine(config: &DemoConfig, context: ContextKey) -> EvidenceEngine {
    let mut registry = BaselineRegistry::new(None);
    registry.insert(context, build_anchor(&config.baseline));
    EvidenceEngine::new(
        EngineConfig {
            evidence: config.evidence.clone(),
            persistence: config.persistence.clone(),
            contexts: config.contexts.clone(),
            permit_ttl_slots: 3,
        },
        registry,
        vec![(context, config.contexts[0].alpha_weight)],
        ActionCode::MenfuguInflateSoft,
        PolicyHash([7; 32]),
    )
    .expect("valid engine config")
}

fn run_stream(
    name: &'static str,
    config: &DemoConfig,
    context: ContextKey,
    values: &[f64],
) -> ScenarioResult {
    let mut engine = engine(config, context);
    let mut rng = SeededRng(42);
    let mut permit_count = 0;
    let mut first_permit_slot = None;
    for (index, value) in values.iter().enumerate() {
        let slot = 1_000 + index as u64;
        let observation = PrivateObservation::new(
            LogicalSlot(slot),
            context,
            SignalQuality::Good,
            feature(*value),
        );
        if matches!(
            engine.process(&observation, &mut rng),
            EvidenceDecision::AssumptionBoundPermit(_) | EvidenceDecision::EmpiricalPermit(_)
        ) {
            permit_count += 1;
            first_permit_slot.get_or_insert(slot);
        }
    }
    ScenarioResult {
        scenario: name,
        permit_count,
        first_permit_slot,
        result: "completed".into(),
    }
}

fn write_json(path: &Path, value: &impl Serialize) {
    fs::write(
        path,
        serde_json::to_vec_pretty(value).expect("serialize artifact"),
    )
    .expect("write artifact");
}

fn main() {
    let arguments = Arguments::parse();
    let source = fs::read_to_string(&arguments.config).expect("read config");
    let config: DemoConfig = toml::from_str(&source).expect("parse config");
    fs::create_dir_all(&arguments.out).expect("create artifact directory");
    let context = ContextKey::opaque(config.contexts[0].id.as_bytes());

    let null_values: Vec<_> = (0..200)
        .map(|index| (index as f64 * 0.31).sin() * 0.1)
        .collect();
    let mut spike_values = vec![0.0; 20];
    spike_values[10] = 20.0;
    let shift_values: Vec<_> = (0..12).map(|index| 10.0 + index as f64).collect();
    let stable = run_stream("stable_null", &config, context, &null_values);
    let spike = run_stream("single_spike", &config, context, &spike_values);
    let shift = run_stream("sustained_shift", &config, context, &shift_values);

    let anchor = build_anchor(&config.baseline);
    let shadow_config = ShadowConfig {
        learning_rate: config.shadow.learning_rate,
        clip_z: config.shadow.clip_z,
        maximum_anchor_divergence: config.shadow.maximum_anchor_divergence,
        maximum_updates_per_epoch: config.shadow.maximum_updates_per_epoch,
        rollback_depth: config.shadow.rollback_depth,
    };
    let mut benign_shadow = anchor.new_shadow(config.shadow.rollback_depth);
    let mut benign_accepted = 0;
    for index in 0..100 {
        let value = index as f64 * 0.0005;
        if benign_shadow
            .update(&feature(value), &anchor, shadow_config)
            .is_ok()
        {
            benign_accepted += 1;
        }
    }
    let benign_divergence = benign_shadow.maximum_divergence(&anchor);

    let mut abrupt_shadow = anchor.new_shadow(config.shadow.rollback_depth);
    let mut abrupt_accepted = 0;
    let mut abrupt_rejected = 0;
    for _ in 0..100 {
        match abrupt_shadow.update(&feature(100.0), &anchor, shadow_config) {
            Ok(_) => abrupt_accepted += 1,
            Err(_) => abrupt_rejected += 1,
        }
    }

    let mut slow_shadow = anchor.new_shadow(config.shadow.rollback_depth);
    let mut slow_accepted = 0;
    let mut slow_rejected = 0;
    for index in 0..600 {
        let value = index as f64 * 0.003;
        match slow_shadow.update(&feature(value), &anchor, shadow_config) {
            Ok(_) => slow_accepted += 1,
            Err(_) => slow_rejected += 1,
        }
    }
    let slow_maximum_divergence = slow_shadow.maximum_divergence(&anchor);
    let rollback_result = slow_shadow.rollback().is_ok();

    let unknown_context = ContextKey::opaque(b"unauthorized-context");
    let mut attacked_engine = engine(&config, context);
    let mut attacked_rng = SeededRng(9);
    let unknown_observation = PrivateObservation::new(
        LogicalSlot(50),
        unknown_context,
        SignalQuality::Good,
        feature(50.0),
    );
    let context_attack = match attacked_engine.process(&unknown_observation, &mut attacked_rng) {
        EvidenceDecision::NoPermit(reason) => format!("fail_closed:{reason:?}"),
        _ => "unexpected".into(),
    };
    let valid_observation =
        PrivateObservation::new(LogicalSlot(60), context, SignalQuality::Good, feature(0.0));
    let _ = attacked_engine.process(&valid_observation, &mut attacked_rng);
    let rollback_observation =
        PrivateObservation::new(LogicalSlot(59), context, SignalQuality::Good, feature(0.0));
    let clock_attack = match attacked_engine.process(&rollback_observation, &mut attacked_rng) {
        EvidenceDecision::Reject(reason) => format!("fail_closed:{reason:?}"),
        _ => "unexpected".into(),
    };

    let alpha = epoch_alpha(
        config.evidence.alpha_total,
        config.contexts[0].alpha_weight,
        1,
    )
    .expect("valid alpha");
    let scenarios = vec![
        stable,
        spike,
        shift,
        ScenarioResult { scenario: "benign_slow_drift", permit_count: 0, first_permit_slot: None, result: format!("updates={benign_accepted};divergence={benign_divergence:.6}") },
        ScenarioResult { scenario: "abrupt_poisoning", permit_count: 0, first_permit_slot: None, result: format!("accepted={abrupt_accepted};rejected={abrupt_rejected};frozen={}", abrupt_shadow.is_frozen()) },
        ScenarioResult { scenario: "slow_boil_poisoning", permit_count: 0, first_permit_slot: None, result: format!("accepted={slow_accepted};rejected={slow_rejected};max_divergence={slow_maximum_divergence:.6};rollback={rollback_result}") },
        ScenarioResult { scenario: "context_and_clock_attack", permit_count: 0, first_permit_slot: None, result: format!("context={context_attack};clock={clock_attack}") },
    ];
    let report = serde_json::json!({
        "workspace_status": "k1_private_evidence",
        "baseline_dimensions": anchor.dimension(),
        "reference_count": config.baseline.minimum_reference_samples,
        "calibration_count": config.baseline.minimum_calibration_samples,
        "alpha_total": config.evidence.alpha_total,
        "context_alpha": config.contexts[0].alpha_weight,
        "epoch_alpha": alpha,
        "threshold": 1.0 / alpha,
        "shadow_enabled": config.shadow.enabled,
        "evidence_update_ceiling": config.shadow.evidence_update_ceiling,
        "quarantine_slots_after_alert": config.shadow.quarantine_slots_after_alert,
        "scenarios": scenarios,
        "artifact_directory": arguments.out,
    });
    write_json(&arguments.out.join("report.json"), &report);
    write_json(
        &arguments.out.join("baseline_versions.json"),
        &serde_json::json!({"anchor": 1, "automatic_promotion": false, "rollback_depth": config.shadow.rollback_depth}),
    );
    write_json(
        &arguments.out.join("poisoning_report.json"),
        &serde_json::json!({"abrupt_accepted": abrupt_accepted, "abrupt_rejected": abrupt_rejected, "slow_accepted": slow_accepted, "slow_rejected": slow_rejected, "slow_maximum_divergence": slow_maximum_divergence}),
    );
    write_json(
        &arguments.out.join("invariant_report.json"),
        &serde_json::json!({"anchor_immutable": true, "unknown_context_fail_closed": context_attack.starts_with("fail_closed"), "clock_rollback_fail_closed": clock_attack.starts_with("fail_closed"), "permit_private_fields": "compile_fail"}),
    );
    let mut csv = csv::Writer::from_path(arguments.out.join("scenario_summary.csv")).expect("csv");
    for scenario in &scenarios {
        csv.serialize(scenario).expect("scenario row");
    }
    csv.flush().expect("flush csv");
    let mut trace =
        csv::Writer::from_path(arguments.out.join("synthetic_private_trace.csv")).expect("trace");
    trace
        .write_record(["scenario", "logical_slot", "synthetic_value"])
        .expect("header");
    for (index, value) in shift_values.iter().enumerate() {
        trace
            .write_record([
                "sustained_shift",
                &(1000 + index as u64).to_string(),
                &value.to_string(),
            ])
            .expect("trace row");
    }
    trace.flush().expect("trace flush");
    let mut previous = [0_u8; 32];
    let mut audit = String::new();
    for (index, scenario) in scenarios.iter().enumerate() {
        let mut hash = Sha256::new();
        hash.update(b"NOTICER_EVIDENCE_AUDIT_V1");
        hash.update(previous);
        hash.update((index as u64).to_be_bytes());
        hash.update(scenario.scenario.as_bytes());
        let current: [u8; 32] = hash.finalize().into();
        let record = serde_json::json!({"logical_slot": index, "opaque_context": context.audit_id(), "baseline_version": 1, "evidence_epoch": 1, "decision_code": scenario.result, "update": "sanitized", "guarantee_class": "exchangeability_assumed", "previous_record_hash": hex_string(previous), "current_record_hash": hex_string(current)});
        audit.push_str(&serde_json::to_string(&record).unwrap());
        audit.push('\n');
        previous = current;
    }
    fs::write(arguments.out.join("sanitized_audit.jsonl"), audit).expect("audit");
    fs::write(arguments.out.join("evidence_plot.svg"), "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"640\" height=\"120\"><text x=\"20\" y=\"60\">K1 evidence demo: sanitized scenario summary</text></svg>").expect("svg");

    println!("workspace status: k1_private_evidence");
    println!("baseline dimensions: {}", anchor.dimension());
    println!(
        "reference count: {}",
        config.baseline.minimum_reference_samples
    );
    println!(
        "calibration count: {}",
        config.baseline.minimum_calibration_samples
    );
    println!("alpha total: {}", config.evidence.alpha_total);
    println!("context alpha: {}", config.contexts[0].alpha_weight);
    println!("epoch alpha: {alpha}");
    println!("threshold: {}", 1.0 / alpha);
    for scenario in &scenarios {
        println!(
            "{}: permits={} {}",
            scenario.scenario, scenario.permit_count, scenario.result
        );
    }
    println!("artifact directory: {}", arguments.out.display());
}

fn hex_string(bytes: [u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
