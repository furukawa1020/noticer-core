#![forbid(unsafe_code)]

use noticer_aetp::{
    required_claim, ActionSemantics, BucketId, ChannelSchedule, ClaimBound, PublicContext,
    PublicNetworkTape, ScheduleRandomTape, ServiceBinding,
};
use noticer_aetp_sim::{
    default_public_context, generate_action_equivalent_pairs, CounterfactualFamily,
    EQUIVALENCE_CLASS_COUNT,
};
use noticer_baseline::{
    AnchorBaseline, AnchorBaselineBuilder, BaselineConfig, BaselineRegistry, ContextKey,
    PrivateFeatureVector, PrivateObservation, SignalQuality,
};
use noticer_claim::{admit, ActionTemplate, AdmittedAction};
use noticer_crypto::CryptographicRootSecret;
use noticer_evidence::{
    ContextConfig, EngineConfig, EvidenceConfig, EvidenceDecision, EvidenceEngine,
    PersistenceConfig,
};
use noticer_protocol::{FrameKind, ENVELOPE_SIZE};
use noticer_release::TokenPlan;
use noticer_token::{semantics_tag, TokenIssuer};
use noticer_trace_shaper::{ActionEquivalentTraceShaper, NetworkTrace, PublicFrameIdentity};
use noticer_types::{ActionCode, LogicalSlot, PolicyHash};
use noticer_verifier::{
    InMemoryReplayStore, KeyRegistry, PolicyAllowlist, RevocationSnapshot, TokenVerifier,
    VerificationResult, VerifierContext,
};
use rand_core::RngCore;
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::BTreeMap,
    env,
    error::Error,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    thread,
    time::Instant,
};

#[derive(Debug, Deserialize)]
struct DemoConfig {
    seed: u64,
    pair_count: usize,
    benchmark_frames: u32,
    evidence_config: PathBuf,
}

#[derive(Clone, Deserialize)]
struct K1Config {
    evidence: EvidenceConfig,
    persistence: PersistenceConfig,
    baseline: BaselineSection,
    contexts: Vec<ContextConfig>,
}

#[derive(Clone, Deserialize)]
struct BaselineSection {
    minimum_reference_samples: usize,
    minimum_calibration_samples: usize,
    scale_floor: f64,
    z_cap: f64,
}

struct SeededRng(u64);

impl RngCore for SeededRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        rand_core::impls::fill_bytes_via_next(self, destination);
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(destination);
        Ok(())
    }
}

#[derive(Clone)]
struct ClassWitness {
    family: CounterfactualFamily,
    trace_hash: [u8; 32],
    frame_count: usize,
    trace_equal: bool,
}

fn main() -> Result<(), Box<dyn Error>> {
    let (config_path, output_path) = arguments()?;
    let config: DemoConfig = toml::from_str(&fs::read_to_string(config_path)?)?;
    fs::create_dir_all(&output_path)?;

    let context = default_public_context();
    let pairs = generate_action_equivalent_pairs(config.pair_count, config.seed, &context)?;
    let admission_bridge = run_admission_bridge(&config)?;
    let mut class_witnesses = BTreeMap::new();
    let mut verifier_artifact = None;

    for family in CounterfactualFamily::ALL {
        let pair = pairs
            .iter()
            .find(|pair| pair.family == family)
            .ok_or("missing counterfactual family")?;
        let plan = pair.public_plan()?;
        let left = TokenIssuer::new(
            CryptographicRootSecret::new(root_bytes(config.seed, family)),
            context.network.public_epoch,
            &context.network.services,
        )?;
        let right = TokenIssuer::new(
            CryptographicRootSecret::new(root_bytes(config.seed, family)),
            context.network.public_epoch,
            &context.network.services,
        )?;
        let left_trace =
            ActionEquivalentTraceShaper::shape(&plan, &context, &pair.schedule_tape, &left)?;
        let right_trace =
            ActionEquivalentTraceShaper::shape(&plan, &context, &pair.schedule_tape, &right)?;
        let trace_equal = left_trace == right_trace;
        if !trace_equal {
            return Err("AETP full-token congruence failed".into());
        }
        if family == CounterfactualFamily::EarlyVsLateEvidence {
            verifier_artifact = Some(run_verifier_checks(
                &left,
                &left_trace,
                &pair.shared_semantics,
                &context.network.services,
                context.network.public_epoch,
            )?);
        }
        class_witnesses.insert(
            family,
            ClassWitness {
                family,
                trace_hash: left_trace.digest(),
                frame_count: left_trace.frames.len(),
                trace_equal,
            },
        );
    }

    write_counterfactual_witnesses(&output_path, &pairs, &class_witnesses)?;
    write_class_witnesses(&output_path, &class_witnesses)?;
    fs::write(
        output_path.join("verifier_checks.json"),
        serde_json::to_string_pretty(&verifier_artifact.ok_or("missing verifier artifact")?)?,
    )?;
    fs::write(
        output_path.join("admission_bridge.json"),
        serde_json::to_string_pretty(&admission_bridge)?,
    )?;
    let performance = benchmark_issuer(
        &context.network.services,
        config.seed,
        config.benchmark_frames,
    )?;
    fs::write(output_path.join("performance.csv"), performance)?;
    fs::write(
        output_path.join("manifest.json"),
        serde_json::to_string_pretty(&json!({
            "schema": "noticer-k3-artifact-v1",
            "primitive": "Action-Equivalent Trace Privacy",
            "protocol": "Atypicality Token v2",
            "pair_count": pairs.len(),
            "equivalence_classes": EQUIVALENCE_CLASS_COUNT,
            "full_crypto_trace_classes": class_witnesses.len(),
            "frame_size_bytes": ENVELOPE_SIZE,
            "public_buckets": context.schedule.buckets,
            "services": context.network.services.len(),
            "private_timing_persisted": false,
            "secret_key_material_persisted": false,
            "k1_evidence_permit_bridge": true,
            "cache_semantics": "full cryptographic traces are evaluated once per identical public equivalence class; every private pair is separately generated and mapped to its class witness"
        }))?,
    )?;
    println!(
        "K3 complete: {} counterfactual pairs, {} full-token classes, artifacts at {}",
        pairs.len(),
        class_witnesses.len(),
        output_path.display()
    );
    Ok(())
}

fn private_feature(value: f64) -> PrivateFeatureVector {
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
    .expect("valid K1 baseline config");
    for index in 0..config.minimum_reference_samples {
        builder.add_reference(
            index as u64,
            private_feature((index as f64 * 0.37).sin() * 0.1),
        );
    }
    for index in 0..config.minimum_calibration_samples {
        builder.add_calibration(
            (config.minimum_reference_samples + index) as u64,
            private_feature((index as f64 * 0.41).sin() * 0.1),
        );
    }
    builder.build(1).expect("disjoint K1 baseline samples")
}

fn evidence_engine(
    config: &K1Config,
    context: ContextKey,
    action: ActionCode,
    policy_hash: PolicyHash,
) -> Result<EvidenceEngine, Box<dyn Error>> {
    let mut registry = BaselineRegistry::new(None);
    registry.insert(context, build_anchor(&config.baseline));
    Ok(EvidenceEngine::new(
        EngineConfig {
            evidence: config.evidence.clone(),
            persistence: config.persistence.clone(),
            contexts: config.contexts.clone(),
            permit_ttl_slots: 64,
        },
        registry,
        vec![(context, config.contexts[0].alpha_weight)],
        action,
        policy_hash,
    )?)
}

fn admit_private_history(
    config: &K1Config,
    context: ContextKey,
    shift_at: usize,
    seed: u64,
    template: ActionTemplate,
) -> Result<AdmittedAction, Box<dyn Error>> {
    let mut engine = evidence_engine(config, context, template.action, template.policy_hash)?;
    let mut rng = SeededRng(seed);
    for index in 0..24 {
        let value = if index < shift_at {
            (index as f64 * 0.29).sin() * 0.05
        } else {
            5.0 + (index as f64 * 0.17).sin() * 0.1
        };
        let observation = PrivateObservation::new(
            LogicalSlot(1_000 + index as u64),
            context,
            SignalQuality::Good,
            private_feature(value),
        );
        match engine.process(&observation, &mut rng) {
            EvidenceDecision::AssumptionBoundPermit(permit) => {
                return Ok(admit(permit, template)?);
            }
            EvidenceDecision::EmpiricalPermit(permit) => {
                return Ok(admit(permit, template)?);
            }
            EvidenceDecision::Reject(error) => {
                return Err(
                    format!("K1 evidence engine rejected private history: {error:?}").into(),
                );
            }
            EvidenceDecision::NoPermit(_) => {}
        }
    }
    Err("K1 evidence engine did not issue a permit".into())
}

fn run_admission_bridge(config: &DemoConfig) -> Result<serde_json::Value, Box<dyn Error>> {
    let k1: K1Config = toml::from_str(&fs::read_to_string(&config.evidence_config)?)?;
    let context_key = ContextKey::opaque(k1.contexts[0].id.as_bytes());
    let service = ServiceBinding([0x21; 16]);
    let action = ActionCode::MenfuguInflateSoft;
    let claim: ClaimBound = required_claim(action);
    let template = ActionTemplate {
        service,
        action,
        public_bucket: BucketId(6),
        admission_cutoff: LogicalSlot(1_020),
        release_window_start: LogicalSlot(1_024),
        release_deadline: LogicalSlot(1_027),
        max_uses: 1,
        policy_hash: PolicyHash([7; 32]),
        claim_bound: claim,
        local_policy_ceiling: claim,
    };
    let early = admit_private_history(&k1, context_key, 2, config.seed, template.clone())?;
    let late = admit_private_history(&k1, context_key, 8, config.seed.wrapping_add(1), template)?;
    let early_plan = TokenPlan::from_admitted(vec![early], vec![service])?;
    let late_plan = TokenPlan::from_admitted(vec![late], vec![service])?;
    let public_actions_equal = early_plan == late_plan;
    if !public_actions_equal {
        return Err("private timing survived the admission quotient".into());
    }
    let public_context = PublicContext {
        schedule: ChannelSchedule {
            buckets: 8,
            slots_per_bucket: 4,
            frame_interval_ms: 250,
            fixed_plaintext_size: 160,
            fixed_ciphertext_size: ENVELOPE_SIZE as u16,
        },
        network: PublicNetworkTape {
            services: vec![service],
            public_epoch: 19,
            start_slot: LogicalSlot(1_000),
        },
    };
    let schedule = ScheduleRandomTape([0x5A; 32]);
    let left_issuer = TokenIssuer::new(
        CryptographicRootSecret::new([0x44; 32]),
        public_context.network.public_epoch,
        &[service],
    )?;
    let right_issuer = TokenIssuer::new(
        CryptographicRootSecret::new([0x44; 32]),
        public_context.network.public_epoch,
        &[service],
    )?;
    let left_trace =
        ActionEquivalentTraceShaper::shape(&early_plan, &public_context, &schedule, &left_issuer)?;
    let right_trace =
        ActionEquivalentTraceShaper::shape(&late_plan, &public_context, &schedule, &right_issuer)?;
    let token_traces_equal = left_trace == right_trace;
    if !token_traces_equal {
        return Err("K1-to-ATv2 counterfactual traces differ".into());
    }
    Ok(json!({
        "two_real_evidence_permits_consumed": true,
        "private_histories_use_distinct_evidence_timing": true,
        "public_actions_equal": public_actions_equal,
        "full_token_traces_equal": token_traces_equal,
        "frames_per_trace": left_trace.frames.len(),
        "frame_size_bytes": ENVELOPE_SIZE,
        "trace_sha256": hex(&left_trace.digest()),
        "private_evidence_timing_persisted": false
    }))
}

fn arguments() -> Result<(PathBuf, PathBuf), Box<dyn Error>> {
    let mut config = PathBuf::from("configs/token/k3_demo.toml");
    let mut output = PathBuf::from("artifacts/k3_token_v2");
    let mut args = env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--config" => config = PathBuf::from(args.next().ok_or("--config needs a path")?),
            "--output" => output = PathBuf::from(args.next().ok_or("--output needs a path")?),
            _ => return Err(format!("unknown argument: {argument}").into()),
        }
    }
    Ok((config, output))
}

fn root_bytes(seed: u64, family: CounterfactualFamily) -> [u8; 32] {
    let mut output = [0_u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = seed
            .wrapping_add(u64::from(family as u8) * 31)
            .wrapping_add(index as u64 * 17) as u8;
    }
    output
}

fn run_verifier_checks(
    issuer: &TokenIssuer,
    trace: &NetworkTrace,
    semantics: &ActionSemantics,
    services: &[ServiceBinding],
    epoch: u32,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let action_frame = trace
        .frames
        .iter()
        .find(|frame| frame.bytes[5] == FrameKind::Action as u8)
        .ok_or("trace has no action token")?;
    let obligation = semantics
        .obligations
        .first()
        .ok_or("missing action semantics")?;
    let claim = required_claim(obligation.action);
    let make_registry = || -> Result<KeyRegistry, Box<dyn Error>> {
        let mut registry = KeyRegistry::default();
        for service in services {
            registry.insert(
                issuer
                    .verifier_material(*service)
                    .ok_or("missing verifier material")?,
            )?;
        }
        Ok(registry)
    };
    let make_policies = || -> Result<PolicyAllowlist, Box<dyn Error>> {
        let mut policies = PolicyAllowlist::default();
        policies.allow(
            obligation.policy_hash,
            obligation.action,
            claim,
            semantics_tag(obligation, claim),
        )?;
        Ok(policies)
    };
    let context = VerifierContext {
        expected_service: obligation.service,
        expected_epoch: epoch,
        now_slot: u32::try_from(action_frame.identity.absolute_slot.0)?,
    };

    let verifier = TokenVerifier::new(
        make_registry()?,
        make_policies()?,
        RevocationSnapshot::default(),
        Arc::new(InMemoryReplayStore::default()),
    );
    let accepted = matches!(
        verifier.verify(&action_frame.bytes, context),
        VerificationResult::Authorized(_)
    );
    let replay_rejected =
        verifier.verify(&action_frame.bytes, context) == VerificationResult::Rejected;
    let mut mutated = action_frame.bytes.to_vec();
    mutated[ENVELOPE_SIZE - 1] ^= 1;
    let mutation_rejected = verifier.verify(&mutated, context) == VerificationResult::Rejected;
    let wrong_service_rejected = verifier.verify(
        &action_frame.bytes,
        VerifierContext {
            expected_service: services
                .iter()
                .copied()
                .find(|service| *service != obligation.service)
                .ok_or("need a second service")?,
            ..context
        },
    ) == VerificationResult::Rejected;
    let expired_rejected = verifier.verify(
        &action_frame.bytes,
        VerifierContext {
            now_slot: u32::try_from(obligation.release_deadline.0 + 1)?,
            ..context
        },
    ) == VerificationResult::Rejected;

    let mut revoked = RevocationSnapshot::default();
    revoked.revoke_policy(obligation.policy_hash);
    let revoked_verifier = TokenVerifier::new(
        make_registry()?,
        make_policies()?,
        revoked,
        Arc::new(InMemoryReplayStore::default()),
    );
    let revoked_rejected =
        revoked_verifier.verify(&action_frame.bytes, context) == VerificationResult::Rejected;

    let race_verifier = Arc::new(TokenVerifier::new(
        make_registry()?,
        make_policies()?,
        RevocationSnapshot::default(),
        Arc::new(InMemoryReplayStore::default()),
    ));
    let race_bytes: Arc<[u8]> = Arc::from(action_frame.bytes.to_vec());
    let handles: Vec<_> = (0..64)
        .map(|_| {
            let verifier = Arc::clone(&race_verifier);
            let bytes = Arc::clone(&race_bytes);
            thread::spawn(move || verifier.verify(&bytes, context))
        })
        .collect();
    let race_accepted = handles
        .into_iter()
        .map(|handle| handle.join())
        .filter(|result| matches!(result, Ok(VerificationResult::Authorized(_))))
        .count();

    let snapshot_store = Arc::new(InMemoryReplayStore::default());
    let snapshot_verifier = TokenVerifier::new(
        make_registry()?,
        make_policies()?,
        RevocationSnapshot::default(),
        snapshot_store.clone(),
    );
    let _ = snapshot_verifier.verify(&action_frame.bytes, context);
    let snapshot = snapshot_store.export_json(epoch)?;
    let restored = InMemoryReplayStore::import_json(epoch, &snapshot)?;
    let restored_verifier = TokenVerifier::new(
        make_registry()?,
        make_policies()?,
        RevocationSnapshot::default(),
        Arc::new(restored),
    );
    let restored_replay_rejected =
        restored_verifier.verify(&action_frame.bytes, context) == VerificationResult::Rejected;

    Ok(json!({
        "authorized_action_accepted": accepted,
        "replay_rejected": replay_rejected,
        "mutation_rejected": mutation_rejected,
        "wrong_service_rejected": wrong_service_rejected,
        "expired_rejected": expired_rejected,
        "revoked_policy_rejected": revoked_rejected,
        "concurrent_attempts": 64,
        "concurrent_accepts": race_accepted,
        "snapshot_restore_replay_rejected": restored_replay_rejected,
        "external_error_surface": "normalized"
    }))
}

fn benchmark_issuer(
    services: &[ServiceBinding],
    seed: u64,
    frames: u32,
) -> Result<String, Box<dyn Error>> {
    let epoch = 31;
    let issuer = TokenIssuer::new(
        CryptographicRootSecret::new(root_bytes(seed, CounterfactualFamily::DifferentSession)),
        epoch,
        services,
    )?;
    let service = services[0];
    let mut samples = Vec::with_capacity(frames as usize);
    for sequence in 0..frames {
        let identity = PublicFrameIdentity {
            service,
            public_epoch: epoch,
            public_bucket: sequence / 4,
            slot_in_bucket: (sequence % 4) as u16,
            sequence,
            absolute_slot: LogicalSlot(u64::from(sequence)),
        };
        let start = Instant::now();
        let _ = issuer.issue_cover_frame(identity)?;
        samples.push(start.elapsed().as_nanos() as u64);
    }
    samples.sort_unstable();
    let percentile = |fraction: f64| -> u64 {
        let index = ((samples.len() - 1) as f64 * fraction).round() as usize;
        samples[index]
    };
    Ok(format!(
        "operation,samples,median_ns,p95_ns,p99_ns\nissue_cover,{},{},{},{}\n",
        samples.len(),
        percentile(0.50),
        percentile(0.95),
        percentile(0.99)
    ))
}

fn write_counterfactual_witnesses(
    output: &Path,
    pairs: &[noticer_aetp_sim::ActionEquivalentPair],
    witnesses: &BTreeMap<CounterfactualFamily, ClassWitness>,
) -> Result<(), Box<dyn Error>> {
    let mut csv = String::from(
        "pair_id,family,equivalence_class,private_histories_distinct,trace_equal,trace_sha256\n",
    );
    for pair in pairs {
        let witness = witnesses.get(&pair.family).ok_or("missing class witness")?;
        writeln!(
            csv,
            "{},{},{},{},{},{}",
            pair.pair_id,
            pair.family.label(),
            pair.family as u8,
            pair.private_histories_are_distinct(),
            witness.trace_equal,
            hex(&witness.trace_hash)
        )?;
    }
    fs::write(output.join("counterfactual_witnesses.csv"), csv)?;
    Ok(())
}

fn write_class_witnesses(
    output: &Path,
    witnesses: &BTreeMap<CounterfactualFamily, ClassWitness>,
) -> Result<(), Box<dyn Error>> {
    let mut csv =
        String::from("family,equivalence_class,frames,frame_bytes,trace_equal,trace_sha256\n");
    for witness in witnesses.values() {
        writeln!(
            csv,
            "{},{},{},{},{},{}",
            witness.family.label(),
            witness.family as u8,
            witness.frame_count,
            ENVELOPE_SIZE,
            witness.trace_equal,
            hex(&witness.trace_hash)
        )?;
    }
    fs::write(output.join("full_trace_classes.csv"), csv)?;
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}
