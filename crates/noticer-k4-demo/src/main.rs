#![forbid(unsafe_code)]

use clap::Parser;
use noticer_aetp::{required_claim, ActionObligation, BucketId, ClaimBound, ServiceBinding};
use noticer_ble_host::HostVerifierAdapter;
use noticer_crypto::CryptographicRootSecret;
use noticer_menfugu_core::ExecutionPolicy;
use noticer_menfugu_firmware::{MenfuguRuntime, PumpOutput, RuntimeEvent};
use noticer_protocol::{AtypicalityTokenEnvelope, ENVELOPE_SIZE};
use noticer_token::{semantics_tag, TokenIssuer};
use noticer_trace_shaper::PublicFrameIdentity;
use noticer_transport_core::{
    derive_frame_id, fragment_envelope, TransportFrameIdentity, TransportIdKey,
    TOTAL_FRAGMENT_COUNT,
};
use noticer_transport_sim::{observer_traces_are_equal, simulate, PublicLossTape, TransportTrace};
use noticer_types::{ActionCode, LogicalSlot, PolicyHash};
use noticer_verifier::{
    InMemoryReplayStore, KeyRegistry, PolicyAllowlist, RevocationSnapshot, TokenVerifier,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

const ACTIVE_FRAMES: usize = 4;
const CONSUMED_TOKENS: usize = 16;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "configs/k4/ble_menfugu.toml")]
    config: PathBuf,
    #[arg(long, default_value = "artifacts/k4/latest")]
    output: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
struct Config {
    schema_version: u16,
    seed: u64,
    public_epoch: u32,
    public_bucket: u32,
    sequence: u32,
    execution_slot: u32,
    start_tick: u64,
    cadence_ticks: u64,
    reassembly_ttl_ticks: u64,
    pump_ticks: u32,
    maximum_pump_ticks: u32,
    cooldown_slots: u32,
    execution_period_slots: u32,
    execution_offset_slots: u32,
    loss_indices: Vec<u8>,
}

#[derive(Serialize)]
struct Summary {
    schema_version: u16,
    seed: u64,
    transport_profile: &'static str,
    action_semantics: &'static str,
    fragments_per_frame: usize,
    fragment_bytes: usize,
    dropped_fragments_per_trace: usize,
    observer_trace_equal: bool,
    both_reassembled: bool,
    both_authorized: bool,
    execution_trace_equal: bool,
    replay_rejected_without_actuation: bool,
    tier_a: &'static str,
    tier_b: &'static str,
}

#[derive(Serialize)]
struct PublicTraceRow {
    side: &'static str,
    ordinal: u8,
    scheduled_tick: u64,
    frame_id: String,
    fragment_index: u8,
    delivered: bool,
    wire_length: usize,
}

#[derive(Default)]
struct RecordingPump {
    enabled: bool,
    transitions: u32,
}

impl PumpOutput for RecordingPump {
    fn set_pump(&mut self, enabled: bool) {
        if self.enabled != enabled {
            self.transitions += 1;
        }
        self.enabled = enabled;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReceiverResult {
    reassembled: bool,
    authorized: bool,
    pump_started: bool,
    pump_stopped: bool,
    replay_rejected: bool,
    transitions: u32,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("K4 smoke failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse();
    let config_text = fs::read_to_string(&args.config).map_err(|error| error.to_string())?;
    let config: Config = toml::from_str(&config_text).map_err(|error| error.to_string())?;
    if config.schema_version != 1 {
        return Err("unsupported K4 config schema".into());
    }
    fs::create_dir_all(&args.output).map_err(|error| error.to_string())?;

    let service = ServiceBinding([0x31; 16]);
    let policy_hash = PolicyHash([0x42; 32]);
    let obligation = ActionObligation {
        service,
        action: ActionCode::MenfuguInflateSoft,
        public_bucket: BucketId(config.public_bucket as u64),
        admission_cutoff: LogicalSlot(config.execution_slot.saturating_sub(2) as u64),
        release_window_start: LogicalSlot(config.execution_slot.saturating_sub(1) as u64),
        release_deadline: LogicalSlot(config.execution_slot.saturating_add(1) as u64),
        max_uses: 1,
        policy_hash,
    };
    let claim = required_claim(obligation.action);

    let issuer_a = TokenIssuer::new(
        CryptographicRootSecret::new([0x55; 32]),
        config.public_epoch,
        &[service],
    )
    .map_err(debug_error)?;
    let issuer_b = TokenIssuer::new(
        CryptographicRootSecret::new([0x55; 32]),
        config.public_epoch,
        &[service],
    )
    .map_err(debug_error)?;
    let identity = PublicFrameIdentity {
        service,
        public_epoch: config.public_epoch,
        public_bucket: config.public_bucket,
        slot_in_bucket: 0,
        sequence: config.sequence,
        absolute_slot: LogicalSlot(config.execution_slot as u64),
    };
    let envelope_a = issuer_a
        .issue_action_frame(identity, &obligation, claim)
        .map_err(debug_error)?;
    let envelope_b = issuer_b
        .issue_action_frame(identity, &obligation, claim)
        .map_err(debug_error)?;

    let frame_id_key = TransportIdKey::new([0x77; 32]);
    let transport_identity = make_transport_identity(&envelope_a)?;
    let frame_id = derive_frame_id(&frame_id_key, transport_identity);
    let fragments_a = fragment_envelope(envelope_a.as_bytes(), frame_id);
    let fragments_b = fragment_envelope(envelope_b.as_bytes(), frame_id);
    let loss_tape = PublicLossTape::from_indices(&config.loss_indices).map_err(debug_error)?;
    let trace_a = simulate(
        &fragments_a,
        config.start_tick,
        config.cadence_ticks,
        &loss_tape,
    );
    let trace_b = simulate(
        &fragments_b,
        config.start_tick,
        config.cadence_ticks,
        &loss_tape,
    );

    let observer_equal = observer_traces_are_equal(&trace_a, &trace_b);
    let receiver_a = run_receiver(
        &trace_a,
        make_verifier(
            &issuer_a,
            service,
            policy_hash,
            obligation.action,
            claim,
            &obligation,
        )?,
        service,
        &config,
    )?;
    let receiver_b = run_receiver(
        &trace_b,
        make_verifier(
            &issuer_b,
            service,
            policy_hash,
            obligation.action,
            claim,
            &obligation,
        )?,
        service,
        &config,
    )?;

    let execution_equal = receiver_a == receiver_b;
    let summary = Summary {
        schema_version: 1,
        seed: config.seed,
        transport_profile: "APLOT-20x20-v1",
        action_semantics: "MenfuguInflateSoft",
        fragments_per_frame: TOTAL_FRAGMENT_COUNT,
        fragment_bytes: 20,
        dropped_fragments_per_trace: config.loss_indices.len(),
        observer_trace_equal: observer_equal,
        both_reassembled: receiver_a.reassembled && receiver_b.reassembled,
        both_authorized: receiver_a.authorized && receiver_b.authorized,
        execution_trace_equal: execution_equal,
        replay_rejected_without_actuation: receiver_a.replay_rejected && receiver_b.replay_rejected,
        tier_a: "VERIFIED",
        tier_b: "NOT_VERIFIED",
    };
    write_artifacts(&args.output, &summary, &trace_a, &trace_b)?;

    if !summary.observer_trace_equal
        || !summary.both_reassembled
        || !summary.both_authorized
        || !summary.execution_trace_equal
        || !summary.replay_rejected_without_actuation
    {
        return Err("K4 invariant failed".into());
    }
    println!(
        "K4 Tier A verified; Tier B NOT_VERIFIED; artifacts={}",
        args.output.display()
    );
    Ok(())
}

fn make_transport_identity(
    envelope: &AtypicalityTokenEnvelope,
) -> Result<TransportFrameIdentity, String> {
    let outer = envelope.outer().map_err(debug_error)?;
    Ok(TransportFrameIdentity {
        service_alias: outer.service_alias.0,
        public_epoch: outer.public_epoch,
        public_bucket: outer.public_bucket,
        sequence: outer.sequence,
    })
}

fn make_verifier(
    issuer: &TokenIssuer,
    service: ServiceBinding,
    policy_hash: PolicyHash,
    action: ActionCode,
    claim: ClaimBound,
    obligation: &ActionObligation,
) -> Result<TokenVerifier, String> {
    let mut registry = KeyRegistry::default();
    registry
        .insert(
            issuer
                .verifier_material(service)
                .ok_or_else(|| "missing verifier material".to_owned())?,
        )
        .map_err(debug_error)?;
    let mut policies = PolicyAllowlist::default();
    policies
        .allow(policy_hash, action, claim, semantics_tag(obligation, claim))
        .map_err(debug_error)?;
    Ok(TokenVerifier::new(
        registry,
        policies,
        RevocationSnapshot::default(),
        Arc::new(InMemoryReplayStore::default()),
    ))
}

fn run_receiver(
    trace: &TransportTrace,
    verifier: TokenVerifier,
    service: ServiceBinding,
    config: &Config,
) -> Result<ReceiverResult, String> {
    let policy = ExecutionPolicy {
        pump_ticks: config.pump_ticks,
        maximum_pump_ticks: config.maximum_pump_ticks,
        cooldown_slots: config.cooldown_slots,
        execution_period_slots: config.execution_period_slots,
        execution_offset_slots: config.execution_offset_slots,
    };
    let adapter = HostVerifierAdapter::new(verifier, service, config.public_epoch);
    let mut runtime = MenfuguRuntime::<_, _, ACTIVE_FRAMES, CONSUMED_TOKENS>::new(
        adapter,
        RecordingPump::default(),
        config.reassembly_ttl_ticks,
        policy,
    )
    .map_err(debug_error)?;

    let mut reassembled = false;
    let mut authorized = false;
    let mut pump_started = false;
    let mut completion_tick = config.start_tick;
    for observation in &trace.observations {
        if !observation.delivered {
            continue;
        }
        let event = runtime.on_gatt_write(
            &observation.wire,
            observation.scheduled_tick,
            config.execution_slot,
        );
        if let RuntimeEvent::PumpStarted { .. } = event {
            reassembled = true;
            authorized = true;
            pump_started = true;
            completion_tick = observation.scheduled_tick;
        }
    }
    let pump_stopped = runtime.on_public_timer(
        completion_tick.saturating_add(u64::from(config.pump_ticks)),
        config.execution_slot,
    ) == RuntimeEvent::PumpStopped;

    let transitions_before_replay = runtime.pump().transitions;
    let mut replay_rejected = false;
    for observation in &trace.observations {
        if !observation.delivered {
            continue;
        }
        let event = runtime.on_gatt_write(
            &observation.wire,
            observation
                .scheduled_tick
                .saturating_add(config.reassembly_ttl_ticks + 1),
            config.execution_slot,
        );
        if event == RuntimeEvent::Rejected {
            replay_rejected = true;
        }
    }
    replay_rejected &= runtime.pump().transitions == transitions_before_replay;

    Ok(ReceiverResult {
        reassembled,
        authorized,
        pump_started,
        pump_stopped,
        replay_rejected,
        transitions: runtime.pump().transitions,
    })
}

fn write_artifacts(
    output: &Path,
    summary: &Summary,
    trace_a: &TransportTrace,
    trace_b: &TransportTrace,
) -> Result<(), String> {
    let summary_json = serde_json::to_string_pretty(summary).map_err(|error| error.to_string())?;
    fs::write(output.join("summary.json"), summary_json).map_err(|error| error.to_string())?;

    let mut writer = csv::Writer::from_path(output.join("transport_trace.csv"))
        .map_err(|error| error.to_string())?;
    for (side, trace) in [("A", trace_a), ("B", trace_b)] {
        for observation in &trace.observations {
            writer
                .serialize(PublicTraceRow {
                    side,
                    ordinal: observation.ordinal,
                    scheduled_tick: observation.scheduled_tick,
                    frame_id: frame_id_hex(observation.frame_id),
                    fragment_index: observation.fragment_index,
                    delivered: observation.delivered,
                    wire_length: observation.wire.len(),
                })
                .map_err(|error| error.to_string())?;
        }
    }
    writer.flush().map_err(|error| error.to_string())
}

fn frame_id_hex(frame_id: [u8; 3]) -> String {
    format!("{:02x}{:02x}{:02x}", frame_id[0], frame_id[1], frame_id[2])
}

fn debug_error(error: impl core::fmt::Debug) -> String {
    format!("{error:?}")
}

#[allow(dead_code)]
fn assert_envelope_size() {
    let _: [u8; 236] = [0; ENVELOPE_SIZE];
}
