//! Measure synthetic, loss-free action-matched AETP runs for a bounded comparison.

#![forbid(unsafe_code)]

use std::io::{self, Write};
use std::sync::Mutex;

use noticer_aetp::{ActionObligation, ClaimBound};
use noticer_aetp_sim::{
    capture_matched_action_runtime, default_public_context, generate_action_equivalent_pairs,
    synthetic_readiness_pair, EQUIVALENCE_CLASS_COUNT,
};
use noticer_trace_shaper::{
    ActionEquivalentTraceShaper, FrameIssueError, FrameIssuer, PublicFrameIdentity,
    SimulationFrameIssuer,
};
use serde::Serialize;

struct RecordedIssuer {
    simulation: SimulationFrameIssuer,
    action_slot: Mutex<Option<u64>>,
}

impl FrameIssuer for RecordedIssuer {
    fn frame_length(&self) -> usize {
        self.simulation.frame_length()
    }

    fn issue_cover(&self, identity: PublicFrameIdentity) -> Result<Vec<u8>, FrameIssueError> {
        self.simulation.issue_cover(identity)
    }

    fn issue_action(
        &self,
        identity: PublicFrameIdentity,
        obligation: &ActionObligation,
        claim: ClaimBound,
    ) -> Result<Vec<u8>, FrameIssueError> {
        let mut slot = self.action_slot.lock().map_err(|_| FrameIssueError)?;
        if slot.replace(identity.absolute_slot.0).is_some() {
            return Err(FrameIssueError);
        }
        self.simulation.issue_action(identity, obligation, claim)
    }
}

#[derive(Serialize)]
struct CaseResult {
    split: &'static str,
    seed: u64,
    family: &'static str,
    service_index: usize,
    horizon_slots: usize,
    services: usize,
    slot_ms: u32,
    frame_bytes: u16,
    window_start: u64,
    deadline: u64,
    action_slot: u64,
    bytes_left: usize,
    bytes_right: usize,
    paired_metadata_equal: bool,
}

#[derive(Serialize)]
struct RecipientCase {
    seed: u64,
    slot_ms: u32,
    frame_bytes: u16,
    horizon_slots: u16,
    early_ready: u64,
    late_ready: u64,
    native_window_start: u64,
    deadline: u64,
    native_action_slot: u64,
    native_paired_full_trace_equal: bool,
}

fn recipient_run() -> Result<(), Box<dyn std::error::Error>> {
    let mut context = default_public_context();
    context.schedule.buckets = 9;
    let start = context.network.start_slot.0;
    let mut output = io::BufWriter::new(io::stdout().lock());
    for seed in 100..164 {
        let early_ready = 4 + seed % 4;
        let late_ready = 24 + seed % 8;
        let pair = synthetic_readiness_pair(seed, &context, early_ready, late_ready)?;
        let [obligation] = pair.shared_semantics.obligations.as_slice() else {
            return Err("expected one synthetic action".into());
        };
        let secret = [8; 32];
        let issuer = RecordedIssuer {
            simulation: SimulationFrameIssuer::new(
                secret,
                usize::from(context.schedule.fixed_ciphertext_size),
            ),
            action_slot: Mutex::new(None),
        };
        let trace = ActionEquivalentTraceShaper::shape(
            &pair.public_plan()?,
            &context,
            &pair.schedule_tape,
            &issuer,
        )?;
        let captures = capture_matched_action_runtime(&pair, secret)?;
        if trace.frames.len() != captures.left.observations.len()
            || !trace
                .frames
                .iter()
                .zip(&captures.left.observations)
                .all(|(frame, observed)| {
                    frame.identity.sequence == observed.sequence
                        && frame.identity.service == observed.service
                        && frame.bytes == observed.ciphertext
                })
        {
            return Err("recorded and captured traces do not match".into());
        }
        let native_action_slot = issuer
            .action_slot
            .into_inner()
            .map_err(|_| "action issuance recording failed")?
            .ok_or("no authorized action issued")?
            - start;
        let result = RecipientCase {
            seed,
            slot_ms: context.schedule.frame_interval_ms,
            frame_bytes: context.schedule.fixed_ciphertext_size,
            horizon_slots: context.schedule.buckets * context.schedule.slots_per_bucket,
            early_ready,
            late_ready,
            native_window_start: obligation.release_window_start.0 - start,
            deadline: obligation.release_deadline.0 - start,
            native_action_slot,
            native_paired_full_trace_equal: captures.pointwise_equal_observations(),
        };
        serde_json::to_writer(&mut output, &result)?;
        writeln!(&mut output)?;
    }
    output.flush()?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().nth(1).as_deref() == Some("--recipient") {
        return recipient_run();
    }
    let context = default_public_context();
    let schedule = context.schedule;
    let start = context.network.start_slot.0;
    let secret = [8; 32];
    let mut output = io::BufWriter::new(io::stdout().lock());
    for (split, seeds) in [("development", 0..8), ("evaluation", 100..124)] {
        for seed in seeds {
            for pair in generate_action_equivalent_pairs(EQUIVALENCE_CLASS_COUNT, seed, &context)? {
                let [obligation] = pair.shared_semantics.obligations.as_slice() else {
                    return Err("expected a single public action per case".into());
                };
                let issuer = RecordedIssuer {
                    simulation: SimulationFrameIssuer::new(
                        secret,
                        usize::from(schedule.fixed_ciphertext_size),
                    ),
                    action_slot: Mutex::new(None),
                };
                let trace = ActionEquivalentTraceShaper::shape(
                    &pair.public_plan()?,
                    &context,
                    &pair.schedule_tape,
                    &issuer,
                )?;
                let action_slot = issuer
                    .action_slot
                    .into_inner()
                    .map_err(|_| "action issuance recording failed")?
                    .ok_or("no authorized action issued")?;
                let captures = capture_matched_action_runtime(&pair, secret)?;
                let left = &captures.left.observations;
                let right = &captures.right.observations;
                if trace.frames.len() != left.len()
                    || !trace.frames.iter().zip(left).all(|(frame, observed)| {
                        frame.identity.sequence == observed.sequence
                            && frame.identity.service == observed.service
                            && frame.bytes == observed.ciphertext
                    })
                {
                    return Err("instrumented trace differs from the uninstrumented trace".into());
                }
                let paired_metadata_equal = left.len() == right.len()
                    && left.iter().zip(right).all(|(a, b)| {
                        a.scheduled_time_ms == b.scheduled_time_ms
                            && a.service == b.service
                            && a.ciphertext.len() == b.ciphertext.len()
                            && a.retry_count == b.retry_count
                            && a.failure == b.failure
                            && a.silence == b.silence
                    });
                let result = CaseResult {
                    split,
                    seed,
                    family: pair.family.label(),
                    service_index: context
                        .network
                        .services
                        .iter()
                        .position(|service| *service == obligation.service)
                        .ok_or("unknown action service")?,
                    horizon_slots: usize::from(schedule.buckets)
                        * usize::from(schedule.slots_per_bucket),
                    services: context.network.services.len(),
                    slot_ms: schedule.frame_interval_ms,
                    frame_bytes: schedule.fixed_ciphertext_size,
                    window_start: obligation.release_window_start.0 - start,
                    deadline: obligation.release_deadline.0 - start,
                    action_slot: action_slot - start,
                    bytes_left: left.iter().map(|frame| frame.ciphertext.len()).sum(),
                    bytes_right: right.iter().map(|frame| frame.ciphertext.len()).sum(),
                    paired_metadata_equal,
                };
                serde_json::to_writer(&mut output, &result)?;
                writeln!(&mut output)?;
            }
        }
    }
    Ok(())
}
