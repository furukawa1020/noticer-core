#![forbid(unsafe_code)]

//! AETP schedule shaping separated from all production cryptographic keys.

use noticer_aetp::{
    ActionObligation, ClaimBound, PublicContext, ScheduleRandomTape, ServiceBinding,
};
use noticer_release::TokenPlan;
use noticer_types::LogicalSlot;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PublicFrameIdentity {
    pub service: ServiceBinding,
    pub public_epoch: u32,
    pub public_bucket: u32,
    pub slot_in_bucket: u16,
    pub sequence: u32,
    pub absolute_slot: LogicalSlot,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("frame issuance failed")]
pub struct FrameIssueError;

pub trait FrameIssuer: Sync {
    fn frame_length(&self) -> usize;

    fn issue_cover(&self, identity: PublicFrameIdentity) -> Result<Vec<u8>, FrameIssueError>;

    fn issue_action(
        &self,
        identity: PublicFrameIdentity,
        obligation: &ActionObligation,
        claim_bound: ClaimBound,
    ) -> Result<Vec<u8>, FrameIssueError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkFrame {
    pub identity: PublicFrameIdentity,
    pub bytes: Box<[u8]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkTrace {
    pub frames: Vec<NetworkFrame>,
}

impl NetworkTrace {
    pub fn byte_stream(&self) -> impl Iterator<Item = &[u8]> {
        self.frames.iter().map(|frame| frame.bytes.as_ref())
    }

    pub fn service_view(&self, service: ServiceBinding) -> Vec<&[u8]> {
        self.frames
            .iter()
            .filter(|frame| frame.identity.service == service)
            .map(|frame| frame.bytes.as_ref())
            .collect()
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"NOTICER_AETP_NETWORK_TRACE_V2");
        for frame in &self.frames {
            digest.update(&frame.bytes);
        }
        digest.finalize().into()
    }
}

pub struct ActionEquivalentTraceShaper;

impl ActionEquivalentTraceShaper {
    pub fn shape(
        plan: &TokenPlan,
        context: &PublicContext,
        schedule_tape: &ScheduleRandomTape,
        issuer: &impl FrameIssuer,
    ) -> Result<NetworkTrace, TraceShapeError> {
        context.validate().map_err(|_| TraceShapeError::InvalidPublicInput)?;
        if context.network.services != plan.services()
            || issuer.frame_length() != usize::from(context.schedule.fixed_ciphertext_size)
        {
            return Err(TraceShapeError::InvalidPublicInput);
        }
        let slots_per_bucket = u64::from(context.schedule.slots_per_bucket);
        let mut placements = BTreeMap::new();
        for planned in plan.actions() {
            let obligation = planned.obligation();
            let bucket_start = context
                .network
                .start_slot
                .0
                .checked_add(obligation.public_bucket.0.saturating_mul(slots_per_bucket))
                .ok_or(TraceShapeError::InvalidPublicInput)?;
            let bucket_end = bucket_start
                .checked_add(slots_per_bucket - 1)
                .ok_or(TraceShapeError::InvalidPublicInput)?;
            let start = obligation.release_window_start.0.max(bucket_start);
            let end = obligation.release_deadline.0.min(bucket_end);
            if start > end || obligation.public_bucket.0 >= u64::from(context.schedule.buckets) {
                return Err(TraceShapeError::InvalidPublicInput);
            }
            let width = end - start + 1;
            let mut domain = Vec::with_capacity(24);
            domain.extend_from_slice(&obligation.service.0);
            domain.extend_from_slice(&obligation.public_bucket.0.to_le_bytes());
            let chosen = start + schedule_tape.sample_u64(&domain, 0) % width;
            placements.insert(
                (obligation.service, obligation.public_bucket.0, chosen),
                planned,
            );
        }

        let capacity = context
            .schedule
            .frame_count(context.network.services.len())
            .map_err(|_| TraceShapeError::InvalidPublicInput)?;
        let mut frames = Vec::with_capacity(capacity);
        for bucket in 0..u64::from(context.schedule.buckets) {
            for slot in 0..context.schedule.slots_per_bucket {
                let offset = bucket * slots_per_bucket + u64::from(slot);
                let absolute_slot = LogicalSlot(
                    context
                        .network
                        .start_slot
                        .0
                        .checked_add(offset)
                        .ok_or(TraceShapeError::InvalidPublicInput)?,
                );
                for service in &context.network.services {
                    let sequence = u32::try_from(offset).map_err(|_| TraceShapeError::InvalidPublicInput)?;
                    let identity = PublicFrameIdentity {
                        service: *service,
                        public_epoch: context.network.public_epoch,
                        public_bucket: u32::try_from(bucket)
                            .map_err(|_| TraceShapeError::InvalidPublicInput)?,
                        slot_in_bucket: slot,
                        sequence,
                        absolute_slot,
                    };
                    let bytes = if let Some(planned) = placements.get(&(*service, bucket, absolute_slot.0)) {
                        issuer.issue_action(
                            identity,
                            planned.obligation(),
                            planned.claim_bound(),
                        )
                    } else {
                        issuer.issue_cover(identity)
                    }
                    .map_err(|_| TraceShapeError::Issuance)?;
                    if bytes.len() != issuer.frame_length() {
                        return Err(TraceShapeError::Issuance);
                    }
                    frames.push(NetworkFrame {
                        identity,
                        bytes: bytes.into_boxed_slice(),
                    });
                }
            }
        }
        Ok(NetworkTrace { frames })
    }
}

/// Deterministic simulation-only frame issuer. The secret is independent from
/// `ScheduleRandomTape`; production token code lives in `noticer-token`.
pub struct SimulationFrameIssuer {
    secret: [u8; 32],
    frame_length: usize,
}

impl SimulationFrameIssuer {
    pub const fn new(secret: [u8; 32], frame_length: usize) -> Self {
        Self {
            secret,
            frame_length,
        }
    }

    fn frame(
        &self,
        identity: PublicFrameIdentity,
        action: Option<(&ActionObligation, ClaimBound)>,
    ) -> Vec<u8> {
        let mut seed = Sha256::new();
        seed.update(b"NOTICER_SIMULATION_FRAME_ONLY");
        seed.update(self.secret);
        seed.update(identity.service.0);
        seed.update(identity.public_epoch.to_le_bytes());
        seed.update(identity.public_bucket.to_le_bytes());
        seed.update(identity.sequence.to_le_bytes());
        if let Some((obligation, bound)) = action {
            seed.update(b"ACTION");
            seed.update((obligation.action as u16).to_le_bytes());
            seed.update(obligation.policy_hash.0);
            seed.update([bound.semantic as u8, bound.audience as u8, bound.impact as u8]);
        } else {
            seed.update(b"COVER");
        }
        let seed: [u8; 32] = seed.finalize().into();
        let mut out = Vec::with_capacity(self.frame_length);
        let mut counter = 0_u32;
        while out.len() < self.frame_length {
            let mut block = Sha256::new();
            block.update(b"NOTICER_SIMULATION_FRAME_EXPAND");
            block.update(seed);
            block.update(counter.to_le_bytes());
            out.extend_from_slice(&block.finalize());
            counter += 1;
        }
        out.truncate(self.frame_length);
        out
    }
}

impl FrameIssuer for SimulationFrameIssuer {
    fn frame_length(&self) -> usize {
        self.frame_length
    }

    fn issue_cover(&self, identity: PublicFrameIdentity) -> Result<Vec<u8>, FrameIssueError> {
        Ok(self.frame(identity, None))
    }

    fn issue_action(
        &self,
        identity: PublicFrameIdentity,
        obligation: &ActionObligation,
        claim_bound: ClaimBound,
    ) -> Result<Vec<u8>, FrameIssueError> {
        Ok(self.frame(identity, Some((obligation, claim_bound))))
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum TraceShapeError {
    #[error("invalid public trace-shaping input")]
    InvalidPublicInput,
    #[error("fixed-width frame issuance failed")]
    Issuance,
}

#[cfg(test)]
mod tests {
    use super::*;
    use noticer_aetp::{
        required_claim, ActionSemantics, BucketId, ChannelSchedule, PublicNetworkTape,
    };
    use noticer_types::{ActionCode, PolicyHash};

    #[test]
    fn same_public_plan_and_schedule_make_identical_simulation_trace() {
        let service = ServiceBinding([1; 16]);
        let context = PublicContext {
            schedule: ChannelSchedule {
                buckets: 2,
                slots_per_bucket: 4,
                frame_interval_ms: 250,
                fixed_plaintext_size: 160,
                fixed_ciphertext_size: 236,
            },
            network: PublicNetworkTape {
                services: vec![service],
                public_epoch: 9,
                start_slot: LogicalSlot(100),
            },
        };
        let semantics = ActionSemantics::new(vec![ActionObligation {
            service,
            action: ActionCode::RenderAmbientPulse,
            public_bucket: BucketId(1),
            admission_cutoff: LogicalSlot(102),
            release_window_start: LogicalSlot(104),
            release_deadline: LogicalSlot(107),
            max_uses: 1,
            policy_hash: PolicyHash([3; 32]),
        }])
        .unwrap();
        assert!(required_claim(ActionCode::RenderAmbientPulse).permits(required_claim(ActionCode::RenderAmbientPulse)));
        let plan = TokenPlan::from_action_semantics(&semantics, vec![service]).unwrap();
        let tape = ScheduleRandomTape([5; 32]);
        let a = SimulationFrameIssuer::new([8; 32], 236);
        let b = SimulationFrameIssuer::new([8; 32], 236);
        let left = ActionEquivalentTraceShaper::shape(&plan, &context, &tape, &a).unwrap();
        let right = ActionEquivalentTraceShaper::shape(&plan, &context, &tape, &b).unwrap();
        assert_eq!(left, right);
    }
}
