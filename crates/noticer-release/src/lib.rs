#![forbid(unsafe_code)]

use noticer_claim::ActionClaim;
use noticer_protocol::{CapabilityBody, BODY_LENGTH};
use noticer_types::{ActionCode, Epoch, LogicalSlot, PolicyHash};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicMintInputs {
    pub audience_binding: [u8; 32],
    pub epoch: Epoch,
    pub nonce: [u8; 16],
}

pub struct CapabilityMint;

impl CapabilityMint {
    pub fn mint(claim: &ActionClaim, inputs: PublicMintInputs) -> CapabilityBody {
        CapabilityBody {
            audience_binding: inputs.audience_binding,
            action: claim.action(),
            policy_hash: claim.policy_hash(),
            epoch: inputs.epoch,
            nonce: inputs.nonce,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimProjection {
    pub action: ActionCode,
    pub policy_hash: PolicyHash,
    pub release_slot: LogicalSlot,
}

impl From<&ActionClaim> for ClaimProjection {
    fn from(claim: &ActionClaim) -> Self {
        Self {
            action: claim.action(),
            policy_hash: claim.policy_hash(),
            release_slot: claim.issued_slot(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TracePolicy {
    pub first_slot: LogicalSlot,
    pub slot_count: u64,
    pub interval_slots: u64,
    pub audience_binding: [u8; 32],
    pub epoch: Epoch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservablePacket {
    pub slot: LogicalSlot,
    pub bytes: [u8; BODY_LENGTH],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservableTrace {
    pub packets: Vec<ObservablePacket>,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum TraceViolation {
    #[error("trace policy has a zero horizon or interval")]
    InvalidPolicy,
    #[error("trace schedule overflowed logical time")]
    TimeOverflow,
    #[error("more than one claim occupies a release slot")]
    ClaimCollision,
}

pub struct MatchedClaimTraceSimulator;

impl MatchedClaimTraceSimulator {
    pub fn shape(
        claims: &[ClaimProjection],
        policy: TracePolicy,
        public_seed: [u8; 32],
    ) -> Result<ObservableTrace, TraceViolation> {
        if policy.slot_count == 0 || policy.interval_slots == 0 {
            return Err(TraceViolation::InvalidPolicy);
        }
        let mut packets = Vec::with_capacity(policy.slot_count as usize);
        for index in 0..policy.slot_count {
            let offset = index
                .checked_mul(policy.interval_slots)
                .ok_or(TraceViolation::TimeOverflow)?;
            let slot = LogicalSlot(
                policy
                    .first_slot
                    .0
                    .checked_add(offset)
                    .ok_or(TraceViolation::TimeOverflow)?,
            );
            let mut matches = claims.iter().filter(|claim| claim.release_slot == slot);
            let selected = matches.next();
            if matches.next().is_some() {
                return Err(TraceViolation::ClaimCollision);
            }
            let (action, policy_hash) = selected
                .map_or((ActionCode::NoAction, PolicyHash([0; 32])), |claim| {
                    (claim.action, claim.policy_hash)
                });
            let nonce = public_nonce(public_seed, slot, policy.audience_binding);
            let body = CapabilityBody {
                audience_binding: policy.audience_binding,
                action,
                policy_hash,
                epoch: policy.epoch,
                nonce,
            };
            packets.push(ObservablePacket {
                slot,
                bytes: body.encode(),
            });
        }
        Ok(ObservableTrace { packets })
    }
}

fn public_nonce(seed: [u8; 32], slot: LogicalSlot, audience: [u8; 32]) -> [u8; 16] {
    let mut hash = Sha256::new();
    hash.update(b"NOTICER_TNMC_PUBLIC_RANDOMNESS_V1");
    hash.update(seed);
    hash.update(slot.0.to_be_bytes());
    hash.update(audience);
    let digest = hash.finalize();
    let mut nonce = [0; 16];
    nonce.copy_from_slice(&digest[..16]);
    nonce
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TnmcSmokeReport {
    pub trials: u64,
    pub trace_mismatches: u64,
    pub packet_mismatches: u64,
}

impl TnmcSmokeReport {
    pub const fn passes(&self) -> bool {
        self.trace_mismatches == 0 && self.packet_mismatches == 0
    }
}

pub fn run_tnmc_smoke_game(
    claims: &[ClaimProjection],
    policy: TracePolicy,
    master_seed: [u8; 32],
    trials: u64,
) -> Result<TnmcSmokeReport, TraceViolation> {
    if trials == 0 {
        return Err(TraceViolation::InvalidPolicy);
    }
    let mut report = TnmcSmokeReport {
        trials,
        trace_mismatches: 0,
        packet_mismatches: 0,
    };
    for trial in 0..trials {
        let mut hash = Sha256::new();
        hash.update(b"NOTICER_TNMC_TRIAL_V1");
        hash.update(master_seed);
        hash.update(trial.to_be_bytes());
        let seed = hash.finalize().into();

        // The two worlds may contain arbitrary different private histories. Neither history is
        // accepted by this Low Side API; only their common claim projection crosses the boundary.
        let left = MatchedClaimTraceSimulator::shape(claims, policy, seed)?;
        let right = MatchedClaimTraceSimulator::shape(claims, policy, seed)?;
        if left != right {
            report.trace_mismatches += 1;
            report.packet_mismatches += left
                .packets
                .iter()
                .zip(&right.packets)
                .filter(|(left, right)| left != right)
                .count() as u64;
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> TracePolicy {
        TracePolicy {
            first_slot: LogicalSlot(100),
            slot_count: 16,
            interval_slots: 5,
            audience_binding: [7; 32],
            epoch: Epoch(3),
        }
    }

    #[test]
    fn matched_claim_worlds_have_identical_full_traces() {
        let claims = [ClaimProjection {
            action: ActionCode::MenfuguInflateSoft,
            policy_hash: PolicyHash([9; 32]),
            release_slot: LogicalSlot(120),
        }];
        let report = run_tnmc_smoke_game(&claims, policy(), [42; 32], 1_000).unwrap();
        assert!(report.passes());
        assert_eq!(report.trace_mismatches, 0);
    }

    #[test]
    fn trace_schedule_is_fixed_size_and_fixed_rate() {
        let trace = MatchedClaimTraceSimulator::shape(&[], policy(), [1; 32]).unwrap();
        assert_eq!(trace.packets.len(), 16);
        assert!(trace
            .packets
            .iter()
            .all(|packet| packet.bytes.len() == BODY_LENGTH));
        assert!(trace
            .packets
            .windows(2)
            .all(|pair| pair[1].slot.0 - pair[0].slot.0 == 5));
    }

    #[test]
    fn claim_collision_fails_closed() {
        let claim = ClaimProjection {
            action: ActionCode::RenderAmbientPulse,
            policy_hash: PolicyHash([4; 32]),
            release_slot: LogicalSlot(100),
        };
        let result = MatchedClaimTraceSimulator::shape(&[claim, claim], policy(), [2; 32]);
        assert_eq!(result, Err(TraceViolation::ClaimCollision));
    }
}
