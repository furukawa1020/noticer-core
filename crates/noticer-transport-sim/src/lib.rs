#![forbid(unsafe_code)]

//! Deterministic public-loss transport simulation with no application retry.

use noticer_transport_core::{Fragment, FrameId, FRAGMENT_SIZE, TOTAL_FRAGMENT_COUNT};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicLossTape {
    dropped: [bool; TOTAL_FRAGMENT_COUNT],
}

impl PublicLossTape {
    pub fn from_indices(indices: &[u8]) -> Result<Self, LossTapeError> {
        let mut dropped = [false; TOTAL_FRAGMENT_COUNT];
        for index in indices {
            let index = usize::from(*index);
            if index >= TOTAL_FRAGMENT_COUNT {
                return Err(LossTapeError::InvalidIndex);
            }
            dropped[index] = true;
        }
        Ok(Self { dropped })
    }

    pub fn from_seed(seed: u64, numerator: u32, denominator: u32) -> Result<Self, LossTapeError> {
        if denominator == 0 || numerator > denominator {
            return Err(LossTapeError::InvalidRate);
        }
        let mut state = seed;
        let mut dropped = [false; TOTAL_FRAGMENT_COUNT];
        for value in &mut dropped {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *value = (state % u64::from(denominator)) < u64::from(numerator);
        }
        Ok(Self { dropped })
    }

    pub fn is_dropped(&self, ordinal: usize) -> bool {
        self.dropped.get(ordinal).copied().unwrap_or(true)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LossTapeError {
    InvalidIndex,
    InvalidRate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransportObservation {
    pub ordinal: u8,
    pub scheduled_tick: u64,
    pub frame_id: [u8; 3],
    pub fragment_index: u8,
    pub delivered: bool,
    #[serde(skip)]
    pub wire: [u8; FRAGMENT_SIZE],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportTrace {
    pub observations: [TransportObservation; TOTAL_FRAGMENT_COUNT],
}

pub fn simulate(
    fragments: &[Fragment; TOTAL_FRAGMENT_COUNT],
    start_tick: u64,
    cadence_ticks: u64,
    loss_tape: &PublicLossTape,
) -> TransportTrace {
    let observations = core::array::from_fn(|ordinal| {
        let fragment = fragments[ordinal];
        TransportObservation {
            ordinal: ordinal as u8,
            scheduled_tick: start_tick.saturating_add(cadence_ticks.saturating_mul(ordinal as u64)),
            frame_id: fragment.frame_id.as_bytes(),
            fragment_index: fragment.index,
            delivered: !loss_tape.is_dropped(ordinal),
            wire: fragment.encode(),
        }
    });
    TransportTrace { observations }
}

/// Includes payload bytes because a BLE observer can see every transmitted octet.
pub fn observer_traces_are_equal(left: &TransportTrace, right: &TransportTrace) -> bool {
    left == right
}

pub fn frame_id(trace: &TransportTrace) -> FrameId {
    let bytes = trace.observations[0].frame_id;
    // FrameId construction is intentionally kept inside the transport crates.
    trace
        .observations
        .iter()
        .find(|observation| observation.frame_id == bytes)
        .map(|_| {
            let wire = trace.observations[0].wire;
            Fragment::parse(&wire)
                .expect("simulator emits canonical fragments")
                .frame_id
        })
        .expect("fixed trace is never empty")
}

#[cfg(test)]
mod tests {
    use super::*;
    use noticer_protocol::ENVELOPE_SIZE;
    use noticer_transport_core::{
        derive_frame_id, fragment_envelope, TransportFrameIdentity, TransportIdKey,
    };

    #[test]
    fn public_tape_and_cadence_are_reproducible_without_retry() {
        let envelope = [3_u8; ENVELOPE_SIZE];
        let frame_id = derive_frame_id(
            &TransportIdKey::new([8; 32]),
            TransportFrameIdentity {
                service_alias: [1; 8],
                public_epoch: 2,
                public_bucket: 3,
                sequence: 4,
            },
        );
        let fragments = fragment_envelope(&envelope, frame_id);
        let tape = PublicLossTape::from_indices(&[0, 5, 10, 15]).unwrap();
        let left = simulate(&fragments, 100, 7, &tape);
        let right = simulate(&fragments, 100, 7, &tape);
        assert!(observer_traces_are_equal(&left, &right));
        assert_eq!(left.observations.len(), 20);
        assert_eq!(left.observations[19].scheduled_tick, 233);
        assert_eq!(
            left.observations
                .iter()
                .filter(|item| !item.delivered)
                .count(),
            4
        );
    }
}
