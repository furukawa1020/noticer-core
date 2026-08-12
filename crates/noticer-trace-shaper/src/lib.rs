#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use noticer_aetp::{
    ActionSemantics, BucketId, PairwiseServiceAlias, PublicContext, RandomTape, ServiceBinding,
    TransportStatus,
};
use noticer_types::{ActionCode, LogicalSlot};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const FIXED_PLAINTEXT_SIZE: usize = 88;
pub const FIXED_CIPHERTEXT_SIZE: usize = 104;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodedFrameKind {
    Cover,
    AuthorizedAction(ActionCode),
    PublicFailure(PublicFailureCode),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicFailureCode {
    ProtocolVersion,
    TransportUnavailable,
    EndpointUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkFrameView {
    pub slot: LogicalSlot,
    pub service_alias: PairwiseServiceAlias,
    pub packet_length: u16,
    pub ciphertext: Box<[u8]>,
    pub transport_status: TransportStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkTrace {
    pub frames: Vec<NetworkFrameView>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceFrameView {
    pub slot: LogicalSlot,
    pub service: ServiceBinding,
    pub decoded_kind: DecodedFrameKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceTrace {
    pub service: ServiceBinding,
    pub frames: Vec<ServiceFrameView>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollusionTrace {
    pub services: Vec<ServiceTrace>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShapedTrace {
    pub network: NetworkTrace,
    pub services: Vec<ServiceTrace>,
    pub collusion: CollusionTrace,
}

pub struct ActionEquivalentTraceShaper;

impl ActionEquivalentTraceShaper {
    pub fn shape(
        semantics: &ActionSemantics,
        context: &PublicContext,
        random_tape: &RandomTape,
    ) -> Result<ShapedTrace, ShaperError> {
        if usize::from(context.channel_schedule.fixed_plaintext_size) != FIXED_PLAINTEXT_SIZE
            || usize::from(context.channel_schedule.fixed_ciphertext_size) != FIXED_CIPHERTEXT_SIZE
            || context.channel_schedule.buckets == 0
            || context.channel_schedule.slots_per_bucket == 0
        {
            return Err(ShaperError::InvalidSchedule);
        }
        semantics
            .validate(context.channel_schedule)
            .map_err(|_| ShaperError::InvalidSemantics)?;
        let services: BTreeSet<_> = semantics
            .obligations
            .iter()
            .map(|obligation| obligation.service)
            .collect();
        let mut placements = BTreeMap::new();
        for (index, obligation) in semantics.obligations.iter().enumerate() {
            let alias = service_alias(obligation.service, context.public_epoch);
            let width = obligation.release_deadline.0 - obligation.release_window_start.0 + 1;
            let offset = domain_u64(
                b"NOTICER_AETP_SCHEDULE_V1",
                random_tape,
                context.public_epoch,
                &alias.0,
                obligation.public_bucket,
                index as u64,
            ) % width;
            let slot = obligation.release_window_start.0 + offset;
            let key = (obligation.service, slot);
            if placements.insert(key, obligation).is_some() {
                return Err(ShaperError::PlacementCollision);
            }
        }

        let total_slots = u64::from(context.channel_schedule.buckets)
            * u64::from(context.channel_schedule.slots_per_bucket);
        let mut network_frames = Vec::new();
        let mut service_frames: BTreeMap<ServiceBinding, Vec<ServiceFrameView>> = services
            .iter()
            .map(|service| (*service, Vec::new()))
            .collect();
        for slot in 0..total_slots {
            for service in &services {
                let alias = service_alias(*service, context.public_epoch);
                let selected = placements.get(&(*service, slot));
                let decoded_kind = selected.map_or(DecodedFrameKind::Cover, |obligation| {
                    DecodedFrameKind::AuthorizedAction(obligation.action)
                });
                let bucket = BucketId(slot / u64::from(context.channel_schedule.slots_per_bucket));
                let slot_in_bucket =
                    (slot % u64::from(context.channel_schedule.slots_per_bucket)) as u16;
                let plain = encode_plain_frame(
                    context,
                    bucket,
                    slot_in_bucket,
                    alias,
                    decoded_kind,
                    selected.map(|obligation| obligation.policy_hash.0),
                );
                let ciphertext = seal(
                    &plain,
                    *service,
                    alias,
                    context.public_epoch,
                    slot,
                    random_tape,
                )?;
                let frame_index = network_frames.len();
                let status = if context.public_network_tape.statuses.is_empty() {
                    TransportStatus::Delivered
                } else {
                    context.public_network_tape.statuses
                        [frame_index % context.public_network_tape.statuses.len()]
                };
                network_frames.push(NetworkFrameView {
                    slot: LogicalSlot(slot),
                    service_alias: alias,
                    packet_length: FIXED_CIPHERTEXT_SIZE as u16,
                    ciphertext: ciphertext.into_boxed_slice(),
                    transport_status: status,
                });
                service_frames
                    .get_mut(service)
                    .ok_or(ShaperError::InvalidSemantics)?
                    .push(ServiceFrameView {
                        slot: LogicalSlot(slot),
                        service: *service,
                        decoded_kind,
                    });
            }
        }
        let services: Vec<_> = service_frames
            .into_iter()
            .map(|(service, frames)| ServiceTrace { service, frames })
            .collect();
        Ok(ShapedTrace {
            network: NetworkTrace {
                frames: network_frames,
            },
            collusion: CollusionTrace {
                services: services.clone(),
            },
            services,
        })
    }
}

pub fn service_alias(service: ServiceBinding, public_epoch: u64) -> PairwiseServiceAlias {
    let mut hash = Sha256::new();
    hash.update(b"NOTICER_AETP_SERVICE_V1");
    hash.update(service.0);
    hash.update(public_epoch.to_be_bytes());
    PairwiseServiceAlias(hash.finalize().into())
}

pub fn trace_hash(trace: &NetworkTrace) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"NOTICER_AETP_TRACE_V1");
    for frame in &trace.frames {
        hash.update(frame.slot.0.to_be_bytes());
        hash.update(frame.service_alias.0);
        hash.update(frame.packet_length.to_be_bytes());
        hash.update(&frame.ciphertext);
        hash.update([frame.transport_status as u8]);
    }
    hash.finalize().into()
}

fn domain_u64(
    domain: &[u8],
    tape: &RandomTape,
    epoch: u64,
    alias: &[u8; 32],
    bucket: BucketId,
    index: u64,
) -> u64 {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(tape.0);
    hash.update(epoch.to_be_bytes());
    hash.update(alias);
    hash.update(bucket.0.to_be_bytes());
    hash.update(index.to_be_bytes());
    let digest = hash.finalize();
    u64::from_be_bytes(
        digest[..8]
            .try_into()
            .expect("SHA-256 prefix has fixed size"),
    )
}

fn encode_plain_frame(
    context: &PublicContext,
    bucket: BucketId,
    slot: u16,
    alias: PairwiseServiceAlias,
    kind: DecodedFrameKind,
    policy_hash: Option<[u8; 32]>,
) -> [u8; FIXED_PLAINTEXT_SIZE] {
    let mut frame = [0; FIXED_PLAINTEXT_SIZE];
    frame[..2].copy_from_slice(&context.protocol_version.to_be_bytes());
    frame[2..10].copy_from_slice(&context.public_epoch.to_be_bytes());
    frame[10..18].copy_from_slice(&bucket.0.to_be_bytes());
    frame[18..20].copy_from_slice(&slot.to_be_bytes());
    frame[20..52].copy_from_slice(&alias.0);
    match kind {
        DecodedFrameKind::Cover => frame[52] = 0,
        DecodedFrameKind::AuthorizedAction(action) => {
            frame[52] = 1;
            frame[53..55].copy_from_slice(&(action as u16).to_be_bytes());
        }
        DecodedFrameKind::PublicFailure(code) => {
            frame[52] = 2;
            frame[53..55].copy_from_slice(&(code as u16).to_be_bytes());
        }
    }
    if let Some(policy) = policy_hash {
        frame[55..63].copy_from_slice(&policy[..8]);
    }
    frame
}

fn seal(
    plaintext: &[u8; FIXED_PLAINTEXT_SIZE],
    service: ServiceBinding,
    alias: PairwiseServiceAlias,
    epoch: u64,
    slot: u64,
    tape: &RandomTape,
) -> Result<Vec<u8>, ShaperError> {
    let mut key_hash = Sha256::new();
    key_hash.update(b"NOTICER_AETP_SEAL_KEY_V1");
    key_hash.update(tape.0);
    key_hash.update(service.0);
    let key_bytes: [u8; 32] = key_hash.finalize().into();
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let mut nonce_hash = Sha256::new();
    nonce_hash.update(b"NOTICER_AETP_NONCE_V1");
    nonce_hash.update(tape.0);
    nonce_hash.update(alias.0);
    nonce_hash.update(epoch.to_be_bytes());
    nonce_hash.update(slot.to_be_bytes());
    let digest = nonce_hash.finalize();
    cipher
        .encrypt(XNonce::from_slice(&digest[..24]), plaintext.as_slice())
        .map_err(|_| ShaperError::SealingFailure)
}

pub fn reject_malformed_ciphertext(ciphertext: &[u8]) -> Result<(), ShaperError> {
    if ciphertext.len() != FIXED_CIPHERTEXT_SIZE {
        return Err(ShaperError::MalformedCiphertext);
    }
    Ok(())
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ShaperError {
    #[error("invalid fixed-rate schedule")]
    InvalidSchedule,
    #[error("invalid action semantics")]
    InvalidSemantics,
    #[error("two actions collide in one service slot")]
    PlacementCollision,
    #[error("frame sealing failed")]
    SealingFailure,
    #[error("malformed ciphertext")]
    MalformedCiphertext,
}

#[cfg(test)]
mod tests {
    use super::*;
    use noticer_aetp::{ActionObligation, ChannelSchedule, PublicNetworkTape};
    use noticer_types::PolicyHash;
    use proptest::prelude::*;

    fn fixture(ready_independent_window: (u64, u64)) -> (ActionSemantics, PublicContext) {
        let schedule = ChannelSchedule {
            buckets: 1,
            slots_per_bucket: 32,
            frame_interval_ms: 1_000,
            fixed_plaintext_size: FIXED_PLAINTEXT_SIZE as u16,
            fixed_ciphertext_size: FIXED_CIPHERTEXT_SIZE as u16,
        };
        (
            ActionSemantics {
                obligations: vec![ActionObligation {
                    service: ServiceBinding::from_u64(1),
                    action: ActionCode::MenfuguInflateSoft,
                    public_bucket: BucketId(0),
                    admission_cutoff: LogicalSlot(7),
                    release_window_start: LogicalSlot(ready_independent_window.0),
                    release_deadline: LogicalSlot(ready_independent_window.1),
                    max_uses: 1,
                    policy_hash: PolicyHash([3; 32]),
                }],
            },
            PublicContext {
                protocol_version: 1,
                public_epoch: 9,
                channel_schedule: schedule,
                public_network_tape: PublicNetworkTape { statuses: vec![] },
            },
        )
    }

    proptest! {
        #[test]
        fn same_semantics_and_tape_are_pointwise_identical(seed in any::<[u8; 32]>()) {
            let (semantics, context) = fixture((8, 31));
            let first = ActionEquivalentTraceShaper::shape(&semantics, &context, &RandomTape(seed)).unwrap();
            let second = ActionEquivalentTraceShaper::shape(&semantics, &context, &RandomTape(seed)).unwrap();
            prop_assert_eq!(first, second);
        }
    }

    #[test]
    fn frame_length_cadence_and_utility_hold() {
        let (semantics, context) = fixture((8, 31));
        let trace =
            ActionEquivalentTraceShaper::shape(&semantics, &context, &RandomTape([7; 32])).unwrap();
        assert!(trace.network.frames.iter().all(|frame| {
            frame.packet_length as usize == FIXED_CIPHERTEXT_SIZE
                && frame.ciphertext.len() == FIXED_CIPHERTEXT_SIZE
        }));
        assert_eq!(
            trace.services[0]
                .frames
                .iter()
                .filter(|frame| matches!(frame.decoded_kind, DecodedFrameKind::AuthorizedAction(_)))
                .count(),
            1
        );
    }

    #[test]
    fn aliases_are_pairwise_and_epoch_scoped() {
        let first = service_alias(ServiceBinding::from_u64(1), 1);
        assert_eq!(first, service_alias(ServiceBinding::from_u64(1), 1));
        assert_ne!(first, service_alias(ServiceBinding::from_u64(2), 1));
        assert_ne!(first, service_alias(ServiceBinding::from_u64(1), 2));
    }

    #[test]
    fn malformed_parser_never_accepts_wrong_length() {
        for length in 0..256 {
            let result = reject_malformed_ciphertext(&vec![0; length]);
            assert_eq!(result.is_ok(), length == FIXED_CIPHERTEXT_SIZE);
        }
    }
}
