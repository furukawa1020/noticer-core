#![no_std]
#![forbid(unsafe_code)]

//! Fixed-shape APLOT transport for 236-byte Atypicality Token v2 envelopes.

use core::fmt;
use hmac::{Hmac, Mac};
use noticer_protocol::ENVELOPE_SIZE;
use sha2::Sha256;

pub const TRANSPORT_PAYLOAD_SIZE: usize = 240;
pub const FRAGMENT_SIZE: usize = 20;
pub const FRAGMENT_HEADER_SIZE: usize = 5;
pub const FRAGMENT_PAYLOAD_SIZE: usize = 15;
pub const DATA_FRAGMENT_COUNT: usize = 16;
pub const PARITY_FRAGMENT_COUNT: usize = 4;
pub const TOTAL_FRAGMENT_COUNT: usize = DATA_FRAGMENT_COUNT + PARITY_FRAGMENT_COUNT;
pub const FRAGMENT_MARKER: u8 = 0x41;
pub const PADDING_SIZE: usize = TRANSPORT_PAYLOAD_SIZE - ENVELOPE_SIZE;

const _: () = assert!(ENVELOPE_SIZE == 236);
const _: () = assert!(TRANSPORT_PAYLOAD_SIZE == DATA_FRAGMENT_COUNT * FRAGMENT_PAYLOAD_SIZE);
const _: () = assert!(FRAGMENT_SIZE == FRAGMENT_HEADER_SIZE + FRAGMENT_PAYLOAD_SIZE);

type HmacSha256 = Hmac<Sha256>;

/// Transport-only key. It must never be derived from private evidence.
pub struct TransportIdKey([u8; 32]);

impl TransportIdKey {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for TransportIdKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TransportIdKey(<redacted>)")
    }
}

impl Drop for TransportIdKey {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FrameId([u8; 3]);

impl FrameId {
    pub const fn as_bytes(self) -> [u8; 3] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportFrameIdentity {
    pub service_alias: [u8; 8],
    pub public_epoch: u32,
    pub public_bucket: u32,
    pub sequence: u32,
}

/// Derives a short, public frame identifier from public scheduling fields only.
pub fn derive_frame_id(key: &TransportIdKey, identity: TransportFrameIdentity) -> FrameId {
    let mut mac =
        HmacSha256::new_from_slice(&key.0).expect("HMAC accepts every fixed-size key length");
    mac.update(b"NOTICER_APLOT_FRAME_ID_V1");
    mac.update(&identity.service_alias);
    mac.update(&identity.public_epoch.to_le_bytes());
    mac.update(&identity.public_bucket.to_le_bytes());
    mac.update(&identity.sequence.to_le_bytes());
    let digest = mac.finalize().into_bytes();
    FrameId([digest[0], digest[1], digest[2]])
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fragment {
    pub frame_id: FrameId,
    pub index: u8,
    pub payload: [u8; FRAGMENT_PAYLOAD_SIZE],
}

impl Fragment {
    const EMPTY: Self = Self {
        frame_id: FrameId([0; 3]),
        index: 0,
        payload: [0; FRAGMENT_PAYLOAD_SIZE],
    };

    pub fn encode(self) -> [u8; FRAGMENT_SIZE] {
        let mut bytes = [0_u8; FRAGMENT_SIZE];
        bytes[0] = FRAGMENT_MARKER;
        bytes[1..4].copy_from_slice(&self.frame_id.0);
        bytes[4] = self.index;
        bytes[FRAGMENT_HEADER_SIZE..].copy_from_slice(&self.payload);
        bytes
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, FragmentError> {
        if bytes.len() != FRAGMENT_SIZE {
            return Err(FragmentError::WrongLength);
        }
        if bytes[0] != FRAGMENT_MARKER {
            return Err(FragmentError::InvalidMarker);
        }
        if usize::from(bytes[4]) >= TOTAL_FRAGMENT_COUNT {
            return Err(FragmentError::InvalidIndex);
        }
        let mut payload = [0_u8; FRAGMENT_PAYLOAD_SIZE];
        payload.copy_from_slice(&bytes[FRAGMENT_HEADER_SIZE..]);
        Ok(Self {
            frame_id: FrameId([bytes[1], bytes[2], bytes[3]]),
            index: bytes[4],
            payload,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FragmentError {
    WrongLength,
    InvalidMarker,
    InvalidIndex,
}

/// Produces exactly 16 data and 4 interleaved-XOR parity fragments.
pub fn fragment_envelope(
    envelope: &[u8; ENVELOPE_SIZE],
    frame_id: FrameId,
) -> [Fragment; TOTAL_FRAGMENT_COUNT] {
    let mut padded = [0_u8; TRANSPORT_PAYLOAD_SIZE];
    padded[..ENVELOPE_SIZE].copy_from_slice(envelope);

    let mut fragments = [Fragment::EMPTY; TOTAL_FRAGMENT_COUNT];
    for (index, chunk) in padded.chunks_exact(FRAGMENT_PAYLOAD_SIZE).enumerate() {
        fragments[index] = Fragment {
            frame_id,
            index: index as u8,
            payload: copy_payload(chunk),
        };
    }
    for group in 0..PARITY_FRAGMENT_COUNT {
        let mut parity = [0_u8; FRAGMENT_PAYLOAD_SIZE];
        for data_index in (group..DATA_FRAGMENT_COUNT).step_by(PARITY_FRAGMENT_COUNT) {
            xor_into(&mut parity, &fragments[data_index].payload);
        }
        let index = DATA_FRAGMENT_COUNT + group;
        fragments[index] = Fragment {
            frame_id,
            index: index as u8,
            payload: parity,
        };
    }
    fragments
}

#[derive(Clone, Copy)]
struct FrameSlot {
    occupied: bool,
    frame_id: FrameId,
    first_tick: u64,
    present: u32,
    payloads: [[u8; FRAGMENT_PAYLOAD_SIZE]; TOTAL_FRAGMENT_COUNT],
}

impl FrameSlot {
    const EMPTY: Self = Self {
        occupied: false,
        frame_id: FrameId([0; 3]),
        first_tick: 0,
        present: 0,
        payloads: [[0; FRAGMENT_PAYLOAD_SIZE]; TOTAL_FRAGMENT_COUNT],
    };

    fn has(&self, index: usize) -> bool {
        self.present & (1_u32 << index) != 0
    }

    fn insert(&mut self, fragment: Fragment) {
        let index = usize::from(fragment.index);
        self.payloads[index] = fragment.payload;
        self.present |= 1_u32 << index;
    }
}

pub struct Reassembler<const ACTIVE_FRAMES: usize> {
    slots: [FrameSlot; ACTIVE_FRAMES],
    ttl_ticks: u64,
}

impl<const ACTIVE_FRAMES: usize> Reassembler<ACTIVE_FRAMES> {
    pub const fn new(ttl_ticks: u64) -> Self {
        Self {
            slots: [FrameSlot::EMPTY; ACTIVE_FRAMES],
            ttl_ticks,
        }
    }

    /// Expires public frame state without triggering verification or retries.
    pub fn expire(&mut self, now_tick: u64) -> usize {
        let mut expired = 0;
        for slot in &mut self.slots {
            if slot.occupied && now_tick.saturating_sub(slot.first_tick) > self.ttl_ticks {
                *slot = FrameSlot::EMPTY;
                expired += 1;
            }
        }
        expired
    }

    pub fn ingest(
        &mut self,
        bytes: &[u8],
        now_tick: u64,
    ) -> Result<IngestOutcome, ReassemblyError> {
        self.expire(now_tick);
        let fragment = Fragment::parse(bytes).map_err(ReassemblyError::Fragment)?;
        let slot_index = self
            .find_slot(fragment.frame_id)
            .ok_or(ReassemblyError::Capacity)?;
        let slot = &mut self.slots[slot_index];
        if !slot.occupied {
            slot.occupied = true;
            slot.frame_id = fragment.frame_id;
            slot.first_tick = now_tick;
        }

        let index = usize::from(fragment.index);
        if slot.has(index) {
            if slot.payloads[index] == fragment.payload {
                return Ok(IngestOutcome::Duplicate);
            }
            self.slots[slot_index] = FrameSlot::EMPTY;
            return Err(ReassemblyError::ConflictingDuplicate);
        }
        slot.insert(fragment);

        match try_complete(slot) {
            Ok(Some(envelope)) => {
                self.slots[slot_index] = FrameSlot::EMPTY;
                Ok(IngestOutcome::Complete(envelope))
            }
            Ok(None) => Ok(IngestOutcome::Pending),
            Err(error) => {
                self.slots[slot_index] = FrameSlot::EMPTY;
                Err(error)
            }
        }
    }

    fn find_slot(&self, frame_id: FrameId) -> Option<usize> {
        let mut empty = None;
        for (index, slot) in self.slots.iter().enumerate() {
            if slot.occupied && slot.frame_id == frame_id {
                return Some(index);
            }
            if !slot.occupied && empty.is_none() {
                empty = Some(index);
            }
        }
        empty
    }
}

// The completed fixed-size envelope intentionally stays inline so firmware
// reassembly never allocates or boxes attacker-controlled input.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngestOutcome {
    Pending,
    Duplicate,
    Complete([u8; ENVELOPE_SIZE]),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReassemblyError {
    Fragment(FragmentError),
    Capacity,
    ConflictingDuplicate,
    ParityMismatch,
    NonZeroPadding,
}

fn try_complete(slot: &mut FrameSlot) -> Result<Option<[u8; ENVELOPE_SIZE]>, ReassemblyError> {
    for group in 0..PARITY_FRAGMENT_COUNT {
        let parity_index = DATA_FRAGMENT_COUNT + group;
        let mut data_xor = [0_u8; FRAGMENT_PAYLOAD_SIZE];
        let mut missing = None;
        let mut missing_count = 0;

        for data_index in (group..DATA_FRAGMENT_COUNT).step_by(PARITY_FRAGMENT_COUNT) {
            if slot.has(data_index) {
                xor_into(&mut data_xor, &slot.payloads[data_index]);
            } else {
                missing = Some(data_index);
                missing_count += 1;
            }
        }

        if missing_count == 0 && slot.has(parity_index) {
            if data_xor != slot.payloads[parity_index] {
                return Err(ReassemblyError::ParityMismatch);
            }
        } else if missing_count == 1 && slot.has(parity_index) {
            let missing_index = missing.expect("one missing index was counted");
            let mut recovered = slot.payloads[parity_index];
            xor_into(&mut recovered, &data_xor);
            slot.payloads[missing_index] = recovered;
            slot.present |= 1_u32 << missing_index;
        }
    }

    let data_mask = (1_u32 << DATA_FRAGMENT_COUNT) - 1;
    if slot.present & data_mask != data_mask {
        return Ok(None);
    }

    let mut padded = [0_u8; TRANSPORT_PAYLOAD_SIZE];
    for index in 0..DATA_FRAGMENT_COUNT {
        let start = index * FRAGMENT_PAYLOAD_SIZE;
        padded[start..start + FRAGMENT_PAYLOAD_SIZE].copy_from_slice(&slot.payloads[index]);
    }
    if padded[ENVELOPE_SIZE..].iter().any(|byte| *byte != 0) {
        return Err(ReassemblyError::NonZeroPadding);
    }
    let mut envelope = [0_u8; ENVELOPE_SIZE];
    envelope.copy_from_slice(&padded[..ENVELOPE_SIZE]);
    Ok(Some(envelope))
}

fn copy_payload(bytes: &[u8]) -> [u8; FRAGMENT_PAYLOAD_SIZE] {
    let mut payload = [0_u8; FRAGMENT_PAYLOAD_SIZE];
    payload.copy_from_slice(bytes);
    payload
}

fn xor_into(target: &mut [u8; FRAGMENT_PAYLOAD_SIZE], source: &[u8; FRAGMENT_PAYLOAD_SIZE]) {
    for (left, right) in target.iter_mut().zip(source) {
        *left ^= *right;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope() -> [u8; ENVELOPE_SIZE] {
        core::array::from_fn(|index| (index % 251) as u8)
    }

    #[test]
    fn shape_is_fixed_and_interleaved_loss_is_recovered() {
        let frame_id = FrameId([1, 2, 3]);
        let fragments = fragment_envelope(&envelope(), frame_id);
        assert_eq!(fragments.len(), 20);
        assert!(fragments
            .iter()
            .all(|fragment| fragment.encode().len() == 20));

        let mut reassembler = Reassembler::<2>::new(100);
        let dropped = [0_usize, 5, 10, 15];
        let mut completed = None;
        for fragment in fragments {
            if dropped.contains(&usize::from(fragment.index)) {
                continue;
            }
            if let IngestOutcome::Complete(bytes) =
                reassembler.ingest(&fragment.encode(), 10).unwrap()
            {
                completed = Some(bytes);
            }
        }
        assert_eq!(completed, Some(envelope()));
    }

    #[test]
    fn parser_rejects_arbitrary_shapes_without_panicking() {
        for length in 0..64 {
            let bytes = [0xA5_u8; 64];
            let _ = Fragment::parse(&bytes[..length]);
        }
        let mut wire = [0_u8; FRAGMENT_SIZE];
        wire[0] = FRAGMENT_MARKER;
        wire[4] = TOTAL_FRAGMENT_COUNT as u8;
        assert_eq!(Fragment::parse(&wire), Err(FragmentError::InvalidIndex));
    }

    #[test]
    fn duplicate_conflict_timeout_and_capacity_fail_closed() {
        let fragments_a = fragment_envelope(&envelope(), FrameId([1, 1, 1]));
        let fragments_b = fragment_envelope(&envelope(), FrameId([2, 2, 2]));
        let mut reassembler = Reassembler::<1>::new(5);
        let first = fragments_a[0].encode();
        assert_eq!(reassembler.ingest(&first, 0), Ok(IngestOutcome::Pending));
        assert_eq!(reassembler.ingest(&first, 1), Ok(IngestOutcome::Duplicate));
        assert_eq!(
            reassembler.ingest(&fragments_b[0].encode(), 1),
            Err(ReassemblyError::Capacity)
        );
        assert_eq!(reassembler.expire(6), 1);
        assert_eq!(
            reassembler.ingest(&fragments_b[0].encode(), 6),
            Ok(IngestOutcome::Pending)
        );

        let mut conflicting = fragments_b[0];
        conflicting.payload[0] ^= 1;
        assert_eq!(
            reassembler.ingest(&conflicting.encode(), 7),
            Err(ReassemblyError::ConflictingDuplicate)
        );
    }

    #[test]
    fn parity_and_padding_corruption_are_rejected() {
        let fragments = fragment_envelope(&envelope(), FrameId([7, 7, 7]));
        let mut parity_first = Reassembler::<1>::new(100);
        let mut corrupt_parity = fragments[16];
        corrupt_parity.payload[0] ^= 1;
        parity_first.ingest(&corrupt_parity.encode(), 0).unwrap();
        let mut parity_rejected = false;
        for fragment in &fragments[..DATA_FRAGMENT_COUNT] {
            match parity_first.ingest(&fragment.encode(), 1) {
                Err(ReassemblyError::ParityMismatch | ReassemblyError::ConflictingDuplicate) => {
                    parity_rejected = true;
                    break;
                }
                Ok(_) => {}
                Err(error) => panic!("unexpected reassembly error: {error:?}"),
            }
        }
        assert!(parity_rejected);

        let mut bad_padding = fragments;
        bad_padding[15].payload[14] = 1;
        let mut padding_reassembler = Reassembler::<1>::new(100);
        for fragment in &bad_padding[..DATA_FRAGMENT_COUNT] {
            let result = padding_reassembler.ingest(&fragment.encode(), 1);
            if usize::from(fragment.index) == DATA_FRAGMENT_COUNT - 1 {
                assert_eq!(result, Err(ReassemblyError::NonZeroPadding));
            } else {
                result.unwrap();
            }
        }
    }
}
