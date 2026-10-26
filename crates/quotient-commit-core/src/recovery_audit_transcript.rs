//! Deterministic causal merge of distributed recovery audit events.

use crate::sha256::sha256;
use std::collections::{BTreeMap, BTreeSet};

const DOMAIN: &[u8] = b"noticer.recovery-audit-event.v1\0";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EventId(pub [u8; 32]);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditEvent {
    pub id: EventId,
    pub node: [u8; 16],
    pub sequence: u64,
    pub parent: Option<EventId>,
    pub payload_digest: [u8; 32],
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditTranscript {
    pub events: Vec<AuditEvent>,
    pub head_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MergeError {
    Empty,
    InvalidEvent,
    DuplicateEvent,
    MissingParent,
    Equivocation,
    Cycle,
}

pub fn event(
    node: [u8; 16],
    sequence: u64,
    parent: Option<EventId>,
    payload_digest: [u8; 32],
) -> Result<AuditEvent, MergeError> {
    if node == [0; 16] || sequence == 0 || payload_digest == [0; 32] {
        return Err(MergeError::InvalidEvent);
    }
    let id = identify(node, sequence, parent, payload_digest);
    Ok(AuditEvent {
        id,
        node,
        sequence,
        parent,
        payload_digest,
    })
}

pub fn merge(events: &[AuditEvent]) -> Result<AuditTranscript, MergeError> {
    if events.is_empty() {
        return Err(MergeError::Empty);
    }
    let mut by_id = BTreeMap::new();
    let mut positions = BTreeMap::new();
    for value in events {
        if value.id
            != identify(
                value.node,
                value.sequence,
                value.parent,
                value.payload_digest,
            )
        {
            return Err(MergeError::InvalidEvent);
        }
        if by_id.insert(value.id, *value).is_some() {
            return Err(MergeError::DuplicateEvent);
        }
        if positions
            .insert((value.node, value.sequence), value.id)
            .is_some()
        {
            return Err(MergeError::Equivocation);
        }
    }
    if by_id.values().any(|value| {
        value
            .parent
            .is_some_and(|parent| !by_id.contains_key(&parent))
    }) {
        return Err(MergeError::MissingParent);
    }
    let mut emitted = BTreeSet::new();
    let mut ordered = Vec::with_capacity(events.len());
    while ordered.len() < events.len() {
        let next = by_id
            .values()
            .filter(|value| {
                !emitted.contains(&value.id)
                    && value.parent.is_none_or(|parent| emitted.contains(&parent))
            })
            .min_by_key(|value| value.id)
            .copied();
        let Some(next) = next else {
            return Err(MergeError::Cycle);
        };
        emitted.insert(next.id);
        ordered.push(next);
    }
    let mut bytes = Vec::with_capacity(ordered.len() * 32);
    for value in &ordered {
        bytes.extend_from_slice(&value.id.0);
    }
    Ok(AuditTranscript {
        events: ordered,
        head_digest: sha256(&bytes),
    })
}

fn identify(node: [u8; 16], sequence: u64, parent: Option<EventId>, payload: [u8; 32]) -> EventId {
    let mut bytes = Vec::with_capacity(DOMAIN.len() + 89);
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&node);
    bytes.extend_from_slice(&sequence.to_be_bytes());
    match parent {
        Some(id) => {
            bytes.push(1);
            bytes.extend_from_slice(&id.0);
        }
        None => {
            bytes.push(0);
            bytes.extend_from_slice(&[0; 32]);
        }
    }
    bytes.extend_from_slice(&payload);
    EventId(sha256(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn merge_is_causal_and_input_order_independent() {
        let root = event([1; 16], 1, None, [1; 32]).unwrap();
        let left = event([1; 16], 2, Some(root.id), [2; 32]).unwrap();
        let right = event([2; 16], 1, Some(root.id), [3; 32]).unwrap();
        let first = merge(&[right, root, left]).unwrap();
        let second = merge(&[left, right, root]).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.events[0], root);
    }
    #[test]
    fn missing_parent_equivocation_and_invalid_id_fail() {
        let root = event([1; 16], 1, None, [1; 32]).unwrap();
        let orphan = event([2; 16], 1, Some(EventId([8; 32])), [2; 32]).unwrap();
        assert_eq!(merge(&[root, orphan]), Err(MergeError::MissingParent));
        let conflicting = event([1; 16], 1, None, [9; 32]).unwrap();
        assert_eq!(merge(&[root, conflicting]), Err(MergeError::Equivocation));
        let mut invalid = root;
        invalid.payload_digest = [7; 32];
        assert_eq!(merge(&[invalid]), Err(MergeError::InvalidEvent));
    }
}
