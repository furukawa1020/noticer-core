use std::collections::BTreeMap;
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TranscriptEntry {
    pub region: u16,
    pub sequence: u64,
    pub digest: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MergeError {
    Fork,
    SequenceGap,
}
pub fn merge(entries: &[TranscriptEntry]) -> Result<Vec<TranscriptEntry>, MergeError> {
    let mut map = BTreeMap::new();
    for e in entries {
        if let Some(old) = map.insert((e.region, e.sequence), *e) {
            if old.digest != e.digest {
                return Err(MergeError::Fork);
            }
        }
    }
    let mut last = BTreeMap::new();
    for e in map.values() {
        let expected = last.get(&e.region).map_or(0, |v: &u64| v + 1);
        if e.sequence != expected {
            return Err(MergeError::SequenceGap);
        }
        last.insert(e.region, e.sequence);
    }
    let mut out = map.into_values().collect::<Vec<_>>();
    out.sort_by_key(|e| (e.sequence, e.region));
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn e(r: u16, s: u64, d: u8) -> TranscriptEntry {
        TranscriptEntry {
            region: r,
            sequence: s,
            digest: [d; 32],
        }
    }
    #[test]
    fn merges_deterministically() {
        assert_eq!(
            merge(&[e(2, 0, 2), e(1, 0, 1)]).unwrap(),
            vec![e(1, 0, 1), e(2, 0, 2)]
        )
    }
    #[test]
    fn rejects_fork() {
        assert_eq!(merge(&[e(1, 0, 1), e(1, 0, 2)]), Err(MergeError::Fork))
    }
}
