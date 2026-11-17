use crate::proof_fragment_envelope::{verify, ProofFragment};
use std::collections::BTreeMap;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryError {
    Empty,
    Authentication,
    ShapeMismatch,
    DuplicateIndex,
    MissingFragment,
}
pub fn recover(fragments: &[ProofFragment], key: [u8; 32]) -> Result<Vec<[u8; 32]>, RecoveryError> {
    let first = *fragments.first().ok_or(RecoveryError::Empty)?;
    let mut map = BTreeMap::new();
    for f in fragments {
        if verify(*f, key).is_err() {
            return Err(RecoveryError::Authentication);
        }
        if f.total != first.total || f.proof_root != first.proof_root {
            return Err(RecoveryError::ShapeMismatch);
        }
        if map.insert(f.index, f.payload_digest).is_some() {
            return Err(RecoveryError::DuplicateIndex);
        }
    }
    if map.len() != first.total as usize || map.keys().copied().ne(0..first.total) {
        return Err(RecoveryError::MissingFragment);
    }
    Ok(map.into_values().collect())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof_fragment_envelope::issue;
    const K: [u8; 32] = [8; 32];
    #[test]
    fn recovers_in_order() {
        let a = issue(0, 2, [1; 32], [9; 32], K).unwrap();
        let b = issue(1, 2, [2; 32], [9; 32], K).unwrap();
        assert_eq!(recover(&[b, a], K), Ok(vec![[1; 32], [2; 32]]))
    }
    #[test]
    fn rejects_missing() {
        let a = issue(0, 2, [1; 32], [9; 32], K).unwrap();
        assert_eq!(recover(&[a], K), Err(RecoveryError::MissingFragment));
    }
}
