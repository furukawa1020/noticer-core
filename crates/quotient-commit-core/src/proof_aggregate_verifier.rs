use crate::proof_aggregate_manifest::{verify, AggregateManifest};
use std::collections::BTreeSet;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AggregateError {
    ManifestInvalid,
    DuplicateProof,
    ProofSetMismatch,
}
pub fn verify_aggregate(
    manifest: &AggregateManifest,
    presented: &[[u8; 32]],
    key: [u8; 32],
) -> Result<(), AggregateError> {
    if verify(manifest, key).is_err() {
        return Err(AggregateError::ManifestInvalid);
    }
    let set = presented.iter().copied().collect::<BTreeSet<_>>();
    if set.len() != presented.len() {
        return Err(AggregateError::DuplicateProof);
    }
    let expected = manifest.roots.iter().copied().collect::<BTreeSet<_>>();
    if set != expected {
        return Err(AggregateError::ProofSetMismatch);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof_aggregate_manifest::issue;
    const K: [u8; 32] = [1; 32];
    #[test]
    fn verifies_complete_set() {
        let m = issue(&[[1; 32], [2; 32]], [3; 32], 4, K).unwrap();
        assert_eq!(verify_aggregate(&m, &[[2; 32], [1; 32]], K), Ok(()))
    }
    #[test]
    fn rejects_missing() {
        let m = issue(&[[1; 32], [2; 32]], [3; 32], 4, K).unwrap();
        assert_eq!(
            verify_aggregate(&m, &[[1; 32]], K),
            Err(AggregateError::ProofSetMismatch)
        );
    }
}
