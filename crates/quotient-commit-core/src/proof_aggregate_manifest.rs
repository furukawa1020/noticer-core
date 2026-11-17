use crate::receipt::hmac_sha256;
use std::collections::BTreeSet;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateManifest {
    pub roots: Vec<[u8; 32]>,
    pub policy_digest: [u8; 32],
    pub epoch: u64,
    pub authenticator: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifestError {
    Empty,
    DuplicateRoot,
    EmptyPolicy,
    Authentication,
}
pub fn issue(
    roots: &[[u8; 32]],
    policy_digest: [u8; 32],
    epoch: u64,
    key: [u8; 32],
) -> Result<AggregateManifest, ManifestError> {
    if roots.is_empty() {
        return Err(ManifestError::Empty);
    }
    if policy_digest == [0; 32] {
        return Err(ManifestError::EmptyPolicy);
    }
    let set = roots.iter().copied().collect::<BTreeSet<_>>();
    if set.len() != roots.len() {
        return Err(ManifestError::DuplicateRoot);
    }
    let mut v = AggregateManifest {
        roots: set.into_iter().collect(),
        policy_digest,
        epoch,
        authenticator: [0; 32],
    };
    v.authenticator = auth(&v, key);
    Ok(v)
}
pub fn verify(v: &AggregateManifest, key: [u8; 32]) -> Result<(), ManifestError> {
    if v.authenticator != auth(v, key) {
        return Err(ManifestError::Authentication);
    }
    Ok(())
}
fn auth(v: &AggregateManifest, key: [u8; 32]) -> [u8; 32] {
    let mut b = Vec::new();
    b.extend_from_slice(b"noticer.aggregate-manifest.v1");
    b.extend_from_slice(&v.policy_digest);
    b.extend_from_slice(&v.epoch.to_be_bytes());
    for r in &v.roots {
        b.extend_from_slice(r)
    }
    hmac_sha256(key, &b)
}
#[cfg(test)]
mod tests {
    use super::*;
    const K: [u8; 32] = [9; 32];
    #[test]
    fn canonicalizes_roots() {
        let v = issue(&[[2; 32], [1; 32]], [3; 32], 4, K).unwrap();
        assert_eq!(v.roots, vec![[1; 32], [2; 32]]);
        assert_eq!(verify(&v, K), Ok(()))
    }
    #[test]
    fn rejects_duplicate() {
        assert_eq!(
            issue(&[[1; 32], [1; 32]], [3; 32], 4, K),
            Err(ManifestError::DuplicateRoot)
        );
    }
}
