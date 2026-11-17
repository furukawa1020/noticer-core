use crate::receipt::hmac_sha256;
const MAX_DEPTH: usize = 64;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InclusionProof {
    pub index: u64,
    pub leaf: [u8; 32],
    pub siblings: Vec<[u8; 32]>,
    pub root: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InclusionError {
    PathTooDeep,
    IndexOutOfRange,
    RootMismatch,
}
pub fn verify(v: &InclusionProof) -> Result<(), InclusionError> {
    if v.siblings.len() > MAX_DEPTH {
        return Err(InclusionError::PathTooDeep);
    }
    if v.siblings.len() < 64 && v.index >= (1u64 << v.siblings.len()) {
        return Err(InclusionError::IndexOutOfRange);
    }
    let mut current = v.leaf;
    for (depth, sibling) in v.siblings.iter().enumerate() {
        current = if (v.index >> depth) & 1 == 0 {
            node(current, *sibling)
        } else {
            node(*sibling, current)
        }
    }
    if current != v.root {
        return Err(InclusionError::RootMismatch);
    }
    Ok(())
}
fn node(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut b = [0u8; 64];
    b[..32].copy_from_slice(&left);
    b[32..].copy_from_slice(&right);
    hmac_sha256([0; 32], &b)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn verifies_inclusion() {
        let leaf = [1; 32];
        let sibling = [2; 32];
        let p = InclusionProof {
            index: 0,
            leaf,
            siblings: vec![sibling],
            root: node(leaf, sibling),
        };
        assert_eq!(verify(&p), Ok(()))
    }
    #[test]
    fn rejects_substitution() {
        let p = InclusionProof {
            index: 0,
            leaf: [1; 32],
            siblings: vec![[2; 32]],
            root: [9; 32],
        };
        assert_eq!(verify(&p), Err(InclusionError::RootMismatch));
    }
}
