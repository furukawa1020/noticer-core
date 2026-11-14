//! Append-only Merkle transparency log for recovery artifact digests.
use crate::sha256::sha256;
const LEAF: &[u8] = b"noticer.transparency.leaf.v1\0";
const NODE: &[u8] = b"noticer.transparency.node.v1\0";
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TransparencyLog {
    entries: Vec<[u8; 32]>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InclusionProof {
    pub index: usize,
    pub size: usize,
    pub siblings: Vec<[u8; 32]>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogError {
    InvalidDigest,
    Duplicate,
    InvalidSize,
    InvalidProof,
}
impl TransparencyLog {
    pub fn append(&mut self, digest: [u8; 32]) -> Result<usize, LogError> {
        if digest == [0; 32] {
            return Err(LogError::InvalidDigest);
        }
        if self.entries.contains(&digest) {
            return Err(LogError::Duplicate);
        }
        self.entries.push(digest);
        Ok(self.entries.len() - 1)
    }
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        root(&self.entries)
    }
    pub fn root_at(&self, size: usize) -> Result<[u8; 32], LogError> {
        if size == 0 || size > self.entries.len() {
            return Err(LogError::InvalidSize);
        }
        Ok(root(&self.entries[..size]))
    }
    pub fn verify_consistency(&self, size: usize, expected: [u8; 32]) -> Result<(), LogError> {
        if self.root_at(size)? == expected {
            Ok(())
        } else {
            Err(LogError::InvalidProof)
        }
    }
    pub fn proof(&self, index: usize) -> Result<InclusionProof, LogError> {
        if index >= self.entries.len() {
            return Err(LogError::InvalidSize);
        }
        let mut level = self.entries.iter().map(|d| leaf(*d)).collect::<Vec<_>>();
        let mut i = index;
        let mut siblings = Vec::new();
        while level.len() > 1 {
            let sibling = if i % 2 == 0 {
                level.get(i + 1).copied().unwrap_or(level[i])
            } else {
                level[i - 1]
            };
            siblings.push(sibling);
            level = next(&level);
            i /= 2;
        }
        Ok(InclusionProof {
            index,
            size: self.entries.len(),
            siblings,
        })
    }
}
pub fn verify_inclusion(
    digest: [u8; 32],
    proof: &InclusionProof,
    expected_root: [u8; 32],
) -> Result<(), LogError> {
    if proof.index >= proof.size || digest == [0; 32] {
        return Err(LogError::InvalidProof);
    }
    let mut hash = leaf(digest);
    let mut index = proof.index;
    for sibling in &proof.siblings {
        hash = if index % 2 == 0 {
            node(hash, *sibling)
        } else {
            node(*sibling, hash)
        };
        index /= 2;
    }
    if hash == expected_root {
        Ok(())
    } else {
        Err(LogError::InvalidProof)
    }
}
fn root(entries: &[[u8; 32]]) -> [u8; 32] {
    if entries.is_empty() {
        return sha256(LEAF);
    }
    let mut level = entries.iter().map(|d| leaf(*d)).collect::<Vec<_>>();
    while level.len() > 1 {
        level = next(&level)
    }
    level[0]
}
fn next(level: &[[u8; 32]]) -> Vec<[u8; 32]> {
    level
        .chunks(2)
        .map(|c| node(c[0], *c.get(1).unwrap_or(&c[0])))
        .collect()
}
fn leaf(d: [u8; 32]) -> [u8; 32] {
    let mut b = Vec::from(LEAF);
    b.extend_from_slice(&d);
    sha256(&b)
}
fn node(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let mut v = Vec::from(NODE);
    v.extend_from_slice(&a);
    v.extend_from_slice(&b);
    sha256(&v)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inclusion_and_prefix_consistency_verify() {
        let mut l = TransparencyLog::default();
        l.append([1; 32]).unwrap();
        let old = l.root();
        l.append([2; 32]).unwrap();
        l.append([3; 32]).unwrap();
        assert_eq!(l.verify_consistency(1, old), Ok(()));
        assert_eq!(
            verify_inclusion([2; 32], &l.proof(1).unwrap(), l.root()),
            Ok(())
        )
    }
    #[test]
    fn duplicate_and_tampered_proof_fail() {
        let mut l = TransparencyLog::default();
        l.append([1; 32]).unwrap();
        assert_eq!(l.append([1; 32]), Err(LogError::Duplicate));
        let mut p = l.proof(0).unwrap();
        p.siblings.push([9; 32]);
        assert_eq!(
            verify_inclusion([1; 32], &p, l.root()),
            Err(LogError::InvalidProof)
        );
    }
}
