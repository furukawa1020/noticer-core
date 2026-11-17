use std::collections::BTreeSet;
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum VerifierFamily {
    Native,
    Wasm,
    Independent,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifierVote {
    pub verifier: [u8; 16],
    pub family: VerifierFamily,
    pub digest: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiversityError {
    DuplicateVerifier,
    DigestMismatch,
    InsufficientVotes,
    InsufficientFamilies,
}
pub fn verify(
    votes: &[VerifierVote],
    digest: [u8; 32],
    threshold: usize,
    min_families: usize,
) -> Result<(), DiversityError> {
    let mut ids = BTreeSet::new();
    let mut families = BTreeSet::new();
    for v in votes {
        if !ids.insert(v.verifier) {
            return Err(DiversityError::DuplicateVerifier);
        }
        if v.digest != digest {
            return Err(DiversityError::DigestMismatch);
        }
        families.insert(v.family);
    }
    if ids.len() < threshold {
        return Err(DiversityError::InsufficientVotes);
    }
    if families.len() < min_families {
        return Err(DiversityError::InsufficientFamilies);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn v(id: u8, f: VerifierFamily) -> VerifierVote {
        VerifierVote {
            verifier: [id; 16],
            family: f,
            digest: [1; 32],
        }
    }
    #[test]
    fn accepts_diversity() {
        assert_eq!(
            verify(
                &[v(1, VerifierFamily::Native), v(2, VerifierFamily::Wasm)],
                [1; 32],
                2,
                2
            ),
            Ok(())
        )
    }
    #[test]
    fn rejects_monoculture() {
        assert_eq!(
            verify(
                &[v(1, VerifierFamily::Native), v(2, VerifierFamily::Native)],
                [1; 32],
                2,
                2
            ),
            Err(DiversityError::InsufficientFamilies)
        )
    }
}
