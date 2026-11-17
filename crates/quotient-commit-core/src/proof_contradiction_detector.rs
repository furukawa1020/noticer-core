use std::collections::BTreeMap;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProofClaim {
    pub subject: [u8; 16],
    pub position: u64,
    pub claim_digest: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Contradiction {
    pub subject: [u8; 16],
    pub position: u64,
    pub first: [u8; 32],
    pub second: [u8; 32],
}
pub fn detect(claims: &[ProofClaim]) -> Option<Contradiction> {
    let mut seen = BTreeMap::new();
    for c in claims {
        if let Some(first) = seen.insert((c.subject, c.position), c.claim_digest) {
            if first != c.claim_digest {
                return Some(Contradiction {
                    subject: c.subject,
                    position: c.position,
                    first,
                    second: c.claim_digest,
                });
            }
        }
    }
    None
}
#[cfg(test)]
mod tests {
    use super::*;
    fn c(d: u8) -> ProofClaim {
        ProofClaim {
            subject: [1; 16],
            position: 2,
            claim_digest: [d; 32],
        }
    }
    #[test]
    fn identical_is_not_contradiction() {
        assert_eq!(detect(&[c(1), c(1)]), None)
    }
    #[test]
    fn detects_fork() {
        assert_eq!(detect(&[c(1), c(2)]).unwrap().position, 2)
    }
}
