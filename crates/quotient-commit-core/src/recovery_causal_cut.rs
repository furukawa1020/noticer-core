use crate::receipt::hmac_sha256;
use std::collections::BTreeSet;
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CutPoint {
    pub region: u16,
    pub sequence: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CausalCutCertificate {
    pub epoch: u64,
    pub points: Vec<CutPoint>,
    pub authenticator: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CutError {
    Empty,
    DuplicateRegion,
    NonCanonical,
    Authentication,
}
pub fn issue(
    epoch: u64,
    mut points: Vec<CutPoint>,
    key: [u8; 32],
) -> Result<CausalCutCertificate, CutError> {
    if points.is_empty() {
        return Err(CutError::Empty);
    }
    points.sort();
    if points
        .iter()
        .map(|p| p.region)
        .collect::<BTreeSet<_>>()
        .len()
        != points.len()
    {
        return Err(CutError::DuplicateRegion);
    }
    let mut v = CausalCutCertificate {
        epoch,
        points,
        authenticator: [0; 32],
    };
    v.authenticator = auth(&v, key);
    Ok(v)
}
pub fn verify(v: &CausalCutCertificate, key: [u8; 32]) -> Result<(), CutError> {
    if !v.points.windows(2).all(|w| w[0] < w[1]) {
        return Err(CutError::NonCanonical);
    }
    if v.authenticator != auth(v, key) {
        return Err(CutError::Authentication);
    }
    Ok(())
}
fn auth(v: &CausalCutCertificate, key: [u8; 32]) -> [u8; 32] {
    let mut b = Vec::new();
    b.extend_from_slice(b"noticer.causal-cut.v1");
    b.extend_from_slice(&v.epoch.to_be_bytes());
    for p in &v.points {
        b.extend_from_slice(&p.region.to_be_bytes());
        b.extend_from_slice(&p.sequence.to_be_bytes())
    }
    hmac_sha256(key, &b)
}
#[cfg(test)]
mod tests {
    use super::*;
    const K: [u8; 32] = [6; 32];
    #[test]
    fn canonical_cut() {
        let v = issue(
            7,
            vec![
                CutPoint {
                    region: 2,
                    sequence: 4,
                },
                CutPoint {
                    region: 1,
                    sequence: 3,
                },
            ],
            K,
        )
        .unwrap();
        assert_eq!(verify(&v, K), Ok(()));
        assert_eq!(v.points[0].region, 1)
    }
    #[test]
    fn rejects_duplicate() {
        assert_eq!(
            issue(
                7,
                vec![
                    CutPoint {
                        region: 1,
                        sequence: 2
                    },
                    CutPoint {
                        region: 1,
                        sequence: 3
                    }
                ],
                K
            ),
            Err(CutError::DuplicateRegion)
        )
    }
}
