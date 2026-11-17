use crate::recovery_causal_cut::CausalCutCertificate;
use std::collections::BTreeMap;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrontierError {
    EpochRollback,
    RegionSetChanged,
    SequenceRollback,
    NoProgress,
}
pub struct ReleaseFrontier {
    epoch: u64,
    sequences: BTreeMap<u16, u64>,
}
impl ReleaseFrontier {
    pub fn new(cut: &CausalCutCertificate) -> Self {
        Self {
            epoch: cut.epoch,
            sequences: cut.points.iter().map(|p| (p.region, p.sequence)).collect(),
        }
    }
    pub fn advance(&mut self, cut: &CausalCutCertificate) -> Result<(), FrontierError> {
        if cut.epoch < self.epoch {
            return Err(FrontierError::EpochRollback);
        }
        let next = cut
            .points
            .iter()
            .map(|p| (p.region, p.sequence))
            .collect::<BTreeMap<_, _>>();
        if next.keys().ne(self.sequences.keys()) {
            return Err(FrontierError::RegionSetChanged);
        }
        if next.iter().any(|(r, s)| *s < self.sequences[r]) {
            return Err(FrontierError::SequenceRollback);
        }
        if cut.epoch == self.epoch && next == self.sequences {
            return Err(FrontierError::NoProgress);
        }
        self.epoch = cut.epoch;
        self.sequences = next;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery_causal_cut::{issue, CutPoint};
    const K: [u8; 32] = [7; 32];
    fn c(e: u64, s: u64) -> CausalCutCertificate {
        issue(
            e,
            vec![CutPoint {
                region: 1,
                sequence: s,
            }],
            K,
        )
        .unwrap()
    }
    #[test]
    fn advances() {
        let mut f = ReleaseFrontier::new(&c(1, 2));
        assert_eq!(f.advance(&c(1, 3)), Ok(()))
    }
    #[test]
    fn rejects_rollback() {
        let mut f = ReleaseFrontier::new(&c(2, 3));
        assert_eq!(f.advance(&c(2, 2)), Err(FrontierError::SequenceRollback));
        assert_eq!(f.advance(&c(1, 4)), Err(FrontierError::EpochRollback));
    }
}
