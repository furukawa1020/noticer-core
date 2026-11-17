use std::collections::BTreeSet;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LedgerError {
    EpochMismatch,
    Replay,
}
pub struct ChallengeLedger {
    epoch: u64,
    consumed: BTreeSet<[u8; 16]>,
}
impl ChallengeLedger {
    pub fn new(epoch: u64) -> Self {
        Self {
            epoch,
            consumed: BTreeSet::new(),
        }
    }
    pub fn consume(&mut self, epoch: u64, nonce: [u8; 16]) -> Result<(), LedgerError> {
        if epoch != self.epoch {
            return Err(LedgerError::EpochMismatch);
        }
        if !self.consumed.insert(nonce) {
            return Err(LedgerError::Replay);
        }
        Ok(())
    }
    pub fn rotate(self, new_epoch: u64) -> Result<Self, LedgerError> {
        if new_epoch <= self.epoch {
            return Err(LedgerError::EpochMismatch);
        }
        Ok(Self::new(new_epoch))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_replay() {
        let mut l = ChallengeLedger::new(2);
        assert_eq!(l.consume(2, [1; 16]), Ok(()));
        assert_eq!(l.consume(2, [1; 16]), Err(LedgerError::Replay))
    }
    #[test]
    fn rejects_cross_epoch() {
        let mut l = ChallengeLedger::new(2);
        assert_eq!(l.consume(3, [1; 16]), Err(LedgerError::EpochMismatch));
    }
}
