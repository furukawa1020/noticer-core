//! Explicit accounting of timeout, OOM, and budget-censored trials.

use crate::trial_sample::Censoring;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub struct CensoringSummary {
    pub complete: u32,
    pub timeout: u32,
    pub out_of_memory: u32,
    pub budget_exhausted: u32,
}

impl CensoringSummary {
    pub fn observe(&mut self, censoring: Censoring) {
        match censoring {
            Censoring::None => self.complete = self.complete.saturating_add(1),
            Censoring::Timeout => self.timeout = self.timeout.saturating_add(1),
            Censoring::OutOfMemory => self.out_of_memory = self.out_of_memory.saturating_add(1),
            Censoring::BudgetExhausted => {
                self.budget_exhausted = self.budget_exhausted.saturating_add(1)
            }
        }
    }
    #[must_use]
    pub const fn has_censoring(self) -> bool {
        self.timeout > 0 || self.out_of_memory > 0 || self.budget_exhausted > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn censoring_reasons_are_not_collapsed_into_missing() {
        let mut summary = CensoringSummary::default();
        summary.observe(Censoring::Timeout);
        summary.observe(Censoring::OutOfMemory);
        assert_eq!(summary.timeout, 1);
        assert_eq!(summary.out_of_memory, 1);
        assert!(summary.has_censoring());
    }
}
