//! Completeness proof for system × workload × attack × metric comparisons.

use crate::trial_sample::MetricKind;
use crate::trial_system_descriptor::EvaluatedSystemKind;
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BenchmarkCell {
    pub system: EvaluatedSystemKind,
    pub workload: u32,
    pub attack: u32,
    pub metric: MetricKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComparativeBenchmarkMatrix {
    required: BTreeSet<BenchmarkCell>,
    observed: BTreeSet<BenchmarkCell>,
}

impl ComparativeBenchmarkMatrix {
    pub fn new(required: BTreeSet<BenchmarkCell>) -> Option<Self> {
        (!required.is_empty()).then_some(Self {
            required,
            observed: BTreeSet::new(),
        })
    }
    pub fn observe(&mut self, cell: BenchmarkCell) -> bool {
        self.required.contains(&cell) && self.observed.insert(cell)
    }
    #[must_use]
    pub fn missing(&self) -> Vec<BenchmarkCell> {
        self.required.difference(&self.observed).copied().collect()
    }
    #[must_use]
    pub fn complete(&self) -> bool {
        self.missing().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unregistered_and_missing_cells_cannot_complete() {
        let cell = BenchmarkCell {
            system: EvaluatedSystemKind::FullStack,
            workload: 1,
            attack: 2,
            metric: MetricKind::LatencyNanos,
        };
        let mut matrix = ComparativeBenchmarkMatrix::new(BTreeSet::from([cell])).unwrap();
        assert!(!matrix.complete());
        assert!(matrix.observe(cell));
        assert!(matrix.complete());
    }
}
