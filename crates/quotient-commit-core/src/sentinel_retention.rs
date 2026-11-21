//! Minimal public counterexample retention with no raw observations.

use crate::sentinel_sample::MonitorSample;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedPublicStep {
    pub sequence: u64,
    pub slot: u32,
    pub action_class: u16,
    pub public_state: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeEvidenceRetention {
    limit: usize,
    steps: Vec<RetainedPublicStep>,
    sealed: bool,
}

impl RuntimeEvidenceRetention {
    pub fn new(limit: usize) -> Option<Self> {
        (limit > 0).then_some(Self {
            limit,
            steps: Vec::new(),
            sealed: false,
        })
    }

    pub fn retain(&mut self, sample: MonitorSample) {
        if self.sealed || self.steps.len() >= self.limit {
            return;
        }
        self.steps.push(RetainedPublicStep {
            sequence: sample.sequence,
            slot: sample.atom.slot,
            action_class: sample.atom.action_class,
            public_state: sample.atom.public_state,
        });
    }

    pub fn seal(&mut self) {
        self.sealed = true;
    }

    #[must_use]
    pub fn steps(&self) -> &[RetainedPublicStep] {
        &self.steps
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sentinel_observation_atom::{PublicRuntimeEvent, RuntimeObservationAtom};

    #[test]
    fn sealed_minimal_trace_cannot_grow() {
        let sample = MonitorSample::new(
            1,
            1,
            RuntimeObservationAtom::new(2, PublicRuntimeEvent::Release, 3, 4).unwrap(),
        )
        .unwrap();
        let mut retention = RuntimeEvidenceRetention::new(2).unwrap();
        retention.retain(sample);
        retention.seal();
        retention.retain(sample);
        assert_eq!(retention.steps().len(), 1);
    }
}
