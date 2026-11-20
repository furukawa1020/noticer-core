//! Deterministic first-violation evaluation over a public observation window.

use crate::sentinel_invariant_spec::RuntimeInvariantSpec;
use crate::sentinel_observation_atom::PublicRuntimeEvent;
use crate::sentinel_sample::MonitorSample;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeViolation {
    FailureReappeared { sequence: u64 },
    ProgressBoundExceeded { sequence: u64 },
}

pub fn first_violation(
    spec: RuntimeInvariantSpec,
    samples: impl IntoIterator<Item = MonitorSample>,
) -> Option<RuntimeViolation> {
    let mut last_release_slot = None;
    for sample in samples {
        if sample.atom.public_state == u32::from(spec.forbidden_failure_code) {
            return Some(RuntimeViolation::FailureReappeared {
                sequence: sample.sequence,
            });
        }
        if sample.atom.event == PublicRuntimeEvent::Release {
            last_release_slot = Some(sample.atom.slot);
        } else if last_release_slot
            .is_some_and(|slot| sample.atom.slot.saturating_sub(slot) > spec.progress_bound_slots)
        {
            return Some(RuntimeViolation::ProgressBoundExceeded {
                sequence: sample.sequence,
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sentinel_observation_atom::RuntimeObservationAtom;

    #[test]
    fn earliest_failure_is_returned() {
        let spec = RuntimeInvariantSpec::new([1; 32], 9, 4, 0, [2; 32]).unwrap();
        let sample = MonitorSample::new(
            3,
            30,
            RuntimeObservationAtom::new(1, PublicRuntimeEvent::Transition, 1, 9).unwrap(),
        )
        .unwrap();
        assert_eq!(
            first_violation(spec, [sample]),
            Some(RuntimeViolation::FailureReappeared { sequence: 3 })
        );
    }
}
