//! Evaluates a candidate repair without changing the live release action.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShadowObservation {
    pub sequence: u64,
    pub live_action_class: u16,
    pub shadow_action_class: u16,
    pub shadow_failure: bool,
    pub shadow_private_distinctions: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShadowViolation {
    ActionDrift { sequence: u64 },
    Failure { sequence: u64 },
    PrivacyRegression { sequence: u64 },
}

pub fn evaluate(
    observation: ShadowObservation,
    maximum_private_distinctions: u32,
) -> Result<(), ShadowViolation> {
    if observation.live_action_class != observation.shadow_action_class {
        return Err(ShadowViolation::ActionDrift {
            sequence: observation.sequence,
        });
    }
    if observation.shadow_failure {
        return Err(ShadowViolation::Failure {
            sequence: observation.sequence,
        });
    }
    if observation.shadow_private_distinctions > maximum_private_distinctions {
        return Err(ShadowViolation::PrivacyRegression {
            sequence: observation.sequence,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shadow_action_drift_is_detected_without_live_mutation() {
        let observation = ShadowObservation {
            sequence: 4,
            live_action_class: 1,
            shadow_action_class: 2,
            shadow_failure: false,
            shadow_private_distinctions: 0,
        };
        assert_eq!(
            evaluate(observation, 0),
            Err(ShadowViolation::ActionDrift { sequence: 4 })
        );
        assert_eq!(observation.live_action_class, 1);
    }
}
