//! Drift detection for the public observer, transport, and policy environment.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssuranceEnvironment {
    pub observer_coalition_digest: [u8; 32],
    pub transport_profile_digest: [u8; 32],
    pub policy_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvironmentDrift {
    ObserverCoalition,
    TransportProfile,
    Policy,
    InvalidZeroDigest,
}

pub fn compare(
    certified: AssuranceEnvironment,
    runtime: AssuranceEnvironment,
) -> Result<(), EnvironmentDrift> {
    if [
        certified.observer_coalition_digest,
        certified.transport_profile_digest,
        certified.policy_digest,
        runtime.observer_coalition_digest,
        runtime.transport_profile_digest,
        runtime.policy_digest,
    ]
    .contains(&[0; 32])
    {
        return Err(EnvironmentDrift::InvalidZeroDigest);
    }
    if certified.observer_coalition_digest != runtime.observer_coalition_digest {
        return Err(EnvironmentDrift::ObserverCoalition);
    }
    if certified.transport_profile_digest != runtime.transport_profile_digest {
        return Err(EnvironmentDrift::TransportProfile);
    }
    if certified.policy_digest != runtime.policy_digest {
        return Err(EnvironmentDrift::Policy);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coalition_change_invalidates_the_environment() {
        let certified = AssuranceEnvironment {
            observer_coalition_digest: [1; 32],
            transport_profile_digest: [2; 32],
            policy_digest: [3; 32],
        };
        let runtime = AssuranceEnvironment {
            observer_coalition_digest: [4; 32],
            ..certified
        };
        assert_eq!(
            compare(certified, runtime),
            Err(EnvironmentDrift::ObserverCoalition)
        );
    }
}
