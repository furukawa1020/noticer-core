//! Canonical scenario labels for comparable experiments.

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ScenarioFamily {
    Nominal,
    IdentityAttack,
    TrafficAnalysis,
    ModelDrift,
    ReleaseFailure,
    Recovery,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrialScenario {
    pub family: ScenarioFamily,
    pub public_id: String,
    pub configuration_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScenarioError {
    UnsafeId,
    ZeroConfiguration,
}

impl TrialScenario {
    pub fn new(
        family: ScenarioFamily,
        public_id: impl Into<String>,
        configuration_digest: [u8; 32],
    ) -> Result<Self, ScenarioError> {
        let public_id = public_id.into();
        if public_id.is_empty()
            || public_id.len() > 64
            || !public_id.is_ascii()
            || public_id.contains(['=', ':'])
        {
            return Err(ScenarioError::UnsafeId);
        }
        if configuration_digest == [0; 32] {
            return Err(ScenarioError::ZeroConfiguration);
        }
        Ok(Self {
            family,
            public_id,
            configuration_digest,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_assignment_id_is_rejected() {
        assert_eq!(
            TrialScenario::new(ScenarioFamily::Nominal, "subject=7", [1; 32]),
            Err(ScenarioError::UnsafeId)
        );
    }
}
