//! Predeclared component ablations for causal attribution of stack costs and benefits.

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TrialComponent {
    Cause,
    Remedy,
    Sentinel,
    DualReplay,
    Authentication,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AblationArm {
    pub removed: TrialComponent,
    pub arm_digest: [u8; 32],
}

pub fn one_at_a_time(full_configuration_digest: [u8; 32]) -> Option<Vec<AblationArm>> {
    if full_configuration_digest == [0; 32] {
        return None;
    }
    Some(
        [
            TrialComponent::Cause,
            TrialComponent::Remedy,
            TrialComponent::Sentinel,
            TrialComponent::DualReplay,
            TrialComponent::Authentication,
        ]
        .into_iter()
        .map(|removed| {
            let mut bytes = b"noticer.quotient-trial.ablation.v1\0".to_vec();
            bytes.extend_from_slice(&full_configuration_digest);
            bytes.push(removed as u8);
            AblationArm {
                removed,
                arm_digest: crate::sha256::sha256(&bytes),
            }
        })
        .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_security_component_gets_one_arm() {
        let arms = one_at_a_time([1; 32]).unwrap();
        assert_eq!(arms.len(), 5);
        assert_eq!(arms[0].removed, TrialComponent::Cause);
    }
}
