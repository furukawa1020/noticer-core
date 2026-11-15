use crate::receipt::hmac_sha256;
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DeploymentTarget(pub [u8; 8]);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeploymentWave {
    pub index: usize,
    pub targets: Vec<DeploymentTarget>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WavePlan {
    pub waves: Vec<DeploymentWave>,
    pub digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WavePlanError {
    Empty,
    InvalidWaveSize,
    CanaryMissing,
    DuplicateTarget,
}

pub fn plan(
    targets: &[DeploymentTarget],
    canary: DeploymentTarget,
    maximum_wave_size: usize,
    key: [u8; 32],
) -> Result<WavePlan, WavePlanError> {
    if targets.is_empty() {
        return Err(WavePlanError::Empty);
    }
    if maximum_wave_size == 0 {
        return Err(WavePlanError::InvalidWaveSize);
    }
    let unique = targets.iter().copied().collect::<BTreeSet<_>>();
    if unique.len() != targets.len() {
        return Err(WavePlanError::DuplicateTarget);
    }
    if !unique.contains(&canary) {
        return Err(WavePlanError::CanaryMissing);
    }
    let mut remaining = unique
        .into_iter()
        .filter(|target| *target != canary)
        .collect::<Vec<_>>();
    let mut groups = vec![vec![canary]];
    while !remaining.is_empty() {
        let take = maximum_wave_size.min(remaining.len());
        groups.push(remaining.drain(..take).collect());
    }
    let waves = groups
        .into_iter()
        .enumerate()
        .map(|(index, targets)| DeploymentWave { index, targets })
        .collect::<Vec<_>>();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"noticer.wave-plan.v1");
    for wave in &waves {
        bytes.extend_from_slice(&(wave.index as u64).to_be_bytes());
        for target in &wave.targets {
            bytes.extend_from_slice(&target.0);
        }
    }
    Ok(WavePlan {
        waves,
        digest: hmac_sha256(key, &bytes),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const KEY: [u8; 32] = [2; 32];
    #[test]
    fn puts_canary_first_and_bounds_wave_size() {
        let targets = [
            DeploymentTarget([3; 8]),
            DeploymentTarget([1; 8]),
            DeploymentTarget([2; 8]),
        ];
        let result = plan(&targets, DeploymentTarget([2; 8]), 1, KEY).unwrap();
        assert_eq!(result.waves[0].targets, vec![DeploymentTarget([2; 8])]);
        assert!(result.waves.iter().all(|wave| wave.targets.len() <= 1));
    }
    #[test]
    fn rejects_duplicate_and_missing_canary() {
        let duplicate = [DeploymentTarget([1; 8]), DeploymentTarget([1; 8])];
        assert_eq!(
            plan(&duplicate, DeploymentTarget([1; 8]), 2, KEY),
            Err(WavePlanError::DuplicateTarget)
        );
        assert_eq!(
            plan(
                &[DeploymentTarget([1; 8])],
                DeploymentTarget([2; 8]),
                1,
                KEY
            ),
            Err(WavePlanError::CanaryMissing)
        );
    }
}
