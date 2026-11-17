#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FabricFault {
    Clean,
    ProducerCollusion,
    ClockSkew,
    DomainLoss,
    FragmentSubstitution,
    CacheReplay,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StageState {
    Verified,
    Detected,
    Blocked,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CampaignStage {
    pub id: u8,
    pub state: StageState,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CampaignResult {
    pub seed: u64,
    pub fault: FabricFault,
    pub stages: Vec<CampaignStage>,
    pub release_allowed: bool,
}
pub fn run(seed: u64, fault: FabricFault) -> CampaignResult {
    let stop = match fault {
        FabricFault::Clean => None,
        FabricFault::ProducerCollusion => Some(0),
        FabricFault::ClockSkew => Some(1),
        FabricFault::DomainLoss => Some(2),
        FabricFault::FragmentSubstitution => Some(3),
        FabricFault::CacheReplay => Some(4),
    };
    let stages = (0..6)
        .map(|id| CampaignStage {
            id,
            state: match stop {
                None => StageState::Verified,
                Some(s) if id < s => StageState::Verified,
                Some(s) if id == s => StageState::Detected,
                Some(_) => StageState::Blocked,
            },
        })
        .collect::<Vec<_>>();
    CampaignResult {
        seed,
        fault,
        release_allowed: stop.is_none(),
        stages,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn clean_releases() {
        let r = run(24301, FabricFault::Clean);
        assert!(r.release_allowed);
        assert!(r.stages.iter().all(|s| s.state == StageState::Verified))
    }
    #[test]
    fn faults_block_downstream() {
        for f in [
            FabricFault::ProducerCollusion,
            FabricFault::ClockSkew,
            FabricFault::DomainLoss,
            FabricFault::FragmentSubstitution,
            FabricFault::CacheReplay,
        ] {
            let r = run(24301, f);
            let p = r
                .stages
                .iter()
                .position(|s| s.state == StageState::Detected)
                .unwrap();
            assert!(!r.release_allowed);
            assert!(r.stages[p + 1..]
                .iter()
                .all(|s| s.state == StageState::Blocked));
        }
    }
}
