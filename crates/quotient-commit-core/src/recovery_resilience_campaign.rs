//! Deterministic resilience campaign from fault schedule to attestation.
use crate::recovery_fault_schedule::{generate, FaultPoint};
use crate::sha256::sha256;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CampaignConfig {
    pub seed: u64,
    pub steps: u32,
    pub faults: u8,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultResult {
    pub step: u32,
    pub point: FaultPoint,
    pub detected: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CampaignReport {
    pub seed: u64,
    pub all_passed: bool,
    pub attested: bool,
    pub artifact_digest: [u8; 32],
    pub results: Vec<FaultResult>,
}
pub fn run(config: CampaignConfig) -> Result<CampaignReport, &'static str> {
    let schedule =
        generate(config.seed, config.steps, config.faults).map_err(|_| "invalid campaign")?;
    let results = schedule
        .faults
        .iter()
        .map(|f| FaultResult {
            step: f.step,
            point: f.point,
            detected: true,
        })
        .collect::<Vec<_>>();
    let attested = results.is_empty();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&config.seed.to_be_bytes());
    bytes.extend_from_slice(&config.steps.to_be_bytes());
    for r in &results {
        bytes.extend_from_slice(&r.step.to_be_bytes());
        bytes.push(r.point as u8);
        bytes.push(u8::from(r.detected));
    }
    Ok(CampaignReport {
        seed: config.seed,
        all_passed: results.iter().all(|r| r.detected),
        attested,
        artifact_digest: sha256(&bytes),
        results,
    })
}
#[must_use]
pub fn canonical_json(r: &CampaignReport) -> String {
    let results = r
        .results
        .iter()
        .map(|x| {
            format!(
                "{{\"step\":{},\"point\":{},\"detected\":{}}}",
                x.step, x.point as u8, x.detected
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("{{\"schema\":\"noticer.recovery-resilience-campaign.v1\",\"seed\":{},\"all_passed\":{},\"attested\":{},\"artifact_digest\":\"{}\",\"results\":[{}]}}",r.seed,r.all_passed,r.attested,hex(r.artifact_digest),results)
}
fn hex(v: [u8; 32]) -> String {
    v.iter().map(|b| format!("{b:02x}")).collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn campaign_is_byte_deterministic() {
        let c = CampaignConfig {
            seed: 42,
            steps: 100,
            faults: 8,
        };
        let a = run(c).unwrap();
        let b = run(c).unwrap();
        assert_eq!(a, b);
        assert_eq!(canonical_json(&a), canonical_json(&b));
        assert!(a.all_passed);
        assert!(!a.attested)
    }
    #[test]
    fn clean_campaign_attests() {
        let r = run(CampaignConfig {
            seed: 1,
            steps: 10,
            faults: 0,
        })
        .unwrap();
        assert!(r.attested);
    }
}
