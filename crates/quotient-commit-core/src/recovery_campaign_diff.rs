//! Regression comparison between baseline and candidate recovery campaigns.
use std::collections::BTreeMap;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScenarioMeasure {
    pub scenario: u16,
    pub safe: bool,
    pub duration_ms: u64,
    pub privacy_spend: u64,
}
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RegressionKind {
    MissingScenario,
    Safety,
    Slo,
    Privacy,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CampaignDiff {
    pub passed: bool,
    pub regressions: Vec<(u16, RegressionKind)>,
}
pub fn compare(
    baseline: &[ScenarioMeasure],
    candidate: &[ScenarioMeasure],
    maximum_duration_increase: u64,
    maximum_privacy_increase: u64,
) -> CampaignDiff {
    let candidates: BTreeMap<_, _> = candidate.iter().map(|x| (x.scenario, *x)).collect();
    let mut regressions = Vec::new();
    for base in baseline {
        let Some(next) = candidates.get(&base.scenario) else {
            regressions.push((base.scenario, RegressionKind::MissingScenario));
            continue;
        };
        if base.safe && !next.safe {
            regressions.push((base.scenario, RegressionKind::Safety))
        }
        if next.duration_ms > base.duration_ms.saturating_add(maximum_duration_increase) {
            regressions.push((base.scenario, RegressionKind::Slo))
        }
        if next.privacy_spend > base.privacy_spend.saturating_add(maximum_privacy_increase) {
            regressions.push((base.scenario, RegressionKind::Privacy))
        }
    }
    regressions.sort();
    CampaignDiff {
        passed: regressions.is_empty(),
        regressions,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn m(id: u16, safe: bool, d: u64, p: u64) -> ScenarioMeasure {
        ScenarioMeasure {
            scenario: id,
            safe,
            duration_ms: d,
            privacy_spend: p,
        }
    }
    #[test]
    fn bounded_changes_pass() {
        assert!(compare(&[m(1, true, 100, 5)], &[m(1, true, 105, 6)], 5, 1).passed)
    }
    #[test]
    fn independent_regressions_are_reported() {
        let d = compare(
            &[m(1, true, 100, 5), m(2, true, 100, 5)],
            &[m(1, false, 120, 9)],
            5,
            1,
        );
        assert_eq!(
            d.regressions,
            vec![
                (1, RegressionKind::Safety),
                (1, RegressionKind::Slo),
                (1, RegressionKind::Privacy),
                (2, RegressionKind::MissingScenario)
            ]
        );
    }
}
