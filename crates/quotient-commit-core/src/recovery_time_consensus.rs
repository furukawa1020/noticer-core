//! Median-based trusted time from independent recovery time authorities.
use std::collections::BTreeSet;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimeSample {
    pub source: [u8; 16],
    pub unix_seconds: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustedTime {
    pub unix_seconds: u64,
    pub agreeing_sources: u16,
    pub maximum_observed_skew: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimeError {
    InsufficientQuorum,
    DuplicateSource,
    InvalidSource,
    Rollback,
    ExcessiveSkew,
}
pub fn establish(
    samples: &[TimeSample],
    minimum_time: u64,
    maximum_skew: u64,
) -> Result<TrustedTime, TimeError> {
    if samples.len() < 3 {
        return Err(TimeError::InsufficientQuorum);
    }
    let mut ids = BTreeSet::new();
    for s in samples {
        if s.source == [0; 16] || s.unix_seconds == 0 {
            return Err(TimeError::InvalidSource);
        }
        if !ids.insert(s.source) {
            return Err(TimeError::DuplicateSource);
        }
    }
    let mut times = samples.iter().map(|s| s.unix_seconds).collect::<Vec<_>>();
    times.sort_unstable();
    let median = times[times.len() / 2];
    if median < minimum_time {
        return Err(TimeError::Rollback);
    }
    let agreeing = times
        .iter()
        .filter(|t| t.abs_diff(median) <= maximum_skew)
        .count();
    if agreeing < 3 {
        return Err(TimeError::InsufficientQuorum);
    }
    let skew = times.iter().map(|t| t.abs_diff(median)).max().unwrap_or(0);
    if times.iter().all(|t| t.abs_diff(median) > maximum_skew) {
        return Err(TimeError::ExcessiveSkew);
    }
    Ok(TrustedTime {
        unix_seconds: median,
        agreeing_sources: agreeing as u16,
        maximum_observed_skew: skew,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn s(id: u8, t: u64) -> TimeSample {
        TimeSample {
            source: [id; 16],
            unix_seconds: t,
        }
    }
    #[test]
    fn median_tolerates_one_outlier() {
        let t = establish(&[s(1, 100), s(2, 101), s(3, 102), s(4, 999)], 90, 2).unwrap();
        assert_eq!(t.unix_seconds, 102);
        assert_eq!(t.agreeing_sources, 3)
    }
    #[test]
    fn duplicate_rollback_and_low_quorum_fail() {
        assert_eq!(
            establish(&[s(1, 100), s(1, 101), s(3, 102)], 0, 2),
            Err(TimeError::DuplicateSource)
        );
        assert_eq!(
            establish(&[s(1, 100), s(2, 101), s(3, 102)], 103, 2),
            Err(TimeError::Rollback)
        );
        assert_eq!(
            establish(&[s(1, 100), s(2, 200), s(3, 300)], 0, 1),
            Err(TimeError::InsufficientQuorum)
        );
    }
}
