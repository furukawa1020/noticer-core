//! Deterministic nearest-rank latency summary in nanoseconds.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LatencyDistribution {
    pub p50_nanos: u64,
    pub p95_nanos: u64,
    pub p99_nanos: u64,
    pub max_nanos: u64,
}

pub fn summarize(mut samples: Vec<u64>) -> Option<LatencyDistribution> {
    if samples.is_empty() {
        return None;
    }
    samples.sort_unstable();
    let rank = |percent: usize| {
        let one_based = (samples.len() * percent).div_ceil(100).max(1);
        samples[one_based - 1]
    };
    Some(LatencyDistribution {
        p50_nanos: rank(50),
        p95_nanos: rank(95),
        p99_nanos: rank(99),
        max_nanos: *samples.last().expect("non-empty"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn summary_is_order_independent() {
        let a = summarize(vec![4, 1, 3, 2]).unwrap();
        let b = summarize(vec![1, 2, 3, 4]).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.max_nanos, 4);
    }
}
