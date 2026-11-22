//! Peak resident and allocation-proxy memory summary.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryObservation {
    pub resident_bytes: u64,
    pub allocated_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeakMemoryMetric {
    pub peak_resident_bytes: u64,
    pub peak_allocated_bytes: u64,
}

pub fn summarize(samples: &[MemoryObservation]) -> Option<PeakMemoryMetric> {
    Some(PeakMemoryMetric {
        peak_resident_bytes: samples.iter().map(|v| v.resident_bytes).max()?,
        peak_allocated_bytes: samples.iter().map(|v| v.allocated_bytes).max()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn peaks_are_tracked_independently() {
        assert_eq!(
            summarize(&[
                MemoryObservation {
                    resident_bytes: 10,
                    allocated_bytes: 30
                },
                MemoryObservation {
                    resident_bytes: 20,
                    allocated_bytes: 15
                },
            ]),
            Some(PeakMemoryMetric {
                peak_resident_bytes: 20,
                peak_allocated_bytes: 30
            })
        );
    }
}
