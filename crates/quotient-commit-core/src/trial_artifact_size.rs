//! Byte cost split by security artifact role.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactSizeMetric {
    pub certificate_bytes: u64,
    pub capsule_bytes: u64,
    pub trace_bytes: u64,
    pub checkpoint_bytes: u64,
}

impl ArtifactSizeMetric {
    pub fn total(self) -> Option<u64> {
        self.certificate_bytes
            .checked_add(self.capsule_bytes)?
            .checked_add(self.trace_bytes)?
            .checked_add(self.checkpoint_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn components_remain_visible_and_total_is_checked() {
        let metric = ArtifactSizeMetric {
            certificate_bytes: 10,
            capsule_bytes: 20,
            trace_bytes: 30,
            checkpoint_bytes: 40,
        };
        assert_eq!(metric.total(), Some(100));
        assert_eq!(
            ArtifactSizeMetric {
                certificate_bytes: u64::MAX,
                ..metric
            }
            .total(),
            None
        );
    }
}
