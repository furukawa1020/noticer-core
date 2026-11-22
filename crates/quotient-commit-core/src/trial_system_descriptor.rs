//! Comparable capabilities for evaluated systems and baselines.

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EvaluatedSystemKind {
    Immediate,
    FixedRate,
    PaddingOnly,
    EncryptionOnly,
    MonitorOnly,
    QuotientCause,
    QuotientRemedy,
    QuotientSentinel,
    FullStack,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystemCapabilities(u16);

impl SystemCapabilities {
    pub const ACTION_EQUIVALENCE: u16 = 1;
    pub const CAUSAL_EXPLANATION: u16 = 2;
    pub const COUNTERFACTUAL_REPAIR: u16 = 4;
    pub const RUNTIME_ASSURANCE: u16 = 8;
    pub const DUAL_REPLAY: u16 = 16;
    pub const AUTHENTICATION: u16 = 32;

    pub fn new(bits: u16) -> Option<Self> {
        (bits != 0 && bits & !0x3f == 0).then_some(Self(bits))
    }
    #[must_use]
    pub const fn contains(self, capability: u16) -> bool {
        self.0 & capability == capability
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvaluatedSystemDescriptor {
    pub kind: EvaluatedSystemKind,
    pub version_digest: [u8; 32],
    pub capabilities: SystemCapabilities,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capability_set_is_closed() {
        assert!(SystemCapabilities::new(0).is_none());
        assert!(SystemCapabilities::new(0x80).is_none());
        let caps = SystemCapabilities::new(
            SystemCapabilities::ACTION_EQUIVALENCE | SystemCapabilities::AUTHENTICATION,
        )
        .unwrap();
        assert!(caps.contains(SystemCapabilities::AUTHENTICATION));
    }
}
