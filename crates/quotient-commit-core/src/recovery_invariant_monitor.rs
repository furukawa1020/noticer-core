#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Invariant {
    Authority,
    EvidenceClosure,
    CausalCut,
    ReleaseFrontier,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MonitorState {
    Healthy,
    Blocked(Invariant),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvariantSnapshot {
    pub authority: bool,
    pub evidence_closure: bool,
    pub causal_cut: bool,
    pub release_frontier: bool,
}
pub struct InvariantMonitor {
    state: MonitorState,
}
impl InvariantMonitor {
    pub fn new() -> Self {
        Self {
            state: MonitorState::Healthy,
        }
    }
    pub fn state(&self) -> MonitorState {
        self.state
    }
    pub fn observe(&mut self, s: InvariantSnapshot) -> MonitorState {
        if !matches!(self.state, MonitorState::Healthy) {
            return self.state;
        }
        let violation = if !s.authority {
            Some(Invariant::Authority)
        } else if !s.evidence_closure {
            Some(Invariant::EvidenceClosure)
        } else if !s.causal_cut {
            Some(Invariant::CausalCut)
        } else if !s.release_frontier {
            Some(Invariant::ReleaseFrontier)
        } else {
            None
        };
        if let Some(v) = violation {
            self.state = MonitorState::Blocked(v)
        }
        self.state
    }
}
impl Default for InvariantMonitor {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn all() -> InvariantSnapshot {
        InvariantSnapshot {
            authority: true,
            evidence_closure: true,
            causal_cut: true,
            release_frontier: true,
        }
    }
    #[test]
    fn stays_healthy() {
        let mut m = InvariantMonitor::new();
        assert_eq!(m.observe(all()), MonitorState::Healthy)
    }
    #[test]
    fn violation_is_sticky() {
        let mut m = InvariantMonitor::new();
        let mut s = all();
        s.causal_cut = false;
        assert_eq!(m.observe(s), MonitorState::Blocked(Invariant::CausalCut));
        assert_eq!(
            m.observe(all()),
            MonitorState::Blocked(Invariant::CausalCut)
        );
    }
}
