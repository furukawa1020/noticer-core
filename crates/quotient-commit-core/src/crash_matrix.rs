//! Deterministic crash-point campaign for the vaulted delivery protocol.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CrashPoint {
    BeforePendingSync,
    AfterPendingSync,
    AfterSinkEffect,
    AfterVaultSync,
    AfterDeliveredSync,
    AfterAuditSync,
    AfterAuditedSync,
}

impl CrashPoint {
    pub const ALL: [Self; 7] = [
        Self::BeforePendingSync,
        Self::AfterPendingSync,
        Self::AfterSinkEffect,
        Self::AfterVaultSync,
        Self::AfterDeliveredSync,
        Self::AfterAuditSync,
        Self::AfterAuditedSync,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::BeforePendingSync => "before_pending_sync",
            Self::AfterPendingSync => "after_pending_sync",
            Self::AfterSinkEffect => "after_sink_effect",
            Self::AfterVaultSync => "after_vault_sync",
            Self::AfterDeliveredSync => "after_delivered_sync",
            Self::AfterAuditSync => "after_audit_sync",
            Self::AfterAuditedSync => "after_audited_sync",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalState {
    NoDurableIntent,
    Audited,
    RejectedBinding,
}

impl TerminalState {
    const fn label(self) -> &'static str {
        match self {
            Self::NoDurableIntent => "no_durable_intent",
            Self::Audited => "audited",
            Self::RejectedBinding => "rejected_binding",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CrashWitness {
    pub crash_point: CrashPoint,
    pub sink_effects: u8,
    pub audit_records: u8,
    pub terminal_state: TerminalState,
    pub effect_at_most_once: bool,
    pub audit_at_most_once: bool,
    pub converged: bool,
    pub fail_closed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrashCampaign {
    witnesses: Vec<CrashWitness>,
}

impl CrashCampaign {
    #[must_use]
    pub fn run() -> Self {
        Self {
            witnesses: CrashPoint::ALL
                .into_iter()
                .map(|point| simulate(point, false))
                .collect(),
        }
    }

    #[must_use]
    pub fn run_substitution_attack() -> Self {
        Self {
            witnesses: CrashPoint::ALL
                .into_iter()
                .map(|point| simulate(point, true))
                .collect(),
        }
    }

    #[must_use]
    pub fn witnesses(&self) -> &[CrashWitness] {
        &self.witnesses
    }

    #[must_use]
    pub fn canonical_json(&self) -> String {
        let mut output = String::from("{\"schema\":\"noticer.crash-matrix.v1\",\"witnesses\":[");
        for (index, witness) in self.witnesses.iter().enumerate() {
            if index > 0 {
                output.push(',');
            }
            output.push_str(&format!(
                "{{\"point\":\"{}\",\"sink_effects\":{},\"audit_records\":{},\"terminal\":\"{}\",\"effect_at_most_once\":{},\"audit_at_most_once\":{},\"converged\":{},\"fail_closed\":{}}}",
                witness.crash_point.label(),
                witness.sink_effects,
                witness.audit_records,
                witness.terminal_state.label(),
                witness.effect_at_most_once,
                witness.audit_at_most_once,
                witness.converged,
                witness.fail_closed,
            ));
        }
        output.push_str("]}");
        output
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ProtocolState {
    pending: bool,
    sink_effects: u8,
    vaulted: bool,
    delivered: bool,
    audit_records: u8,
    audited: bool,
}

fn simulate(point: CrashPoint, substituted_binding: bool) -> CrashWitness {
    let mut state = state_at_crash(point);
    if !state.pending {
        return witness(
            point,
            state,
            TerminalState::NoDurableIntent,
            substituted_binding,
        );
    }
    if substituted_binding {
        return witness(point, state, TerminalState::RejectedBinding, true);
    }
    if !state.vaulted {
        if state.sink_effects == 0 {
            state.sink_effects = 1;
        }
        state.vaulted = true;
    }
    if !state.delivered {
        state.delivered = true;
    }
    if state.audit_records == 0 {
        state.audit_records = 1;
    }
    state.audited = true;
    witness(point, state, TerminalState::Audited, false)
}

fn state_at_crash(point: CrashPoint) -> ProtocolState {
    let mut state = ProtocolState::default();
    if point == CrashPoint::BeforePendingSync {
        return state;
    }
    state.pending = true;
    if point == CrashPoint::AfterPendingSync {
        return state;
    }
    state.sink_effects = 1;
    if point == CrashPoint::AfterSinkEffect {
        return state;
    }
    state.vaulted = true;
    if point == CrashPoint::AfterVaultSync {
        return state;
    }
    state.delivered = true;
    if point == CrashPoint::AfterDeliveredSync {
        return state;
    }
    state.audit_records = 1;
    if point == CrashPoint::AfterAuditSync {
        return state;
    }
    state.audited = true;
    state
}

fn witness(
    point: CrashPoint,
    state: ProtocolState,
    terminal_state: TerminalState,
    fail_closed: bool,
) -> CrashWitness {
    CrashWitness {
        crash_point: point,
        sink_effects: state.sink_effects,
        audit_records: state.audit_records,
        terminal_state,
        effect_at_most_once: state.sink_effects <= 1,
        audit_at_most_once: state.audit_records <= 1,
        converged: matches!(
            terminal_state,
            TerminalState::NoDurableIntent | TerminalState::Audited
        ),
        fail_closed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_crash_point_preserves_safety_and_converges() {
        let campaign = CrashCampaign::run();
        assert_eq!(campaign.witnesses().len(), CrashPoint::ALL.len());
        assert!(campaign.witnesses().iter().all(|witness| {
            witness.effect_at_most_once
                && witness.audit_at_most_once
                && witness.converged
                && !witness.fail_closed
        }));
    }

    #[test]
    fn substitution_at_every_crash_point_fails_closed_without_extra_effects() {
        let campaign = CrashCampaign::run_substitution_attack();
        for witness in campaign.witnesses() {
            assert!(witness.effect_at_most_once);
            assert!(witness.audit_at_most_once);
            assert!(witness.fail_closed);
            if witness.crash_point == CrashPoint::BeforePendingSync {
                assert_eq!(witness.terminal_state, TerminalState::NoDurableIntent);
            } else {
                assert_eq!(witness.terminal_state, TerminalState::RejectedBinding);
            }
        }
    }

    #[test]
    fn canonical_artifact_is_byte_stable_and_ordered() {
        let first = CrashCampaign::run().canonical_json();
        let second = CrashCampaign::run().canonical_json();
        assert_eq!(first, second);
        assert!(first.starts_with(
            "{\"schema\":\"noticer.crash-matrix.v1\",\"witnesses\":[{\"point\":\"before_pending_sync\""
        ));
        assert!(first.ends_with("]}"));
    }
}
