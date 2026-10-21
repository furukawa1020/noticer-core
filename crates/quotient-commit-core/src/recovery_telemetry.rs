//! Aggregate recovery telemetry with an identifier-free public schema.

use crate::delivery_outbox::{DeliveryOutbox, OutboxState, OutboxStore};
use crate::startup_recovery::RecoveryAction;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryFailureKind {
    Binding,
    Storage,
    SinkUnavailable,
    Authentication,
    ResourceLimit,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RecoveryTelemetrySnapshot {
    pub pending_count: u64,
    pub delivered_count: u64,
    pub audited_count: u64,
    pub pending_attempts: u64,
    pub audit_attempts: u64,
    pub completed_noops: u64,
    pub succeeded: u64,
    pub failed: u64,
    pub latency_under_10_ms: u64,
    pub latency_under_100_ms: u64,
    pub latency_under_1_s: u64,
    pub latency_1_s_or_more: u64,
    pub binding_failures: u64,
    pub storage_failures: u64,
    pub sink_unavailable_failures: u64,
    pub authentication_failures: u64,
    pub resource_limit_failures: u64,
}

impl RecoveryTelemetrySnapshot {
    #[must_use]
    pub fn from_outbox<S: OutboxStore>(outbox: &DeliveryOutbox<S>) -> Self {
        let mut snapshot = Self::default();
        for (_, state, _) in outbox.entries() {
            match state {
                OutboxState::Pending => snapshot.pending_count += 1,
                OutboxState::Delivered => snapshot.delivered_count += 1,
                OutboxState::Audited => snapshot.audited_count += 1,
            }
        }
        snapshot
    }

    pub fn record_success(&mut self, action: RecoveryAction, latency_ms: u64) {
        self.record_attempt(action, latency_ms);
        self.succeeded += 1;
    }

    pub fn record_failure(
        &mut self,
        action: RecoveryAction,
        kind: RecoveryFailureKind,
        latency_ms: u64,
    ) {
        self.record_attempt(action, latency_ms);
        self.failed += 1;
        match kind {
            RecoveryFailureKind::Binding => self.binding_failures += 1,
            RecoveryFailureKind::Storage => self.storage_failures += 1,
            RecoveryFailureKind::SinkUnavailable => self.sink_unavailable_failures += 1,
            RecoveryFailureKind::Authentication => self.authentication_failures += 1,
            RecoveryFailureKind::ResourceLimit => self.resource_limit_failures += 1,
        }
    }

    #[must_use]
    pub fn canonical_json(&self) -> String {
        format!(
            concat!(
                "{{\"schema\":\"noticer.recovery-aggregate.v1\"",
                ",\"states\":{{\"pending\":{},\"delivered\":{},\"audited\":{}}}",
                ",\"attempts\":{{\"pending\":{},\"audit\":{},\"noop\":{}}}",
                ",\"results\":{{\"succeeded\":{},\"failed\":{}}}",
                ",\"latency_ms\":{{\"lt_10\":{},\"lt_100\":{},\"lt_1000\":{},\"gte_1000\":{}}}",
                ",\"failures\":{{\"binding\":{},\"storage\":{},\"sink_unavailable\":{},\"authentication\":{},\"resource_limit\":{}}}}}"
            ),
            self.pending_count,
            self.delivered_count,
            self.audited_count,
            self.pending_attempts,
            self.audit_attempts,
            self.completed_noops,
            self.succeeded,
            self.failed,
            self.latency_under_10_ms,
            self.latency_under_100_ms,
            self.latency_under_1_s,
            self.latency_1_s_or_more,
            self.binding_failures,
            self.storage_failures,
            self.sink_unavailable_failures,
            self.authentication_failures,
            self.resource_limit_failures,
        )
    }

    fn record_attempt(&mut self, action: RecoveryAction, latency_ms: u64) {
        match action {
            RecoveryAction::PendingDelivery => self.pending_attempts += 1,
            RecoveryAction::DeliveredAudit => self.audit_attempts += 1,
            RecoveryAction::AlreadyAudited => self.completed_noops += 1,
        }
        match latency_ms {
            0..=9 => self.latency_under_10_ms += 1,
            10..=99 => self.latency_under_100_ms += 1,
            100..=999 => self.latency_under_1_s += 1,
            _ => self.latency_1_s_or_more += 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery_outbox::{DeliveryIntent, OutboxError, OutboxRecord};
    use crate::TransactionId;

    const KEY: [u8; 32] = [7; 32];

    #[derive(Debug, Default)]
    struct MemoryStore(Vec<OutboxRecord>);

    impl OutboxStore for MemoryStore {
        fn append_and_sync(&mut self, record: OutboxRecord) -> Result<(), OutboxError> {
            self.0.push(record);
            Ok(())
        }

        fn load(&self) -> Result<Vec<OutboxRecord>, OutboxError> {
            Ok(self.0.clone())
        }
    }

    fn intent(value: u8) -> DeliveryIntent {
        DeliveryIntent {
            transaction_id: TransactionId([value; 32]),
            public_trace_digest: [value + 10; 32],
            release_sequence: u64::from(value),
            policy_epoch: 4,
            receipt_epoch: 5,
        }
    }

    fn mixed_outbox() -> DeliveryOutbox<MemoryStore> {
        let mut outbox = DeliveryOutbox::open(MemoryStore::default(), KEY, 16).unwrap();
        outbox.prepare(intent(1)).unwrap();
        outbox.prepare(intent(2)).unwrap();
        outbox
            .mark_delivered(intent(2).transaction_id, [22; 32])
            .unwrap();
        outbox.prepare(intent(3)).unwrap();
        outbox
            .mark_delivered(intent(3).transaction_id, [23; 32])
            .unwrap();
        outbox
            .mark_audited(intent(3).transaction_id, [23; 32])
            .unwrap();
        outbox
    }

    #[test]
    fn snapshot_counts_states_and_typed_results() {
        let mut snapshot = RecoveryTelemetrySnapshot::from_outbox(&mixed_outbox());
        assert_eq!(snapshot.pending_count, 1);
        assert_eq!(snapshot.delivered_count, 1);
        assert_eq!(snapshot.audited_count, 1);
        snapshot.record_success(RecoveryAction::PendingDelivery, 5);
        snapshot.record_success(RecoveryAction::AlreadyAudited, 50);
        snapshot.record_failure(
            RecoveryAction::DeliveredAudit,
            RecoveryFailureKind::Storage,
            500,
        );
        snapshot.record_failure(
            RecoveryAction::PendingDelivery,
            RecoveryFailureKind::Binding,
            1_500,
        );
        assert_eq!(snapshot.succeeded, 2);
        assert_eq!(snapshot.failed, 2);
        assert_eq!(snapshot.storage_failures, 1);
        assert_eq!(snapshot.binding_failures, 1);
        assert_eq!(snapshot.latency_under_10_ms, 1);
        assert_eq!(snapshot.latency_under_100_ms, 1);
        assert_eq!(snapshot.latency_under_1_s, 1);
        assert_eq!(snapshot.latency_1_s_or_more, 1);
    }

    #[test]
    fn public_json_is_deterministic_and_contains_no_identifier_fields() {
        let mut snapshot = RecoveryTelemetrySnapshot::from_outbox(&mixed_outbox());
        snapshot.record_success(RecoveryAction::PendingDelivery, 7);
        let first = snapshot.canonical_json();
        let second = snapshot.canonical_json();
        assert_eq!(first, second);
        for forbidden in [
            "transaction",
            "trace",
            "receipt",
            "subject",
            "biosignal",
            "digest",
            "authenticator",
        ] {
            assert!(!first.contains(forbidden));
        }
    }
}
