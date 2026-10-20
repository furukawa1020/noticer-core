//! Deterministic, bounded routing of durable startup recovery work.

use crate::delivery_outbox::{DeliveryIntent, DeliveryOutbox, OutboxState, OutboxStore};
use crate::TransactionId;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryAction {
    PendingDelivery,
    DeliveredAudit,
    AlreadyAudited,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryItemResult<E> {
    Succeeded {
        transaction_id: TransactionId,
        action: RecoveryAction,
    },
    Failed {
        transaction_id: TransactionId,
        action: RecoveryAction,
        error: E,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupRecoveryError {
    InvalidBatchLimit,
}

pub trait StartupRecoveryExecutor {
    type Error;

    fn recover_pending(&mut self, intent: DeliveryIntent) -> Result<(), Self::Error>;

    fn recover_delivered(
        &mut self,
        intent: DeliveryIntent,
        receipt_authenticator: [u8; 32],
    ) -> Result<(), Self::Error>;
}

pub fn run_startup_recovery<S, E>(
    outbox: &DeliveryOutbox<S>,
    executor: &mut E,
    batch_limit: usize,
) -> Result<Vec<RecoveryItemResult<E::Error>>, StartupRecoveryError>
where
    S: OutboxStore,
    E: StartupRecoveryExecutor,
{
    if batch_limit == 0 {
        return Err(StartupRecoveryError::InvalidBatchLimit);
    }
    let entries = outbox.entries();
    let mut results = Vec::with_capacity(entries.len().min(batch_limit));
    for (intent, state, receipt_authenticator) in entries.into_iter().take(batch_limit) {
        let (action, result) = match state {
            OutboxState::Pending => (
                RecoveryAction::PendingDelivery,
                executor.recover_pending(intent),
            ),
            OutboxState::Delivered => (
                RecoveryAction::DeliveredAudit,
                executor.recover_delivered(intent, receipt_authenticator),
            ),
            OutboxState::Audited => (RecoveryAction::AlreadyAudited, Ok(())),
        };
        results.push(match result {
            Ok(()) => RecoveryItemResult::Succeeded {
                transaction_id: intent.transaction_id,
                action,
            },
            Err(error) => RecoveryItemResult::Failed {
                transaction_id: intent.transaction_id,
                action,
                error,
            },
        });
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery_outbox::{OutboxError, OutboxRecord};

    const KEY: [u8; 32] = [7; 32];

    #[derive(Debug, Default)]
    struct MemoryOutboxStore(Vec<OutboxRecord>);

    impl OutboxStore for MemoryOutboxStore {
        fn append_and_sync(&mut self, record: OutboxRecord) -> Result<(), OutboxError> {
            self.0.push(record);
            Ok(())
        }

        fn load(&self) -> Result<Vec<OutboxRecord>, OutboxError> {
            Ok(self.0.clone())
        }
    }

    #[derive(Debug, Default)]
    struct RecordingExecutor {
        pending: Vec<TransactionId>,
        delivered: Vec<TransactionId>,
        fail: Option<TransactionId>,
    }

    impl StartupRecoveryExecutor for RecordingExecutor {
        type Error = &'static str;

        fn recover_pending(&mut self, intent: DeliveryIntent) -> Result<(), Self::Error> {
            self.pending.push(intent.transaction_id);
            if self.fail == Some(intent.transaction_id) {
                Err("injected")
            } else {
                Ok(())
            }
        }

        fn recover_delivered(
            &mut self,
            intent: DeliveryIntent,
            _receipt_authenticator: [u8; 32],
        ) -> Result<(), Self::Error> {
            self.delivered.push(intent.transaction_id);
            if self.fail == Some(intent.transaction_id) {
                Err("injected")
            } else {
                Ok(())
            }
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

    fn mixed_outbox() -> DeliveryOutbox<MemoryOutboxStore> {
        let mut outbox = DeliveryOutbox::open(MemoryOutboxStore::default(), KEY, 16).unwrap();
        outbox.prepare(intent(3)).unwrap();
        outbox.prepare(intent(1)).unwrap();
        outbox
            .mark_delivered(intent(1).transaction_id, [21; 32])
            .unwrap();
        outbox.prepare(intent(2)).unwrap();
        outbox
            .mark_delivered(intent(2).transaction_id, [22; 32])
            .unwrap();
        outbox
            .mark_audited(intent(2).transaction_id, [22; 32])
            .unwrap();
        outbox
    }

    #[test]
    fn mixed_states_route_in_transaction_order_without_sink_for_audited() {
        let outbox = mixed_outbox();
        let mut executor = RecordingExecutor::default();
        let results = run_startup_recovery(&outbox, &mut executor, 16).unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(executor.delivered, vec![intent(1).transaction_id]);
        assert_eq!(executor.pending, vec![intent(3).transaction_id]);
        assert!(matches!(
            results[1],
            RecoveryItemResult::Succeeded {
                action: RecoveryAction::AlreadyAudited,
                ..
            }
        ));
    }

    #[test]
    fn one_failure_is_isolated_and_later_transactions_continue() {
        let outbox = mixed_outbox();
        let mut executor = RecordingExecutor {
            fail: Some(intent(1).transaction_id),
            ..RecordingExecutor::default()
        };
        let results = run_startup_recovery(&outbox, &mut executor, 16).unwrap();
        assert!(matches!(results[0], RecoveryItemResult::Failed { .. }));
        assert_eq!(results.len(), 3);
        assert_eq!(executor.pending, vec![intent(3).transaction_id]);
    }

    #[test]
    fn limit_is_deterministic_and_zero_is_rejected() {
        let outbox = mixed_outbox();
        let mut executor = RecordingExecutor::default();
        let results = run_startup_recovery(&outbox, &mut executor, 2).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(
            run_startup_recovery(&outbox, &mut executor, 0),
            Err(StartupRecoveryError::InvalidBatchLimit)
        );
    }
}
