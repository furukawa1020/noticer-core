//! Startup recovery worker with privacy-safe authenticated witness output.

use crate::delivery_outbox::{DeliveryIntent, DeliveryOutbox, OutboxState, OutboxStore};
use crate::receipt::hmac_sha256;
use crate::recovery_witness::{
    build_witness_batch, RecoveryWitness, RecoveryWitnessBatch, RecoveryWitnessError,
    WitnessAction, WitnessResult, WitnessState,
};
use crate::startup_recovery::{
    run_startup_recovery, RecoveryAction, RecoveryItemResult, StartupRecoveryError,
    StartupRecoveryExecutor,
};

const BINDING_DOMAIN: &[u8] = b"noticer.quotient-commit.recovery-public-binding.v1\0";

pub trait RecoveryWitnessSink {
    type Error;

    fn append_and_sync(
        &mut self,
        entries: &[RecoveryWitness],
        batch: RecoveryWitnessBatch,
    ) -> Result<(), Self::Error>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessedRecovery<E> {
    pub item_results: Vec<RecoveryItemResult<E>>,
    pub witnesses: Vec<RecoveryWitness>,
    pub batch: RecoveryWitnessBatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WitnessedRecoveryError<E> {
    Startup(StartupRecoveryError),
    Witness(RecoveryWitnessError),
    Sink(E),
}

pub fn run_witnessed_startup_recovery<S, E, W>(
    outbox: &DeliveryOutbox<S>,
    executor: &mut E,
    sink: &mut W,
    batch_limit: usize,
    witness_key: [u8; 32],
) -> Result<WitnessedRecovery<E::Error>, WitnessedRecoveryError<W::Error>>
where
    S: OutboxStore,
    E: StartupRecoveryExecutor,
    W: RecoveryWitnessSink,
{
    let source = outbox
        .entries()
        .into_iter()
        .take(batch_limit)
        .collect::<Vec<_>>();
    let item_results = run_startup_recovery(outbox, executor, batch_limit)
        .map_err(WitnessedRecoveryError::Startup)?;
    let decisions = source
        .iter()
        .zip(&item_results)
        .map(|((intent, state, _), result)| {
            (
                public_binding_digest(*intent, witness_key),
                witness_state(*state),
                witness_action(result),
                witness_result(result),
            )
        })
        .collect::<Vec<_>>();
    let (witnesses, batch) =
        build_witness_batch(&decisions, witness_key).map_err(WitnessedRecoveryError::Witness)?;
    sink.append_and_sync(&witnesses, batch)
        .map_err(WitnessedRecoveryError::Sink)?;
    Ok(WitnessedRecovery {
        item_results,
        witnesses,
        batch,
    })
}

fn public_binding_digest(intent: DeliveryIntent, key: [u8; 32]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(BINDING_DOMAIN.len() + 56);
    bytes.extend_from_slice(BINDING_DOMAIN);
    bytes.extend_from_slice(&intent.public_trace_digest);
    bytes.extend_from_slice(&intent.release_sequence.to_be_bytes());
    bytes.extend_from_slice(&intent.policy_epoch.to_be_bytes());
    bytes.extend_from_slice(&intent.receipt_epoch.to_be_bytes());
    hmac_sha256(key, &bytes)
}

fn witness_state(state: OutboxState) -> WitnessState {
    match state {
        OutboxState::Pending => WitnessState::Pending,
        OutboxState::Delivered => WitnessState::Delivered,
        OutboxState::Audited => WitnessState::Audited,
    }
}

fn witness_action<E>(result: &RecoveryItemResult<E>) -> WitnessAction {
    match result {
        RecoveryItemResult::Succeeded { action, .. }
        | RecoveryItemResult::Failed { action, .. } => match action {
            RecoveryAction::PendingDelivery => WitnessAction::RetryDelivery,
            RecoveryAction::DeliveredAudit => WitnessAction::RetryAudit,
            RecoveryAction::AlreadyAudited => WitnessAction::Noop,
        },
    }
}

fn witness_result<E>(result: &RecoveryItemResult<E>) -> WitnessResult {
    match result {
        RecoveryItemResult::Succeeded { .. } => WitnessResult::Succeeded,
        RecoveryItemResult::Failed { .. } => WitnessResult::FailedClosed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery_outbox::{OutboxError, OutboxRecord};
    use crate::recovery_witness::{canonical_json, verify_witness_batch};
    use crate::TransactionId;

    const KEY: [u8; 32] = [7; 32];

    #[derive(Default)]
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

    #[derive(Default)]
    struct Executor {
        fail: Option<TransactionId>,
        calls: usize,
    }

    impl StartupRecoveryExecutor for Executor {
        type Error = &'static str;

        fn recover_pending(&mut self, intent: DeliveryIntent) -> Result<(), Self::Error> {
            self.execute(intent)
        }

        fn recover_delivered(
            &mut self,
            intent: DeliveryIntent,
            _receipt_authenticator: [u8; 32],
        ) -> Result<(), Self::Error> {
            self.execute(intent)
        }
    }

    impl Executor {
        fn execute(&mut self, intent: DeliveryIntent) -> Result<(), &'static str> {
            self.calls += 1;
            if self.fail == Some(intent.transaction_id) {
                Err("injected")
            } else {
                Ok(())
            }
        }
    }

    #[derive(Default)]
    struct MemorySink(Option<(Vec<RecoveryWitness>, RecoveryWitnessBatch)>);

    impl RecoveryWitnessSink for MemorySink {
        type Error = &'static str;

        fn append_and_sync(
            &mut self,
            entries: &[RecoveryWitness],
            batch: RecoveryWitnessBatch,
        ) -> Result<(), Self::Error> {
            self.0 = Some((entries.to_vec(), batch));
            Ok(())
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
    fn every_recovery_action_produces_a_verifiable_private_safe_witness() {
        let outbox = mixed_outbox();
        let mut executor = Executor::default();
        let mut sink = MemorySink::default();
        let report =
            run_witnessed_startup_recovery(&outbox, &mut executor, &mut sink, 16, KEY).unwrap();
        assert_eq!(report.witnesses.len(), 3);
        assert_eq!(report.witnesses[0].action, WitnessAction::RetryDelivery);
        assert_eq!(report.witnesses[1].action, WitnessAction::RetryAudit);
        assert_eq!(report.witnesses[2].action, WitnessAction::Noop);
        assert_eq!(
            verify_witness_batch(&report.witnesses, report.batch, KEY),
            Ok(())
        );
        let artifact = canonical_json(report.batch);
        assert!(!artifact.contains("transaction"));
        assert!(!artifact.contains("subject"));
    }

    #[test]
    fn one_item_failure_is_witnessed_and_does_not_stop_later_items() {
        let outbox = mixed_outbox();
        let mut executor = Executor {
            fail: Some(intent(1).transaction_id),
            calls: 0,
        };
        let mut sink = MemorySink::default();
        let report =
            run_witnessed_startup_recovery(&outbox, &mut executor, &mut sink, 16, KEY).unwrap();
        assert_eq!(executor.calls, 2);
        assert_eq!(report.witnesses[0].result, WitnessResult::FailedClosed);
        assert_eq!(report.witnesses[1].result, WitnessResult::Succeeded);
        assert_eq!(report.witnesses[2].result, WitnessResult::Succeeded);
        assert_eq!(report.batch.failed_closed, 1);
        assert!(sink.0.is_some());
    }
}
