#![forbid(unsafe_code)]

pub mod audited_delivery;
pub mod authenticated_compaction;
pub mod authenticated_compaction_file;
pub mod ceremony_checkpoint_store;
pub mod chaos_campaign;
pub mod checkpoint;
pub mod coordinator;
pub mod crash_matrix;
pub mod cross_store_certifier;
pub mod delivery;
pub mod delivery_outbox;
pub mod file_sink;
pub mod file_store;
pub mod keyring;
pub mod ledger;
pub mod oracle_adversarial_matrix;
pub mod oracle_artifact;
pub mod oracle_artifact_auth;
pub mod oracle_bfs;
pub mod oracle_counterexample_selector;
pub mod oracle_dual_replay;
pub mod oracle_exploration_budget;
pub mod oracle_frontier_order;
pub mod oracle_inconclusive_taxonomy;
pub mod oracle_input;
pub mod oracle_invalid_classifier;
pub mod oracle_minimizer;
pub mod oracle_mutation_detector;
pub mod oracle_one_minimal;
pub mod oracle_predecessor_graph;
pub mod oracle_promotion_gate;
pub mod oracle_replay;
pub mod oracle_replay_disagreement;
pub mod oracle_repro_manifest;
pub mod oracle_state_digest;
pub mod oracle_state_pair;
pub mod oracle_symmetry_reduction;
pub mod oracle_symmetry_witness;
pub mod oracle_trace_reconstruction;
pub mod oracle_trace_step;
pub mod oracle_trace_validator;
pub mod oracle_transition_memo;
pub mod oracle_verdict;
pub mod oracle_visited_set;
pub mod pending_recovery;
pub mod proof_aggregate_manifest;
pub mod proof_aggregate_verifier;
pub mod proof_audit_checkpoint;
pub mod proof_audit_checkpoint_chain;
pub mod proof_audit_compaction;
pub mod proof_audit_consistency;
pub mod proof_audit_inclusion;
pub mod proof_availability_vector;
pub mod proof_cache_binding;
pub mod proof_cache_invalidation;
pub mod proof_clock_interval;
pub mod proof_contradiction_detector;
pub mod proof_degraded_quorum;
pub mod proof_fabric_campaign;
pub mod proof_fault_domain_label;
pub mod proof_fault_domain_quorum;
pub mod proof_fragment_envelope;
pub mod proof_fragment_recovery;
pub mod proof_freshness_lease;
pub mod proof_independence_policy;
pub mod proof_lease_renewal;
pub mod proof_producer_identity;
pub mod proof_producer_key_rotation;
pub mod proof_producer_quorum;
pub mod proof_quarantine_controller;
pub mod proof_release_audit_bridge;
pub mod proof_temporal_ordering;
pub mod proof_temporal_overlap;
pub mod proof_timestamp_envelope;
pub mod receipt;
pub mod receipt_coordinator;
pub mod receipt_file;
pub mod receipt_log;
pub mod recovery_acceptance;
pub mod recovery_admission;
pub mod recovery_artifact_envelope;
pub mod recovery_audit_transcript;
pub mod recovery_authority_attenuation;
pub mod recovery_authority_decay;
pub mod recovery_authority_lattice;
pub mod recovery_bootstrap_capsule;
pub mod recovery_break_glass;
pub mod recovery_break_glass_ledger;
pub mod recovery_campaign_diff;
pub mod recovery_canary_gate;
pub mod recovery_causal_cut;
pub mod recovery_ceremony;
pub mod recovery_challenge_ledger;
pub mod recovery_checkpoint_gossip;
pub mod recovery_checkpoint_quorum;
pub mod recovery_cross_region;
pub mod recovery_decision_capsule;
pub mod recovery_decision_commitment;
pub mod recovery_decision_reproducibility;
pub mod recovery_decision_view;
pub mod recovery_delegation_certificate;
pub mod recovery_delegation_chain;
pub mod recovery_drill;
pub mod recovery_epoch_transition;
pub mod recovery_equivocation_ledger;
pub mod recovery_evidence_closure;
pub mod recovery_evidence_graph;
pub mod recovery_export_permit;
pub mod recovery_fault_budget;
pub mod recovery_fault_schedule;
pub mod recovery_freshness;
pub mod recovery_handoff;
pub mod recovery_incident_capsule;
pub mod recovery_incident_escalation;
pub mod recovery_invariant_monitor;
pub mod recovery_key_custody;
pub mod recovery_key_rotation;
pub mod recovery_lease;
pub mod recovery_lease_handoff_proof;
pub mod recovery_liveness_watchdog;
pub mod recovery_nonce_ledger;
pub mod recovery_operator_challenge;
pub mod recovery_operator_quorum;
pub mod recovery_operator_session;
pub mod recovery_policy_bundle;
pub mod recovery_policy_guard;
pub mod recovery_policy_migration;
pub mod recovery_privacy_accountant;
pub mod recovery_proof_bundle;
pub mod recovery_proof_verifier;
pub mod recovery_provenance;
pub mod recovery_quorum_policy;
pub mod recovery_quorum_witness;
pub mod recovery_readiness;
pub mod recovery_redaction;
pub mod recovery_region_quorum;
pub mod recovery_release_attestation;
pub mod recovery_release_frontier;
pub mod recovery_release_proof_chain;
pub mod recovery_replication_manifest;
pub mod recovery_resilience_campaign;
pub mod recovery_restore_executor;
pub mod recovery_restore_plan;
pub mod recovery_retention;
pub mod recovery_revocation;
pub mod recovery_rollback_controller;
pub mod recovery_rollback_witness;
pub mod recovery_safe_mode;
pub mod recovery_showcase;
pub mod recovery_simulator;
pub mod recovery_slo;
pub mod recovery_telemetry;
pub mod recovery_telemetry_budget;
pub mod recovery_telemetry_oracle;
pub mod recovery_time_consensus;
pub mod recovery_transcript_merge;
pub mod recovery_transparency_log;
pub mod recovery_verifier_diversity;
pub mod recovery_violation_capsule;
pub mod recovery_wave_certificate;
pub mod recovery_wave_plan;
pub mod recovery_witness;
pub mod recovery_witness_freshness;
pub mod recovery_witness_worker;
pub mod recovery_worker;
pub mod retired_epoch_manifest;
pub mod rollback_anchor;
pub mod rollback_anchor_file;
pub mod sealed_receipt_vault;
mod sha256;
pub mod startup_admission_gate;
pub mod startup_fault_oracle;
pub mod startup_recovery;
pub mod startup_security_gate;
pub mod vaulted_delivery;

const TRANSACTION_DOMAIN: &[u8] = b"noticer.quotient-commit.transaction.v1\0";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TransactionId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleaseBindings {
    pub certificate_digest: [u8; 32],
    pub relation_digest: [u8; 32],
    pub profile_digest: [u8; 32],
    pub public_trace_digest: [u8; 32],
    pub release_sequence: u64,
    pub policy_epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MonitorAcceptance {
    pub transaction_id: TransactionId,
    pub certificate_digest: [u8; 32],
    pub relation_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BudgetReservation {
    pub transaction_id: TransactionId,
    pub profile_digest: [u8; 32],
    pub reservation_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitEvidence {
    pub transaction_id: TransactionId,
    pub public_trace_digest: [u8; 32],
    pub reservation_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleasePermit {
    pub transaction_id: TransactionId,
    pub public_trace_digest: [u8; 32],
    pub reservation_digest: [u8; 32],
    pub release_sequence: u64,
    pub policy_epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionState {
    Prepared,
    MonitorAccepted,
    BudgetReserved,
    Committed,
    Rejected,
    Aborted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleaseTransaction {
    id: TransactionId,
    bindings: ReleaseBindings,
    state: TransactionState,
    reservation_digest: Option<[u8; 32]>,
}

impl ReleaseTransaction {
    pub fn prepare(bindings: ReleaseBindings) -> Result<Self, CommitError> {
        validate_bindings(bindings)?;
        Ok(Self {
            id: transaction_id(bindings),
            bindings,
            state: TransactionState::Prepared,
            reservation_digest: None,
        })
    }

    #[must_use]
    pub const fn id(&self) -> TransactionId {
        self.id
    }

    #[must_use]
    pub const fn state(&self) -> TransactionState {
        self.state
    }

    pub fn accept_monitor(&mut self, evidence: MonitorAcceptance) -> Result<(), CommitError> {
        self.require_state(TransactionState::Prepared)?;
        self.require_transaction(evidence.transaction_id)?;
        if evidence.certificate_digest != self.bindings.certificate_digest
            || evidence.relation_digest != self.bindings.relation_digest
        {
            return Err(CommitError::MonitorBindingMismatch);
        }
        self.state = TransactionState::MonitorAccepted;
        Ok(())
    }

    pub fn reserve_budget(&mut self, evidence: BudgetReservation) -> Result<(), CommitError> {
        self.require_state(TransactionState::MonitorAccepted)?;
        self.require_transaction(evidence.transaction_id)?;
        if evidence.profile_digest != self.bindings.profile_digest {
            return Err(CommitError::ProfileBindingMismatch);
        }
        if is_zero(evidence.reservation_digest) {
            return Err(CommitError::InvalidReservation);
        }
        self.reservation_digest = Some(evidence.reservation_digest);
        self.state = TransactionState::BudgetReserved;
        Ok(())
    }

    pub fn commit(&mut self, evidence: CommitEvidence) -> Result<ReleasePermit, CommitError> {
        self.require_state(TransactionState::BudgetReserved)?;
        self.require_transaction(evidence.transaction_id)?;
        if evidence.public_trace_digest != self.bindings.public_trace_digest {
            return Err(CommitError::TraceBindingMismatch);
        }
        let reservation_digest = self
            .reservation_digest
            .ok_or(CommitError::MissingReservation)?;
        if evidence.reservation_digest != reservation_digest {
            return Err(CommitError::ReservationBindingMismatch);
        }
        self.state = TransactionState::Committed;
        Ok(ReleasePermit {
            transaction_id: self.id,
            public_trace_digest: self.bindings.public_trace_digest,
            reservation_digest,
            release_sequence: self.bindings.release_sequence,
            policy_epoch: self.bindings.policy_epoch,
        })
    }

    pub fn reject(&mut self, transaction_id: TransactionId) -> Result<(), CommitError> {
        self.finish_without_release(transaction_id, TransactionState::Rejected)
    }

    pub fn abort(&mut self, transaction_id: TransactionId) -> Result<(), CommitError> {
        self.finish_without_release(transaction_id, TransactionState::Aborted)
    }

    #[must_use]
    pub fn release_permit(&self) -> Option<ReleasePermit> {
        if self.state != TransactionState::Committed {
            return None;
        }
        Some(ReleasePermit {
            transaction_id: self.id,
            public_trace_digest: self.bindings.public_trace_digest,
            reservation_digest: self.reservation_digest?,
            release_sequence: self.bindings.release_sequence,
            policy_epoch: self.bindings.policy_epoch,
        })
    }

    fn finish_without_release(
        &mut self,
        transaction_id: TransactionId,
        terminal: TransactionState,
    ) -> Result<(), CommitError> {
        if matches!(
            self.state,
            TransactionState::Committed | TransactionState::Rejected | TransactionState::Aborted
        ) {
            return Err(CommitError::TerminalState);
        }
        self.require_transaction(transaction_id)?;
        self.state = terminal;
        Ok(())
    }

    fn require_state(&self, expected: TransactionState) -> Result<(), CommitError> {
        if self.state == expected {
            Ok(())
        } else if matches!(
            self.state,
            TransactionState::Committed | TransactionState::Rejected | TransactionState::Aborted
        ) {
            Err(CommitError::TerminalState)
        } else {
            Err(CommitError::InvalidTransition)
        }
    }

    fn require_transaction(&self, transaction_id: TransactionId) -> Result<(), CommitError> {
        if transaction_id == self.id {
            Ok(())
        } else {
            Err(CommitError::TransactionMismatch)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitError {
    ZeroBinding,
    InvalidPolicyEpoch,
    TransactionMismatch,
    MonitorBindingMismatch,
    ProfileBindingMismatch,
    TraceBindingMismatch,
    ReservationBindingMismatch,
    InvalidReservation,
    MissingReservation,
    InvalidTransition,
    TerminalState,
}

fn validate_bindings(bindings: ReleaseBindings) -> Result<(), CommitError> {
    if is_zero(bindings.certificate_digest)
        || is_zero(bindings.relation_digest)
        || is_zero(bindings.profile_digest)
        || is_zero(bindings.public_trace_digest)
    {
        return Err(CommitError::ZeroBinding);
    }
    if bindings.policy_epoch == 0 {
        return Err(CommitError::InvalidPolicyEpoch);
    }
    Ok(())
}

fn transaction_id(bindings: ReleaseBindings) -> TransactionId {
    let mut bytes = Vec::with_capacity(TRANSACTION_DOMAIN.len() + 32 * 4 + 8 * 2);
    bytes.extend_from_slice(TRANSACTION_DOMAIN);
    bytes.extend_from_slice(&bindings.certificate_digest);
    bytes.extend_from_slice(&bindings.relation_digest);
    bytes.extend_from_slice(&bindings.profile_digest);
    bytes.extend_from_slice(&bindings.public_trace_digest);
    bytes.extend_from_slice(&bindings.release_sequence.to_be_bytes());
    bytes.extend_from_slice(&bindings.policy_epoch.to_be_bytes());
    TransactionId(sha256::sha256(&bytes))
}

const fn is_zero(value: [u8; 32]) -> bool {
    let mut index = 0;
    while index < value.len() {
        if value[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bindings() -> ReleaseBindings {
        ReleaseBindings {
            certificate_digest: [1; 32],
            relation_digest: [2; 32],
            profile_digest: [3; 32],
            public_trace_digest: [4; 32],
            release_sequence: 7,
            policy_epoch: 9,
        }
    }

    fn accepted_transaction() -> ReleaseTransaction {
        let mut transaction = ReleaseTransaction::prepare(bindings()).unwrap();
        transaction
            .accept_monitor(MonitorAcceptance {
                transaction_id: transaction.id(),
                certificate_digest: [1; 32],
                relation_digest: [2; 32],
            })
            .unwrap();
        transaction
    }

    #[test]
    fn release_permit_exists_only_after_ordered_commit() {
        let mut transaction = accepted_transaction();
        assert_eq!(transaction.release_permit(), None);
        transaction
            .reserve_budget(BudgetReservation {
                transaction_id: transaction.id(),
                profile_digest: [3; 32],
                reservation_digest: [5; 32],
            })
            .unwrap();
        assert_eq!(transaction.release_permit(), None);
        let permit = transaction
            .commit(CommitEvidence {
                transaction_id: transaction.id(),
                public_trace_digest: [4; 32],
                reservation_digest: [5; 32],
            })
            .unwrap();
        assert_eq!(permit.release_sequence, 7);
        assert_eq!(transaction.release_permit(), Some(permit));
    }

    #[test]
    fn out_of_order_and_replayed_transitions_fail_closed() {
        let mut transaction = ReleaseTransaction::prepare(bindings()).unwrap();
        assert_eq!(
            transaction.reserve_budget(BudgetReservation {
                transaction_id: transaction.id(),
                profile_digest: [3; 32],
                reservation_digest: [5; 32],
            }),
            Err(CommitError::InvalidTransition)
        );
        transaction.abort(transaction.id()).unwrap();
        assert_eq!(
            transaction.abort(transaction.id()),
            Err(CommitError::TerminalState)
        );
        assert_eq!(transaction.release_permit(), None);
    }

    #[test]
    fn cross_transaction_and_binding_substitution_are_rejected() {
        let mut transaction = ReleaseTransaction::prepare(bindings()).unwrap();
        let other = ReleaseTransaction::prepare(ReleaseBindings {
            release_sequence: 8,
            ..bindings()
        })
        .unwrap();
        assert_eq!(
            transaction.accept_monitor(MonitorAcceptance {
                transaction_id: other.id(),
                certificate_digest: [1; 32],
                relation_digest: [2; 32],
            }),
            Err(CommitError::TransactionMismatch)
        );
        assert_eq!(transaction.state(), TransactionState::Prepared);
        assert_eq!(
            transaction.accept_monitor(MonitorAcceptance {
                transaction_id: transaction.id(),
                certificate_digest: [9; 32],
                relation_digest: [2; 32],
            }),
            Err(CommitError::MonitorBindingMismatch)
        );
        assert_eq!(transaction.state(), TransactionState::Prepared);
    }

    #[test]
    fn reservation_and_trace_substitution_are_rejected_without_release() {
        let mut transaction = accepted_transaction();
        assert_eq!(
            transaction.reserve_budget(BudgetReservation {
                transaction_id: transaction.id(),
                profile_digest: [8; 32],
                reservation_digest: [5; 32],
            }),
            Err(CommitError::ProfileBindingMismatch)
        );
        transaction
            .reserve_budget(BudgetReservation {
                transaction_id: transaction.id(),
                profile_digest: [3; 32],
                reservation_digest: [5; 32],
            })
            .unwrap();
        assert_eq!(
            transaction.commit(CommitEvidence {
                transaction_id: transaction.id(),
                public_trace_digest: [8; 32],
                reservation_digest: [5; 32],
            }),
            Err(CommitError::TraceBindingMismatch)
        );
        assert_eq!(transaction.release_permit(), None);
    }

    #[test]
    fn terminal_rejection_cannot_be_promoted_to_release() {
        let mut transaction = accepted_transaction();
        transaction.reject(transaction.id()).unwrap();
        assert_eq!(transaction.state(), TransactionState::Rejected);
        assert_eq!(transaction.release_permit(), None);
        assert_eq!(
            transaction.reserve_budget(BudgetReservation {
                transaction_id: transaction.id(),
                profile_digest: [3; 32],
                reservation_digest: [5; 32],
            }),
            Err(CommitError::TerminalState)
        );
    }

    #[test]
    fn invalid_bindings_never_create_a_transaction() {
        assert_eq!(
            ReleaseTransaction::prepare(ReleaseBindings {
                certificate_digest: [0; 32],
                ..bindings()
            }),
            Err(CommitError::ZeroBinding)
        );
        assert_eq!(
            ReleaseTransaction::prepare(ReleaseBindings {
                policy_epoch: 0,
                ..bindings()
            }),
            Err(CommitError::InvalidPolicyEpoch)
        );
    }
}
