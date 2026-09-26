#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;

pub const MAX_COALITION_MEMBERS: usize = 64;

macro_rules! hash_type {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 32]);

        impl $name {
            pub const fn new(bytes: [u8; 32]) -> Result<Self, SemanticsError> {
                if all_zero(&bytes) {
                    Err(SemanticsError::ZeroHash)
                } else {
                    Ok(Self(bytes))
                }
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
    };
}

hash_type!(ActionQuotientHash);
hash_type!(SecretFamilyHash);
hash_type!(CoalitionHash);
hash_type!(PolicyHash);
hash_type!(PublicContextHash);
hash_type!(MechanismHash);
hash_type!(TranscriptHash);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PublicEpoch(pub u64);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ServiceBinding(pub u32);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ActionCode(pub u16);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ObserverId(pub u32);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SecretModelVersion(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicReleaseWindow {
    pub earliest_slot: u64,
    pub latest_slot: u64,
}

impl PublicReleaseWindow {
    pub const fn new(earliest_slot: u64, latest_slot: u64) -> Result<Self, SemanticsError> {
        if earliest_slot > latest_slot {
            Err(SemanticsError::InvalidReleaseWindow)
        } else {
            Ok(Self {
                earliest_slot,
                latest_slot,
            })
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizedActionEvent {
    pub public_epoch: PublicEpoch,
    pub service: ServiceBinding,
    pub action: ActionCode,
    pub public_window: PublicReleaseWindow,
    pub policy_hash: PolicyHash,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedActionTranscript {
    events: Vec<AuthorizedActionEvent>,
}

impl AuthorizedActionTranscript {
    pub fn new(events: Vec<AuthorizedActionEvent>) -> Result<Self, SemanticsError> {
        ensure_monotone_epochs(events.iter().map(|event| event.public_epoch))?;
        Ok(Self { events })
    }

    pub fn events(&self) -> &[AuthorizedActionEvent] {
        &self.events
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservableKind {
    Token,
    Silence,
    Failure,
    Retry,
    Reconnect,
    PublicReceipt,
    ActionExecution,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservableReleaseSegment {
    pub public_epoch: PublicEpoch,
    pub slot: u64,
    pub service: ServiceBinding,
    pub kind: ObservableKind,
    pub size_class: u16,
    pub public_status: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservableReleaseTranscript {
    segments: Vec<ObservableReleaseSegment>,
}

impl ObservableReleaseTranscript {
    pub fn new(segments: Vec<ObservableReleaseSegment>) -> Result<Self, SemanticsError> {
        ensure_monotone_epochs(segments.iter().map(|segment| segment.public_epoch))?;
        ensure_monotone_slots(segments.iter().map(|segment| segment.slot))?;
        Ok(Self { segments })
    }

    pub fn segments(&self) -> &[ObservableReleaseSegment] {
        &self.segments
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicInputEvent {
    pub public_epoch: PublicEpoch,
    pub input_code: u16,
    pub public_value: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicFaultEvent {
    pub public_epoch: PublicEpoch,
    pub fault_code: u16,
    pub public_slot: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicPolicyEvent {
    pub public_epoch: PublicEpoch,
    pub policy_hash: PolicyHash,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicTranscript {
    pub authorized_actions: AuthorizedActionTranscript,
    pub release_trace: ObservableReleaseTranscript,
    pub public_inputs: Vec<PublicInputEvent>,
    pub public_faults: Vec<PublicFaultEvent>,
    pub public_policy_events: Vec<PublicPolicyEvent>,
}

impl PublicTranscript {
    pub fn validate(&self) -> Result<(), SemanticsError> {
        ensure_monotone_epochs(self.public_inputs.iter().map(|event| event.public_epoch))?;
        ensure_monotone_epochs(self.public_faults.iter().map(|event| event.public_epoch))?;
        ensure_monotone_epochs(
            self.public_policy_events
                .iter()
                .map(|event| event.public_epoch),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretFamily {
    PrivateTiming,
    StableIdentity,
    PhysiologicalMorphology,
    DemographicAttribute,
    PrivateContext,
    BaselineTrajectory,
    Composite(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObserverScope {
    Network,
    Service(ServiceBinding),
    DeclaredCoalition(CoalitionHash),
    PublicReceiptReader,
    PhysicalActionObserver,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObserverCoalition {
    members: Vec<ObserverId>,
    coalition_hash: CoalitionHash,
}

impl ObserverCoalition {
    pub fn new(
        members: Vec<ObserverId>,
        coalition_hash: CoalitionHash,
    ) -> Result<Self, SemanticsError> {
        if members.is_empty() {
            return Err(SemanticsError::EmptyCoalition);
        }
        if members.len() > MAX_COALITION_MEMBERS {
            return Err(SemanticsError::ResourceLimit);
        }
        if members.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(SemanticsError::CoalitionNotCanonical);
        }
        Ok(Self {
            members,
            coalition_hash,
        })
    }

    pub fn members(&self) -> &[ObserverId] {
        &self.members
    }

    pub const fn coalition_hash(&self) -> CoalitionHash {
        self.coalition_hash
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionQuotientSecretPairFamily {
    pub family_hash: SecretFamilyHash,
    pub action_quotient_hash: ActionQuotientHash,
    pub model_version: SecretModelVersion,
    pub observer_scope: ObserverScope,
    pub secret_family: SecretFamily,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicActionView {
    pub action_quotient_hash: ActionQuotientHash,
    pub action_transcript_hash: TranscriptHash,
    pub policy_hash: PolicyHash,
    pub public_context_hash: PublicContextHash,
    pub model_version: SecretModelVersion,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionEquivalenceWitness {
    pub action_quotient_hash: ActionQuotientHash,
    pub action_transcript_hash: TranscriptHash,
    pub policy_hash: PolicyHash,
    pub public_context_hash: PublicContextHash,
    pub model_version: SecretModelVersion,
}

pub fn certify_action_equivalent(
    left: PublicActionView,
    right: PublicActionView,
    family: ActionQuotientSecretPairFamily,
) -> Result<ActionEquivalenceWitness, SemanticsError> {
    if left.action_quotient_hash != family.action_quotient_hash
        || right.action_quotient_hash != family.action_quotient_hash
    {
        return Err(SemanticsError::ActionQuotientMismatch);
    }
    if left.model_version != family.model_version || right.model_version != family.model_version {
        return Err(SemanticsError::ModelVersionMismatch);
    }
    if left.action_transcript_hash != right.action_transcript_hash {
        return Err(SemanticsError::AuthorizedActionMismatch);
    }
    if left.policy_hash != right.policy_hash {
        return Err(SemanticsError::PublicPolicyMismatch);
    }
    if left.public_context_hash != right.public_context_hash {
        return Err(SemanticsError::PublicContextMismatch);
    }
    Ok(ActionEquivalenceWitness {
        action_quotient_hash: left.action_quotient_hash,
        action_transcript_hash: left.action_transcript_hash,
        policy_hash: left.policy_hash,
        public_context_hash: left.public_context_hash,
        model_version: left.model_version,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicBudgetState {
    pub budget_epoch: u64,
    pub remaining_epsilon_q16_16: u64,
    pub remaining_releases: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicUtilityObligation {
    pub action: ActionCode,
    pub deadline_slot: u64,
    pub audience_class: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicNetworkState {
    pub congestion_class: u8,
    pub connected: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdaptiveSelectionContext {
    pub transcript_hash: TranscriptHash,
    pub budget: PublicBudgetState,
    pub utility: PublicUtilityObligation,
    pub network: PublicNetworkState,
    pub public_context_hash: PublicContextHash,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertifiedMechanismChoice {
    pub mechanism_hash: MechanismHash,
    pub profile_epoch: u64,
}

pub trait PublicMechanismSelector {
    fn select(&self, context: AdaptiveSelectionContext) -> CertifiedMechanismChoice;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SemanticsError {
    ZeroHash,
    InvalidReleaseWindow,
    EpochRollback,
    SlotRollback,
    EmptyCoalition,
    CoalitionNotCanonical,
    ResourceLimit,
    ActionQuotientMismatch,
    ModelVersionMismatch,
    AuthorizedActionMismatch,
    PublicPolicyMismatch,
    PublicContextMismatch,
}

const fn all_zero(bytes: &[u8; 32]) -> bool {
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

fn ensure_monotone_epochs(epochs: impl Iterator<Item = PublicEpoch>) -> Result<(), SemanticsError> {
    let mut previous = None;
    for epoch in epochs {
        if previous.is_some_and(|value: PublicEpoch| epoch < value) {
            return Err(SemanticsError::EpochRollback);
        }
        previous = Some(epoch);
    }
    Ok(())
}

fn ensure_monotone_slots(slots: impl Iterator<Item = u64>) -> Result<(), SemanticsError> {
    let mut previous = None;
    for slot in slots {
        if previous.is_some_and(|value| slot < value) {
            return Err(SemanticsError::SlotRollback);
        }
        previous = Some(slot);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn bytes(value: u8) -> [u8; 32] {
        [value; 32]
    }

    fn view(action: u8, transcript: u8, policy: u8, context: u8) -> PublicActionView {
        PublicActionView {
            action_quotient_hash: ActionQuotientHash::new(bytes(action)).unwrap(),
            action_transcript_hash: TranscriptHash::new(bytes(transcript)).unwrap(),
            policy_hash: PolicyHash::new(bytes(policy)).unwrap(),
            public_context_hash: PublicContextHash::new(bytes(context)).unwrap(),
            model_version: SecretModelVersion(3),
        }
    }

    fn family() -> ActionQuotientSecretPairFamily {
        ActionQuotientSecretPairFamily {
            family_hash: SecretFamilyHash::new(bytes(9)).unwrap(),
            action_quotient_hash: ActionQuotientHash::new(bytes(1)).unwrap(),
            model_version: SecretModelVersion(3),
            observer_scope: ObserverScope::Network,
            secret_family: SecretFamily::PrivateTiming,
        }
    }

    #[test]
    fn matching_public_action_views_are_certified() {
        let left = view(1, 2, 3, 4);
        let right = view(1, 2, 3, 4);
        let witness = certify_action_equivalent(left, right, family()).unwrap();
        assert_eq!(witness.action_quotient_hash, family().action_quotient_hash);
    }

    #[test]
    fn action_policy_context_and_model_mismatches_are_rejected() {
        let base = view(1, 2, 3, 4);
        let cases = [
            (view(1, 8, 3, 4), SemanticsError::AuthorizedActionMismatch),
            (view(1, 2, 8, 4), SemanticsError::PublicPolicyMismatch),
            (view(1, 2, 3, 8), SemanticsError::PublicContextMismatch),
        ];
        for (other, expected) in cases {
            assert_eq!(
                certify_action_equivalent(base, other, family()),
                Err(expected)
            );
        }
        let mut old_model = base;
        old_model.model_version = SecretModelVersion(2);
        assert_eq!(
            certify_action_equivalent(base, old_model, family()),
            Err(SemanticsError::ModelVersionMismatch)
        );
    }

    #[test]
    fn quotient_mismatch_is_not_action_equivalence() {
        assert_eq!(
            certify_action_equivalent(view(1, 2, 3, 4), view(7, 2, 3, 4), family()),
            Err(SemanticsError::ActionQuotientMismatch)
        );
    }

    #[test]
    fn coalition_is_nonempty_sorted_unique_and_bounded() {
        let hash = CoalitionHash::new(bytes(5)).unwrap();
        let coalition = ObserverCoalition::new(vec![ObserverId(1), ObserverId(4)], hash).unwrap();
        assert_eq!(coalition.members(), &[ObserverId(1), ObserverId(4)]);
        assert_eq!(
            ObserverCoalition::new(vec![ObserverId(4), ObserverId(1)], hash),
            Err(SemanticsError::CoalitionNotCanonical)
        );
        assert_eq!(
            ObserverCoalition::new(vec![ObserverId(1), ObserverId(1)], hash),
            Err(SemanticsError::CoalitionNotCanonical)
        );
        assert_eq!(
            ObserverCoalition::new(vec![], hash),
            Err(SemanticsError::EmptyCoalition)
        );
    }

    #[test]
    fn public_transcripts_reject_epoch_and_slot_rollback() {
        let policy = PolicyHash::new(bytes(3)).unwrap();
        let actions = AuthorizedActionTranscript::new(vec![
            AuthorizedActionEvent {
                public_epoch: PublicEpoch(2),
                service: ServiceBinding(1),
                action: ActionCode(7),
                public_window: PublicReleaseWindow::new(1, 2).unwrap(),
                policy_hash: policy,
            },
            AuthorizedActionEvent {
                public_epoch: PublicEpoch(1),
                service: ServiceBinding(1),
                action: ActionCode(7),
                public_window: PublicReleaseWindow::new(3, 4).unwrap(),
                policy_hash: policy,
            },
        ]);
        assert_eq!(actions, Err(SemanticsError::EpochRollback));

        let releases = ObservableReleaseTranscript::new(vec![
            ObservableReleaseSegment {
                public_epoch: PublicEpoch(1),
                slot: 4,
                service: ServiceBinding(1),
                kind: ObservableKind::Token,
                size_class: 2,
                public_status: 0,
            },
            ObservableReleaseSegment {
                public_epoch: PublicEpoch(1),
                slot: 3,
                service: ServiceBinding(1),
                kind: ObservableKind::Silence,
                size_class: 0,
                public_status: 0,
            },
        ]);
        assert_eq!(releases, Err(SemanticsError::SlotRollback));
    }

    #[test]
    fn zero_hash_and_invalid_window_are_rejected() {
        assert_eq!(PolicyHash::new([0; 32]), Err(SemanticsError::ZeroHash));
        assert_eq!(
            PublicReleaseWindow::new(9, 8),
            Err(SemanticsError::InvalidReleaseWindow)
        );
    }
}
