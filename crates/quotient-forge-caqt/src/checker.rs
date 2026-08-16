use alloc::collections::{BTreeSet, VecDeque};
use alloc::vec;
use alloc::vec::Vec;

use crate::format::{
    Certificate, CertificateLimits, CostVector, Digest, DomainHashes, HashDomain, ObserverRecord,
    OutputRecord, ParseError, RelationPair, TransitionRecord, Writer, FORMAT_VERSION,
};
use crate::sha256::sha256;

const CONTRACT: &[u8] = b"CAQT-v1|total-transition-table|unordered-state-pair-relation|observer-presence-payload-actions|utility-authorized-required-exactly-once|recoverable-fault-required-action|cost=states,emitting-transitions,payload-bytes,action-emissions|reachable-states-and-outputs";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpectedContract {
    pub version: u16,
    pub hashes: DomainHashes,
    pub state_bound: u32,
    pub max_cost: CostVector,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationReport {
    pub certificate_digest: Digest,
    pub cost: CostVector,
    pub states: u32,
    pub transitions: usize,
    pub relation_pairs: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IncompatibleReason {
    Magic,
    Version { expected: u16, actual: u16 },
    CheckerContract,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalViolation {
    EmptyStateDomain,
    EmptyInputDomain,
    ObserverCount,
    ObserverOrder { index: usize, id: u32 },
    OutputOrder { index: usize, id: u32 },
    TransitionCount,
    TransitionOrder { index: usize },
    TransitionTarget { index: usize },
    OutputReference { index: usize },
    SilentOutputCarriesData { output: u32 },
    ActionOrder { output: u32 },
    AuthorizedActionOrder { transition: usize },
    ReservedAction { record: usize },
    EmptyRelation,
    RelationOrder { index: usize },
    RelationPair { index: usize },
    UnreferencedOutput { output: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UtilityViolation {
    UnauthorizedAction {
        state: u32,
        input: u32,
        action: u32,
    },
    DuplicateAction {
        state: u32,
        input: u32,
        action: u32,
    },
    RequiredActionCount {
        state: u32,
        input: u32,
        action: u32,
        actual: usize,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InvalidReason {
    Parse(ParseError),
    NonCanonical(CanonicalViolation),
    HashMismatch(HashDomain),
    StateBound {
        states: u32,
        certificate_bound: u32,
        expected_bound: u32,
    },
    CostMismatch {
        claimed: CostVector,
        recomputed: CostVector,
    },
    CostBudget {
        recomputed: CostVector,
        maximum: CostVector,
    },
    ObserverDivergence {
        left: u32,
        right: u32,
        input: u32,
        observer: u32,
    },
    RelationNotClosed {
        left: u32,
        right: u32,
        input: u32,
        next_left: u32,
        next_right: u32,
    },
    Utility(UtilityViolation),
    RecoverableFault {
        state: u32,
        input: u32,
        action: u32,
        actual: usize,
    },
    UnreachableState {
        state: u32,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CertificateVerdict {
    Valid(ValidationReport),
    Invalid(InvalidReason),
    Incompatible(IncompatibleReason),
}

impl CertificateVerdict {
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Valid(_) => "VALID",
            Self::Invalid(_) => "INVALID",
            Self::Incompatible(_) => "INCOMPATIBLE",
        }
    }
}

#[must_use]
pub fn verify(
    bytes: &[u8],
    expected: ExpectedContract,
    limits: CertificateLimits,
) -> CertificateVerdict {
    let certificate = match Certificate::decode(bytes, limits) {
        Ok(certificate) => certificate,
        Err(ParseError::BadMagic) => {
            return CertificateVerdict::Incompatible(IncompatibleReason::Magic);
        }
        Err(error) => return CertificateVerdict::Invalid(InvalidReason::Parse(error)),
    };

    if expected.version != FORMAT_VERSION {
        return CertificateVerdict::Incompatible(IncompatibleReason::Version {
            expected: FORMAT_VERSION,
            actual: expected.version,
        });
    }
    if certificate.version != expected.version {
        return CertificateVerdict::Incompatible(IncompatibleReason::Version {
            expected: expected.version,
            actual: certificate.version,
        });
    }
    let local_contract = local_checker_contract_hash();
    if expected.hashes.checker_contract != local_contract
        || certificate.hashes.checker_contract != local_contract
    {
        return CertificateVerdict::Incompatible(IncompatibleReason::CheckerContract);
    }

    if let Err(reason) = validate_canonical(&certificate) {
        return CertificateVerdict::Invalid(InvalidReason::NonCanonical(reason));
    }
    if certificate.state_count > certificate.state_bound
        || certificate.state_bound != expected.state_bound
    {
        return CertificateVerdict::Invalid(InvalidReason::StateBound {
            states: certificate.state_count,
            certificate_bound: certificate.state_bound,
            expected_bound: expected.state_bound,
        });
    }

    let recomputed_hashes = recompute_hashes(&certificate);
    for domain in HashDomain::ALL {
        if certificate.hashes.get(domain) != recomputed_hashes.get(domain)
            || expected.hashes.get(domain) != recomputed_hashes.get(domain)
        {
            return CertificateVerdict::Invalid(InvalidReason::HashMismatch(domain));
        }
    }

    let cost = recompute_cost(&certificate);
    if certificate.claimed_cost != cost {
        return CertificateVerdict::Invalid(InvalidReason::CostMismatch {
            claimed: certificate.claimed_cost,
            recomputed: cost,
        });
    }
    if !cost.componentwise_within(expected.max_cost) {
        return CertificateVerdict::Invalid(InvalidReason::CostBudget {
            recomputed: cost,
            maximum: expected.max_cost,
        });
    }

    if let Some(reason) = check_observers_and_relation(&certificate) {
        return CertificateVerdict::Invalid(reason);
    }
    if let Some(reason) = check_utility_and_faults(&certificate) {
        return CertificateVerdict::Invalid(reason);
    }
    if let Some(state) = first_unreachable_state(&certificate) {
        return CertificateVerdict::Invalid(InvalidReason::UnreachableState { state });
    }

    CertificateVerdict::Valid(ValidationReport {
        certificate_digest: domain_hash(b"certificate", bytes),
        cost,
        states: certificate.state_count,
        transitions: certificate.transitions.len(),
        relation_pairs: certificate.relation.len(),
    })
}

impl Certificate {
    /// Recomputes all derived fields. The resulting hashes still need to be
    /// anchored in an independently obtained `ExpectedContract`.
    pub fn seal(&mut self) {
        self.observer_count = u32::try_from(self.observers.len()).unwrap_or(u32::MAX);
        self.claimed_cost = recompute_cost(self);
        self.hashes = recompute_hashes(self);
    }
}

#[must_use]
pub fn local_checker_contract_hash() -> Digest {
    domain_hash(b"checker-contract", CONTRACT)
}

#[must_use]
pub fn recompute_cost(certificate: &Certificate) -> CostVector {
    let mut cost = CostVector {
        states: u64::from(certificate.state_count),
        ..CostVector::default()
    };
    for transition in &certificate.transitions {
        let Some(output) = certificate.outputs.get(usize_index(transition.output)) else {
            continue;
        };
        cost.emitting_transitions = cost
            .emitting_transitions
            .saturating_add(u64::from(output.emitted));
        cost.payload_bytes = cost
            .payload_bytes
            .saturating_add(u64::try_from(output.payload.len()).unwrap_or(u64::MAX));
        cost.action_emissions = cost
            .action_emissions
            .saturating_add(u64::try_from(output.actions.len()).unwrap_or(u64::MAX));
    }
    cost
}

#[must_use]
pub fn recompute_hashes(certificate: &Certificate) -> DomainHashes {
    let plant = hash_plant(certificate);
    let quotient = hash_quotient(certificate);
    let observer = hash_observer(certificate);
    let utility = hash_utility(certificate);
    let fault = hash_fault(certificate);
    let transducer = hash_transducer(certificate);
    let checker_contract = local_checker_contract_hash();
    let mut spec_bytes = Writer::default();
    spec_bytes.u16(certificate.version);
    for digest in [plant, quotient, observer, utility, fault] {
        spec_bytes.bytes(digest.as_bytes());
    }
    let spec = domain_hash(b"spec", &spec_bytes.finish());
    DomainHashes {
        spec,
        plant,
        quotient,
        observer,
        utility,
        fault,
        transducer,
        checker_contract,
    }
}

fn validate_canonical(certificate: &Certificate) -> Result<(), CanonicalViolation> {
    if certificate.state_count == 0 {
        return Err(CanonicalViolation::EmptyStateDomain);
    }
    if certificate.input_count == 0 {
        return Err(CanonicalViolation::EmptyInputDomain);
    }
    if usize_index(certificate.observer_count) != certificate.observers.len() {
        return Err(CanonicalViolation::ObserverCount);
    }
    for (index, observer) in certificate.observers.iter().enumerate() {
        if usize_index(observer.id) != index {
            return Err(CanonicalViolation::ObserverOrder {
                index,
                id: observer.id,
            });
        }
    }
    for (index, output) in certificate.outputs.iter().enumerate() {
        if usize_index(output.id) != index {
            return Err(CanonicalViolation::OutputOrder {
                index,
                id: output.id,
            });
        }
        if !output.emitted && (!output.payload.is_empty() || !output.actions.is_empty()) {
            return Err(CanonicalViolation::SilentOutputCarriesData { output: output.id });
        }
        if !is_non_decreasing(&output.actions) {
            return Err(CanonicalViolation::ActionOrder { output: output.id });
        }
        if output.actions.contains(&u32::MAX) {
            return Err(CanonicalViolation::ReservedAction { record: index });
        }
    }

    let expected_transitions = usize_index(certificate.state_count)
        .checked_mul(usize_index(certificate.input_count))
        .ok_or(CanonicalViolation::TransitionCount)?;
    if certificate.transitions.len() != expected_transitions {
        return Err(CanonicalViolation::TransitionCount);
    }
    let mut referenced_outputs = vec![false; certificate.outputs.len()];
    for (index, transition) in certificate.transitions.iter().enumerate() {
        let expected_from =
            u32::try_from(index / usize_index(certificate.input_count)).unwrap_or(u32::MAX);
        let expected_input =
            u32::try_from(index % usize_index(certificate.input_count)).unwrap_or(u32::MAX);
        if transition.from != expected_from || transition.input != expected_input {
            return Err(CanonicalViolation::TransitionOrder { index });
        }
        if transition.to >= certificate.state_count {
            return Err(CanonicalViolation::TransitionTarget { index });
        }
        let output_index = usize_index(transition.output);
        let Some(referenced) = referenced_outputs.get_mut(output_index) else {
            return Err(CanonicalViolation::OutputReference { index });
        };
        *referenced = true;
        if !is_strictly_increasing(&transition.authorized_actions) {
            return Err(CanonicalViolation::AuthorizedActionOrder { transition: index });
        }
        if transition.authorized_actions.contains(&u32::MAX)
            || transition.required_action == Some(u32::MAX)
            || transition.recoverable_fault_action == Some(u32::MAX)
        {
            return Err(CanonicalViolation::ReservedAction { record: index });
        }
    }
    if let Some(output) = referenced_outputs.iter().position(|referenced| !referenced) {
        return Err(CanonicalViolation::UnreferencedOutput {
            output: u32::try_from(output).unwrap_or(u32::MAX),
        });
    }

    if certificate.relation.is_empty() {
        return Err(CanonicalViolation::EmptyRelation);
    }
    let mut previous = None;
    for (index, pair) in certificate.relation.iter().copied().enumerate() {
        if pair.left >= pair.right || pair.right >= certificate.state_count {
            return Err(CanonicalViolation::RelationPair { index });
        }
        if previous.is_some_and(|prior| prior >= pair) {
            return Err(CanonicalViolation::RelationOrder { index });
        }
        previous = Some(pair);
    }
    Ok(())
}

fn check_observers_and_relation(certificate: &Certificate) -> Option<InvalidReason> {
    let relation: BTreeSet<_> = certificate.relation.iter().copied().collect();
    for pair in &certificate.relation {
        for input in 0..certificate.input_count {
            let left_transition = transition(certificate, pair.left, input);
            let right_transition = transition(certificate, pair.right, input);
            let left_output = &certificate.outputs[usize_index(left_transition.output)];
            let right_output = &certificate.outputs[usize_index(right_transition.output)];
            for observer in &certificate.observers {
                if !observer_equal(observer, left_output, right_output) {
                    return Some(InvalidReason::ObserverDivergence {
                        left: pair.left,
                        right: pair.right,
                        input,
                        observer: observer.id,
                    });
                }
            }

            if left_transition.to != right_transition.to {
                let next = ordered_pair(left_transition.to, right_transition.to);
                if !relation.contains(&next) {
                    return Some(InvalidReason::RelationNotClosed {
                        left: pair.left,
                        right: pair.right,
                        input,
                        next_left: next.left,
                        next_right: next.right,
                    });
                }
            }
        }
    }
    None
}

fn check_utility_and_faults(certificate: &Certificate) -> Option<InvalidReason> {
    for transition in &certificate.transitions {
        let output = &certificate.outputs[usize_index(transition.output)];
        for window in output.actions.windows(2) {
            if window[0] == window[1] {
                return Some(InvalidReason::Utility(UtilityViolation::DuplicateAction {
                    state: transition.from,
                    input: transition.input,
                    action: window[0],
                }));
            }
        }
        for action in &output.actions {
            if transition.authorized_actions.binary_search(action).is_err() {
                return Some(InvalidReason::Utility(
                    UtilityViolation::UnauthorizedAction {
                        state: transition.from,
                        input: transition.input,
                        action: *action,
                    },
                ));
            }
        }
        if let Some(required) = transition.required_action {
            let actual = output
                .actions
                .iter()
                .filter(|action| **action == required)
                .count();
            if actual != 1 {
                return Some(InvalidReason::Utility(
                    UtilityViolation::RequiredActionCount {
                        state: transition.from,
                        input: transition.input,
                        action: required,
                        actual,
                    },
                ));
            }
        }
        if let Some(recovery) = transition.recoverable_fault_action {
            let actual = output
                .actions
                .iter()
                .filter(|action| **action == recovery)
                .count();
            if actual != 1 {
                return Some(InvalidReason::RecoverableFault {
                    state: transition.from,
                    input: transition.input,
                    action: recovery,
                    actual,
                });
            }
        }
    }
    None
}

fn first_unreachable_state(certificate: &Certificate) -> Option<u32> {
    let mut reachable = vec![false; usize_index(certificate.state_count)];
    reachable[0] = true;
    let mut queue = VecDeque::from([0_u32]);
    while let Some(state) = queue.pop_front() {
        for input in 0..certificate.input_count {
            let next = transition(certificate, state, input).to;
            if !reachable[usize_index(next)] {
                reachable[usize_index(next)] = true;
                queue.push_back(next);
            }
        }
    }
    reachable
        .iter()
        .position(|is_reachable| !is_reachable)
        .map(|state| u32::try_from(state).unwrap_or(u32::MAX))
}

fn transition(certificate: &Certificate, state: u32, input: u32) -> &TransitionRecord {
    let index = usize_index(state) * usize_index(certificate.input_count) + usize_index(input);
    &certificate.transitions[index]
}

fn observer_equal(observer: &ObserverRecord, left: &OutputRecord, right: &OutputRecord) -> bool {
    (!observer.sees_presence || left.emitted == right.emitted)
        && (!observer.sees_payload || left.payload == right.payload)
        && (!observer.sees_actions || left.actions == right.actions)
}

const fn ordered_pair(left: u32, right: u32) -> RelationPair {
    if left < right {
        RelationPair { left, right }
    } else {
        RelationPair {
            left: right,
            right: left,
        }
    }
}

fn is_non_decreasing(values: &[u32]) -> bool {
    values.windows(2).all(|window| window[0] <= window[1])
}

fn is_strictly_increasing(values: &[u32]) -> bool {
    values.windows(2).all(|window| window[0] < window[1])
}

fn usize_index(value: u32) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

fn hash_plant(certificate: &Certificate) -> Digest {
    let mut writer = domain_writer(certificate);
    writer.u32(certificate.state_count);
    writer.u32(certificate.input_count);
    for transition in &certificate.transitions {
        writer.u32(transition.from);
        writer.u32(transition.input);
        writer.u32(transition.to);
    }
    domain_hash(b"plant", &writer.finish())
}

fn hash_quotient(certificate: &Certificate) -> Digest {
    let mut writer = domain_writer(certificate);
    writer.u32(u32::try_from(certificate.relation.len()).unwrap_or(u32::MAX));
    for pair in &certificate.relation {
        writer.u32(pair.left);
        writer.u32(pair.right);
    }
    domain_hash(b"quotient", &writer.finish())
}

fn hash_observer(certificate: &Certificate) -> Digest {
    let mut writer = domain_writer(certificate);
    writer.u32(certificate.observer_count);
    for observer in &certificate.observers {
        writer.u32(observer.id);
        writer.bool(observer.sees_presence);
        writer.bool(observer.sees_payload);
        writer.bool(observer.sees_actions);
    }
    domain_hash(b"observer", &writer.finish())
}

fn hash_utility(certificate: &Certificate) -> Digest {
    let mut writer = domain_writer(certificate);
    for transition in &certificate.transitions {
        writer.u32(transition.from);
        writer.u32(transition.input);
        writer.u32(u32::try_from(transition.authorized_actions.len()).unwrap_or(u32::MAX));
        for action in &transition.authorized_actions {
            writer.u32(*action);
        }
        writer.optional_u32(transition.required_action);
    }
    domain_hash(b"utility", &writer.finish())
}

fn hash_fault(certificate: &Certificate) -> Digest {
    let mut writer = domain_writer(certificate);
    for transition in &certificate.transitions {
        writer.u32(transition.from);
        writer.u32(transition.input);
        writer.optional_u32(transition.recoverable_fault_action);
    }
    domain_hash(b"fault", &writer.finish())
}

fn hash_transducer(certificate: &Certificate) -> Digest {
    let mut writer = domain_writer(certificate);
    writer.u32(certificate.state_count);
    writer.u32(certificate.input_count);
    writer.u32(u32::try_from(certificate.outputs.len()).unwrap_or(u32::MAX));
    for output in &certificate.outputs {
        writer.u32(output.id);
        writer.bool(output.emitted);
        writer.length_prefixed(&output.payload);
        writer.u32(u32::try_from(output.actions.len()).unwrap_or(u32::MAX));
        for action in &output.actions {
            writer.u32(*action);
        }
    }
    for transition in &certificate.transitions {
        writer.u32(transition.from);
        writer.u32(transition.input);
        writer.u32(transition.to);
        writer.u32(transition.output);
    }
    domain_hash(b"transducer", &writer.finish())
}

fn domain_writer(certificate: &Certificate) -> Writer {
    let mut writer = Writer::default();
    writer.u16(certificate.version);
    writer
}

fn domain_hash(domain: &[u8], payload: &[u8]) -> Digest {
    let mut preimage = Vec::with_capacity(16 + domain.len() + payload.len());
    preimage.extend_from_slice(b"CAQT-DOMAIN\0");
    preimage.push(u8::try_from(domain.len()).unwrap_or(u8::MAX));
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(payload);
    Digest::new(sha256(&preimage))
}
