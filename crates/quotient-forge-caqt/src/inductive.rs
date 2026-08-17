use alloc::collections::{BTreeSet, VecDeque};
use alloc::vec::Vec;

use crate::checker::{
    verify, CertificateVerdict, ExpectedContract, IncompatibleReason, InvalidReason,
    ValidationReport,
};
use crate::format::{
    Certificate, CertificateLimits, Digest, DomainHashes, HashDomain, ParseError, RelationPair,
};
use crate::sha256::sha256;

pub const INDUCTIVE_FORMAT_VERSION: u16 = 1;
const MAGIC: [u8; 4] = *b"CAQI";
const NO_PAIR_INDEX: u32 = u32::MAX;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ClosureRecord {
    pub pair_index: u32,
    pub input: u32,
    pub next_left: u32,
    pub next_right: u32,
    pub next_pair_index: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InductiveCertificate {
    pub version: u16,
    pub bound_hashes: DomainHashes,
    pub base_digest: Digest,
    pub base_certificate: Vec<u8>,
    pub initial_pairs: Vec<RelationPair>,
    pub invariant: Vec<RelationPair>,
    pub closure: Vec<ClosureRecord>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InductiveLimits {
    pub max_bytes: usize,
    pub max_base_bytes: usize,
    pub max_product_states: usize,
    pub max_closure_records: usize,
    pub base_limits: CertificateLimits,
}

impl Default for InductiveLimits {
    fn default() -> Self {
        Self {
            max_bytes: 16 * 1024 * 1024,
            max_base_bytes: 8 * 1024 * 1024,
            max_product_states: 1_000_000,
            max_closure_records: 4_000_000,
            base_limits: CertificateLimits::default(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedInductiveContract {
    pub base: ExpectedContract,
    pub initial_pairs: Vec<RelationPair>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InductiveValidationReport {
    pub certificate_digest: Digest,
    pub certificate_bytes: usize,
    pub initial_pairs: usize,
    pub product_states: usize,
    pub closure_records: usize,
    pub check_work_units: usize,
    pub base: ValidationReport,
}

#[cfg(feature = "std")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimedInductiveVerification {
    pub verdict: InductiveVerdict,
    pub certificate_bytes: usize,
    pub elapsed: core::time::Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InductiveResourceBound {
    CertificateBytes { actual: usize, limit: usize },
    BaseCertificateBytes { actual: usize, limit: usize },
    ProductStates { actual: usize, limit: usize },
    ClosureRecords { actual: usize, limit: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InductiveParseError {
    BadMagic,
    UnexpectedEof { offset: usize },
    TrailingData { offset: usize, remaining: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InductiveDecodeError {
    Parse(InductiveParseError),
    ResourceBound(InductiveResourceBound),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InductiveCanonicalViolation {
    EmptyInitialSet,
    InitialPair { index: usize },
    InitialOrder { index: usize },
    EmptyInvariant,
    InvariantPair { index: usize },
    InvariantOrder { index: usize },
    InitialNotIncluded { index: usize },
    ClosureCount,
    ClosureOrder { index: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InductiveBuildError {
    EmptyInitialSet,
    InvalidInitialPair { index: usize },
    MalformedTransitionTable,
    TransitionTarget { state: u32, input: u32 },
    InitialOutsideBaseRelation { pair: RelationPair },
    SuccessorOutsideBaseRelation { pair: RelationPair, input: u32 },
    RecordCountOverflow,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InductiveInvalidReason {
    Parse(InductiveParseError),
    Base(InvalidReason),
    BaseDigest,
    BoundHashes,
    InitialContractMismatch,
    NonCanonical(InductiveCanonicalViolation),
    InvariantOutsideBaseRelation { pair_index: u32 },
    ClosureSuccessor { pair_index: u32, input: u32 },
    ClosurePairReference { pair_index: u32, input: u32 },
    UnreachableInvariantPair { pair_index: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InductiveIncompatibleReason {
    Magic,
    Version { expected: u16, actual: u16 },
    Base(IncompatibleReason),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InductiveVerdict {
    Valid(InductiveValidationReport),
    Invalid(InductiveInvalidReason),
    Incompatible(InductiveIncompatibleReason),
    ResourceBound(InductiveResourceBound),
}

impl InductiveVerdict {
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Valid(_) => "VALID",
            Self::Invalid(_) => "INVALID",
            Self::Incompatible(_) => "INCOMPATIBLE",
            Self::ResourceBound(_) => "RESOURCE_BOUND",
        }
    }
}

impl InductiveCertificate {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::default();
        writer.bytes(&MAGIC);
        writer.u16(self.version);
        for domain in HashDomain::ALL {
            writer.bytes(self.bound_hashes.get(domain).as_bytes());
        }
        writer.bytes(self.base_digest.as_bytes());
        writer.length_prefixed(&self.base_certificate);
        writer.u32(length_u32(self.initial_pairs.len()));
        writer.u32(length_u32(self.invariant.len()));
        writer.u32(length_u32(self.closure.len()));
        for pair in &self.initial_pairs {
            writer.pair(*pair);
        }
        for pair in &self.invariant {
            writer.pair(*pair);
        }
        for record in &self.closure {
            writer.u32(record.pair_index);
            writer.u32(record.input);
            writer.u32(record.next_left);
            writer.u32(record.next_right);
            writer.u32(record.next_pair_index.unwrap_or(NO_PAIR_INDEX));
        }
        writer.finish()
    }

    pub fn decode(bytes: &[u8], limits: InductiveLimits) -> Result<Self, InductiveDecodeError> {
        if bytes.len() > limits.max_bytes {
            return Err(InductiveDecodeError::ResourceBound(
                InductiveResourceBound::CertificateBytes {
                    actual: bytes.len(),
                    limit: limits.max_bytes,
                },
            ));
        }
        let mut reader = Reader::new(bytes);
        if reader.array::<4>()? != MAGIC {
            return Err(InductiveDecodeError::Parse(InductiveParseError::BadMagic));
        }
        let version = reader.u16()?;
        let bound_hashes = DomainHashes {
            spec: reader.digest()?,
            plant: reader.digest()?,
            quotient: reader.digest()?,
            observer: reader.digest()?,
            utility: reader.digest()?,
            fault: reader.digest()?,
            transducer: reader.digest()?,
            checker_contract: reader.digest()?,
        };
        let base_digest = reader.digest()?;
        let base_length = reader.count()?;
        if base_length > limits.max_base_bytes {
            return Err(InductiveDecodeError::ResourceBound(
                InductiveResourceBound::BaseCertificateBytes {
                    actual: base_length,
                    limit: limits.max_base_bytes,
                },
            ));
        }
        let base_certificate = reader.slice(base_length)?.to_vec();
        let initial_count = reader.count()?;
        let invariant_count = reader.count()?;
        let closure_count = reader.count()?;
        for count in [initial_count, invariant_count] {
            if count > limits.max_product_states {
                return Err(InductiveDecodeError::ResourceBound(
                    InductiveResourceBound::ProductStates {
                        actual: count,
                        limit: limits.max_product_states,
                    },
                ));
            }
        }
        if closure_count > limits.max_closure_records {
            return Err(InductiveDecodeError::ResourceBound(
                InductiveResourceBound::ClosureRecords {
                    actual: closure_count,
                    limit: limits.max_closure_records,
                },
            ));
        }
        let mut initial_pairs = Vec::with_capacity(initial_count);
        for _ in 0..initial_count {
            initial_pairs.push(reader.pair()?);
        }
        let mut invariant = Vec::with_capacity(invariant_count);
        for _ in 0..invariant_count {
            invariant.push(reader.pair()?);
        }
        let mut closure = Vec::with_capacity(closure_count);
        for _ in 0..closure_count {
            let pair_index = reader.u32()?;
            let input = reader.u32()?;
            let next_left = reader.u32()?;
            let next_right = reader.u32()?;
            let encoded_index = reader.u32()?;
            closure.push(ClosureRecord {
                pair_index,
                input,
                next_left,
                next_right,
                next_pair_index: (encoded_index != NO_PAIR_INDEX).then_some(encoded_index),
            });
        }
        reader.finish()?;
        Ok(Self {
            version,
            bound_hashes,
            base_digest,
            base_certificate,
            initial_pairs,
            invariant,
            closure,
        })
    }
}

pub fn build_inductive_certificate(
    base: &Certificate,
    mut initial_pairs: Vec<RelationPair>,
) -> Result<InductiveCertificate, InductiveBuildError> {
    if initial_pairs.is_empty() {
        return Err(InductiveBuildError::EmptyInitialSet);
    }
    initial_pairs.sort_unstable();
    initial_pairs.dedup();
    for (index, pair) in initial_pairs.iter().copied().enumerate() {
        if !valid_pair(pair, base.state_count) {
            return Err(InductiveBuildError::InvalidInitialPair { index });
        }
    }
    let transition_count = usize_index(base.state_count)
        .checked_mul(usize_index(base.input_count))
        .ok_or(InductiveBuildError::MalformedTransitionTable)?;
    if base.state_count == 0 || base.input_count == 0 || base.transitions.len() != transition_count
    {
        return Err(InductiveBuildError::MalformedTransitionTable);
    }
    let base_relation: BTreeSet<_> = base.relation.iter().copied().collect();
    for pair in &initial_pairs {
        if !base_relation.contains(pair) {
            return Err(InductiveBuildError::InitialOutsideBaseRelation { pair: *pair });
        }
    }

    let mut reached: BTreeSet<RelationPair> = initial_pairs.iter().copied().collect();
    let mut queue: VecDeque<RelationPair> = initial_pairs.iter().copied().collect();
    while let Some(pair) = queue.pop_front() {
        for input in 0..base.input_count {
            let left = transition_target(base, pair.left, input)?;
            let right = transition_target(base, pair.right, input)?;
            if left == right {
                continue;
            }
            let successor = ordered_pair(left, right);
            if !base_relation.contains(&successor) {
                return Err(InductiveBuildError::SuccessorOutsideBaseRelation { pair, input });
            }
            if reached.insert(successor) {
                queue.push_back(successor);
            }
        }
    }
    let invariant: Vec<_> = reached.into_iter().collect();
    let closure_count = invariant
        .len()
        .checked_mul(usize_index(base.input_count))
        .ok_or(InductiveBuildError::RecordCountOverflow)?;
    let mut closure = Vec::with_capacity(closure_count);
    for (pair_index, pair) in invariant.iter().copied().enumerate() {
        for input in 0..base.input_count {
            let left = transition_target(base, pair.left, input)?;
            let right = transition_target(base, pair.right, input)?;
            let next_pair_index = if left == right {
                None
            } else {
                let successor = ordered_pair(left, right);
                let index = invariant.binary_search(&successor).map_err(|_| {
                    InductiveBuildError::SuccessorOutsideBaseRelation { pair, input }
                })?;
                Some(u32::try_from(index).map_err(|_| InductiveBuildError::RecordCountOverflow)?)
            };
            closure.push(ClosureRecord {
                pair_index: u32::try_from(pair_index)
                    .map_err(|_| InductiveBuildError::RecordCountOverflow)?,
                input,
                next_left: left,
                next_right: right,
                next_pair_index,
            });
        }
    }
    let base_certificate = base.encode();
    Ok(InductiveCertificate {
        version: INDUCTIVE_FORMAT_VERSION,
        bound_hashes: base.hashes,
        base_digest: domain_digest(b"base-caqt", &base_certificate),
        base_certificate,
        initial_pairs,
        invariant,
        closure,
    })
}

#[must_use]
pub fn verify_inductive(
    bytes: &[u8],
    expected: &ExpectedInductiveContract,
    limits: InductiveLimits,
) -> InductiveVerdict {
    let certificate = match InductiveCertificate::decode(bytes, limits) {
        Ok(certificate) => certificate,
        Err(InductiveDecodeError::Parse(InductiveParseError::BadMagic)) => {
            return InductiveVerdict::Incompatible(InductiveIncompatibleReason::Magic);
        }
        Err(InductiveDecodeError::Parse(error)) => {
            return InductiveVerdict::Invalid(InductiveInvalidReason::Parse(error));
        }
        Err(InductiveDecodeError::ResourceBound(reason)) => {
            return InductiveVerdict::ResourceBound(reason);
        }
    };
    if certificate.version != INDUCTIVE_FORMAT_VERSION {
        return InductiveVerdict::Incompatible(InductiveIncompatibleReason::Version {
            expected: INDUCTIVE_FORMAT_VERSION,
            actual: certificate.version,
        });
    }
    if certificate.bound_hashes != expected.base.hashes {
        return InductiveVerdict::Invalid(InductiveInvalidReason::BoundHashes);
    }
    if certificate.base_digest != domain_digest(b"base-caqt", &certificate.base_certificate) {
        return InductiveVerdict::Invalid(InductiveInvalidReason::BaseDigest);
    }

    let base_report = match verify(
        &certificate.base_certificate,
        expected.base,
        limits.base_limits,
    ) {
        CertificateVerdict::Valid(report) => report,
        CertificateVerdict::Invalid(reason) => {
            return InductiveVerdict::Invalid(InductiveInvalidReason::Base(reason));
        }
        CertificateVerdict::Incompatible(reason) => {
            return InductiveVerdict::Incompatible(InductiveIncompatibleReason::Base(reason));
        }
    };
    let base = match Certificate::decode(&certificate.base_certificate, limits.base_limits) {
        Ok(base) => base,
        Err(error) => {
            return InductiveVerdict::Invalid(InductiveInvalidReason::Base(InvalidReason::Parse(
                error,
            )));
        }
    };
    if base.hashes != certificate.bound_hashes {
        return InductiveVerdict::Invalid(InductiveInvalidReason::BoundHashes);
    }
    if let Err(reason) = validate_canonical(&certificate, base.state_count, base.input_count) {
        return InductiveVerdict::Invalid(InductiveInvalidReason::NonCanonical(reason));
    }
    if certificate.initial_pairs != expected.initial_pairs {
        return InductiveVerdict::Invalid(InductiveInvalidReason::InitialContractMismatch);
    }
    for (index, pair) in certificate.invariant.iter().enumerate() {
        if base.relation.binary_search(pair).is_err() {
            return InductiveVerdict::Invalid(
                InductiveInvalidReason::InvariantOutsideBaseRelation {
                    pair_index: u32::try_from(index).unwrap_or(u32::MAX),
                },
            );
        }
    }
    if let Some(reason) = check_closure(&certificate, &base) {
        return InductiveVerdict::Invalid(reason);
    }
    if let Some(pair_index) = first_unreachable_pair(&certificate, base.input_count) {
        return InductiveVerdict::Invalid(InductiveInvalidReason::UnreachableInvariantPair {
            pair_index,
        });
    }

    let work = certificate
        .initial_pairs
        .len()
        .saturating_add(certificate.invariant.len())
        .saturating_add(certificate.closure.len());
    InductiveVerdict::Valid(InductiveValidationReport {
        certificate_digest: domain_digest(b"inductive-certificate", bytes),
        certificate_bytes: bytes.len(),
        initial_pairs: certificate.initial_pairs.len(),
        product_states: certificate.invariant.len(),
        closure_records: certificate.closure.len(),
        check_work_units: work,
        base: base_report,
    })
}

#[cfg(feature = "std")]
#[must_use]
pub fn verify_inductive_timed(
    bytes: &[u8],
    expected: &ExpectedInductiveContract,
    limits: InductiveLimits,
) -> TimedInductiveVerification {
    let started = std::time::Instant::now();
    let verdict = verify_inductive(bytes, expected, limits);
    TimedInductiveVerification {
        verdict,
        certificate_bytes: bytes.len(),
        elapsed: started.elapsed(),
    }
}

fn validate_canonical(
    certificate: &InductiveCertificate,
    state_count: u32,
    input_count: u32,
) -> Result<(), InductiveCanonicalViolation> {
    if certificate.initial_pairs.is_empty() {
        return Err(InductiveCanonicalViolation::EmptyInitialSet);
    }
    validate_pair_sequence(&certificate.initial_pairs, state_count, true)?;
    if certificate.invariant.is_empty() {
        return Err(InductiveCanonicalViolation::EmptyInvariant);
    }
    validate_pair_sequence(&certificate.invariant, state_count, false)?;
    for (index, pair) in certificate.initial_pairs.iter().enumerate() {
        if certificate.invariant.binary_search(pair).is_err() {
            return Err(InductiveCanonicalViolation::InitialNotIncluded { index });
        }
    }
    let expected_closure = certificate
        .invariant
        .len()
        .checked_mul(usize_index(input_count))
        .ok_or(InductiveCanonicalViolation::ClosureCount)?;
    if certificate.closure.len() != expected_closure {
        return Err(InductiveCanonicalViolation::ClosureCount);
    }
    for (index, record) in certificate.closure.iter().enumerate() {
        let expected_pair = index / usize_index(input_count);
        let expected_input = index % usize_index(input_count);
        if usize_index(record.pair_index) != expected_pair
            || usize_index(record.input) != expected_input
        {
            return Err(InductiveCanonicalViolation::ClosureOrder { index });
        }
    }
    Ok(())
}

fn validate_pair_sequence(
    pairs: &[RelationPair],
    state_count: u32,
    initial: bool,
) -> Result<(), InductiveCanonicalViolation> {
    let mut previous = None;
    for (index, pair) in pairs.iter().copied().enumerate() {
        if !valid_pair(pair, state_count) {
            return Err(if initial {
                InductiveCanonicalViolation::InitialPair { index }
            } else {
                InductiveCanonicalViolation::InvariantPair { index }
            });
        }
        if previous.is_some_and(|prior| prior >= pair) {
            return Err(if initial {
                InductiveCanonicalViolation::InitialOrder { index }
            } else {
                InductiveCanonicalViolation::InvariantOrder { index }
            });
        }
        previous = Some(pair);
    }
    Ok(())
}

fn check_closure(
    certificate: &InductiveCertificate,
    base: &Certificate,
) -> Option<InductiveInvalidReason> {
    for record in &certificate.closure {
        let pair = certificate.invariant[usize_index(record.pair_index)];
        let left = transition_target(base, pair.left, record.input).ok()?;
        let right = transition_target(base, pair.right, record.input).ok()?;
        if record.next_left != left || record.next_right != right {
            return Some(InductiveInvalidReason::ClosureSuccessor {
                pair_index: record.pair_index,
                input: record.input,
            });
        }
        if left == right {
            if record.next_pair_index.is_some() {
                return Some(InductiveInvalidReason::ClosurePairReference {
                    pair_index: record.pair_index,
                    input: record.input,
                });
            }
            continue;
        }
        let successor = ordered_pair(left, right);
        let Ok(expected_index) = certificate.invariant.binary_search(&successor) else {
            return Some(InductiveInvalidReason::ClosurePairReference {
                pair_index: record.pair_index,
                input: record.input,
            });
        };
        if record.next_pair_index != u32::try_from(expected_index).ok() {
            return Some(InductiveInvalidReason::ClosurePairReference {
                pair_index: record.pair_index,
                input: record.input,
            });
        }
    }
    None
}

fn first_unreachable_pair(certificate: &InductiveCertificate, input_count: u32) -> Option<u32> {
    let mut reached = alloc::vec![false; certificate.invariant.len()];
    let mut queue = VecDeque::new();
    for pair in &certificate.initial_pairs {
        let index = certificate.invariant.binary_search(pair).ok()?;
        if !reached[index] {
            reached[index] = true;
            queue.push_back(index);
        }
    }
    while let Some(pair_index) = queue.pop_front() {
        for input in 0..input_count {
            let closure_index = pair_index
                .checked_mul(usize_index(input_count))?
                .checked_add(usize_index(input))?;
            let record = certificate.closure.get(closure_index)?;
            let Some(next) = record.next_pair_index.map(usize_index) else {
                continue;
            };
            if next >= reached.len() {
                return Some(u32::try_from(pair_index).unwrap_or(u32::MAX));
            }
            if !reached[next] {
                reached[next] = true;
                queue.push_back(next);
            }
        }
    }
    reached
        .iter()
        .position(|value| !value)
        .map(|index| u32::try_from(index).unwrap_or(u32::MAX))
}

fn transition_target(
    certificate: &Certificate,
    state: u32,
    input: u32,
) -> Result<u32, InductiveBuildError> {
    let index = usize_index(state)
        .checked_mul(usize_index(certificate.input_count))
        .and_then(|base| base.checked_add(usize_index(input)))
        .ok_or(InductiveBuildError::MalformedTransitionTable)?;
    let target = certificate
        .transitions
        .get(index)
        .ok_or(InductiveBuildError::MalformedTransitionTable)?
        .to;
    if target >= certificate.state_count {
        Err(InductiveBuildError::TransitionTarget { state, input })
    } else {
        Ok(target)
    }
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

const fn valid_pair(pair: RelationPair, state_count: u32) -> bool {
    pair.left < pair.right && pair.right < state_count
}

fn domain_digest(domain: &[u8], payload: &[u8]) -> Digest {
    let mut preimage = Vec::with_capacity(16 + domain.len() + payload.len());
    preimage.extend_from_slice(b"CAQI-DOMAIN\0");
    preimage.push(u8::try_from(domain.len()).unwrap_or(u8::MAX));
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(payload);
    Digest::new(sha256(&preimage))
}

const fn length_u32(length: usize) -> u32 {
    if length > u32::MAX as usize {
        u32::MAX
    } else {
        length as u32
    }
}

fn usize_index(value: u32) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

#[derive(Default)]
struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn bytes(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    fn length_prefixed(&mut self, value: &[u8]) {
        self.u32(length_u32(value.len()));
        self.bytes(value);
    }

    fn pair(&mut self, pair: RelationPair) {
        self.u32(pair.left);
        self.u32(pair.right);
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn array<const LENGTH: usize>(&mut self) -> Result<[u8; LENGTH], InductiveDecodeError> {
        let end = self.position.checked_add(LENGTH).ok_or({
            InductiveDecodeError::Parse(InductiveParseError::UnexpectedEof {
                offset: self.position,
            })
        })?;
        let slice = self.bytes.get(self.position..end).ok_or({
            InductiveDecodeError::Parse(InductiveParseError::UnexpectedEof {
                offset: self.position,
            })
        })?;
        let mut result = [0; LENGTH];
        result.copy_from_slice(slice);
        self.position = end;
        Ok(result)
    }

    fn u16(&mut self) -> Result<u16, InductiveDecodeError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, InductiveDecodeError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn count(&mut self) -> Result<usize, InductiveDecodeError> {
        Ok(usize::try_from(self.u32()?).unwrap_or(usize::MAX))
    }

    fn digest(&mut self) -> Result<Digest, InductiveDecodeError> {
        Ok(Digest::new(self.array()?))
    }

    fn pair(&mut self) -> Result<RelationPair, InductiveDecodeError> {
        Ok(RelationPair {
            left: self.u32()?,
            right: self.u32()?,
        })
    }

    fn slice(&mut self, length: usize) -> Result<&'a [u8], InductiveDecodeError> {
        let end = self.position.checked_add(length).ok_or({
            InductiveDecodeError::Parse(InductiveParseError::UnexpectedEof {
                offset: self.position,
            })
        })?;
        let result = self.bytes.get(self.position..end).ok_or({
            InductiveDecodeError::Parse(InductiveParseError::UnexpectedEof {
                offset: self.position,
            })
        })?;
        self.position = end;
        Ok(result)
    }

    fn finish(self) -> Result<(), InductiveDecodeError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(InductiveDecodeError::Parse(
                InductiveParseError::TrailingData {
                    offset: self.position,
                    remaining: self.bytes.len() - self.position,
                },
            ))
        }
    }
}

impl From<InductiveParseError> for InductiveDecodeError {
    fn from(error: InductiveParseError) -> Self {
        Self::Parse(error)
    }
}

impl From<ParseError> for InductiveInvalidReason {
    fn from(error: ParseError) -> Self {
        Self::Base(InvalidReason::Parse(error))
    }
}
