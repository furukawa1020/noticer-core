#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{format, vec::Vec};
use quotient_limit_rational::{Rational, RationalError};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PolicyKey {
    pub public_state: u32,
    pub quotient: u16,
    pub public_input: u16,
    pub fault_input: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReleaseDecision {
    pub symbol: u16,
    pub next_public_state: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WeightedDecision {
    pub decision: ReleaseDecision,
    pub probability: Rational,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InformationSetPolicy {
    pub key: PolicyKey,
    pub distribution: Vec<WeightedDecision>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedPolicySet {
    pub model_digest: [u8; 32],
    pub certificate_model_digest: [u8; 32],
    pub matrix_digest: [u8; 32],
    pub optimality_gap: Rational,
    pub policies: Vec<InformationSetPolicy>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CodegenLimits {
    pub maximum_denominator: u64,
    pub maximum_draws: u32,
    pub maximum_policies: usize,
    pub maximum_decisions_per_policy: usize,
}

impl Default for CodegenLimits {
    fn default() -> Self {
        Self {
            maximum_denominator: 1 << 32,
            maximum_draws: 128,
            maximum_policies: 65_536,
            maximum_decisions_per_policy: 1_024,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SamplingEntry {
    pub cumulative_exclusive: u64,
    pub decision: ReleaseDecision,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SamplingTable {
    pub denominator: u64,
    pub entries: Vec<SamplingEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledPolicy {
    pub key: PolicyKey,
    pub table: SamplingTable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledMechanism {
    pub model_digest: [u8; 32],
    pub matrix_digest: [u8; 32],
    pub policies: Vec<CompiledPolicy>,
    pub maximum_draws: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuotientInput(pub u16);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicInput(pub u16);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FaultInput(pub u16);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseOutput {
    Decision {
        symbol: u16,
        public_state: u32,
        random_draws: u32,
    },
    FailClosed {
        public_state: u32,
        random_draws: u32,
    },
}

pub trait RandomSource {
    fn next_u64(&mut self) -> Option<u64>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OptimalReleaseMachine<R: RandomSource> {
    state: u32,
    random: R,
    mechanism: CompiledMechanism,
    total_random_draws: u64,
}

impl<R: RandomSource> OptimalReleaseMachine<R> {
    pub fn new(initial_state: u32, random: R, mechanism: CompiledMechanism) -> Self {
        Self {
            state: initial_state,
            random,
            mechanism,
            total_random_draws: 0,
        }
    }

    pub fn public_state(&self) -> u32 {
        self.state
    }

    pub fn total_random_draws(&self) -> u64 {
        self.total_random_draws
    }

    pub fn step(
        &mut self,
        quotient: QuotientInput,
        public: PublicInput,
        fault: FaultInput,
    ) -> ReleaseOutput {
        let key = PolicyKey {
            public_state: self.state,
            quotient: quotient.0,
            public_input: public.0,
            fault_input: fault.0,
        };
        let Some(policy) = self
            .mechanism
            .policies
            .iter()
            .find(|policy| policy.key == key)
        else {
            return ReleaseOutput::FailClosed {
                public_state: self.state,
                random_draws: 0,
            };
        };
        let result = sample_table(
            &mut self.random,
            &policy.table,
            self.mechanism.maximum_draws,
        );
        self.total_random_draws = self
            .total_random_draws
            .saturating_add(u64::from(result.draws));
        let Some(decision) = result.decision else {
            return ReleaseOutput::FailClosed {
                public_state: self.state,
                random_draws: result.draws,
            };
        };
        self.state = decision.next_public_state;
        ReleaseOutput::Decision {
            symbol: decision.symbol,
            public_state: self.state,
            random_draws: result.draws,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SampleResult {
    pub decision: Option<ReleaseDecision>,
    pub draws: u32,
}

pub fn sample_table<R: RandomSource>(
    random: &mut R,
    table: &SamplingTable,
    maximum_draws: u32,
) -> SampleResult {
    if validate_table(table).is_err() || maximum_draws == 0 {
        return SampleResult {
            decision: None,
            draws: 0,
        };
    }
    let threshold = table.denominator.wrapping_neg() % table.denominator;
    for draw in 1..=maximum_draws {
        let Some(value) = random.next_u64() else {
            return SampleResult {
                decision: None,
                draws: draw - 1,
            };
        };
        if value < threshold {
            continue;
        }
        let ticket = value % table.denominator;
        let decision = table
            .entries
            .iter()
            .find(|entry| ticket < entry.cumulative_exclusive)
            .map(|entry| entry.decision);
        return SampleResult {
            decision,
            draws: draw,
        };
    }
    SampleResult {
        decision: None,
        draws: maximum_draws,
    }
}

pub fn compile_certified_mechanism(
    source: &CertifiedPolicySet,
    limits: CodegenLimits,
) -> Result<CompiledMechanism, CodegenError> {
    if source.model_digest != source.certificate_model_digest {
        return Err(CodegenError::CertificateModelMismatch);
    }
    if source.optimality_gap != Rational::ZERO {
        return Err(CodegenError::NonZeroOptimalityGap);
    }
    if source.policies.is_empty() || source.policies.len() > limits.maximum_policies {
        return Err(CodegenError::PolicyLimit);
    }
    let mut policies = Vec::with_capacity(source.policies.len());
    let mut previous = None;
    for policy in &source.policies {
        if previous.is_some_and(|key| key >= policy.key) {
            return Err(CodegenError::NonCanonicalPolicyOrder);
        }
        if policy.distribution.is_empty()
            || policy.distribution.len() > limits.maximum_decisions_per_policy
        {
            return Err(CodegenError::DecisionLimit);
        }
        policies.push(CompiledPolicy {
            key: policy.key,
            table: compile_distribution(&policy.distribution, limits.maximum_denominator)?,
        });
        previous = Some(policy.key);
    }
    Ok(CompiledMechanism {
        model_digest: source.model_digest,
        matrix_digest: source.matrix_digest,
        policies,
        maximum_draws: limits.maximum_draws,
    })
}

pub fn compile_distribution(
    distribution: &[WeightedDecision],
    maximum_denominator: u64,
) -> Result<SamplingTable, CodegenError> {
    if distribution.is_empty() {
        return Err(CodegenError::EmptyDistribution);
    }
    let mut common = 1_u128;
    for weighted in distribution {
        if weighted.probability.is_negative() || weighted.probability == Rational::ZERO {
            return Err(CodegenError::NonPositiveProbability);
        }
        let denominator = u128::try_from(weighted.probability.denominator())
            .map_err(|_| CodegenError::DenominatorOverflow)?;
        common = checked_lcm(common, denominator)?;
        if common > u128::from(maximum_denominator) {
            return Err(CodegenError::DenominatorLimit);
        }
    }
    let denominator = u64::try_from(common).map_err(|_| CodegenError::DenominatorOverflow)?;
    let mut cumulative = 0_u128;
    let mut entries = Vec::with_capacity(distribution.len());
    for weighted in distribution {
        let numerator = u128::try_from(weighted.probability.numerator())
            .map_err(|_| CodegenError::NonPositiveProbability)?;
        let factor = common
            / u128::try_from(weighted.probability.denominator())
                .map_err(|_| CodegenError::DenominatorOverflow)?;
        let weight = numerator
            .checked_mul(factor)
            .ok_or(CodegenError::DenominatorOverflow)?;
        cumulative = cumulative
            .checked_add(weight)
            .ok_or(CodegenError::DenominatorOverflow)?;
        entries.push(SamplingEntry {
            cumulative_exclusive: u64::try_from(cumulative)
                .map_err(|_| CodegenError::DenominatorOverflow)?,
            decision: weighted.decision,
        });
    }
    if cumulative != common {
        return Err(CodegenError::DistributionNotNormalized);
    }
    let table = SamplingTable {
        denominator,
        entries,
    };
    validate_table(&table)?;
    Ok(table)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SamplerCost {
    pub expected_draws: Rational,
    pub expected_random_bits: Rational,
    pub worst_case_draws: u32,
    pub rejection_probability: Rational,
}

pub fn sampler_cost(denominator: u64, maximum_draws: u32) -> Result<SamplerCost, CodegenError> {
    if denominator == 0 || maximum_draws == 0 {
        return Err(CodegenError::InvalidSamplerBound);
    }
    let sample_space = 1_i128 << 64;
    let rejected = i128::from(denominator.wrapping_neg() % denominator);
    let accepted = sample_space
        .checked_sub(rejected)
        .ok_or(CodegenError::Arithmetic)?;
    let expected_draws = Rational::new(sample_space, accepted)?;
    Ok(SamplerCost {
        expected_draws,
        expected_random_bits: expected_draws.checked_mul(Rational::new(64, 1)?)?,
        worst_case_draws: maximum_draws,
        rejection_probability: Rational::new(rejected, sample_space)?,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneratedFile {
    pub path: &'static str,
    pub contents: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneratedBundle {
    pub files: Vec<GeneratedFile>,
}

pub fn emit_generated_bundle(mechanism: &CompiledMechanism, certificate: &[u8]) -> GeneratedBundle {
    let manifest = format!(
        "{{\"format\":\"quotient-limit-generated-v1\",\"policies\":{},\"maximum_draws\":{}}}\n",
        mechanism.policies.len(),
        mechanism.maximum_draws
    );
    let distributions = format!(
        "{{\"policy_count\":{},\"exact_rational\":true}}\n",
        mechanism.policies.len()
    );
    GeneratedBundle {
        files: alloc::vec![
            file("Cargo.toml", b"[package]\nname = \"generated-release-machine\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"),
            file("src/lib.rs", b"#![no_std]\n#![forbid(unsafe_code)]\npub mod policy;\npub mod sampler;\npub mod tables;\n"),
            file("src/policy.rs", b"// Generated public policy dispatch.\n"),
            file("src/sampler.rs", b"// Generated bias-free rejection sampler.\n"),
            file("src/tables.rs", b"// Generated exact cumulative tables.\n"),
            GeneratedFile { path: "certificate.qlc", contents: certificate.to_vec() },
            GeneratedFile { path: "exact_distribution.json", contents: distributions.into_bytes() },
            file("test_vectors.tsv", b"policy\trandom\toutput\tnext_state\tdraws\n"),
            GeneratedFile { path: "manifest.json", contents: manifest.into_bytes() },
        ],
    }
}

fn file(path: &'static str, contents: &[u8]) -> GeneratedFile {
    GeneratedFile {
        path,
        contents: contents.to_vec(),
    }
}

fn validate_table(table: &SamplingTable) -> Result<(), CodegenError> {
    if table.denominator == 0 || table.entries.is_empty() {
        return Err(CodegenError::InvalidSamplingTable);
    }
    let mut prior = 0;
    for entry in &table.entries {
        if entry.cumulative_exclusive <= prior || entry.cumulative_exclusive > table.denominator {
            return Err(CodegenError::InvalidSamplingTable);
        }
        prior = entry.cumulative_exclusive;
    }
    if prior != table.denominator {
        return Err(CodegenError::InvalidSamplingTable);
    }
    Ok(())
}

fn checked_lcm(left: u128, right: u128) -> Result<u128, CodegenError> {
    let gcd = gcd(left, right);
    (left / gcd)
        .checked_mul(right)
        .ok_or(CodegenError::DenominatorOverflow)
}

fn gcd(mut left: u128, mut right: u128) -> u128 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CodegenError {
    CertificateModelMismatch,
    NonZeroOptimalityGap,
    PolicyLimit,
    DecisionLimit,
    NonCanonicalPolicyOrder,
    EmptyDistribution,
    NonPositiveProbability,
    DistributionNotNormalized,
    DenominatorLimit,
    DenominatorOverflow,
    InvalidSamplingTable,
    InvalidSamplerBound,
    Arithmetic,
    Rational(RationalError),
}

impl From<RationalError> for CodegenError {
    fn from(value: RationalError) -> Self {
        Self::Rational(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn r(numerator: i128, denominator: i128) -> Rational {
        Rational::new(numerator, denominator).unwrap()
    }

    fn decision(symbol: u16, state: u32, probability: Rational) -> WeightedDecision {
        WeightedDecision {
            decision: ReleaseDecision {
                symbol,
                next_public_state: state,
            },
            probability,
        }
    }

    #[derive(Clone, Debug)]
    struct ScriptedRandom {
        values: Vec<u64>,
        position: usize,
    }

    impl RandomSource for ScriptedRandom {
        fn next_u64(&mut self) -> Option<u64> {
            let value = self.values.get(self.position).copied();
            self.position += usize::from(value.is_some());
            value
        }
    }

    #[test]
    fn compiles_exact_rational_distribution() {
        let table =
            compile_distribution(&[decision(7, 1, r(1, 3)), decision(9, 2, r(2, 3))], 100).unwrap();
        assert_eq!(table.denominator, 3);
        assert_eq!(table.entries[0].cumulative_exclusive, 1);
        assert_eq!(table.entries[1].cumulative_exclusive, 3);
    }

    #[test]
    fn rejection_sampling_has_no_modulo_bias_and_records_draws() {
        let table =
            compile_distribution(&[decision(7, 1, r(1, 3)), decision(9, 2, r(2, 3))], 100).unwrap();
        let mut random = ScriptedRandom {
            values: vec![0, 1],
            position: 0,
        };
        let result = sample_table(&mut random, &table, 4);
        assert_eq!(
            result.decision,
            Some(ReleaseDecision {
                symbol: 9,
                next_public_state: 2
            })
        );
        assert_eq!(result.draws, 2);
    }

    #[test]
    fn runtime_has_only_public_inputs_and_fails_closed() {
        let digest = [3; 32];
        let source = CertifiedPolicySet {
            model_digest: digest,
            certificate_model_digest: digest,
            matrix_digest: [4; 32],
            optimality_gap: Rational::ZERO,
            policies: vec![InformationSetPolicy {
                key: PolicyKey {
                    public_state: 0,
                    quotient: 1,
                    public_input: 2,
                    fault_input: 3,
                },
                distribution: vec![decision(8, 1, Rational::ONE)],
            }],
        };
        let mechanism = compile_certified_mechanism(&source, CodegenLimits::default()).unwrap();
        let mut machine = OptimalReleaseMachine::new(
            0,
            ScriptedRandom {
                values: vec![5],
                position: 0,
            },
            mechanism,
        );
        assert_eq!(
            machine.step(QuotientInput(1), PublicInput(2), FaultInput(3)),
            ReleaseOutput::Decision {
                symbol: 8,
                public_state: 1,
                random_draws: 1
            }
        );
        assert_eq!(
            machine.step(QuotientInput(1), PublicInput(2), FaultInput(3)),
            ReleaseOutput::FailClosed {
                public_state: 1,
                random_draws: 0
            }
        );
    }

    #[test]
    fn rejects_unbound_or_nonoptimal_certificate() {
        let mut source = CertifiedPolicySet {
            model_digest: [1; 32],
            certificate_model_digest: [2; 32],
            matrix_digest: [3; 32],
            optimality_gap: Rational::ZERO,
            policies: vec![InformationSetPolicy {
                key: PolicyKey {
                    public_state: 0,
                    quotient: 0,
                    public_input: 0,
                    fault_input: 0,
                },
                distribution: vec![decision(0, 0, Rational::ONE)],
            }],
        };
        assert_eq!(
            compile_certified_mechanism(&source, CodegenLimits::default()),
            Err(CodegenError::CertificateModelMismatch)
        );
        source.certificate_model_digest = source.model_digest;
        source.optimality_gap = r(1, 10);
        assert_eq!(
            compile_certified_mechanism(&source, CodegenLimits::default()),
            Err(CodegenError::NonZeroOptimalityGap)
        );
    }

    #[test]
    fn reports_sampler_cost_and_complete_bundle() {
        let cost = sampler_cost(3, 128).unwrap();
        assert_eq!(cost.worst_case_draws, 128);
        assert_eq!(cost.rejection_probability, r(1, 1_i128 << 64));
        let mechanism = CompiledMechanism {
            model_digest: [1; 32],
            matrix_digest: [2; 32],
            policies: vec![],
            maximum_draws: 128,
        };
        let bundle = emit_generated_bundle(&mechanism, b"certificate");
        assert_eq!(bundle.files.len(), 9);
        assert!(bundle.files.iter().any(|file| file.path == "manifest.json"));
        assert!(bundle
            .files
            .iter()
            .all(|file| !file.path.contains("private")));
    }
}
