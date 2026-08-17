use std::collections::{BTreeSet, VecDeque};

use quotient_forge_caqt::{
    artifact_digest, verify_inductive, Certificate, ExpectedInductiveContract,
    InductiveCertificate, InductiveLimits, InductiveVerdict, RelationPair,
};
use quotient_forge_codegen::{
    validate_translation, TargetKind, TranslationLimits, TranslationTranscript, TranslationVerdict,
};
use quotient_seal_small_step::{
    CheckerMemoryPatch, CheckerSeed, ExecutionEvent, HostDirective, HostOutcome, InterpreterLimits,
    MachineStatus, MemoryAccessKind, PublicHostTape, ResourceExhaustion, Value, WasmMachine,
};
use quotient_seal_target_ir::{
    target_ir_hash, CanonicalTargetIr, ConsensusVerdict as ParserConsensusVerdict,
};

use crate::certificate::{
    GlobalPredicate, MemoryPredicate, RelationCertificate, RelationDecodeError, RelationLimits,
    RelationRecord,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelationValidationLimits {
    pub relation: RelationLimits,
    pub inductive: InductiveLimits,
    pub translation: TranslationLimits,
    pub interpreter: InterpreterLimits,
    pub max_cases: usize,
    pub max_events_per_case: usize,
}

impl Default for RelationValidationLimits {
    fn default() -> Self {
        Self {
            relation: RelationLimits::default(),
            inductive: InductiveLimits::default(),
            translation: TranslationLimits::default(),
            interpreter: InterpreterLimits::default(),
            max_cases: 4_000_000,
            max_events_per_case: 1_000_000,
        }
    }
}

pub struct RelationValidationInput<'a> {
    pub relation_bytes: &'a [u8],
    pub inductive_bytes: &'a [u8],
    pub expected_inductive: &'a ExpectedInductiveContract,
    pub k7_reference: &'a TranslationTranscript,
    pub k7_observed: &'a TranslationTranscript,
    pub parser_consensus: ParserConsensusVerdict,
    pub target_ir: &'a CanonicalTargetIr,
    pub limits: RelationValidationLimits,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DivergenceKind {
    RelationCertificate,
    Binding,
    K7Translation,
    InductiveCertificate,
    ParserRejected,
    ReachableCoverage,
    ExtraRelationRecord,
    AxisProduct,
    EntryPc,
    EntryGlobal,
    EntryMemory,
    TargetInstantiation,
    TargetTrap,
    TargetTermination,
    TargetResourceBound,
    TargetResult,
    HostCallCount,
    HostCallKind,
    HostArguments,
    OutputPresence,
    Payload,
    UnauthorizedAction,
    DuplicateAction,
    MissingRequiredAction,
    MissingRecoveryAction,
    ActionOrder,
    UnknownFailure,
    ExtraMemoryWrite,
    ExitPc,
    NextGlobal,
    NextMemory,
    Reset,
    Handoff,
    Status,
    ObserverTrace,
    ContextCoupling,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationCounterexample {
    pub kind: DivergenceKind,
    pub source_state: Option<u32>,
    pub flat_input: Option<u32>,
    pub pair_left: Option<u32>,
    pub pair_right: Option<u32>,
    pub event_index: Option<u32>,
    pub expected: u64,
    pub actual: u64,
}

impl RelationCounterexample {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(48);
        bytes.extend_from_slice(b"QSCE");
        bytes.extend_from_slice(&(self.kind as u16).to_le_bytes());
        encode_optional_u32(&mut bytes, self.source_state);
        encode_optional_u32(&mut bytes, self.flat_input);
        encode_optional_u32(&mut bytes, self.pair_left);
        encode_optional_u32(&mut bytes, self.pair_right);
        encode_optional_u32(&mut bytes, self.event_index);
        bytes.extend_from_slice(&self.expected.to_le_bytes());
        bytes.extend_from_slice(&self.actual.to_le_bytes());
        bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelationIncompatible {
    RelationMagic,
    RelationVersion(u16),
    K7Translation,
    InductiveCertificate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelationResourceBound {
    RelationCertificate(RelationDecodeError),
    K7Translation,
    InductiveCertificate,
    SourceCases { actual: usize, limit: usize },
    TargetEvents { actual: usize, limit: usize },
    TargetExecution(ResourceExhaustion),
    ArithmeticOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelationUnresolved {
    ParserConsensus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationValidationReport {
    pub relation_digest: quotient_forge_caqt::Digest,
    pub inductive_digest: quotient_forge_caqt::Digest,
    pub target_ir_digest: quotient_forge_caqt::Digest,
    pub reachable_states: usize,
    pub checked_source_steps: usize,
    pub checked_lifecycle_calls: usize,
    pub checked_two_run_cases: usize,
    pub checked_observer_events: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelationVerdict {
    Valid(Box<RelationValidationReport>),
    Invalid(RelationCounterexample),
    Incompatible(RelationIncompatible),
    ResourceBound(RelationResourceBound),
    Unresolved(RelationUnresolved),
}

struct Checker<'a> {
    input: RelationValidationInput<'a>,
    relation: RelationCertificate,
    inductive: InductiveCertificate,
    base: Certificate,
    cases: usize,
    source_steps: usize,
    lifecycle_calls: usize,
    two_run_cases: usize,
    observer_events: usize,
}

struct CaseExecution {
    events: Vec<ExecutionEvent>,
    status: MachineStatus,
    globals: Vec<Value>,
    memory: Vec<u8>,
    pc: quotient_seal_small_step::ProgramCounter,
    consumed_host: usize,
}

pub fn validate_relation(input: RelationValidationInput<'_>) -> RelationVerdict {
    let target_digest = target_ir_hash(input.target_ir);
    match input.parser_consensus {
        ParserConsensusVerdict::Valid(digest) if digest == target_digest => {}
        ParserConsensusVerdict::Valid(_) | ParserConsensusVerdict::Invalid => {
            return RelationVerdict::Invalid(counterexample(
                DivergenceKind::ParserRejected,
                None,
                None,
            ));
        }
        ParserConsensusVerdict::ResourceBound => {
            return RelationVerdict::ResourceBound(RelationResourceBound::SourceCases {
                actual: 1,
                limit: 0,
            });
        }
        ParserConsensusVerdict::Unresolved => {
            return RelationVerdict::Unresolved(RelationUnresolved::ParserConsensus);
        }
    }

    let translation_report = match validate_translation(
        input.k7_reference,
        input.k7_observed,
        input.limits.translation,
    ) {
        TranslationVerdict::Valid(report) if report.target == TargetKind::Wasm32UnknownUnknown => {
            report
        }
        TranslationVerdict::Valid(_) | TranslationVerdict::Mismatch(_) => {
            return RelationVerdict::Invalid(counterexample(
                DivergenceKind::K7Translation,
                None,
                None,
            ));
        }
        TranslationVerdict::Incompatible(_) => {
            return RelationVerdict::Incompatible(RelationIncompatible::K7Translation);
        }
        TranslationVerdict::ResourceBound(_) => {
            return RelationVerdict::ResourceBound(RelationResourceBound::K7Translation);
        }
    };

    let inductive_report = match verify_inductive(
        input.inductive_bytes,
        input.expected_inductive,
        input.limits.inductive,
    ) {
        InductiveVerdict::Valid(report) => report,
        InductiveVerdict::Invalid(_) => {
            return RelationVerdict::Invalid(counterexample(
                DivergenceKind::InductiveCertificate,
                None,
                None,
            ));
        }
        InductiveVerdict::Incompatible(_) => {
            return RelationVerdict::Incompatible(RelationIncompatible::InductiveCertificate);
        }
        InductiveVerdict::ResourceBound(_) => {
            return RelationVerdict::ResourceBound(RelationResourceBound::InductiveCertificate);
        }
    };
    let inductive =
        match InductiveCertificate::decode(input.inductive_bytes, input.limits.inductive) {
            Ok(certificate) => certificate,
            Err(_) => {
                return RelationVerdict::Invalid(counterexample(
                    DivergenceKind::InductiveCertificate,
                    None,
                    None,
                ));
            }
        };
    let base = match Certificate::decode(
        &inductive.base_certificate,
        input.limits.inductive.base_limits,
    ) {
        Ok(certificate) => certificate,
        Err(_) => {
            return RelationVerdict::Invalid(counterexample(
                DivergenceKind::InductiveCertificate,
                None,
                None,
            ));
        }
    };
    let relation = match RelationCertificate::decode(input.relation_bytes, input.limits.relation) {
        Ok(certificate) => certificate,
        Err(RelationDecodeError::BadMagic) => {
            return RelationVerdict::Incompatible(RelationIncompatible::RelationMagic);
        }
        Err(RelationDecodeError::UnsupportedVersion { actual }) => {
            return RelationVerdict::Incompatible(RelationIncompatible::RelationVersion(actual));
        }
        Err(
            error @ (RelationDecodeError::SizeLimit { .. }
            | RelationDecodeError::RecordLimit { .. }
            | RelationDecodeError::PcLimit { .. }
            | RelationDecodeError::GlobalLimit { .. }
            | RelationDecodeError::MemoryPredicateLimit { .. }
            | RelationDecodeError::WriteRangeLimit { .. }
            | RelationDecodeError::PredicateBytesLimit { .. }),
        ) => {
            return RelationVerdict::ResourceBound(RelationResourceBound::RelationCertificate(
                error,
            ));
        }
        Err(_) => {
            return RelationVerdict::Invalid(counterexample(
                DivergenceKind::RelationCertificate,
                None,
                None,
            ));
        }
    };

    if relation.inductive_digest != inductive_report.certificate_digest
        || relation.target_ir_digest != target_digest
        || relation.k7_manifest_digest != translation_report.manifest_digest
    {
        return RelationVerdict::Invalid(counterexample(DivergenceKind::Binding, None, None));
    }
    let axis_product = u32::from(relation.quotient_inputs)
        .checked_mul(u32::from(relation.public_inputs))
        .and_then(|value| value.checked_mul(u32::from(relation.fault_inputs)));
    if axis_product != Some(base.input_count) {
        return RelationVerdict::Invalid(counterexample(DivergenceKind::AxisProduct, None, None));
    }

    let relation_digest = artifact_digest(
        b"noticer-core/quotient-seal/relation-certificate/v1",
        input.relation_bytes,
    );
    let mut checker = Checker {
        input,
        relation,
        inductive,
        base,
        cases: 0,
        source_steps: 0,
        lifecycle_calls: 0,
        two_run_cases: 0,
        observer_events: 0,
    };
    match checker.check_all() {
        Ok(reachable_states) => RelationVerdict::Valid(Box::new(RelationValidationReport {
            relation_digest,
            inductive_digest: inductive_report.certificate_digest,
            target_ir_digest: target_digest,
            reachable_states,
            checked_source_steps: checker.source_steps,
            checked_lifecycle_calls: checker.lifecycle_calls,
            checked_two_run_cases: checker.two_run_cases,
            checked_observer_events: checker.observer_events,
        })),
        Err(verdict) => verdict,
    }
}

impl Checker<'_> {
    fn check_all(&mut self) -> Result<usize, RelationVerdict> {
        let transitions = self.transition_table()?;
        let reachable = self.reachable_states(&transitions)?;
        self.check_coverage(&reachable)?;

        for state in reachable.iter().copied() {
            let record = self
                .relation
                .record(state)
                .ok_or_else(|| invalid_at(DivergenceKind::ReachableCoverage, state, None))?
                .clone();
            for flat_input in 0..self.base.input_count {
                let transition = transitions
                    [transition_index(state, flat_input, self.base.input_count)?]
                .as_ref()
                .ok_or_else(|| {
                    invalid_at(
                        DivergenceKind::InductiveCertificate,
                        state,
                        Some(flat_input),
                    )
                })?
                .clone();
                let output = self
                    .base
                    .outputs
                    .get(transition.output as usize)
                    .ok_or_else(|| {
                        invalid_at(
                            DivergenceKind::InductiveCertificate,
                            state,
                            Some(flat_input),
                        )
                    })?
                    .clone();
                let next = self
                    .relation
                    .record(transition.to)
                    .ok_or_else(|| {
                        invalid_at(DivergenceKind::ReachableCoverage, state, Some(flat_input))
                    })?
                    .clone();
                let execution = self.execute_tick(&record, flat_input, &output)?;
                self.validate_tick(
                    state,
                    flat_input,
                    &record,
                    &next,
                    &transition,
                    &output,
                    &execution,
                )?;
                self.source_steps += 1;
            }
            self.validate_lifecycle(state, &record)?;
        }
        self.validate_two_run(&transitions)?;
        Ok(reachable.len())
    }

    fn transition_table(
        &self,
    ) -> Result<Vec<Option<quotient_forge_caqt::TransitionRecord>>, RelationVerdict> {
        let count = usize::try_from(self.base.state_count)
            .ok()
            .and_then(|states| {
                usize::try_from(self.base.input_count)
                    .ok()
                    .and_then(|inputs| states.checked_mul(inputs))
            })
            .ok_or(RelationVerdict::ResourceBound(
                RelationResourceBound::ArithmeticOverflow,
            ))?;
        if count > self.input.limits.max_cases {
            return Err(RelationVerdict::ResourceBound(
                RelationResourceBound::SourceCases {
                    actual: count,
                    limit: self.input.limits.max_cases,
                },
            ));
        }
        let mut table = vec![None; count];
        for transition in &self.base.transitions {
            let index = transition_index(transition.from, transition.input, self.base.input_count)?;
            let slot = table.get_mut(index).ok_or_else(|| {
                invalid_at(
                    DivergenceKind::InductiveCertificate,
                    transition.from,
                    Some(transition.input),
                )
            })?;
            if slot.is_some() {
                return Err(invalid_at(
                    DivergenceKind::InductiveCertificate,
                    transition.from,
                    Some(transition.input),
                ));
            }
            *slot = Some(transition.clone());
        }
        Ok(table)
    }

    fn reachable_states(
        &self,
        transitions: &[Option<quotient_forge_caqt::TransitionRecord>],
    ) -> Result<BTreeSet<u32>, RelationVerdict> {
        let mut reachable = BTreeSet::new();
        let mut queue = VecDeque::new();
        reachable.insert(0);
        queue.push_back(0);
        while let Some(state) = queue.pop_front() {
            for input in 0..self.base.input_count {
                let index = transition_index(state, input, self.base.input_count)?;
                let transition =
                    transitions
                        .get(index)
                        .and_then(Option::as_ref)
                        .ok_or_else(|| {
                            invalid_at(DivergenceKind::InductiveCertificate, state, Some(input))
                        })?;
                if reachable.insert(transition.to) {
                    queue.push_back(transition.to);
                }
            }
        }
        Ok(reachable)
    }

    fn check_coverage(&self, reachable: &BTreeSet<u32>) -> Result<(), RelationVerdict> {
        for state in reachable {
            if self.relation.record(*state).is_none() {
                return Err(invalid_at(DivergenceKind::ReachableCoverage, *state, None));
            }
        }
        for record in &self.relation.records {
            if !reachable.contains(&record.source_state) {
                return Err(invalid_at(
                    DivergenceKind::ExtraRelationRecord,
                    record.source_state,
                    None,
                ));
            }
        }
        Ok(())
    }

    fn execute_tick(
        &mut self,
        record: &RelationRecord,
        flat_input: u32,
        output: &quotient_forge_caqt::OutputRecord,
    ) -> Result<CaseExecution, RelationVerdict> {
        let (quotient, public, fault) = unflatten_input(&self.relation, flat_input);
        let arguments = vec![Value::I32(quotient), Value::I32(public), Value::I32(fault)];
        let mut directives = Vec::new();
        if output.emitted {
            directives.push(HostDirective::new("emit_frame", HostOutcome::Continue));
        }
        for _ in &output.actions {
            directives.push(HostDirective::new("emit_action", HostOutcome::Continue));
        }
        self.execute_case(
            record,
            "tick",
            arguments,
            PublicHostTape::new(directives),
            Some(flat_input),
        )
    }

    fn execute_case(
        &mut self,
        record: &RelationRecord,
        export: &str,
        arguments: Vec<Value>,
        tape: PublicHostTape,
        flat_input: Option<u32>,
    ) -> Result<CaseExecution, RelationVerdict> {
        self.cases = self
            .cases
            .checked_add(1)
            .ok_or(RelationVerdict::ResourceBound(
                RelationResourceBound::ArithmeticOverflow,
            ))?;
        if self.cases > self.input.limits.max_cases {
            return Err(RelationVerdict::ResourceBound(
                RelationResourceBound::SourceCases {
                    actual: self.cases,
                    limit: self.input.limits.max_cases,
                },
            ));
        }
        let seed = seed(record);
        let machine = WasmMachine::instantiate_for_checker(
            self.input.target_ir,
            export,
            arguments,
            self.input.limits.interpreter.max_initial_fuel,
            tape,
            self.input.limits.interpreter,
            &seed,
        )
        .map_err(|_| {
            invalid_at(
                DivergenceKind::TargetInstantiation,
                record.source_state,
                flat_input,
            )
        })?;
        validate_entry(machine.state(), record, flat_input)?;
        let report = machine.run();
        let state = report.state();
        if state.events().len() > self.input.limits.max_events_per_case {
            return Err(RelationVerdict::ResourceBound(
                RelationResourceBound::TargetEvents {
                    actual: state.events().len(),
                    limit: self.input.limits.max_events_per_case,
                },
            ));
        }
        self.observer_events = self
            .observer_events
            .checked_add(state.events().len())
            .ok_or(RelationVerdict::ResourceBound(
                RelationResourceBound::ArithmeticOverflow,
            ))?;
        Ok(CaseExecution {
            events: state.events().to_vec(),
            status: state.status().clone(),
            globals: state.globals().to_vec(),
            memory: state.memory().to_vec(),
            pc: state.pc(),
            consumed_host: report.consumed_host_directives(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_tick(
        &self,
        state: u32,
        flat_input: u32,
        current: &RelationRecord,
        next: &RelationRecord,
        transition: &quotient_forge_caqt::TransitionRecord,
        output: &quotient_forge_caqt::OutputRecord,
        execution: &CaseExecution,
    ) -> Result<(), RelationVerdict> {
        validate_returned(execution, state, Some(flat_input))?;
        validate_exit_pc(
            execution,
            current,
            state,
            Some(flat_input),
            DivergenceKind::ExitPc,
        )?;
        validate_host_output(execution, output, transition, state, flat_input)?;
        validate_writes(execution, current, state, Some(flat_input))?;
        validate_final_relation(
            execution,
            next,
            state,
            Some(flat_input),
            DivergenceKind::NextGlobal,
            DivergenceKind::NextMemory,
        )
    }

    fn validate_lifecycle(
        &mut self,
        state: u32,
        record: &RelationRecord,
    ) -> Result<(), RelationVerdict> {
        let zero = self
            .relation
            .record(0)
            .ok_or_else(|| invalid_at(DivergenceKind::ReachableCoverage, state, None))?
            .clone();
        for (export, expected, kind) in [
            ("reset", zero, DivergenceKind::Reset),
            ("handoff", record.clone(), DivergenceKind::Handoff),
            ("status", record.clone(), DivergenceKind::Status),
        ] {
            let execution =
                self.execute_case(record, export, Vec::new(), PublicHostTape::default(), None)?;
            validate_returned(&execution, state, None)
                .map_err(|_| invalid_at(kind, state, None))?;
            if execution
                .events
                .iter()
                .any(|event| matches!(event, ExecutionEvent::HostCall { .. }))
                || execution.consumed_host != 0
            {
                return Err(invalid_at(kind, state, None));
            }
            validate_exit_pc(&execution, record, state, None, kind)?;
            validate_writes(&execution, record, state, None)
                .map_err(|_| invalid_at(kind, state, None))?;
            validate_final_relation(&execution, &expected, state, None, kind, kind)?;
            self.lifecycle_calls += 1;
        }
        Ok(())
    }

    fn validate_two_run(
        &mut self,
        transitions: &[Option<quotient_forge_caqt::TransitionRecord>],
    ) -> Result<(), RelationVerdict> {
        let pairs = self.inductive.invariant.clone();
        for pair in pairs {
            let left_record = self
                .relation
                .record(pair.left)
                .ok_or_else(|| invalid_pair(DivergenceKind::ReachableCoverage, pair, None))?
                .clone();
            let right_record = self
                .relation
                .record(pair.right)
                .ok_or_else(|| invalid_pair(DivergenceKind::ReachableCoverage, pair, None))?
                .clone();
            for flat_input in 0..self.base.input_count {
                let left_transition = transitions
                    [transition_index(pair.left, flat_input, self.base.input_count)?]
                .as_ref()
                .ok_or_else(|| {
                    invalid_pair(DivergenceKind::InductiveCertificate, pair, Some(flat_input))
                })?
                .clone();
                let right_transition = transitions
                    [transition_index(pair.right, flat_input, self.base.input_count)?]
                .as_ref()
                .ok_or_else(|| {
                    invalid_pair(DivergenceKind::InductiveCertificate, pair, Some(flat_input))
                })?
                .clone();
                let left_output = self.base.outputs[left_transition.output as usize].clone();
                let right_output = self.base.outputs[right_transition.output as usize].clone();
                let left = self.execute_tick(&left_record, flat_input, &left_output)?;
                let right = self.execute_tick(&right_record, flat_input, &right_output)?;
                if left.status != right.status || left.events != right.events {
                    let event_index = first_event_difference(&left.events, &right.events);
                    return Err(RelationVerdict::Invalid(RelationCounterexample {
                        kind: DivergenceKind::ObserverTrace,
                        source_state: None,
                        flat_input: Some(flat_input),
                        pair_left: Some(pair.left),
                        pair_right: Some(pair.right),
                        event_index,
                        expected: left.events.len() as u64,
                        actual: right.events.len() as u64,
                    }));
                }
                if left_transition.to != right_transition.to {
                    let successor = RelationPair {
                        left: left_transition.to.min(right_transition.to),
                        right: left_transition.to.max(right_transition.to),
                    };
                    if self.inductive.invariant.binary_search(&successor).is_err() {
                        return Err(invalid_pair(
                            DivergenceKind::ContextCoupling,
                            pair,
                            Some(flat_input),
                        ));
                    }
                }
                self.two_run_cases += 1;
            }
        }
        Ok(())
    }
}

fn validate_entry(
    state: &quotient_seal_small_step::WasmState,
    record: &RelationRecord,
    flat_input: Option<u32>,
) -> Result<(), RelationVerdict> {
    let pc = u32::try_from(state.pc().instruction_index).unwrap_or(u32::MAX);
    if record.entry_pcs.binary_search(&pc).is_err() {
        return Err(invalid_at(
            DivergenceKind::EntryPc,
            record.source_state,
            flat_input,
        ));
    }
    validate_predicates(
        state.globals(),
        state.memory(),
        &record.globals,
        &record.memory,
        record.source_state,
        flat_input,
        DivergenceKind::EntryGlobal,
        DivergenceKind::EntryMemory,
    )
}

fn validate_returned(
    execution: &CaseExecution,
    state: u32,
    flat_input: Option<u32>,
) -> Result<(), RelationVerdict> {
    match &execution.status {
        MachineStatus::Returned(results) if results.is_empty() => Ok(()),
        MachineStatus::Returned(results) => Err(RelationVerdict::Invalid(RelationCounterexample {
            kind: DivergenceKind::TargetResult,
            source_state: Some(state),
            flat_input,
            pair_left: None,
            pair_right: None,
            event_index: None,
            expected: 0,
            actual: results.len() as u64,
        })),
        MachineStatus::Trapped(_) => Err(invalid_at(DivergenceKind::TargetTrap, state, flat_input)),
        MachineStatus::Terminated => Err(invalid_at(
            DivergenceKind::TargetTermination,
            state,
            flat_input,
        )),
        MachineStatus::ResourceBound(resource) => Err(RelationVerdict::ResourceBound(
            RelationResourceBound::TargetExecution(*resource),
        )),
        MachineStatus::Running => Err(invalid_at(
            DivergenceKind::TargetResourceBound,
            state,
            flat_input,
        )),
    }
}

fn validate_exit_pc(
    execution: &CaseExecution,
    record: &RelationRecord,
    state: u32,
    flat_input: Option<u32>,
    kind: DivergenceKind,
) -> Result<(), RelationVerdict> {
    let pc = u32::try_from(execution.pc.instruction_index).unwrap_or(u32::MAX);
    if record.exit_pcs.binary_search(&pc).is_err() {
        Err(invalid_at(kind, state, flat_input))
    } else {
        Ok(())
    }
}

fn validate_host_output(
    execution: &CaseExecution,
    output: &quotient_forge_caqt::OutputRecord,
    transition: &quotient_forge_caqt::TransitionRecord,
    state: u32,
    flat_input: u32,
) -> Result<(), RelationVerdict> {
    let host_calls: Vec<_> = execution
        .events
        .iter()
        .enumerate()
        .filter_map(|(index, event)| match event {
            ExecutionEvent::HostCall {
                import, arguments, ..
            } => Some((index, import.as_str(), arguments.as_slice())),
            _ => None,
        })
        .collect();
    let expected_count = usize::from(output.emitted) + output.actions.len();
    if host_calls.len() != expected_count || execution.consumed_host != expected_count {
        return Err(RelationVerdict::Invalid(RelationCounterexample {
            kind: DivergenceKind::HostCallCount,
            source_state: Some(state),
            flat_input: Some(flat_input),
            pair_left: None,
            pair_right: None,
            event_index: None,
            expected: expected_count as u64,
            actual: host_calls.len() as u64,
        }));
    }
    let mut cursor = 0;
    if output.emitted {
        let (event_index, import, arguments) = host_calls[cursor];
        if import != "emit_frame" {
            return Err(invalid_event(
                DivergenceKind::HostCallKind,
                state,
                flat_input,
                event_index,
            ));
        }
        let [Value::I32(pointer), Value::I32(length)] = arguments else {
            return Err(invalid_event(
                DivergenceKind::HostArguments,
                state,
                flat_input,
                event_index,
            ));
        };
        let start = *pointer as usize;
        let len = *length as usize;
        let end = start.checked_add(len).ok_or_else(|| {
            invalid_event(DivergenceKind::Payload, state, flat_input, event_index)
        })?;
        if execution.memory.get(start..end) != Some(output.payload.as_slice()) {
            return Err(invalid_event(
                DivergenceKind::Payload,
                state,
                flat_input,
                event_index,
            ));
        }
        if execution.events.iter().skip(event_index + 1).any(|event| {
            matches!(
                event,
                ExecutionEvent::Memory {
                    kind: MemoryAccessKind::Store,
                    address,
                    width,
                    ..
                } if ranges_overlap(*address, u64::from(*width), u64::from(*pointer), u64::from(*length))
            )
        }) {
            return Err(invalid_event(
                DivergenceKind::Payload,
                state,
                flat_input,
                event_index,
            ));
        }
        cursor += 1;
    }
    let mut actual_actions = Vec::new();
    for (action_index, expected_action) in output.actions.iter().enumerate() {
        let (event_index, import, arguments) = host_calls[cursor + action_index];
        if import == "public_failure" {
            return Err(invalid_event(
                DivergenceKind::UnknownFailure,
                state,
                flat_input,
                event_index,
            ));
        }
        if import != "emit_action" {
            return Err(invalid_event(
                DivergenceKind::HostCallKind,
                state,
                flat_input,
                event_index,
            ));
        }
        let Some(Value::I32(action)) = arguments.first() else {
            return Err(invalid_event(
                DivergenceKind::HostArguments,
                state,
                flat_input,
                event_index,
            ));
        };
        actual_actions.push(*action);
        if action != expected_action {
            return Err(invalid_event(
                DivergenceKind::ActionOrder,
                state,
                flat_input,
                event_index,
            ));
        }
    }
    let mut unique = BTreeSet::new();
    for action in &actual_actions {
        if !unique.insert(*action) {
            return Err(invalid_at(
                DivergenceKind::DuplicateAction,
                state,
                Some(flat_input),
            ));
        }
        if transition.authorized_actions.binary_search(action).is_err() {
            return Err(invalid_at(
                DivergenceKind::UnauthorizedAction,
                state,
                Some(flat_input),
            ));
        }
    }
    if let Some(required) = transition.required_action {
        if actual_actions
            .iter()
            .filter(|action| **action == required)
            .count()
            != 1
        {
            return Err(invalid_at(
                DivergenceKind::MissingRequiredAction,
                state,
                Some(flat_input),
            ));
        }
    }
    if let Some(recovery) = transition.recoverable_fault_action {
        if actual_actions
            .iter()
            .filter(|action| **action == recovery)
            .count()
            != 1
        {
            return Err(invalid_at(
                DivergenceKind::MissingRecoveryAction,
                state,
                Some(flat_input),
            ));
        }
    }
    Ok(())
}

fn validate_writes(
    execution: &CaseExecution,
    record: &RelationRecord,
    state: u32,
    flat_input: Option<u32>,
) -> Result<(), RelationVerdict> {
    for (event_index, event) in execution.events.iter().enumerate() {
        let ExecutionEvent::Memory {
            kind: MemoryAccessKind::Store,
            address,
            width,
            ..
        } = event
        else {
            continue;
        };
        if !record
            .allowed_writes
            .iter()
            .any(|range| range.contains(*address, *width))
        {
            return Err(RelationVerdict::Invalid(RelationCounterexample {
                kind: DivergenceKind::ExtraMemoryWrite,
                source_state: Some(state),
                flat_input,
                pair_left: None,
                pair_right: None,
                event_index: u32::try_from(event_index).ok(),
                expected: 0,
                actual: *address,
            }));
        }
    }
    Ok(())
}

fn validate_final_relation(
    execution: &CaseExecution,
    expected: &RelationRecord,
    state: u32,
    flat_input: Option<u32>,
    global_kind: DivergenceKind,
    memory_kind: DivergenceKind,
) -> Result<(), RelationVerdict> {
    validate_predicates(
        &execution.globals,
        &execution.memory,
        &expected.globals,
        &expected.memory,
        state,
        flat_input,
        global_kind,
        memory_kind,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_predicates(
    globals: &[Value],
    memory: &[u8],
    expected_globals: &[GlobalPredicate],
    expected_memory: &[MemoryPredicate],
    state: u32,
    flat_input: Option<u32>,
    global_kind: DivergenceKind,
    memory_kind: DivergenceKind,
) -> Result<(), RelationVerdict> {
    for predicate in expected_globals {
        if globals.get(predicate.index as usize) != Some(&predicate.value) {
            return Err(invalid_at(global_kind, state, flat_input));
        }
    }
    for predicate in expected_memory {
        let start = predicate.offset as usize;
        let end = start
            .checked_add(predicate.bytes.len())
            .ok_or_else(|| invalid_at(memory_kind, state, flat_input))?;
        if memory.get(start..end) != Some(predicate.bytes.as_slice()) {
            return Err(invalid_at(memory_kind, state, flat_input));
        }
    }
    Ok(())
}

fn seed(record: &RelationRecord) -> CheckerSeed {
    CheckerSeed {
        globals: record
            .globals
            .iter()
            .map(|predicate| (predicate.index, predicate.value))
            .collect(),
        memory: record
            .memory
            .iter()
            .map(|predicate| CheckerMemoryPatch {
                offset: predicate.offset,
                bytes: predicate.bytes.clone(),
            })
            .collect(),
    }
}

fn transition_index(state: u32, input: u32, input_count: u32) -> Result<usize, RelationVerdict> {
    let index = u64::from(state)
        .checked_mul(u64::from(input_count))
        .and_then(|value| value.checked_add(u64::from(input)))
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(RelationVerdict::ResourceBound(
            RelationResourceBound::ArithmeticOverflow,
        ))?;
    Ok(index)
}

fn unflatten_input(certificate: &RelationCertificate, input: u32) -> (u32, u32, u32) {
    let faults = u32::from(certificate.fault_inputs);
    let publics = u32::from(certificate.public_inputs);
    let fault = input % faults;
    let rest = input / faults;
    let public = rest % publics;
    let quotient = rest / publics;
    (quotient, public, fault)
}

fn first_event_difference(left: &[ExecutionEvent], right: &[ExecutionEvent]) -> Option<u32> {
    left.iter()
        .zip(right)
        .position(|(left, right)| left != right)
        .or_else(|| (left.len() != right.len()).then_some(left.len().min(right.len())))
        .and_then(|index| u32::try_from(index).ok())
}

fn ranges_overlap(left_start: u64, left_len: u64, right_start: u64, right_len: u64) -> bool {
    let left_end = left_start.saturating_add(left_len);
    let right_end = right_start.saturating_add(right_len);
    left_start < right_end && right_start < left_end
}

fn invalid_at(kind: DivergenceKind, state: u32, flat_input: Option<u32>) -> RelationVerdict {
    RelationVerdict::Invalid(RelationCounterexample {
        kind,
        source_state: Some(state),
        flat_input,
        pair_left: None,
        pair_right: None,
        event_index: None,
        expected: 0,
        actual: 0,
    })
}

fn invalid_pair(
    kind: DivergenceKind,
    pair: RelationPair,
    flat_input: Option<u32>,
) -> RelationVerdict {
    RelationVerdict::Invalid(RelationCounterexample {
        kind,
        source_state: None,
        flat_input,
        pair_left: Some(pair.left),
        pair_right: Some(pair.right),
        event_index: None,
        expected: 0,
        actual: 0,
    })
}

fn invalid_event(
    kind: DivergenceKind,
    state: u32,
    flat_input: u32,
    event_index: usize,
) -> RelationVerdict {
    RelationVerdict::Invalid(RelationCounterexample {
        kind,
        source_state: Some(state),
        flat_input: Some(flat_input),
        pair_left: None,
        pair_right: None,
        event_index: u32::try_from(event_index).ok(),
        expected: 0,
        actual: 0,
    })
}

fn counterexample(
    kind: DivergenceKind,
    source_state: Option<u32>,
    flat_input: Option<u32>,
) -> RelationCounterexample {
    RelationCounterexample {
        kind,
        source_state,
        flat_input,
        pair_left: None,
        pair_right: None,
        event_index: None,
        expected: 0,
        actual: 0,
    }
}

fn encode_optional_u32(bytes: &mut Vec<u8>, value: Option<u32>) {
    bytes.extend_from_slice(&value.unwrap_or(u32::MAX).to_le_bytes());
}
