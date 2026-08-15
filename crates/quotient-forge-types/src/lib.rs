#![forbid(unsafe_code)]

//! Secrecy and semantic type checking for the bounded QuotientForge language.

use quotient_forge_syntax::{
    Assignment, AssignmentOperator, Block, BlockKind, Clause, Directive, FieldKind, Item, Module,
    SourceSpan, ValueToken,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const MAX_HORIZON: u64 = 512;
pub const MAX_TRANSDUCER_STATES: u64 = 256;

const OBSERVABLE_FIELDS: &[&str] = &[
    "action_slot",
    "connection",
    "cost",
    "failure",
    "frame_kind",
    "packet_size",
    "public_error",
    "radio_on",
    "reconnect",
    "retry_count",
    "send",
    "send_slot",
    "service_alias",
];

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ObserverId(pub String);

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SymbolId(pub String);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VisibilityClass {
    Private,
    Quotient,
    Public,
    ObserverOnly(ObserverId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SymbolType {
    Bool,
    Slot,
    Enumeration(Vec<String>),
    ActionSemantics,
    Observable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypedSymbol {
    pub id: SymbolId,
    pub visibility: VisibilityClass,
    pub symbol_type: SymbolType,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypedAction {
    pub name: String,
    pub service: String,
    pub release_window_start: u64,
    pub release_window_end: u64,
    pub exactly_once: bool,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypedObserver {
    pub id: ObserverId,
    pub fields: BTreeSet<String>,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypedFault {
    pub name: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypedFlow {
    pub sink: String,
    pub sources: Vec<SymbolId>,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypedModule {
    pub name: String,
    pub horizon: u64,
    pub transducer_state_bound: u64,
    pub symbols: BTreeMap<SymbolId, TypedSymbol>,
    pub actions: BTreeMap<String, TypedAction>,
    pub observers: BTreeMap<ObserverId, TypedObserver>,
    pub faults: BTreeMap<String, TypedFault>,
    pub flows: Vec<TypedFlow>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairOperator {
    InsertAdmissionCutoff,
    BucketizeTime,
    FixPacketSize,
    NormalizeFailure,
    ReplacePrivateRetryWithPublicRetry,
    AddPairwiseServiceDomain,
    AddPublicExecutionSlot,
}

impl RepairOperator {
    pub const fn label(self) -> &'static str {
        match self {
            Self::InsertAdmissionCutoff => "insert admission cutoff",
            Self::BucketizeTime => "bucketize time",
            Self::FixPacketSize => "use fixed-size framing",
            Self::NormalizeFailure => "normalize public failure",
            Self::ReplacePrivateRetryWithPublicRetry => "replace private retry with public retry",
            Self::AddPairwiseServiceDomain => "add pairwise service domain",
            Self::AddPublicExecutionSlot => "add public execution slot",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypeDiagnostic {
    pub code: &'static str,
    pub message: String,
    pub source_name: String,
    pub span: SourceSpan,
    pub source: Option<String>,
    pub sink: Option<String>,
    pub flow_path: Vec<String>,
    pub suggested_repair: Option<RepairOperator>,
}

impl TypeDiagnostic {
    fn simple(
        code: &'static str,
        message: impl Into<String>,
        source_name: &str,
        span: SourceSpan,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            source_name: source_name.to_owned(),
            span,
            source: None,
            sink: None,
            flow_path: Vec::new(),
            suggested_repair: None,
        }
    }

    fn private_flow(
        source_name: &str,
        span: SourceSpan,
        source: String,
        sink: String,
        observers: &[ObserverId],
    ) -> Self {
        let repair = repair_for_sink(&sink);
        let mut flow_path = vec![source.clone(), format!("release.{sink}")];
        flow_path.extend(
            observers
                .iter()
                .map(|observer| format!("observer.{}.{}", observer.0, sink)),
        );
        Self {
            code: "QF031",
            message: format!(
                "private source `{source}` cannot flow to public release sink `{sink}`"
            ),
            source_name: source_name.to_owned(),
            span,
            source: Some(source),
            sink: Some(sink),
            flow_path,
            suggested_repair: Some(repair),
        }
    }
}

impl fmt::Display for TypeDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "error[{}]: {}", self.code, self.message)?;
        write!(
            formatter,
            "  --> {}:{}:{}",
            self.source_name, self.span.line, self.span.column
        )?;
        if !self.flow_path.is_empty() {
            write!(formatter, "\n  flow: {}", self.flow_path.join(" -> "))?;
        }
        if let Some(repair) = self.suggested_repair {
            write!(formatter, "\n  suggested repair: {}", repair.label())?;
        }
        Ok(())
    }
}

pub fn check_module(
    source_name: &str,
    module: &Module,
) -> Result<TypedModule, Vec<TypeDiagnostic>> {
    Checker::new(source_name, module).check()
}

struct Checker<'a> {
    source_name: &'a str,
    module: &'a Module,
    diagnostics: Vec<TypeDiagnostic>,
    horizon: Option<u64>,
    state_bound: Option<u64>,
    symbols: BTreeMap<SymbolId, TypedSymbol>,
    simple_symbols: BTreeMap<String, SymbolId>,
    actions: BTreeMap<String, TypedAction>,
    observers: BTreeMap<ObserverId, TypedObserver>,
    faults: BTreeMap<String, TypedFault>,
    service_names: BTreeSet<String>,
    flows: Vec<TypedFlow>,
}

impl<'a> Checker<'a> {
    fn new(source_name: &'a str, module: &'a Module) -> Self {
        Self {
            source_name,
            module,
            diagnostics: Vec::new(),
            horizon: None,
            state_bound: None,
            symbols: BTreeMap::new(),
            simple_symbols: BTreeMap::new(),
            actions: BTreeMap::new(),
            observers: BTreeMap::new(),
            faults: BTreeMap::new(),
            service_names: BTreeSet::new(),
            flows: Vec::new(),
        }
    }

    fn check(mut self) -> Result<TypedModule, Vec<TypeDiagnostic>> {
        self.collect_settings();
        self.collect_fields();
        self.collect_observers();
        self.collect_faults();
        self.collect_actions();
        self.check_quotient();
        self.check_faults();
        self.check_utility();
        self.check_release_flows();

        let horizon = self.horizon.unwrap_or_default();
        let state_bound = self.state_bound.unwrap_or_default();
        if self.diagnostics.is_empty() {
            Ok(TypedModule {
                name: self.module.name.clone(),
                horizon,
                transducer_state_bound: state_bound,
                symbols: self.symbols,
                actions: self.actions,
                observers: self.observers,
                faults: self.faults,
                flows: self.flows,
            })
        } else {
            Err(self.diagnostics)
        }
    }

    fn collect_settings(&mut self) {
        for item in &self.module.items {
            match item {
                Item::Horizon(setting) => {
                    if self.horizon.replace(setting.value).is_some() {
                        self.error("QF030", "horizon is declared more than once", setting.span);
                    }
                    if setting.value == 0 || setting.value > MAX_HORIZON {
                        self.error(
                            "QF030",
                            format!("horizon must be in 1..={MAX_HORIZON}"),
                            setting.span,
                        );
                    }
                }
                Item::TransducerStates(setting) => {
                    if self.state_bound.replace(setting.value).is_some() {
                        self.error(
                            "QF030",
                            "transducer state bound is declared more than once",
                            setting.span,
                        );
                    }
                    if setting.value == 0 || setting.value > MAX_TRANSDUCER_STATES {
                        self.error(
                            "QF030",
                            format!(
                                "transducer state bound must be in 1..={MAX_TRANSDUCER_STATES}"
                            ),
                            setting.span,
                        );
                    }
                }
                Item::Block(_) => {}
            }
        }
        if self.horizon.is_none() {
            self.error(
                "QF030",
                "a module requires exactly one horizon",
                self.module.span,
            );
        }
        if self.state_bound.is_none() {
            self.error(
                "QF030",
                "a module requires one transducer state bound",
                self.module.span,
            );
        }
    }

    fn collect_fields(&mut self) {
        let blocks: Vec<Block> = self.blocks().cloned().collect();
        for block in &blocks {
            let visibility = match block.kind {
                BlockKind::Private => VisibilityClass::Private,
                BlockKind::Public => VisibilityClass::Public,
                _ => continue,
            };
            let prefix = block.kind_name();
            for clause in &block.clauses {
                match clause {
                    Clause::Field(field) => {
                        let symbol_type = match field.kind {
                            FieldKind::Bool => SymbolType::Bool,
                            FieldKind::Slot => SymbolType::Slot,
                        };
                        self.insert_symbol(
                            prefix,
                            &field.name,
                            visibility.clone(),
                            symbol_type,
                            field.span,
                        );
                    }
                    Clause::Enum(declaration) => self.insert_symbol(
                        prefix,
                        &declaration.name,
                        visibility.clone(),
                        SymbolType::Enumeration(declaration.variants.clone()),
                        declaration.span,
                    ),
                    _ => self.error(
                        "QF030",
                        "visibility blocks may contain only field declarations",
                        block.span,
                    ),
                }
            }
        }
    }

    fn collect_observers(&mut self) {
        let blocks: Vec<Block> = self.blocks_of(BlockKind::Observer).cloned().collect();
        for block in &blocks {
            let id = observer_id(block);
            if self.observers.contains_key(&id) {
                self.error(
                    "QF034",
                    format!("observer `{}` is declared more than once", id.0),
                    block.span,
                );
                continue;
            }
            if block.name.as_deref() == Some("service") {
                if let Some(service) = &block.argument {
                    if service != "*" {
                        self.service_names.insert(service.clone());
                    }
                }
            }
            let mut fields = BTreeSet::new();
            for directive in directives(block, "sees") {
                let Some(field) = single_identifier(&directive.arguments) else {
                    self.error(
                        "QF034",
                        "`sees` requires one observable field",
                        directive.span,
                    );
                    continue;
                };
                if !OBSERVABLE_FIELDS.contains(&field) {
                    self.error(
                        "QF034",
                        format!("observer field `{field}` is not declared by version 1"),
                        directive.span,
                    );
                    continue;
                }
                fields.insert(field.to_owned());
                let symbol_id = SymbolId(format!("observer.{}.{}", id.0, field));
                self.symbols
                    .entry(symbol_id.clone())
                    .or_insert(TypedSymbol {
                        id: symbol_id,
                        visibility: VisibilityClass::ObserverOnly(id.clone()),
                        symbol_type: SymbolType::Observable,
                        span: directive.span,
                    });
            }
            self.observers.insert(
                id.clone(),
                TypedObserver {
                    id,
                    fields,
                    span: block.span,
                },
            );
        }
    }

    fn collect_faults(&mut self) {
        let blocks: Vec<Block> = self.blocks_of(BlockKind::Fault).cloned().collect();
        for block in &blocks {
            let Some(name) = &block.name else {
                continue;
            };
            if self.faults.contains_key(name) {
                self.error(
                    "QF032",
                    format!("fault `{name}` is declared more than once"),
                    block.span,
                );
            } else {
                self.faults.insert(
                    name.clone(),
                    TypedFault {
                        name: name.clone(),
                        span: block.span,
                    },
                );
            }
        }
    }

    fn collect_actions(&mut self) {
        let horizon = self.horizon.unwrap_or_default();
        let blocks: Vec<Block> = self.blocks_of(BlockKind::Action).cloned().collect();
        for block in &blocks {
            let Some(name) = &block.name else {
                continue;
            };
            if self.actions.contains_key(name) {
                self.error(
                    "QF033",
                    format!("action `{name}` is declared more than once"),
                    block.span,
                );
                continue;
            }
            let service = directives(block, "service")
                .next()
                .and_then(|directive| single_identifier(&directive.arguments))
                .map(str::to_owned);
            let window = directives(block, "release_window")
                .next()
                .and_then(|directive| parse_range(&directive.arguments));
            let exactly_once = directives(block, "exactly_once").next().is_some();
            let Some(service) = service else {
                self.error("QF033", "action requires one service", block.span);
                continue;
            };
            let Some((start, end)) = window else {
                self.error(
                    "QF033",
                    "action requires a numeric release window",
                    block.span,
                );
                continue;
            };
            if !self.service_names.contains(&service) {
                self.error(
                    "QF033",
                    format!("action service `{service}` has no service observer declaration"),
                    block.span,
                );
            }
            if start > end || end >= horizon {
                self.error(
                    "QF033",
                    "action release window is empty or outside the horizon",
                    block.span,
                );
            }
            if !exactly_once {
                self.error(
                    "QF033",
                    "version 1 actions require `exactly_once`",
                    block.span,
                );
            }
            self.actions.insert(
                name.clone(),
                TypedAction {
                    name: name.clone(),
                    service,
                    release_window_start: start,
                    release_window_end: end,
                    exactly_once,
                    span: block.span,
                },
            );
            let id = SymbolId(format!("quotient.{name}"));
            self.symbols.insert(
                id.clone(),
                TypedSymbol {
                    id,
                    visibility: VisibilityClass::Quotient,
                    symbol_type: SymbolType::ActionSemantics,
                    span: block.span,
                },
            );
        }
    }

    fn check_quotient(&mut self) {
        let quotient_blocks: Vec<Block> = self.blocks_of(BlockKind::Quotient).cloned().collect();
        if quotient_blocks.len() != 1 {
            self.error(
                "QF035",
                "a module requires exactly one quotient block",
                self.module.span,
            );
            return;
        }
        let block = &quotient_blocks[0];
        let mut projected_actions = BTreeSet::new();
        let mut erased = BTreeSet::new();
        for directive in directives(block, "by") {
            match directive.arguments.as_slice() {
                [ValueToken::Identifier(kind), ValueToken::Identifier(name)]
                    if kind == "action" =>
                {
                    if self.actions.contains_key(name) {
                        projected_actions.insert(name.clone());
                    } else {
                        self.error(
                            "QF035",
                            format!("quotient references undeclared action `{name}`"),
                            directive.span,
                        );
                    }
                }
                _ => self.error(
                    "QF035",
                    "`by` requires `action <declared-name>`",
                    directive.span,
                ),
            }
        }
        for directive in directives(block, "erase") {
            let Some(name) = single_identifier(&directive.arguments) else {
                self.error(
                    "QF035",
                    "`erase` requires one private field",
                    directive.span,
                );
                continue;
            };
            let id = SymbolId(format!("private.{name}"));
            if self
                .symbols
                .get(&id)
                .is_some_and(|symbol| symbol.visibility == VisibilityClass::Private)
            {
                erased.insert(id);
            } else {
                self.error(
                    "QF035",
                    format!("quotient erase target `{name}` is not a private field"),
                    directive.span,
                );
            }
        }
        let action_names: Vec<String> = self.actions.keys().cloned().collect();
        for action in action_names {
            if !projected_actions.contains(&action) {
                self.error(
                    "QF035",
                    format!("action `{action}` is missing from the quotient projection"),
                    block.span,
                );
            }
        }
        let private_ids: Vec<SymbolId> = self
            .symbols
            .values()
            .filter(|symbol| symbol.visibility == VisibilityClass::Private)
            .map(|symbol| symbol.id.clone())
            .collect();
        for id in private_ids {
            if !erased.contains(&id) {
                self.error(
                    "QF035",
                    format!("private field `{}` is not explicitly erased", id.0),
                    block.span,
                );
            }
        }
    }

    fn check_faults(&mut self) {
        let blocks: Vec<Block> = self.blocks_of(BlockKind::Fault).cloned().collect();
        for block in &blocks {
            for clause in &block.clauses {
                let Clause::Directive(directive) = clause else {
                    continue;
                };
                if contains_private_reference(&directive.arguments) {
                    self.error(
                        "QF032",
                        "fault automata are public adversarial inputs and cannot read private state",
                        directive.span,
                    );
                }
                match directive.keyword.as_str() {
                    "max_drop" if !valid_max_drop(&directive.arguments) => self.error(
                        "QF032",
                        "`max_drop` must be `<n> per window <positive-n>`",
                        directive.span,
                    ),
                    "reorder" if !valid_nonnegative_bound(&directive.arguments) => {
                        self.error("QF032", "`reorder` must be `<= <n>`", directive.span)
                    }
                    _ => {}
                }
            }
        }
    }

    fn check_utility(&mut self) {
        let utility_blocks: Vec<Block> = self.blocks_of(BlockKind::Utility).cloned().collect();
        if utility_blocks.len() != 1 {
            self.error(
                "QF036",
                "a module requires exactly one utility block",
                self.module.span,
            );
            return;
        }
        let block = &utility_blocks[0];
        let mut preserved = BTreeSet::new();
        let mut forbids_unauthorized = false;
        let mut global_deadline = None;
        for clause in &block.clauses {
            match clause {
                Clause::Directive(directive) if directive.keyword == "preserve" => {
                    self.check_action_reference(directive, &mut preserved);
                }
                Clause::Directive(directive) if directive.keyword == "deadline" => {
                    global_deadline = single_integer(&directive.arguments);
                    if global_deadline.is_none() {
                        self.error(
                            "QF036",
                            "utility deadline requires one slot",
                            directive.span,
                        );
                    }
                }
                Clause::Directive(directive) if directive.keyword == "forbid" => {
                    if single_identifier(&directive.arguments) == Some("unauthorized_action") {
                        forbids_unauthorized = true;
                    }
                }
                Clause::Assignment(assignment) if assignment.target == "unauthorized_actions" => {
                    forbids_unauthorized = assignment.operator == AssignmentOperator::Equal
                        && single_integer(&assignment.expression) == Some(0);
                    if !forbids_unauthorized {
                        self.error(
                            "QF036",
                            "unauthorized_actions must equal zero",
                            assignment.span,
                        );
                    }
                }
                Clause::Block(obligation) if obligation.kind == BlockKind::Obligation => {
                    self.check_obligation(obligation, &mut preserved);
                }
                _ => {}
            }
        }
        let action_names: Vec<String> = self.actions.keys().cloned().collect();
        for action in action_names {
            if !preserved.contains(&action) {
                self.error(
                    "QF036",
                    format!("utility does not preserve action `{action}`"),
                    block.span,
                );
            }
        }
        if !forbids_unauthorized {
            self.error(
                "QF036",
                "utility must forbid unauthorized actions",
                block.span,
            );
        }
        if let Some(deadline) = global_deadline {
            let latest_start = self
                .actions
                .values()
                .map(|action| action.release_window_start)
                .max()
                .unwrap_or_default();
            if deadline < latest_start || deadline >= self.horizon.unwrap_or_default() {
                self.error(
                    "QF036",
                    "utility deadline conflicts with an action window or horizon",
                    block.span,
                );
            }
        }
    }

    fn check_action_reference(&mut self, directive: &Directive, preserved: &mut BTreeSet<String>) {
        let Some(name) = single_identifier(&directive.arguments) else {
            self.error(
                "QF036",
                "utility action reference requires one name",
                directive.span,
            );
            return;
        };
        if self.actions.contains_key(name) {
            preserved.insert(name.to_owned());
        } else {
            self.error(
                "QF036",
                format!("utility references undeclared action `{name}`"),
                directive.span,
            );
        }
    }

    fn check_obligation(&mut self, block: &Block, preserved: &mut BTreeSet<String>) {
        let Some(name) = &block.name else {
            return;
        };
        if self.actions.contains_key(name) {
            preserved.insert(name.clone());
        } else {
            self.error(
                "QF036",
                format!("utility obligation references undeclared action `{name}`"),
                block.span,
            );
        }
        if directives(block, "exactly_once").next().is_none() {
            self.error(
                "QF036",
                "utility obligation requires exactly_once",
                block.span,
            );
        }
        if let Some(under) = directives(block, "under").next() {
            match under.arguments.as_slice() {
                [ValueToken::Identifier(kind), ValueToken::Identifier(fault)]
                    if kind == "fault" && self.faults.contains_key(fault) => {}
                _ => self.error(
                    "QF036",
                    "utility `under` requires one declared fault",
                    under.span,
                ),
            }
        }
    }

    fn check_release_flows(&mut self) {
        let blocks: Vec<Block> = self.blocks_of(BlockKind::Release).cloned().collect();
        for block in &blocks {
            for clause in &block.clauses {
                let Clause::Assignment(assignment) = clause else {
                    continue;
                };
                if !OBSERVABLE_FIELDS.contains(&assignment.target.as_str()) {
                    self.error(
                        "QF030",
                        format!("release sink `{}` is not declared", assignment.target),
                        assignment.span,
                    );
                    continue;
                }
                let observers: Vec<ObserverId> = self
                    .observers
                    .values()
                    .filter(|observer| observer.fields.contains(&assignment.target))
                    .map(|observer| observer.id.clone())
                    .collect();
                let sink_visibility = if observers.len() == 1 {
                    VisibilityClass::ObserverOnly(observers[0].clone())
                } else {
                    VisibilityClass::Public
                };
                let sources = self.resolve_expression(assignment);
                for source in &sources {
                    let Some(symbol) = self.symbols.get(source) else {
                        continue;
                    };
                    if !flow_is_allowed(&symbol.visibility, &sink_visibility) {
                        self.diagnostics.push(TypeDiagnostic::private_flow(
                            self.source_name,
                            assignment.span,
                            symbol.id.0.clone(),
                            assignment.target.clone(),
                            &observers,
                        ));
                    }
                }
                self.flows.push(TypedFlow {
                    sink: assignment.target.clone(),
                    sources,
                    span: assignment.span,
                });
            }
        }
    }

    fn resolve_expression(&mut self, assignment: &Assignment) -> Vec<SymbolId> {
        let mut sources = Vec::new();
        let mut index = 0;
        while index < assignment.expression.len() {
            let ValueToken::Identifier(first) = &assignment.expression[index] else {
                index += 1;
                continue;
            };
            let mut parts = vec![first.clone()];
            index += 1;
            while matches!(assignment.expression.get(index), Some(ValueToken::Dot)) {
                let Some(ValueToken::Identifier(part)) = assignment.expression.get(index + 1)
                else {
                    break;
                };
                parts.push(part.clone());
                index += 2;
            }
            if matches!(parts[0].as_str(), "true" | "false" | "cover" | "action") {
                continue;
            }
            let candidate = if parts.len() == 1 {
                self.simple_symbols.get(&parts[0]).cloned()
            } else if parts[0] == "action" {
                Some(SymbolId(format!("quotient.{}", parts[1])))
            } else {
                Some(SymbolId(parts.join(".")))
            };
            match candidate {
                Some(id) if self.symbols.contains_key(&id) => {
                    if !sources.contains(&id) {
                        sources.push(id);
                    }
                }
                _ => self.error(
                    "QF030",
                    format!(
                        "release expression references unknown symbol `{}`",
                        parts.join(".")
                    ),
                    assignment.span,
                ),
            }
        }
        sources
    }

    fn insert_symbol(
        &mut self,
        prefix: &str,
        name: &str,
        visibility: VisibilityClass,
        symbol_type: SymbolType,
        span: SourceSpan,
    ) {
        if self.simple_symbols.contains_key(name) {
            self.error(
                "QF030",
                format!("symbol `{name}` is declared more than once"),
                span,
            );
            return;
        }
        let id = SymbolId(format!("{prefix}.{name}"));
        self.simple_symbols.insert(name.to_owned(), id.clone());
        self.symbols.insert(
            id.clone(),
            TypedSymbol {
                id,
                visibility,
                symbol_type,
                span,
            },
        );
    }

    fn blocks(&self) -> impl Iterator<Item = &Block> {
        self.module.items.iter().filter_map(|item| match item {
            Item::Block(block) => Some(block),
            _ => None,
        })
    }

    fn blocks_of(&self, kind: BlockKind) -> impl Iterator<Item = &Block> {
        self.blocks().filter(move |block| block.kind == kind)
    }

    fn error(&mut self, code: &'static str, message: impl Into<String>, span: SourceSpan) {
        self.diagnostics.push(TypeDiagnostic::simple(
            code,
            message,
            self.source_name,
            span,
        ));
    }
}

trait BlockName {
    fn kind_name(&self) -> &'static str;
}

impl BlockName for Block {
    fn kind_name(&self) -> &'static str {
        match self.kind {
            BlockKind::Private => "private",
            BlockKind::Public => "public",
            _ => "invalid",
        }
    }
}

fn observer_id(block: &Block) -> ObserverId {
    let name = block.name.as_deref().unwrap_or("unknown");
    match &block.argument {
        Some(argument) => ObserverId(format!("{name}({argument})")),
        None => ObserverId(name.to_owned()),
    }
}

fn directives<'a>(block: &'a Block, keyword: &'a str) -> impl Iterator<Item = &'a Directive> {
    block.clauses.iter().filter_map(move |clause| match clause {
        Clause::Directive(directive) if directive.keyword == keyword => Some(directive),
        _ => None,
    })
}

fn single_identifier(values: &[ValueToken]) -> Option<&str> {
    match values {
        [ValueToken::Identifier(value)] => Some(value),
        _ => None,
    }
}

fn single_integer(values: &[ValueToken]) -> Option<u64> {
    match values {
        [ValueToken::Integer(value)] => Some(*value),
        _ => None,
    }
}

fn parse_range(values: &[ValueToken]) -> Option<(u64, u64)> {
    match values {
        [ValueToken::Integer(start), ValueToken::Range, ValueToken::Integer(end)] => {
            Some((*start, *end))
        }
        _ => None,
    }
}

fn contains_private_reference(values: &[ValueToken]) -> bool {
    values.windows(2).any(|window| {
        matches!(
            window,
            [ValueToken::Identifier(prefix), ValueToken::Dot] if prefix == "private"
        )
    })
}

fn valid_max_drop(values: &[ValueToken]) -> bool {
    match values {
        [ValueToken::Integer(drop), ValueToken::Identifier(per), ValueToken::Identifier(window), ValueToken::Integer(width)] => {
            per == "per" && window == "window" && *width > 0 && drop <= width
        }
        _ => false,
    }
}

fn valid_nonnegative_bound(values: &[ValueToken]) -> bool {
    matches!(values, [ValueToken::LessEqual, ValueToken::Integer(_)])
}

fn flow_is_allowed(source: &VisibilityClass, sink: &VisibilityClass) -> bool {
    match source {
        VisibilityClass::Private => matches!(sink, VisibilityClass::Private),
        VisibilityClass::Quotient | VisibilityClass::Public => true,
        VisibilityClass::ObserverOnly(source_observer) => {
            matches!(sink, VisibilityClass::ObserverOnly(sink_observer) if source_observer == sink_observer)
        }
    }
}

fn repair_for_sink(sink: &str) -> RepairOperator {
    match sink {
        "packet_size" => RepairOperator::FixPacketSize,
        "retry_count" | "reconnect" => RepairOperator::ReplacePrivateRetryWithPublicRetry,
        "failure" | "public_error" => RepairOperator::NormalizeFailure,
        "service_alias" => RepairOperator::AddPairwiseServiceDomain,
        "send_slot" | "action_slot" => RepairOperator::AddPublicExecutionSlot,
        _ => RepairOperator::InsertAdmissionCutoff,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quotient_forge_syntax::{parse_module, ParseLimits};

    fn check(source: &str) -> Result<TypedModule, Vec<TypeDiagnostic>> {
        let module = parse_module("test.qf", source, ParseLimits::default()).unwrap();
        check_module("test.qf", &module)
    }

    fn module_with_release(private_fields: &str, erasures: &str, release: &str) -> String {
        format!(
            r#"
            module flow version 1 {{
              horizon 32;
              transducer_states <= 4;
              private {{ {private_fields} }}
              public {{ slot now; }}
              action soft_inflate {{
                service menfugu;
                release_window 16..31;
                exactly_once;
              }}
              quotient {{
                by action soft_inflate;
                {erasures}
              }}
              observer network {{
                sees send_slot;
                sees packet_size;
                sees retry_count;
                sees public_error;
                sees service_alias;
                sees action_slot;
              }}
              observer service(menfugu) {{ sees action_slot; }}
              fault bounded_loss {{ max_drop 1 per window 4; reorder <= 2; }}
              utility {{
                preserve soft_inflate;
                deadline 31;
                unauthorized_actions == 0;
              }}
              release {{ {release} }}
            }}
            "#
        )
    }

    #[test]
    fn quotient_and_public_flows_are_allowed() {
        let source = module_with_release(
            "bool hidden;",
            "erase hidden;",
            "send_slot = public.now; action_slot = quotient.soft_inflate;",
        );
        let typed = check(&source).unwrap();
        assert_eq!(typed.horizon, 32);
        assert_eq!(typed.flows.len(), 2);
        assert!(typed
            .symbols
            .values()
            .any(|symbol| symbol.visibility == VisibilityClass::Quotient));
    }

    #[test]
    fn private_to_release_flows_are_rejected_with_repairs() {
        let cases = [
            (
                "slot permit_ready_slot;",
                "erase permit_ready_slot;",
                "send_slot = private.permit_ready_slot;",
                RepairOperator::AddPublicExecutionSlot,
            ),
            (
                "enum margin { low, high };",
                "erase margin;",
                "packet_size = private.margin;",
                RepairOperator::FixPacketSize,
            ),
            (
                "bool confidence;",
                "erase confidence;",
                "retry_count = private.confidence;",
                RepairOperator::ReplacePrivateRetryWithPublicRetry,
            ),
            (
                "enum failure_reason { low, high };",
                "erase failure_reason;",
                "public_error = private.failure_reason;",
                RepairOperator::NormalizeFailure,
            ),
            (
                "enum identity_class { a, b };",
                "erase identity_class;",
                "service_alias = private.identity_class;",
                RepairOperator::AddPairwiseServiceDomain,
            ),
        ];
        for (fields, erasures, release, expected_repair) in cases {
            let source = module_with_release(fields, erasures, release);
            let diagnostics = check(&source).unwrap_err();
            let flow = diagnostics
                .iter()
                .find(|diagnostic| diagnostic.code == "QF031")
                .unwrap();
            assert_eq!(flow.suggested_repair, Some(expected_repair));
            assert!(flow.source.as_deref().unwrap().starts_with("private."));
            assert!(flow.flow_path.len() >= 3);
        }
    }

    #[test]
    fn observer_unknown_field_is_rejected() {
        let source =
            module_with_release("bool hidden;", "erase hidden;", "send_slot = public.now;")
                .replace("sees send_slot;", "sees secret_timestamp;");
        let diagnostics = check(&source).unwrap_err();
        assert!(diagnostics.iter().any(|error| error.code == "QF034"));
    }

    #[test]
    fn impossible_action_window_is_rejected() {
        let source =
            module_with_release("bool hidden;", "erase hidden;", "send_slot = public.now;")
                .replace("release_window 16..31", "release_window 31..16");
        let diagnostics = check(&source).unwrap_err();
        assert!(diagnostics.iter().any(|error| error.code == "QF033"));
    }

    #[test]
    fn undeclared_service_is_rejected() {
        let source =
            module_with_release("bool hidden;", "erase hidden;", "send_slot = public.now;")
                .replace("service menfugu;", "service unknown_service;");
        let diagnostics = check(&source).unwrap_err();
        assert!(diagnostics
            .iter()
            .any(|error| { error.code == "QF033" && error.message.contains("unknown_service") }));
    }

    #[test]
    fn private_dependent_fault_is_rejected() {
        let source = module_with_release("slot loss;", "erase loss;", "send_slot = public.now;")
            .replace(
                "max_drop 1 per window 4",
                "max_drop private.loss per window 4",
            );
        let diagnostics = check(&source).unwrap_err();
        assert!(diagnostics.iter().any(|error| error.code == "QF032"));
    }

    #[test]
    fn inconsistent_utility_reference_is_rejected() {
        let source =
            module_with_release("bool hidden;", "erase hidden;", "send_slot = public.now;")
                .replace("preserve soft_inflate;", "preserve missing_action;");
        let diagnostics = check(&source).unwrap_err();
        assert!(diagnostics.iter().any(|error| error.code == "QF036"));
    }

    #[test]
    fn every_private_field_requires_explicit_erasure() {
        let source = module_with_release("bool hidden;", "", "send_slot = public.now;");
        let diagnostics = check(&source).unwrap_err();
        assert!(diagnostics
            .iter()
            .any(|error| { error.code == "QF035" && error.message.contains("explicitly erased") }));
    }
}
