#![forbid(unsafe_code)]

//! Bounded syntax frontend for the QuotientForge `.qf` language.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write};

pub const LANGUAGE_VERSION: u64 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceSpan {
    pub start: usize,
    pub end: usize,
    pub line: usize,
    pub column: usize,
}

impl SourceSpan {
    const fn merge(self, other: Self) -> Self {
        Self {
            start: self.start,
            end: other.end,
            line: self.line,
            column: self.column,
        }
    }

    const fn origin() -> Self {
        Self {
            start: 0,
            end: 0,
            line: 1,
            column: 1,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Diagnostic {
    pub code: &'static str,
    pub message: String,
    pub source_name: String,
    pub span: SourceSpan,
}

impl Diagnostic {
    fn new(
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
        }
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "error[{}]: {}\n  --> {}:{}:{}",
            self.code, self.message, self.source_name, self.span.line, self.span.column
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseLimits {
    pub max_source_bytes: usize,
    pub max_tokens: usize,
    pub max_imports: usize,
    pub max_import_depth: usize,
}

impl Default for ParseLimits {
    fn default() -> Self {
        Self {
            max_source_bytes: 1_000_000,
            max_tokens: 100_000,
            max_imports: 256,
            max_import_depth: 64,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Module {
    pub name: String,
    pub version: u64,
    pub imports: Vec<ImportDecl>,
    pub items: Vec<Item>,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportDecl {
    pub path: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Item {
    Horizon(BoundedSetting),
    TransducerStates(BoundedSetting),
    Block(Block),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedSetting {
    pub value: u64,
    pub span: SourceSpan,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockKind {
    Private,
    Public,
    Action,
    Quotient,
    Observer,
    Fault,
    Utility,
    Objective,
    Release,
    Obligation,
}

impl BlockKind {
    const fn keyword(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::Public => "public",
            Self::Action => "action",
            Self::Quotient => "quotient",
            Self::Observer => "observer",
            Self::Fault => "fault",
            Self::Utility => "utility",
            Self::Objective => "objective",
            Self::Release => "release",
            Self::Obligation => "obligation",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Block {
    pub kind: BlockKind,
    pub name: Option<String>,
    pub argument: Option<String>,
    pub clauses: Vec<Clause>,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Clause {
    Field(FieldDecl),
    Enum(EnumDecl),
    Directive(Directive),
    Assignment(Assignment),
    Block(Block),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FieldKind {
    Bool,
    Slot,
}

impl FieldKind {
    const fn keyword(self) -> &'static str {
        match self {
            Self::Bool => "bool",
            Self::Slot => "slot",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FieldDecl {
    pub kind: FieldKind,
    pub name: String,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnumDecl {
    pub name: String,
    pub variants: Vec<String>,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Directive {
    pub keyword: String,
    pub arguments: Vec<ValueToken>,
    pub span: SourceSpan,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssignmentOperator {
    Set,
    Equal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Assignment {
    pub target: String,
    pub operator: AssignmentOperator,
    pub expression: Vec<ValueToken>,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValueToken {
    Identifier(String),
    Integer(u64),
    StringLiteral(String),
    Dot,
    Range,
    LessEqual,
    Equal,
    Star,
    LeftParen,
    RightParen,
    Comma,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadedSource {
    pub canonical_name: String,
    pub source: String,
}

pub trait ModuleLoader {
    fn load(&self, importer: Option<&str>, requested: &str) -> Result<LoadedSource, String>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleGraph {
    pub root: String,
    pub modules: BTreeMap<String, Module>,
}

pub fn parse_module(
    source_name: &str,
    source: &str,
    limits: ParseLimits,
) -> Result<Module, Vec<Diagnostic>> {
    if source.len() > limits.max_source_bytes {
        return Err(vec![Diagnostic::new(
            "QF005",
            format!(
                "source has {} bytes, limit is {}",
                source.len(),
                limits.max_source_bytes
            ),
            source_name,
            SourceSpan::origin(),
        )]);
    }
    if let Some((offset, _)) = source
        .char_indices()
        .find(|(_, character)| !character.is_ascii())
    {
        let (line, column) = source_position(source, offset);
        return Err(vec![Diagnostic::new(
            "QF001",
            "the version 1 grammar accepts ASCII source only",
            source_name,
            SourceSpan {
                start: offset,
                end: offset + 1,
                line,
                column,
            },
        )]);
    }

    let (tokens, mut diagnostics) = Lexer::new(source_name, source, limits.max_tokens).lex();
    let mut parser = Parser::new(source_name, tokens);
    let module = parser.parse();
    diagnostics.extend(parser.diagnostics);
    if diagnostics.is_empty() {
        module.ok_or_else(|| {
            vec![Diagnostic::new(
                "QF001",
                "module could not be parsed",
                source_name,
                SourceSpan::origin(),
            )]
        })
    } else {
        Err(diagnostics)
    }
}

pub fn parse_module_graph(
    root: &str,
    loader: &impl ModuleLoader,
    limits: ParseLimits,
) -> Result<ModuleGraph, Vec<Diagnostic>> {
    let mut state = GraphState {
        loader,
        limits,
        modules: BTreeMap::new(),
        visiting: BTreeSet::new(),
        diagnostics: Vec::new(),
    };
    let root_name = state.visit(None, root, SourceSpan::origin(), 0);
    if state.diagnostics.is_empty() {
        Ok(ModuleGraph {
            root: root_name.unwrap_or_else(|| root.to_owned()),
            modules: state.modules,
        })
    } else {
        Err(state.diagnostics)
    }
}

pub fn format_module(module: &Module) -> String {
    let mut output = String::new();
    let _ = writeln!(
        output,
        "module {} version {} {{",
        module.name, module.version
    );
    for import in &module.imports {
        let _ = writeln!(output, "  import \"{}\";", escape_string(&import.path));
    }
    if !module.imports.is_empty() && !module.items.is_empty() {
        output.push('\n');
    }
    for (index, item) in module.items.iter().enumerate() {
        format_item(&mut output, item, 1);
        if index + 1 < module.items.len() && matches!(item, Item::Block(_)) {
            output.push('\n');
        }
    }
    output.push_str("}\n");
    output
}

struct GraphState<'a, L: ModuleLoader> {
    loader: &'a L,
    limits: ParseLimits,
    modules: BTreeMap<String, Module>,
    visiting: BTreeSet<String>,
    diagnostics: Vec<Diagnostic>,
}

impl<L: ModuleLoader> GraphState<'_, L> {
    fn visit(
        &mut self,
        importer: Option<&str>,
        requested: &str,
        import_span: SourceSpan,
        depth: usize,
    ) -> Option<String> {
        if depth > self.limits.max_import_depth {
            self.diagnostics.push(Diagnostic::new(
                "QF008",
                "module import depth exceeds the configured limit",
                importer.unwrap_or(requested),
                import_span,
            ));
            return None;
        }
        let loaded = match self.loader.load(importer, requested) {
            Ok(source) => source,
            Err(message) => {
                self.diagnostics.push(Diagnostic::new(
                    "QF007",
                    format!("module load failed: {message}"),
                    importer.unwrap_or(requested),
                    import_span,
                ));
                return None;
            }
        };
        if self.visiting.contains(&loaded.canonical_name) {
            self.diagnostics.push(Diagnostic::new(
                "QF006",
                format!("module import cycle reaches `{}`", loaded.canonical_name),
                importer.unwrap_or(&loaded.canonical_name),
                import_span,
            ));
            return None;
        }
        if self.modules.contains_key(&loaded.canonical_name) {
            return Some(loaded.canonical_name);
        }
        if self.modules.len() + self.visiting.len() >= self.limits.max_imports {
            self.diagnostics.push(Diagnostic::new(
                "QF008",
                "module count exceeds the configured import limit",
                importer.unwrap_or(&loaded.canonical_name),
                import_span,
            ));
            return None;
        }

        let module = match parse_module(&loaded.canonical_name, &loaded.source, self.limits) {
            Ok(module) => module,
            Err(mut errors) => {
                self.diagnostics.append(&mut errors);
                return None;
            }
        };
        self.visiting.insert(loaded.canonical_name.clone());
        for import in &module.imports {
            self.visit(
                Some(&loaded.canonical_name),
                &import.path,
                import.span,
                depth + 1,
            );
        }
        self.visiting.remove(&loaded.canonical_name);
        self.modules.insert(loaded.canonical_name.clone(), module);
        Some(loaded.canonical_name)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Token {
    kind: TokenKind,
    span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum TokenKind {
    Identifier(String),
    Integer(u64),
    StringLiteral(String),
    LeftBrace,
    RightBrace,
    LeftParen,
    RightParen,
    Semicolon,
    Comma,
    Dot,
    Range,
    LessEqual,
    Equal,
    EqualEqual,
    Star,
}

struct Lexer<'a> {
    source_name: &'a str,
    source: &'a [u8],
    index: usize,
    line: usize,
    column: usize,
    max_tokens: usize,
    tokens: Vec<Token>,
    diagnostics: Vec<Diagnostic>,
}

impl<'a> Lexer<'a> {
    fn new(source_name: &'a str, source: &'a str, max_tokens: usize) -> Self {
        Self {
            source_name,
            source: source.as_bytes(),
            index: 0,
            line: 1,
            column: 1,
            max_tokens,
            tokens: Vec::new(),
            diagnostics: Vec::new(),
        }
    }

    fn lex(mut self) -> (Vec<Token>, Vec<Diagnostic>) {
        while self.index < self.source.len() {
            if self.skip_layout() {
                continue;
            }
            if self.index >= self.source.len() {
                break;
            }
            if self.tokens.len() >= self.max_tokens {
                self.diagnostics.push(Diagnostic::new(
                    "QF008",
                    "token count exceeds the configured limit",
                    self.source_name,
                    self.current_span(0),
                ));
                break;
            }

            let start = self.index;
            let line = self.line;
            let column = self.column;
            let byte = self.source[self.index];
            if is_identifier_start(byte) {
                self.advance();
                while self
                    .source
                    .get(self.index)
                    .copied()
                    .is_some_and(is_identifier_continue)
                {
                    self.advance();
                }
                let value = String::from_utf8_lossy(&self.source[start..self.index]).into_owned();
                self.push(TokenKind::Identifier(value), start, line, column);
            } else if byte.is_ascii_digit() {
                self.advance();
                while self.source.get(self.index).is_some_and(u8::is_ascii_digit) {
                    self.advance();
                }
                let digits = String::from_utf8_lossy(&self.source[start..self.index]);
                match digits.parse::<u64>() {
                    Ok(value) => self.push(TokenKind::Integer(value), start, line, column),
                    Err(_) => self.diagnostics.push(Diagnostic::new(
                        "QF004",
                        "integer literal exceeds u64",
                        self.source_name,
                        SourceSpan {
                            start,
                            end: self.index,
                            line,
                            column,
                        },
                    )),
                }
            } else if byte == b'"' {
                self.lex_string(start, line, column);
            } else {
                let kind = match (byte, self.source.get(self.index + 1).copied()) {
                    (b'.', Some(b'.')) => {
                        self.advance();
                        self.advance();
                        TokenKind::Range
                    }
                    (b'<', Some(b'=')) => {
                        self.advance();
                        self.advance();
                        TokenKind::LessEqual
                    }
                    (b'=', Some(b'=')) => {
                        self.advance();
                        self.advance();
                        TokenKind::EqualEqual
                    }
                    (b'{', _) => self.single(TokenKind::LeftBrace),
                    (b'}', _) => self.single(TokenKind::RightBrace),
                    (b'(', _) => self.single(TokenKind::LeftParen),
                    (b')', _) => self.single(TokenKind::RightParen),
                    (b';', _) => self.single(TokenKind::Semicolon),
                    (b',', _) => self.single(TokenKind::Comma),
                    (b'.', _) => self.single(TokenKind::Dot),
                    (b'=', _) => self.single(TokenKind::Equal),
                    (b'*', _) => self.single(TokenKind::Star),
                    _ => {
                        self.advance();
                        self.diagnostics.push(Diagnostic::new(
                            "QF001",
                            format!("unexpected character `{}`", char::from(byte)),
                            self.source_name,
                            SourceSpan {
                                start,
                                end: self.index,
                                line,
                                column,
                            },
                        ));
                        continue;
                    }
                };
                self.push(kind, start, line, column);
            }
        }
        (self.tokens, self.diagnostics)
    }

    fn skip_layout(&mut self) -> bool {
        let mut skipped = false;
        while let Some(byte) = self.source.get(self.index).copied() {
            if byte.is_ascii_whitespace() {
                self.advance();
                skipped = true;
            } else if byte == b'/' && self.source.get(self.index + 1) == Some(&b'/') {
                while self
                    .source
                    .get(self.index)
                    .is_some_and(|value| *value != b'\n')
                {
                    self.advance();
                }
                skipped = true;
            } else if byte == b'/' && self.source.get(self.index + 1) == Some(&b'*') {
                let start = self.current_span(0);
                self.advance();
                self.advance();
                let mut closed = false;
                while self.index < self.source.len() {
                    if self.source.get(self.index) == Some(&b'*')
                        && self.source.get(self.index + 1) == Some(&b'/')
                    {
                        self.advance();
                        self.advance();
                        closed = true;
                        break;
                    }
                    self.advance();
                }
                if !closed {
                    self.diagnostics.push(Diagnostic::new(
                        "QF002",
                        "unterminated block comment",
                        self.source_name,
                        start,
                    ));
                }
                skipped = true;
            } else {
                break;
            }
        }
        skipped
    }

    fn lex_string(&mut self, start: usize, line: usize, column: usize) {
        self.advance();
        let mut value = String::new();
        let mut closed = false;
        while let Some(byte) = self.source.get(self.index).copied() {
            if byte == b'"' {
                self.advance();
                closed = true;
                break;
            }
            if byte == b'\n' || byte == b'\r' {
                break;
            }
            if byte == b'\\' {
                self.advance();
                let Some(escaped) = self.source.get(self.index).copied() else {
                    break;
                };
                match escaped {
                    b'"' => value.push('"'),
                    b'\\' => value.push('\\'),
                    b'n' => value.push('\n'),
                    b'r' => value.push('\r'),
                    b't' => value.push('\t'),
                    _ => {
                        self.diagnostics.push(Diagnostic::new(
                            "QF001",
                            "unsupported string escape",
                            self.source_name,
                            self.current_span(1),
                        ));
                        value.push(char::from(escaped));
                    }
                }
                self.advance();
            } else {
                value.push(char::from(byte));
                self.advance();
            }
        }
        if closed {
            self.push(TokenKind::StringLiteral(value), start, line, column);
        } else {
            self.diagnostics.push(Diagnostic::new(
                "QF002",
                "unterminated string literal",
                self.source_name,
                SourceSpan {
                    start,
                    end: self.index,
                    line,
                    column,
                },
            ));
        }
    }

    fn single(&mut self, kind: TokenKind) -> TokenKind {
        self.advance();
        kind
    }

    fn push(&mut self, kind: TokenKind, start: usize, line: usize, column: usize) {
        self.tokens.push(Token {
            kind,
            span: SourceSpan {
                start,
                end: self.index,
                line,
                column,
            },
        });
    }

    fn advance(&mut self) {
        if self.source.get(self.index) == Some(&b'\n') {
            self.line += 1;
            self.column = 1;
        } else {
            self.column += 1;
        }
        self.index += 1;
    }

    fn current_span(&self, width: usize) -> SourceSpan {
        SourceSpan {
            start: self.index,
            end: self.index.saturating_add(width).min(self.source.len()),
            line: self.line,
            column: self.column,
        }
    }
}

struct Parser<'a> {
    source_name: &'a str,
    tokens: Vec<Token>,
    index: usize,
    diagnostics: Vec<Diagnostic>,
}

impl<'a> Parser<'a> {
    fn new(source_name: &'a str, tokens: Vec<Token>) -> Self {
        Self {
            source_name,
            tokens,
            index: 0,
            diagnostics: Vec::new(),
        }
    }

    fn parse(&mut self) -> Option<Module> {
        let start = self.expect_keyword("module")?;
        let (name, _) = self.expect_identifier("module name")?;
        self.expect_keyword("version")?;
        let (version, version_span) = self.expect_integer("language version")?;
        if version != LANGUAGE_VERSION {
            self.error(
                "QF003",
                format!("unsupported language version {version}"),
                version_span,
            );
        }
        self.expect_punctuation(Punctuation::LeftBrace, "`{`")?;

        let mut imports = Vec::new();
        let mut items = Vec::new();
        while !self.at_end() && !self.check_punctuation(Punctuation::RightBrace) {
            let Some(keyword) = self.peek_identifier().map(str::to_owned) else {
                let span = self.peek_span();
                self.error("QF001", "expected a module item", span);
                self.index += 1;
                continue;
            };
            match keyword.as_str() {
                "import" => {
                    if let Some(import) = self.parse_import() {
                        imports.push(import);
                    }
                }
                "horizon" => {
                    if let Some(setting) = self.parse_bounded_setting("horizon", false) {
                        items.push(Item::Horizon(setting));
                    }
                }
                "transducer_states" => {
                    if let Some(setting) = self.parse_bounded_setting("transducer_states", true) {
                        items.push(Item::TransducerStates(setting));
                    }
                }
                "private" => self.push_block(&mut items, BlockKind::Private),
                "public" => self.push_block(&mut items, BlockKind::Public),
                "action" => self.push_block(&mut items, BlockKind::Action),
                "quotient" => self.push_block(&mut items, BlockKind::Quotient),
                "observer" => self.push_block(&mut items, BlockKind::Observer),
                "fault" => self.push_block(&mut items, BlockKind::Fault),
                "utility" => self.push_block(&mut items, BlockKind::Utility),
                "objective" => self.push_block(&mut items, BlockKind::Objective),
                "release" => self.push_block(&mut items, BlockKind::Release),
                _ => {
                    let span = self.peek_span();
                    self.error("QF021", format!("unknown module keyword `{keyword}`"), span);
                    self.skip_unknown_item();
                }
            }
        }
        let end = self.expect_punctuation(Punctuation::RightBrace, "`}`")?;
        if !self.at_end() {
            self.error("QF001", "trailing tokens after module", self.peek_span());
        }
        Some(Module {
            name,
            version,
            imports,
            items,
            span: start.merge(end),
        })
    }

    fn push_block(&mut self, items: &mut Vec<Item>, kind: BlockKind) {
        if let Some(block) = self.parse_block(kind) {
            items.push(Item::Block(block));
        }
    }

    fn parse_import(&mut self) -> Option<ImportDecl> {
        let start = self.expect_keyword("import")?;
        let token = self.take()?;
        let path = match token.kind {
            TokenKind::StringLiteral(path) if !path.is_empty() => path,
            _ => {
                self.error("QF001", "expected a non-empty import string", token.span);
                return None;
            }
        };
        let end = self.expect_punctuation(Punctuation::Semicolon, "`;`")?;
        Some(ImportDecl {
            path,
            span: start.merge(end),
        })
    }

    fn parse_bounded_setting(
        &mut self,
        keyword: &str,
        has_less_equal: bool,
    ) -> Option<BoundedSetting> {
        let start = self.expect_keyword(keyword)?;
        if has_less_equal {
            self.expect_punctuation(Punctuation::LessEqual, "`<=`")?;
        }
        let (value, _) = self.expect_integer("bounded integer")?;
        let end = self.expect_punctuation(Punctuation::Semicolon, "`;`")?;
        Some(BoundedSetting {
            value,
            span: start.merge(end),
        })
    }

    fn parse_block(&mut self, kind: BlockKind) -> Option<Block> {
        let start = self.expect_keyword(kind.keyword())?;
        let mut name = None;
        let mut argument = None;
        match kind {
            BlockKind::Action | BlockKind::Fault | BlockKind::Objective => {
                name = self.expect_identifier("block name").map(|(value, _)| value);
            }
            BlockKind::Observer => {
                name = self
                    .expect_identifier("observer name")
                    .map(|(value, _)| value);
                if self.consume_punctuation(Punctuation::LeftParen).is_some() {
                    argument = if self.check_punctuation(Punctuation::Star) {
                        self.index += 1;
                        Some("*".to_owned())
                    } else {
                        self.expect_identifier("observer argument")
                            .map(|(value, _)| value)
                    };
                    self.expect_punctuation(Punctuation::RightParen, "`)`")?;
                }
            }
            BlockKind::Obligation => {
                name = self
                    .expect_identifier("obligation name")
                    .map(|(value, _)| value);
            }
            BlockKind::Private
            | BlockKind::Public
            | BlockKind::Quotient
            | BlockKind::Utility
            | BlockKind::Release => {}
        }
        self.expect_punctuation(Punctuation::LeftBrace, "`{`")?;
        let mut clauses = Vec::new();
        while !self.at_end() && !self.check_punctuation(Punctuation::RightBrace) {
            let clause = if matches!(kind, BlockKind::Private | BlockKind::Public) {
                self.parse_field_clause()
            } else {
                self.parse_general_clause(kind)
            };
            if let Some(clause) = clause {
                clauses.push(clause);
            }
        }
        let end = self.expect_punctuation(Punctuation::RightBrace, "`}`")?;
        Some(Block {
            kind,
            name,
            argument,
            clauses,
            span: start.merge(end),
        })
    }

    fn parse_field_clause(&mut self) -> Option<Clause> {
        let (keyword, start) = self.expect_identifier("field type")?;
        match keyword.as_str() {
            "bool" | "slot" => {
                let kind = if keyword == "bool" {
                    FieldKind::Bool
                } else {
                    FieldKind::Slot
                };
                let (name, _) = self.expect_identifier("field name")?;
                let end = self.expect_punctuation(Punctuation::Semicolon, "`;`")?;
                Some(Clause::Field(FieldDecl {
                    kind,
                    name,
                    span: start.merge(end),
                }))
            }
            "enum" => {
                let (name, _) = self.expect_identifier("enum name")?;
                self.expect_punctuation(Punctuation::LeftBrace, "`{`")?;
                let mut variants = Vec::new();
                loop {
                    let (variant, _) = self.expect_identifier("enum variant")?;
                    variants.push(variant);
                    if self.consume_punctuation(Punctuation::Comma).is_none() {
                        break;
                    }
                    if self.check_punctuation(Punctuation::RightBrace) {
                        break;
                    }
                }
                self.expect_punctuation(Punctuation::RightBrace, "`}`")?;
                let end = self.expect_punctuation(Punctuation::Semicolon, "`;`")?;
                Some(Clause::Enum(EnumDecl {
                    name,
                    variants,
                    span: start.merge(end),
                }))
            }
            _ => {
                self.error("QF021", format!("unknown field type `{keyword}`"), start);
                self.skip_to_semicolon();
                None
            }
        }
    }

    fn parse_general_clause(&mut self, block_kind: BlockKind) -> Option<Clause> {
        let (keyword, start) = self.expect_identifier("clause keyword")?;
        if block_kind == BlockKind::Utility && keyword == "obligation" {
            self.index -= 1;
            return self.parse_block(BlockKind::Obligation).map(Clause::Block);
        }
        let assignment = self.check_punctuation(Punctuation::Equal)
            || self.check_punctuation(Punctuation::EqualEqual);
        if !(known_clause(block_kind, &keyword) || block_kind == BlockKind::Release && assignment) {
            self.error(
                "QF021",
                format!(
                    "unknown `{}` clause keyword `{keyword}`",
                    block_kind.keyword()
                ),
                start,
            );
            self.skip_to_semicolon();
            return None;
        }
        if assignment {
            let operator = if self.consume_punctuation(Punctuation::Equal).is_some() {
                AssignmentOperator::Set
            } else {
                self.expect_punctuation(Punctuation::EqualEqual, "`==`")?;
                AssignmentOperator::Equal
            };
            let (expression, end) = self.collect_value_tokens()?;
            Some(Clause::Assignment(Assignment {
                target: keyword,
                operator,
                expression,
                span: start.merge(end),
            }))
        } else {
            let (arguments, end) = self.collect_value_tokens()?;
            Some(Clause::Directive(Directive {
                keyword,
                arguments,
                span: start.merge(end),
            }))
        }
    }

    fn collect_value_tokens(&mut self) -> Option<(Vec<ValueToken>, SourceSpan)> {
        let mut values = Vec::new();
        while !self.at_end() && !self.check_punctuation(Punctuation::Semicolon) {
            if self.check_punctuation(Punctuation::RightBrace) {
                self.error("QF001", "missing `;` before `}`", self.peek_span());
                return None;
            }
            let token = self.take()?;
            let value = match token.kind {
                TokenKind::Identifier(value) => ValueToken::Identifier(value),
                TokenKind::Integer(value) => ValueToken::Integer(value),
                TokenKind::StringLiteral(value) => ValueToken::StringLiteral(value),
                TokenKind::Dot => ValueToken::Dot,
                TokenKind::Range => ValueToken::Range,
                TokenKind::LessEqual => ValueToken::LessEqual,
                TokenKind::EqualEqual => ValueToken::Equal,
                TokenKind::Star => ValueToken::Star,
                TokenKind::LeftParen => ValueToken::LeftParen,
                TokenKind::RightParen => ValueToken::RightParen,
                TokenKind::Comma => ValueToken::Comma,
                _ => {
                    self.error("QF001", "invalid token in clause", token.span);
                    continue;
                }
            };
            values.push(value);
        }
        let end = self.expect_punctuation(Punctuation::Semicolon, "`;`")?;
        Some((values, end))
    }

    fn skip_unknown_item(&mut self) {
        self.index += 1;
        if self.consume_punctuation(Punctuation::LeftBrace).is_some() {
            let mut depth = 1_usize;
            while !self.at_end() && depth > 0 {
                if self.consume_punctuation(Punctuation::LeftBrace).is_some() {
                    depth += 1;
                } else if self.consume_punctuation(Punctuation::RightBrace).is_some() {
                    depth -= 1;
                } else {
                    self.index += 1;
                }
            }
        } else {
            self.skip_to_semicolon();
        }
    }

    fn skip_to_semicolon(&mut self) {
        while !self.at_end() && !self.check_punctuation(Punctuation::Semicolon) {
            if self.check_punctuation(Punctuation::RightBrace) {
                return;
            }
            self.index += 1;
        }
        if self.check_punctuation(Punctuation::Semicolon) {
            self.index += 1;
        }
    }

    fn expect_keyword(&mut self, expected: &str) -> Option<SourceSpan> {
        let token = self.take()?;
        match token.kind {
            TokenKind::Identifier(value) if value == expected => Some(token.span),
            _ => {
                self.error(
                    "QF001",
                    format!("expected keyword `{expected}`"),
                    token.span,
                );
                None
            }
        }
    }

    fn expect_identifier(&mut self, expected: &str) -> Option<(String, SourceSpan)> {
        let token = self.take()?;
        match token.kind {
            TokenKind::Identifier(value) => Some((value, token.span)),
            _ => {
                self.error("QF001", format!("expected {expected}"), token.span);
                None
            }
        }
    }

    fn expect_integer(&mut self, expected: &str) -> Option<(u64, SourceSpan)> {
        let token = self.take()?;
        match token.kind {
            TokenKind::Integer(value) => Some((value, token.span)),
            _ => {
                self.error("QF001", format!("expected {expected}"), token.span);
                None
            }
        }
    }

    fn expect_punctuation(
        &mut self,
        punctuation: Punctuation,
        expected: &str,
    ) -> Option<SourceSpan> {
        if let Some(span) = self.consume_punctuation(punctuation) {
            Some(span)
        } else {
            self.error("QF001", format!("expected {expected}"), self.peek_span());
            None
        }
    }

    fn consume_punctuation(&mut self, punctuation: Punctuation) -> Option<SourceSpan> {
        if self.check_punctuation(punctuation) {
            let span = self.tokens[self.index].span;
            self.index += 1;
            Some(span)
        } else {
            None
        }
    }

    fn check_punctuation(&self, punctuation: Punctuation) -> bool {
        self.tokens
            .get(self.index)
            .is_some_and(|token| punctuation.matches(&token.kind))
    }

    fn peek_identifier(&self) -> Option<&str> {
        match self.tokens.get(self.index).map(|token| &token.kind) {
            Some(TokenKind::Identifier(value)) => Some(value),
            _ => None,
        }
    }

    fn peek_span(&self) -> SourceSpan {
        self.tokens
            .get(self.index)
            .map_or_else(SourceSpan::origin, |token| token.span)
    }

    fn take(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.index).cloned();
        if token.is_some() {
            self.index += 1;
        } else {
            self.error("QF001", "unexpected end of source", self.peek_span());
        }
        token
    }

    fn at_end(&self) -> bool {
        self.index >= self.tokens.len()
    }

    fn error(&mut self, code: &'static str, message: impl Into<String>, span: SourceSpan) {
        self.diagnostics
            .push(Diagnostic::new(code, message, self.source_name, span));
    }
}

#[derive(Clone, Copy)]
enum Punctuation {
    LeftBrace,
    RightBrace,
    LeftParen,
    RightParen,
    Semicolon,
    Comma,
    LessEqual,
    Equal,
    EqualEqual,
    Star,
}

impl Punctuation {
    const fn matches(self, kind: &TokenKind) -> bool {
        matches!(
            (self, kind),
            (Self::LeftBrace, TokenKind::LeftBrace)
                | (Self::RightBrace, TokenKind::RightBrace)
                | (Self::LeftParen, TokenKind::LeftParen)
                | (Self::RightParen, TokenKind::RightParen)
                | (Self::Semicolon, TokenKind::Semicolon)
                | (Self::Comma, TokenKind::Comma)
                | (Self::LessEqual, TokenKind::LessEqual)
                | (Self::Equal, TokenKind::Equal)
                | (Self::EqualEqual, TokenKind::EqualEqual)
                | (Self::Star, TokenKind::Star)
        )
    }
}

fn known_clause(kind: BlockKind, keyword: &str) -> bool {
    match kind {
        BlockKind::Action => matches!(keyword, "service" | "release_window" | "exactly_once"),
        BlockKind::Quotient => matches!(keyword, "by" | "erase"),
        BlockKind::Observer => matches!(keyword, "sees" | "combines"),
        BlockKind::Fault => matches!(
            keyword,
            "max_drop" | "reorder" | "duplicate" | "disconnect" | "reconnect" | "endpoint_failure"
        ),
        BlockKind::Utility => matches!(
            keyword,
            "preserve" | "deadline" | "unauthorized_actions" | "forbid"
        ),
        BlockKind::Objective => keyword == "minimize",
        BlockKind::Obligation => matches!(keyword, "exactly_once" | "release" | "under"),
        BlockKind::Release => true,
        BlockKind::Private | BlockKind::Public => false,
    }
}

fn format_item(output: &mut String, item: &Item, depth: usize) {
    let indent = "  ".repeat(depth);
    match item {
        Item::Horizon(setting) => {
            let _ = writeln!(output, "{indent}horizon {};", setting.value);
        }
        Item::TransducerStates(setting) => {
            let _ = writeln!(output, "{indent}transducer_states <= {};", setting.value);
        }
        Item::Block(block) => format_block(output, block, depth),
    }
}

fn format_block(output: &mut String, block: &Block, depth: usize) {
    let indent = "  ".repeat(depth);
    let _ = write!(output, "{indent}{}", block.kind.keyword());
    if let Some(name) = &block.name {
        let _ = write!(output, " {name}");
    }
    if let Some(argument) = &block.argument {
        let _ = write!(output, "({argument})");
    }
    output.push_str(" {\n");
    for clause in &block.clauses {
        format_clause(output, clause, depth + 1);
    }
    let _ = writeln!(output, "{indent}}}");
}

fn format_clause(output: &mut String, clause: &Clause, depth: usize) {
    let indent = "  ".repeat(depth);
    match clause {
        Clause::Field(field) => {
            let _ = writeln!(output, "{indent}{} {};", field.kind.keyword(), field.name);
        }
        Clause::Enum(declaration) => {
            let _ = writeln!(
                output,
                "{indent}enum {} {{ {} }};",
                declaration.name,
                declaration.variants.join(", ")
            );
        }
        Clause::Directive(directive) => {
            let _ = write!(output, "{indent}{}", directive.keyword);
            let arguments = format_values(&directive.arguments);
            if !arguments.is_empty() {
                let _ = write!(output, " {arguments}");
            }
            output.push_str(";\n");
        }
        Clause::Assignment(assignment) => {
            let operator = match assignment.operator {
                AssignmentOperator::Set => "=",
                AssignmentOperator::Equal => "==",
            };
            let expression = format_values(&assignment.expression);
            let _ = writeln!(
                output,
                "{indent}{} {operator} {expression};",
                assignment.target
            );
        }
        Clause::Block(block) => format_block(output, block, depth),
    }
}

fn format_values(values: &[ValueToken]) -> String {
    let mut output = String::new();
    let mut previous: Option<&ValueToken> = None;
    for value in values {
        let tight_left = matches!(
            value,
            ValueToken::Dot | ValueToken::Range | ValueToken::RightParen | ValueToken::Comma
        );
        let tight_right = previous.is_some_and(|token| {
            matches!(
                token,
                ValueToken::Dot | ValueToken::Range | ValueToken::LeftParen
            )
        });
        if !output.is_empty() && !tight_left && !tight_right {
            output.push(' ');
        }
        match value {
            ValueToken::Identifier(value) => output.push_str(value),
            ValueToken::Integer(value) => {
                let _ = write!(output, "{value}");
            }
            ValueToken::StringLiteral(value) => {
                let _ = write!(output, "\"{}\"", escape_string(value));
            }
            ValueToken::Dot => output.push('.'),
            ValueToken::Range => output.push_str(".."),
            ValueToken::LessEqual => output.push_str("<="),
            ValueToken::Equal => output.push_str("=="),
            ValueToken::Star => output.push('*'),
            ValueToken::LeftParen => output.push('('),
            ValueToken::RightParen => output.push(')'),
            ValueToken::Comma => output.push(','),
        }
        if matches!(value, ValueToken::Comma) {
            output.push(' ');
        }
        previous = Some(value);
    }
    output.trim_end().to_owned()
}

fn escape_string(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

const fn is_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

const fn is_identifier_continue(byte: u8) -> bool {
    is_identifier_start(byte) || byte.is_ascii_digit() || byte == b'-'
}

fn source_position(source: &str, offset: usize) -> (usize, usize) {
    let prefix = &source[..offset];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix.len() + 1, |(_, tail)| tail.len() + 1);
    (line, column)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
        // A complete syntax smoke specification.
        module menfugu_release version 1 {
          horizon 32;
          transducer_states <= 4;

          private {
            bool permit_ready;
            enum margin { low, high };
          }

          public {
            bool network_available;
            slot now;
          }

          action soft_inflate {
            service menfugu;
            release_window 16..31;
            exactly_once;
          }

          quotient {
            by action soft_inflate;
            erase permit_ready;
            erase margin;
          }

          observer network {
            sees send;
            sees packet_size;
          }

          observer service(menfugu) {
            sees action_slot;
          }

          fault bounded_loss {
            max_drop 1 per window 4;
            reorder <= 2;
          }

          utility {
            obligation soft_inflate {
              exactly_once;
              release 16..31;
              under fault bounded_loss;
            }
            forbid unauthorized_action;
          }

          objective lexicographic {
            minimize dummy_frames;
            minimize worst_latency;
          }

          release {
            send_slot = public.now;
          }
        }
    "#;

    #[test]
    fn parses_restricted_language_and_preserves_spans() {
        let module = parse_module("valid.qf", VALID, ParseLimits::default()).unwrap();
        assert_eq!(module.name, "menfugu_release");
        assert_eq!(module.version, LANGUAGE_VERSION);
        assert_eq!(module.span.line, 3);
        assert_eq!(module.items.len(), 12);
    }

    #[test]
    fn canonical_format_is_idempotent() {
        let module = parse_module("valid.qf", VALID, ParseLimits::default()).unwrap();
        let once = format_module(&module);
        let reparsed = parse_module("formatted.qf", &once, ParseLimits::default()).unwrap();
        let twice = format_module(&reparsed);
        assert_eq!(once, twice);
        assert!(once.contains("release_window 16..31;"));
        assert!(once.contains("observer service(menfugu)"));
    }

    #[test]
    fn unknown_keyword_has_positioned_diagnostic() {
        let source = "module bad version 1 {\n  mystery 1;\n}";
        let diagnostics = parse_module("bad.qf", source, ParseLimits::default()).unwrap_err();
        let error = diagnostics
            .iter()
            .find(|error| error.code == "QF021")
            .unwrap();
        assert_eq!((error.span.line, error.span.column), (2, 3));
        assert!(error.to_string().contains("bad.qf:2:3"));
    }

    #[test]
    fn integer_overflow_is_rejected() {
        let source = "module bad version 1 { horizon 18446744073709551616; }";
        let diagnostics = parse_module("overflow.qf", source, ParseLimits::default()).unwrap_err();
        assert!(diagnostics.iter().any(|error| error.code == "QF004"));
    }

    #[test]
    fn source_and_token_limits_are_enforced() {
        let source = "module small version 1 {}";
        let limits = ParseLimits {
            max_source_bytes: 4,
            ..ParseLimits::default()
        };
        assert_eq!(
            parse_module("large.qf", source, limits).unwrap_err()[0].code,
            "QF005"
        );

        let limits = ParseLimits {
            max_tokens: 2,
            ..ParseLimits::default()
        };
        assert!(parse_module("tokens.qf", source, limits)
            .unwrap_err()
            .iter()
            .any(|error| error.code == "QF008"));
    }

    struct MemoryLoader {
        sources: BTreeMap<String, String>,
    }

    impl ModuleLoader for MemoryLoader {
        fn load(&self, _importer: Option<&str>, requested: &str) -> Result<LoadedSource, String> {
            self.sources
                .get(requested)
                .cloned()
                .map(|source| LoadedSource {
                    canonical_name: requested.to_owned(),
                    source,
                })
                .ok_or_else(|| format!("missing {requested}"))
        }
    }

    #[test]
    fn imports_form_a_bounded_graph() {
        let loader = MemoryLoader {
            sources: BTreeMap::from([
                (
                    "root.qf".to_owned(),
                    "module root version 1 { import \"shared.qf\"; horizon 8; }".to_owned(),
                ),
                (
                    "shared.qf".to_owned(),
                    "module shared version 1 { horizon 4; }".to_owned(),
                ),
            ]),
        };
        let graph = parse_module_graph("root.qf", &loader, ParseLimits::default()).unwrap();
        assert_eq!(graph.root, "root.qf");
        assert_eq!(graph.modules.len(), 2);
    }

    #[test]
    fn import_cycle_is_rejected() {
        let loader = MemoryLoader {
            sources: BTreeMap::from([
                (
                    "a.qf".to_owned(),
                    "module a version 1 { import \"b.qf\"; }".to_owned(),
                ),
                (
                    "b.qf".to_owned(),
                    "module b version 1 { import \"a.qf\"; }".to_owned(),
                ),
            ]),
        };
        let diagnostics = parse_module_graph("a.qf", &loader, ParseLimits::default()).unwrap_err();
        assert!(diagnostics.iter().any(|error| error.code == "QF006"));
    }

    #[test]
    fn arbitrary_ascii_input_does_not_panic() {
        for byte in 0_u8..=127 {
            let source = format!("module fuzz version 1 {{ {} }}", char::from(byte));
            let _ = parse_module("fuzz.qf", &source, ParseLimits::default());
        }
    }
}
