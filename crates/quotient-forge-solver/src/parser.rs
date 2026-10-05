use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParsedSolverOutput {
    Sat(BTreeMap<String, i64>),
    Unsat,
    Unknown(Option<String>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseModelError {
    Empty,
    UnknownStatus(String),
    UnexpectedClose,
    UnclosedList,
    MissingAtom,
    InvalidInteger { name: String, value: String },
    DuplicateDefinition(String),
    MissingDefinition(String),
    ResourceLimit(&'static str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SolverOutputLimits {
    pub max_bytes: usize,
    pub max_tokens: usize,
    pub max_atom_bytes: usize,
    pub max_depth: usize,
    pub max_variables: usize,
}

impl Default for SolverOutputLimits {
    fn default() -> Self {
        Self {
            max_bytes: 1_048_576,
            max_tokens: 262_144,
            max_atom_bytes: 4_096,
            max_depth: 256,
            max_variables: 65_536,
        }
    }
}

impl std::fmt::Display for ParseModelError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "solver output parse error: {self:?}")
    }
}

impl std::error::Error for ParseModelError {}

pub fn parse_solver_output(
    output: &str,
    expected_variables: &[String],
) -> Result<ParsedSolverOutput, ParseModelError> {
    parse_solver_output_bounded(output, expected_variables, SolverOutputLimits::default())
}

pub fn parse_solver_output_bounded(
    output: &str,
    expected_variables: &[String],
    limits: SolverOutputLimits,
) -> Result<ParsedSolverOutput, ParseModelError> {
    preflight(output, expected_variables.len(), limits)?;
    let tokens = tokenize(output);
    let mut position = 0;
    while matches!(tokens.get(position), Some(Token::Atom(value)) if value == "success") {
        position += 1;
    }
    let status = match tokens.get(position) {
        Some(Token::Atom(value)) => value.clone(),
        _ => return Err(ParseModelError::Empty),
    };
    position += 1;
    match status.as_str() {
        "unsat" => Ok(ParsedSolverOutput::Unsat),
        "unknown" => Ok(ParsedSolverOutput::Unknown(reason_unknown(
            &tokens[position..],
        ))),
        "sat" => {
            let expressions = parse_all(&tokens[position..])?;
            let expected: BTreeSet<_> = expected_variables.iter().cloned().collect();
            let mut definitions = BTreeMap::new();
            for expression in &expressions {
                collect_definitions(expression, &expected, &mut definitions)?;
            }
            for name in expected_variables {
                if !definitions.contains_key(name) {
                    return Err(ParseModelError::MissingDefinition(name.clone()));
                }
            }
            Ok(ParsedSolverOutput::Sat(definitions))
        }
        other => Err(ParseModelError::UnknownStatus(other.to_owned())),
    }
}

fn preflight(
    output: &str,
    variable_count: usize,
    limits: SolverOutputLimits,
) -> Result<(), ParseModelError> {
    if limits.max_bytes == 0
        || limits.max_tokens == 0
        || limits.max_atom_bytes == 0
        || limits.max_depth == 0
        || limits.max_variables == 0
    {
        return Err(ParseModelError::ResourceLimit("invalid_limits"));
    }
    if output.len() > limits.max_bytes {
        return Err(ParseModelError::ResourceLimit("bytes"));
    }
    if variable_count > limits.max_variables {
        return Err(ParseModelError::ResourceLimit("variables"));
    }
    let mut depth = 0_usize;
    let mut tokens = 0_usize;
    let mut atom_bytes = 0_usize;
    let mut in_comment = false;
    for byte in output.bytes() {
        if in_comment {
            if byte == b'\n' {
                in_comment = false;
            }
            continue;
        }
        match byte {
            b';' => in_comment = true,
            b'(' => {
                depth = depth.saturating_add(1);
                tokens = tokens.saturating_add(1);
                atom_bytes = 0;
                if depth > limits.max_depth {
                    return Err(ParseModelError::ResourceLimit("depth"));
                }
            }
            b')' => {
                depth = depth.saturating_sub(1);
                tokens = tokens.saturating_add(1);
                atom_bytes = 0;
            }
            value if value.is_ascii_whitespace() => atom_bytes = 0,
            _ => {
                if atom_bytes == 0 {
                    tokens = tokens.saturating_add(1);
                }
                atom_bytes = atom_bytes.saturating_add(1);
                if atom_bytes > limits.max_atom_bytes {
                    return Err(ParseModelError::ResourceLimit("atom"));
                }
            }
        }
        if tokens > limits.max_tokens {
            return Err(ParseModelError::ResourceLimit("tokens"));
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Token {
    Open,
    Close,
    Atom(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Expression {
    Atom(String),
    List(Vec<Expression>),
}

fn tokenize(input: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut atom = String::new();
    let mut comment = false;
    let mut quoted = false;
    for character in input.chars() {
        if comment {
            if character == '\n' {
                comment = false;
            }
            continue;
        }
        if quoted {
            atom.push(character);
            if character == '"' {
                quoted = false;
                flush_atom(&mut atom, &mut tokens);
            }
            continue;
        }
        match character {
            ';' => {
                flush_atom(&mut atom, &mut tokens);
                comment = true;
            }
            '"' => {
                flush_atom(&mut atom, &mut tokens);
                quoted = true;
                atom.push(character);
            }
            '(' => {
                flush_atom(&mut atom, &mut tokens);
                tokens.push(Token::Open);
            }
            ')' => {
                flush_atom(&mut atom, &mut tokens);
                tokens.push(Token::Close);
            }
            value if value.is_whitespace() => flush_atom(&mut atom, &mut tokens),
            value => atom.push(value),
        }
    }
    flush_atom(&mut atom, &mut tokens);
    tokens
}

fn flush_atom(atom: &mut String, tokens: &mut Vec<Token>) {
    if !atom.is_empty() {
        tokens.push(Token::Atom(std::mem::take(atom)));
    }
}

fn parse_all(tokens: &[Token]) -> Result<Vec<Expression>, ParseModelError> {
    let mut expressions = Vec::new();
    let mut position = 0;
    while position < tokens.len() {
        expressions.push(parse_expression(tokens, &mut position)?);
    }
    Ok(expressions)
}

fn parse_expression(tokens: &[Token], position: &mut usize) -> Result<Expression, ParseModelError> {
    match tokens.get(*position) {
        Some(Token::Atom(value)) => {
            *position += 1;
            Ok(Expression::Atom(value.clone()))
        }
        Some(Token::Open) => {
            *position += 1;
            let mut values = Vec::new();
            loop {
                match tokens.get(*position) {
                    Some(Token::Close) => {
                        *position += 1;
                        return Ok(Expression::List(values));
                    }
                    Some(_) => values.push(parse_expression(tokens, position)?),
                    None => return Err(ParseModelError::UnclosedList),
                }
            }
        }
        Some(Token::Close) => Err(ParseModelError::UnexpectedClose),
        None => Err(ParseModelError::MissingAtom),
    }
}

fn collect_definitions(
    expression: &Expression,
    expected: &BTreeSet<String>,
    definitions: &mut BTreeMap<String, i64>,
) -> Result<(), ParseModelError> {
    let Expression::List(values) = expression else {
        return Ok(());
    };
    if matches!(values.first(), Some(Expression::Atom(name)) if name == "define-fun") {
        if let [_, Expression::Atom(name), Expression::List(arguments), Expression::Atom(sort), value] =
            values.as_slice()
        {
            if arguments.is_empty() && sort == "Int" && expected.contains(name) {
                let integer =
                    integer_value(value).ok_or_else(|| ParseModelError::InvalidInteger {
                        name: name.clone(),
                        value: expression_text(value),
                    })?;
                if definitions.insert(name.clone(), integer).is_some() {
                    return Err(ParseModelError::DuplicateDefinition(name.clone()));
                }
            }
        }
    }
    for child in values {
        collect_definitions(child, expected, definitions)?;
    }
    Ok(())
}

fn integer_value(expression: &Expression) -> Option<i64> {
    match expression {
        Expression::Atom(value) => value.parse().ok(),
        Expression::List(values) => match values.as_slice() {
            [Expression::Atom(operator), Expression::Atom(value)] if operator == "-" => {
                value.parse::<i64>().ok()?.checked_neg()
            }
            _ => None,
        },
    }
}

fn expression_text(expression: &Expression) -> String {
    match expression {
        Expression::Atom(value) => value.clone(),
        Expression::List(values) => format!(
            "({})",
            values
                .iter()
                .map(expression_text)
                .collect::<Vec<_>>()
                .join(" ")
        ),
    }
}

fn reason_unknown(tokens: &[Token]) -> Option<String> {
    tokens.iter().find_map(|token| match token {
        Token::Atom(value) if value.contains("timeout") || value.contains("resource") => {
            Some(value.trim_matches('"').to_owned())
        }
        _ => None,
    })
}
