//! Canonical release-machine equivalence modulo state names and unreachable states.

use std::collections::VecDeque;
use std::error::Error;
use std::fmt::{Display, Formatter};

use sha2::{Digest, Sha256};

use crate::ReleaseMachine;

const HASH_DOMAIN: &[u8] = b"NOTICER_K7_CANONICAL_RELEASE_MACHINE_V1\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalCell {
    pub next_state: u32,
    pub output: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalMachine {
    pub state_count: u32,
    pub symbol_count: u32,
    pub cells: Vec<CanonicalCell>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TemplateRelation {
    Equivalent,
    NonEquivalent,
    NoTemplate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CanonicalizationError {
    EmptyStateDomain,
    EmptySymbolDomain,
    CellCountOverflow,
    CellCountMismatch {
        expected: usize,
        actual: usize,
    },
    UnknownTarget {
        state: u32,
        symbol: u32,
        target: u32,
    },
}

impl Display for CanonicalizationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyStateDomain => formatter.write_str("machine has no states"),
            Self::EmptySymbolDomain => formatter.write_str("machine has no symbols"),
            Self::CellCountOverflow => formatter.write_str("machine cell count overflowed"),
            Self::CellCountMismatch { expected, actual } => write!(
                formatter,
                "machine has {actual} cells but {expected} are required"
            ),
            Self::UnknownTarget {
                state,
                symbol,
                target,
            } => write!(
                formatter,
                "state {state} symbol {symbol} targets unknown state {target}"
            ),
        }
    }
}

impl Error for CanonicalizationError {}

pub fn canonicalize_release_machine(
    machine: &ReleaseMachine,
) -> Result<CanonicalMachine, CanonicalizationError> {
    let state_count = usize::try_from(machine.state_count)
        .map_err(|_| CanonicalizationError::CellCountOverflow)?;
    let symbol_count = usize::try_from(machine.symbol_count)
        .map_err(|_| CanonicalizationError::CellCountOverflow)?;
    if state_count == 0 {
        return Err(CanonicalizationError::EmptyStateDomain);
    }
    if symbol_count == 0 {
        return Err(CanonicalizationError::EmptySymbolDomain);
    }
    let expected = state_count
        .checked_mul(symbol_count)
        .ok_or(CanonicalizationError::CellCountOverflow)?;
    if machine.cells.len() != expected {
        return Err(CanonicalizationError::CellCountMismatch {
            expected,
            actual: machine.cells.len(),
        });
    }
    for (index, cell) in machine.cells.iter().enumerate() {
        if usize::try_from(cell.next_state).map_or(true, |target| target >= state_count) {
            return Err(CanonicalizationError::UnknownTarget {
                state: u32::try_from(index / symbol_count)
                    .map_err(|_| CanonicalizationError::CellCountOverflow)?,
                symbol: u32::try_from(index % symbol_count)
                    .map_err(|_| CanonicalizationError::CellCountOverflow)?,
                target: cell.next_state,
            });
        }
    }

    let mut old_to_new = vec![None; state_count];
    let mut reachable = Vec::with_capacity(state_count);
    let mut queue = VecDeque::new();
    old_to_new[0] = Some(0_u32);
    reachable.push(0_usize);
    queue.push_back(0_usize);
    while let Some(state) = queue.pop_front() {
        for symbol in 0..symbol_count {
            let target = usize::try_from(machine.cells[state * symbol_count + symbol].next_state)
                .map_err(|_| CanonicalizationError::CellCountOverflow)?;
            if old_to_new[target].is_none() {
                let canonical = u32::try_from(reachable.len())
                    .map_err(|_| CanonicalizationError::CellCountOverflow)?;
                old_to_new[target] = Some(canonical);
                reachable.push(target);
                queue.push_back(target);
            }
        }
    }

    let mut cells = Vec::with_capacity(reachable.len() * symbol_count);
    for old_state in &reachable {
        for symbol in 0..symbol_count {
            let cell = &machine.cells[*old_state * symbol_count + symbol];
            let target = usize::try_from(cell.next_state)
                .map_err(|_| CanonicalizationError::CellCountOverflow)?;
            cells.push(CanonicalCell {
                next_state: old_to_new[target].expect("reachable transition target"),
                output: cell.output,
            });
        }
    }
    Ok(CanonicalMachine {
        state_count: u32::try_from(reachable.len())
            .map_err(|_| CanonicalizationError::CellCountOverflow)?,
        symbol_count: machine.symbol_count,
        cells,
    })
}

pub fn canonical_machine_sha256(machine: &ReleaseMachine) -> Result<String, CanonicalizationError> {
    let canonical = canonicalize_release_machine(machine)?;
    let mut hasher = Sha256::new();
    hasher.update(HASH_DOMAIN);
    hasher.update(canonical.state_count.to_be_bytes());
    hasher.update(canonical.symbol_count.to_be_bytes());
    for cell in canonical.cells {
        hasher.update(cell.next_state.to_be_bytes());
        hasher.update(cell.output.to_be_bytes());
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn compare_to_author_template(
    discovered: &ReleaseMachine,
    author_template: Option<&ReleaseMachine>,
) -> Result<TemplateRelation, CanonicalizationError> {
    let discovered = canonicalize_release_machine(discovered)?;
    let Some(template) = author_template else {
        return Ok(TemplateRelation::NoTemplate);
    };
    let template = canonicalize_release_machine(template)?;
    Ok(if discovered == template {
        TemplateRelation::Equivalent
    } else {
        TemplateRelation::NonEquivalent
    })
}
