use quotient_forge_check::{FieldId, Release};
use quotient_forge_synth::{MachineCell, ReleaseMachine, SynthesisProblem};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum RepairOperator {
    Cutoff {
        field: String,
        max_bytes: usize,
    },
    Bucket {
        field: String,
        width: i64,
    },
    FixedSize {
        field: String,
        bytes: usize,
    },
    Cover,
    FailureNormalization {
        field: String,
        normalized: String,
    },
    PublicRetryReconnect {
        retry_field: String,
        reconnect_field: String,
    },
    ServiceSeparation {
        service_field: String,
    },
    ReleaseWindow {
        slots: u32,
    },
}

impl RepairOperator {
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Cutoff { .. } => "cutoff",
            Self::Bucket { .. } => "bucket",
            Self::FixedSize { .. } => "fixed_size",
            Self::Cover => "cover",
            Self::FailureNormalization { .. } => "failure_normalization",
            Self::PublicRetryReconnect { .. } => "public_retry_reconnect",
            Self::ServiceSeparation { .. } => "service_separation",
            Self::ReleaseWindow { .. } => "release_window",
        }
    }

    pub(crate) const fn rank(&self) -> u8 {
        match self {
            Self::Cutoff { .. } => 0,
            Self::Bucket { .. } => 1,
            Self::FixedSize { .. } => 2,
            Self::Cover => 3,
            Self::FailureNormalization { .. } => 4,
            Self::PublicRetryReconnect { .. } => 5,
            Self::ServiceSeparation { .. } => 6,
            Self::ReleaseWindow { .. } => 7,
        }
    }

    pub(crate) fn validate(&self) -> bool {
        match self {
            Self::Cutoff { field, .. }
            | Self::FixedSize { field, .. }
            | Self::FailureNormalization { field, .. } => !field.is_empty(),
            Self::Bucket { field, width } => !field.is_empty() && *width > 0,
            Self::Cover => true,
            Self::PublicRetryReconnect {
                retry_field,
                reconnect_field,
            } => !retry_field.is_empty() && !reconnect_field.is_empty(),
            Self::ServiceSeparation { service_field } => !service_field.is_empty(),
            Self::ReleaseWindow { slots } => *slots > 0,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Variant {
    pub problem: SynthesisProblem,
    pub machine: ReleaseMachine,
    pub operators: Vec<RepairOperator>,
    pub added_cover_releases: u64,
    pub added_latency: u64,
}

impl Variant {
    pub(crate) fn apply(&self, operator: &RepairOperator) -> Option<Self> {
        let mut next = self.clone();
        let changed = match operator {
            RepairOperator::Cutoff { field, max_bytes } => {
                mutate_field(&mut next.problem.outputs, field, |value| {
                    let mut truncated = value.to_owned();
                    while truncated.len() > *max_bytes {
                        truncated.pop();
                    }
                    truncated
                })
            }
            RepairOperator::Bucket { field, width } => {
                mutate_field(&mut next.problem.outputs, field, |value| {
                    value.parse::<i64>().ok().map_or_else(
                        || value.to_owned(),
                        |number| number.div_euclid(*width).saturating_mul(*width).to_string(),
                    )
                })
            }
            RepairOperator::FixedSize { field, bytes } => {
                mutate_field(&mut next.problem.outputs, field, |_| {
                    format!("<fixed:{bytes}>")
                })
            }
            RepairOperator::Cover => apply_cover(&mut next),
            RepairOperator::FailureNormalization { field, normalized } => {
                mutate_field(&mut next.problem.outputs, field, |_| normalized.clone())
            }
            RepairOperator::PublicRetryReconnect {
                retry_field,
                reconnect_field,
            } => {
                let retry = mutate_field(&mut next.problem.outputs, retry_field, |_| {
                    "public".to_owned()
                });
                let reconnect = mutate_field(&mut next.problem.outputs, reconnect_field, |_| {
                    "public".to_owned()
                });
                retry || reconnect
            }
            RepairOperator::ServiceSeparation { service_field } => {
                mutate_field(&mut next.problem.outputs, service_field, |_| {
                    "service-scoped".to_owned()
                })
            }
            RepairOperator::ReleaseWindow { slots } => apply_release_window(&mut next, *slots),
        };
        if !changed {
            return None;
        }
        next.operators.push(operator.clone());
        Some(next)
    }
}

fn mutate_field<F>(outputs: &mut [Release], field: &str, transform: F) -> bool
where
    F: Fn(&str) -> String,
{
    let id = FieldId::from(field);
    let mut changed = false;
    for output in outputs {
        if let Some(value) = output.fields.get_mut(&id) {
            let replacement = transform(value);
            if *value != replacement {
                *value = replacement;
                changed = true;
            }
        }
    }
    changed
}

fn apply_cover(variant: &mut Variant) -> bool {
    let mut changed = false;
    for output in &mut variant.problem.outputs {
        if !output.emitted {
            *output = Release::emitted();
            variant.added_cover_releases = variant.added_cover_releases.saturating_add(1);
            changed = true;
        }
    }
    changed
}

fn apply_release_window(variant: &mut Variant, slots: u32) -> bool {
    for _ in 0..slots {
        delay_once(variant);
    }
    variant.added_latency = variant.added_latency.saturating_add(u64::from(slots));
    true
}

fn delay_once(variant: &mut Variant) {
    let cover_output = variant
        .problem
        .outputs
        .iter()
        .position(|output| *output == Release::emitted())
        .map(|index| u32::try_from(index).unwrap_or(u32::MAX))
        .unwrap_or_else(|| {
            variant.problem.outputs.push(Release::emitted());
            variant.added_cover_releases = variant.added_cover_releases.saturating_add(1);
            u32::try_from(variant.problem.outputs.len() - 1).unwrap_or(u32::MAX)
        });
    let source = variant.machine.clone();
    let mut cells = Vec::with_capacity(source.cells.len().saturating_mul(2));
    for state in 0..source.state_count {
        for _symbol in 0..source.symbol_count {
            cells.push(MachineCell {
                next_state: state.saturating_mul(2).saturating_add(1),
                output: cover_output,
            });
        }
        for symbol in 0..source.symbol_count {
            let source_cell = source.cell(state, symbol);
            cells.push(MachineCell {
                next_state: source_cell.next_state.saturating_mul(2),
                output: source_cell.output,
            });
        }
    }
    variant.machine = ReleaseMachine {
        state_count: source.state_count.saturating_mul(2),
        symbol_count: source.symbol_count,
        cells,
    };
}
