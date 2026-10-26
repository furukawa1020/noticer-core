//! Regression oracle for action-equivalent recovery telemetry traces.

use crate::recovery_telemetry_budget::TelemetryRelease;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ActionClass(pub [u8; 16]);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceObservation {
    pub action_class: ActionClass,
    pub buckets: [u8; 4],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegressionPolicy {
    pub maximum_bucket_changes: u8,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegressionReport {
    pub passed: bool,
    pub compared: u32,
    pub violating_classes: Vec<ActionClass>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OracleError {
    EmptyBaseline,
    EmptyCandidate,
    InvalidBucket,
}

#[must_use]
pub fn observation(action_class: ActionClass, release: TelemetryRelease) -> TraceObservation {
    TraceObservation {
        action_class,
        buckets: [
            release.completed_bucket,
            release.aborted_bucket,
            release.restart_bucket,
            release.backlog_halt_bucket,
        ],
    }
}

pub fn compare(
    baseline: &[TraceObservation],
    candidate: &[TraceObservation],
    policy: RegressionPolicy,
) -> Result<RegressionReport, OracleError> {
    if baseline.is_empty() {
        return Err(OracleError::EmptyBaseline);
    }
    if candidate.is_empty() {
        return Err(OracleError::EmptyCandidate);
    }
    if baseline
        .iter()
        .chain(candidate)
        .any(|entry| entry.buckets.iter().any(|bucket| *bucket > 4))
    {
        return Err(OracleError::InvalidBucket);
    }
    let mut classes: BTreeMap<ActionClass, Vec<[u8; 4]>> = BTreeMap::new();
    for entry in baseline {
        classes
            .entry(entry.action_class)
            .or_default()
            .push(entry.buckets);
    }
    let mut violations = Vec::new();
    for entry in candidate {
        let acceptable = classes.get(&entry.action_class).is_some_and(|traces| {
            traces
                .iter()
                .any(|trace| distance(*trace, entry.buckets) <= policy.maximum_bucket_changes)
        });
        if !acceptable && !violations.contains(&entry.action_class) {
            violations.push(entry.action_class);
        }
    }
    violations.sort();
    Ok(RegressionReport {
        passed: violations.is_empty(),
        compared: candidate.len() as u32,
        violating_classes: violations,
    })
}

#[must_use]
pub fn canonical_json(report: &RegressionReport) -> String {
    let classes = report
        .violating_classes
        .iter()
        .map(|class| format!("\"{}\"", hex(class.0)))
        .collect::<Vec<_>>()
        .join(",");
    format!("{{\"schema\":\"noticer.recovery-telemetry-regression.v1\",\"passed\":{},\"compared\":{},\"violating_classes\":[{}]}}", report.passed, report.compared, classes)
}
fn distance(left: [u8; 4], right: [u8; 4]) -> u8 {
    left.iter().zip(right).filter(|(a, b)| **a != *b).count() as u8
}
fn hex(value: [u8; 16]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn trace(class: u8, buckets: [u8; 4]) -> TraceObservation {
        TraceObservation {
            action_class: ActionClass([class; 16]),
            buckets,
        }
    }
    #[test]
    fn equivalent_traces_pass_within_budget() {
        let report = compare(
            &[trace(1, [1, 0, 2, 0])],
            &[trace(1, [1, 0, 3, 0])],
            RegressionPolicy {
                maximum_bucket_changes: 1,
            },
        )
        .unwrap();
        assert!(report.passed);
        assert_eq!(report.compared, 1);
    }
    #[test]
    fn changed_and_unknown_classes_fail_deterministically() {
        let report = compare(
            &[trace(1, [0; 4])],
            &[trace(2, [0; 4]), trace(1, [1, 1, 0, 0])],
            RegressionPolicy {
                maximum_bucket_changes: 1,
            },
        )
        .unwrap();
        assert!(!report.passed);
        assert_eq!(
            report.violating_classes,
            vec![ActionClass([1; 16]), ActionClass([2; 16])]
        );
        assert!(canonical_json(&report).contains("\"passed\":false"));
    }
    #[test]
    fn invalid_inputs_are_rejected() {
        assert_eq!(
            compare(
                &[],
                &[trace(1, [0; 4])],
                RegressionPolicy {
                    maximum_bucket_changes: 0
                }
            ),
            Err(OracleError::EmptyBaseline)
        );
        assert_eq!(
            compare(
                &[trace(1, [9, 0, 0, 0])],
                &[trace(1, [0; 4])],
                RegressionPolicy {
                    maximum_bucket_changes: 0
                }
            ),
            Err(OracleError::InvalidBucket)
        );
    }
}
