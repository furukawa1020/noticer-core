#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PldAtom {
    pub privacy_loss: f64,
    pub probability_under_p: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DiscretePld {
    atoms: Vec<PldAtom>,
}

impl DiscretePld {
    pub fn new(mut atoms: Vec<PldAtom>) -> Result<Self, AuditError> {
        if atoms.is_empty() {
            return Err(AuditError::EmptyDistribution);
        }
        if atoms.iter().any(|atom| {
            !atom.privacy_loss.is_finite()
                || !atom.probability_under_p.is_finite()
                || atom.probability_under_p <= 0.0
        }) {
            return Err(AuditError::InvalidAtom);
        }
        atoms.sort_by(|left, right| left.privacy_loss.total_cmp(&right.privacy_loss));
        let p_sum: f64 = atoms.iter().map(|atom| atom.probability_under_p).sum();
        let q_sum: f64 = atoms
            .iter()
            .map(|atom| atom.probability_under_p * (-atom.privacy_loss).exp())
            .sum();
        if (p_sum - 1.0).abs() > 1e-9 || (q_sum - 1.0).abs() > 1e-9 {
            return Err(AuditError::DistributionNotNormalized);
        }
        Ok(Self { atoms })
    }

    #[must_use]
    pub fn atoms(&self) -> &[PldAtom] {
        &self.atoms
    }

    pub fn compose(&self, other: &Self, maximum_atoms: usize) -> Result<Self, AuditError> {
        let required = self
            .atoms
            .len()
            .checked_mul(other.atoms.len())
            .ok_or(AuditError::ResourceLimitExceeded)?;
        if maximum_atoms == 0 || required > maximum_atoms {
            return Err(AuditError::ResourceLimitExceeded);
        }
        let mut atoms = Vec::with_capacity(required);
        for left in &self.atoms {
            for right in &other.atoms {
                atoms.push(PldAtom {
                    privacy_loss: left.privacy_loss + right.privacy_loss,
                    probability_under_p: left.probability_under_p * right.probability_under_p,
                });
            }
        }
        Self::new(atoms)
    }

    #[must_use]
    pub fn hockey_stick_delta(&self, epsilon: f64) -> f64 {
        self.atoms
            .iter()
            .map(|atom| {
                if atom.privacy_loss > epsilon {
                    atom.probability_under_p * (1.0 - (epsilon - atom.privacy_loss).exp())
                } else {
                    0.0
                }
            })
            .sum()
    }

    pub fn epsilon_for_delta(&self, delta: f64) -> Result<f64, AuditError> {
        if !delta.is_finite() || !(0.0..1.0).contains(&delta) {
            return Err(AuditError::InvalidDelta);
        }
        if self.hockey_stick_delta(0.0) <= delta {
            return Ok(0.0);
        }
        let mut low = 0.0;
        let mut high = self
            .atoms
            .iter()
            .map(|atom| atom.privacy_loss)
            .fold(0.0_f64, f64::max);
        for _ in 0..100 {
            let middle = (low + high) / 2.0;
            if self.hockey_stick_delta(middle) > delta {
                low = middle;
            } else {
                high = middle;
            }
        }
        Ok(high)
    }

    #[must_use]
    pub fn likelihood_ratio_roc(&self) -> Vec<FdpPoint> {
        let mut atoms = self.atoms.clone();
        atoms.sort_by(|left, right| right.privacy_loss.total_cmp(&left.privacy_loss));
        let mut cumulative_p = 0.0;
        let mut cumulative_q = 0.0;
        let mut points = Vec::with_capacity(atoms.len() + 1);
        points.push(FdpPoint {
            probability_under_q: 0.0,
            probability_under_p: 0.0,
        });
        for atom in atoms {
            cumulative_p += atom.probability_under_p;
            cumulative_q += atom.probability_under_p * (-atom.privacy_loss).exp();
            points.push(FdpPoint {
                probability_under_q: cumulative_q,
                probability_under_p: cumulative_p,
            });
        }
        points
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FdpPoint {
    pub probability_under_q: f64,
    pub probability_under_p: f64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditVerdict {
    SoundUpperBound,
    UnderestimateDetected,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AuditReport {
    pub delta: f64,
    pub runtime_epsilon_upper: f64,
    pub offline_pld_epsilon: f64,
    pub signed_margin: f64,
    pub verdict: AuditVerdict,
    pub fdp_points: usize,
}

pub fn audit_runtime_bound(
    pld: &DiscretePld,
    delta: f64,
    runtime_epsilon_upper: f64,
    numerical_tolerance: f64,
) -> Result<AuditReport, AuditError> {
    if !runtime_epsilon_upper.is_finite()
        || runtime_epsilon_upper < 0.0
        || !numerical_tolerance.is_finite()
        || numerical_tolerance < 0.0
    {
        return Err(AuditError::InvalidRuntimeBound);
    }
    let offline = pld.epsilon_for_delta(delta)?;
    let margin = runtime_epsilon_upper - offline;
    let verdict = if runtime_epsilon_upper + numerical_tolerance < offline {
        AuditVerdict::UnderestimateDetected
    } else {
        AuditVerdict::SoundUpperBound
    };
    Ok(AuditReport {
        delta,
        runtime_epsilon_upper,
        offline_pld_epsilon: offline,
        signed_margin: margin,
        verdict,
        fdp_points: pld.atoms.len() + 1,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditError {
    EmptyDistribution,
    InvalidAtom,
    DistributionNotNormalized,
    InvalidDelta,
    InvalidRuntimeBound,
    ResourceLimitExceeded,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn randomized_response() -> DiscretePld {
        let loss = 3.0_f64.ln();
        DiscretePld::new(vec![
            PldAtom {
                privacy_loss: loss,
                probability_under_p: 0.75,
            },
            PldAtom {
                privacy_loss: -loss,
                probability_under_p: 0.25,
            },
        ])
        .unwrap()
    }

    #[test]
    fn detects_runtime_underestimate() {
        let report = audit_runtime_bound(&randomized_response(), 0.0, 0.5, 1e-10).unwrap();
        assert_eq!(report.verdict, AuditVerdict::UnderestimateDetected);
        assert!((report.offline_pld_epsilon - 3.0_f64.ln()).abs() < 1e-9);
    }

    #[test]
    fn accepts_conservative_runtime_upper_bound() {
        let report = audit_runtime_bound(&randomized_response(), 0.0, 1.2, 1e-10).unwrap();
        assert_eq!(report.verdict, AuditVerdict::SoundUpperBound);
        assert!(report.signed_margin > 0.0);
    }

    #[test]
    fn composition_is_independent_and_additive_at_zero_delta() {
        let pld = randomized_response();
        let composed = pld.compose(&pld, 4).unwrap();
        let epsilon = composed.epsilon_for_delta(0.0).unwrap();
        assert!((epsilon - 2.0 * 3.0_f64.ln()).abs() < 1e-9);
    }

    #[test]
    fn fdp_roc_is_monotone_and_normalized() {
        let points = randomized_response().likelihood_ratio_roc();
        assert_eq!(
            points.first().unwrap(),
            &FdpPoint {
                probability_under_q: 0.0,
                probability_under_p: 0.0
            }
        );
        let last = points.last().unwrap();
        assert!((last.probability_under_q - 1.0).abs() < 1e-9);
        assert!((last.probability_under_p - 1.0).abs() < 1e-9);
        assert!(points.windows(2).all(|pair| pair[0].probability_under_q
            <= pair[1].probability_under_q
            && pair[0].probability_under_p <= pair[1].probability_under_p));
    }

    #[test]
    fn malformed_pld_and_resource_explosion_are_rejected() {
        assert_eq!(
            DiscretePld::new(vec![PldAtom {
                privacy_loss: 0.0,
                probability_under_p: 0.5
            }]),
            Err(AuditError::DistributionNotNormalized)
        );
        let pld = randomized_response();
        assert_eq!(pld.compose(&pld, 3), Err(AuditError::ResourceLimitExceeded));
    }
}
