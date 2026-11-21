//! Canonical attacks against runtime assurance and revocation.

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SentinelAttack {
    SampleReplay,
    ClockRollback,
    MonitorSuppression,
    SplitView,
    AlarmFlood,
    CertificateSubstitution,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SentinelAttackResult {
    pub attack: SentinelAttack,
    pub blocked: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SentinelMatrixError {
    Incomplete,
    Duplicate,
    AttackSucceeded(SentinelAttack),
}

pub fn verify(mut results: Vec<SentinelAttackResult>) -> Result<usize, SentinelMatrixError> {
    results.sort_by_key(|result| result.attack);
    if results
        .windows(2)
        .any(|pair| pair[0].attack == pair[1].attack)
    {
        return Err(SentinelMatrixError::Duplicate);
    }
    let expected = [
        SentinelAttack::SampleReplay,
        SentinelAttack::ClockRollback,
        SentinelAttack::MonitorSuppression,
        SentinelAttack::SplitView,
        SentinelAttack::AlarmFlood,
        SentinelAttack::CertificateSubstitution,
    ];
    if results.iter().map(|result| result.attack).ne(expected) {
        return Err(SentinelMatrixError::Incomplete);
    }
    if let Some(result) = results.iter().find(|result| !result.blocked) {
        return Err(SentinelMatrixError::AttackSucceeded(result.attack));
    }
    Ok(results.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_unblocked_runtime_attack_fails_the_matrix() {
        let results = [
            SentinelAttack::SampleReplay,
            SentinelAttack::ClockRollback,
            SentinelAttack::MonitorSuppression,
            SentinelAttack::SplitView,
            SentinelAttack::AlarmFlood,
            SentinelAttack::CertificateSubstitution,
        ]
        .map(|attack| SentinelAttackResult {
            attack,
            blocked: attack != SentinelAttack::SplitView,
        });
        assert_eq!(
            verify(results.to_vec()),
            Err(SentinelMatrixError::AttackSucceeded(
                SentinelAttack::SplitView
            ))
        );
    }
}
