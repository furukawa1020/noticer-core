use crate::proof_clock_interval::ClockInterval;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OverlapError {
    Empty,
    Disjoint,
}
pub fn common_cut(intervals: &[ClockInterval]) -> Result<ClockInterval, OverlapError> {
    let first = *intervals.first().ok_or(OverlapError::Empty)?;
    let earliest = intervals
        .iter()
        .fold(first.earliest, |v, i| v.max(i.earliest));
    let latest = intervals.iter().fold(first.latest, |v, i| v.min(i.latest));
    if earliest > latest {
        return Err(OverlapError::Disjoint);
    }
    Ok(ClockInterval { earliest, latest })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn finds_common_cut() {
        assert_eq!(
            common_cut(&[
                ClockInterval {
                    earliest: 1,
                    latest: 5
                },
                ClockInterval {
                    earliest: 3,
                    latest: 7
                }
            ]),
            Ok(ClockInterval {
                earliest: 3,
                latest: 5
            })
        )
    }
    #[test]
    fn rejects_disjoint() {
        assert_eq!(
            common_cut(&[
                ClockInterval {
                    earliest: 1,
                    latest: 2
                },
                ClockInterval {
                    earliest: 3,
                    latest: 4
                }
            ]),
            Err(OverlapError::Disjoint)
        );
    }
}
