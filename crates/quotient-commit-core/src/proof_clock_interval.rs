#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockInterval {
    pub earliest: u64,
    pub latest: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntervalError {
    Underflow,
    Overflow,
    Inverted,
}
impl ClockInterval {
    pub fn around(center: u64, uncertainty: u64) -> Result<Self, IntervalError> {
        let earliest = center
            .checked_sub(uncertainty)
            .ok_or(IntervalError::Underflow)?;
        let latest = center
            .checked_add(uncertainty)
            .ok_or(IntervalError::Overflow)?;
        Ok(Self { earliest, latest })
    }
    pub fn new(earliest: u64, latest: u64) -> Result<Self, IntervalError> {
        if earliest > latest {
            return Err(IntervalError::Inverted);
        }
        Ok(Self { earliest, latest })
    }
    pub fn overlaps(self, other: Self) -> bool {
        self.earliest <= other.latest && other.earliest <= self.latest
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn constructs_closed_interval() {
        let i = ClockInterval::around(10, 2).unwrap();
        assert_eq!(
            i,
            ClockInterval {
                earliest: 8,
                latest: 12
            }
        );
        assert!(i.overlaps(ClockInterval::new(12, 14).unwrap()))
    }
    #[test]
    fn rejects_bounds() {
        assert_eq!(ClockInterval::around(1, 2), Err(IntervalError::Underflow));
        assert_eq!(ClockInterval::new(3, 2), Err(IntervalError::Inverted));
    }
}
