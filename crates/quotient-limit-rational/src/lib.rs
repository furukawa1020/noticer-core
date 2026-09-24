#![no_std]
#![forbid(unsafe_code)]

use core::cmp::Ordering;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RationalError {
    ZeroDenominator,
    Overflow,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Rational {
    numerator: i128,
    denominator: i128,
}

impl Rational {
    pub const ZERO: Self = Self {
        numerator: 0,
        denominator: 1,
    };
    pub const ONE: Self = Self {
        numerator: 1,
        denominator: 1,
    };

    pub fn new(numerator: i128, denominator: i128) -> Result<Self, RationalError> {
        if denominator == 0 {
            return Err(RationalError::ZeroDenominator);
        }
        let (numerator, denominator) = if denominator < 0 {
            (
                numerator.checked_neg().ok_or(RationalError::Overflow)?,
                denominator.checked_neg().ok_or(RationalError::Overflow)?,
            )
        } else {
            (numerator, denominator)
        };
        let divisor = gcd(numerator.unsigned_abs(), denominator as u128);
        Ok(Self {
            numerator: numerator / divisor as i128,
            denominator: denominator / divisor as i128,
        })
    }
    pub const fn numerator(self) -> i128 {
        self.numerator
    }
    pub const fn denominator(self) -> i128 {
        self.denominator
    }
    pub fn is_canonical(self) -> bool {
        self.denominator > 0 && gcd(self.numerator.unsigned_abs(), self.denominator as u128) == 1
    }
    pub const fn is_negative(self) -> bool {
        self.numerator < 0
    }
    pub fn checked_neg(self) -> Result<Self, RationalError> {
        Self::new(
            self.numerator
                .checked_neg()
                .ok_or(RationalError::Overflow)?,
            self.denominator,
        )
    }
    pub fn checked_add(self, other: Self) -> Result<Self, RationalError> {
        let left = self
            .numerator
            .checked_mul(other.denominator)
            .ok_or(RationalError::Overflow)?;
        let right = other
            .numerator
            .checked_mul(self.denominator)
            .ok_or(RationalError::Overflow)?;
        let numerator = left.checked_add(right).ok_or(RationalError::Overflow)?;
        let denominator = self
            .denominator
            .checked_mul(other.denominator)
            .ok_or(RationalError::Overflow)?;
        Self::new(numerator, denominator)
    }
    pub fn checked_mul(self, other: Self) -> Result<Self, RationalError> {
        Self::new(
            self.numerator
                .checked_mul(other.numerator)
                .ok_or(RationalError::Overflow)?,
            self.denominator
                .checked_mul(other.denominator)
                .ok_or(RationalError::Overflow)?,
        )
    }
    pub fn checked_cmp(self, other: Self) -> Result<Ordering, RationalError> {
        Ok(self
            .numerator
            .checked_mul(other.denominator)
            .ok_or(RationalError::Overflow)?
            .cmp(
                &other
                    .numerator
                    .checked_mul(self.denominator)
                    .ok_or(RationalError::Overflow)?,
            ))
    }
    pub fn bit_length(self) -> u32 {
        let numerator = 128 - self.numerator.unsigned_abs().leading_zeros();
        let denominator = 128 - (self.denominator as u128).leading_zeros();
        numerator.max(denominator)
    }
}

fn gcd(mut left: u128, mut right: u128) -> u128 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonicalizes_sign_and_gcd() {
        assert_eq!(Rational::new(6, -8).unwrap(), Rational::new(-3, 4).unwrap());
    }
    #[test]
    fn arithmetic_is_exact() {
        assert_eq!(
            Rational::new(1, 3)
                .unwrap()
                .checked_add(Rational::new(1, 6).unwrap())
                .unwrap(),
            Rational::new(1, 2).unwrap()
        );
    }
    #[test]
    fn zero_denominator_is_rejected() {
        assert_eq!(Rational::new(1, 0), Err(RationalError::ZeroDenominator));
    }
}
