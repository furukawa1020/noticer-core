use crate::{oracle_input::OracleInput, oracle_verdict::InvalidReason};
pub fn decode(
    bytes: &[u8],
    maximum_symbols: usize,
    maximum_value: u16,
) -> Result<OracleInput, InvalidReason> {
    if bytes.len() < 10 {
        return Err(InvalidReason::Parse);
    }
    let slot = u64::from_be_bytes(bytes[0..8].try_into().map_err(|_| InvalidReason::Parse)?);
    let count =
        u16::from_be_bytes(bytes[8..10].try_into().map_err(|_| InvalidReason::Parse)?) as usize;
    if count == 0 || count > maximum_symbols {
        return Err(InvalidReason::Domain);
    }
    let expected = 10usize
        .checked_add(count.checked_mul(2).ok_or(InvalidReason::Parse)?)
        .ok_or(InvalidReason::Parse)?;
    if bytes.len() != expected {
        return Err(if bytes.len() > expected {
            InvalidReason::NonCanonical
        } else {
            InvalidReason::Parse
        });
    }
    let mut symbols = Vec::with_capacity(count);
    for chunk in bytes[10..].chunks_exact(2) {
        let v = u16::from_be_bytes([chunk[0], chunk[1]]);
        if v > maximum_value {
            return Err(InvalidReason::Domain);
        }
        symbols.push(v)
    }
    Ok(OracleInput { slot, symbols })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn decodes_canonical() {
        assert_eq!(
            decode(&[0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 2], 2, 3)
                .unwrap()
                .symbols,
            vec![2]
        )
    }
    #[test]
    fn trailing_is_invalid() {
        assert_eq!(
            decode(&[0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 2, 0], 2, 3),
            Err(InvalidReason::NonCanonical)
        );
    }
}
