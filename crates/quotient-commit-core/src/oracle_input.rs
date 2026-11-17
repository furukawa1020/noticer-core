use crate::oracle_verdict::InvalidReason;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OracleInput {
    pub slot: u64,
    pub symbols: Vec<u16>,
}
pub fn validate(
    slot: u64,
    symbols: &[u16],
    maximum_symbols: usize,
    maximum_value: u16,
) -> Result<OracleInput, InvalidReason> {
    if symbols.is_empty() || symbols.len() > maximum_symbols {
        return Err(InvalidReason::Domain);
    }
    if symbols.iter().any(|s| *s > maximum_value) {
        return Err(InvalidReason::Domain);
    }
    Ok(OracleInput {
        slot,
        symbols: symbols.to_vec(),
    })
}
pub fn encode(v: &OracleInput) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + v.symbols.len() * 2);
    out.extend_from_slice(&v.slot.to_be_bytes());
    out.extend_from_slice(&(v.symbols.len() as u16).to_be_bytes());
    for s in &v.symbols {
        out.extend_from_slice(&s.to_be_bytes())
    }
    out
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encoding_is_canonical() {
        let v = validate(3, &[1, 2], 4, 9).unwrap();
        assert_eq!(encode(&v), vec![0, 0, 0, 0, 0, 0, 0, 3, 0, 2, 0, 1, 0, 2])
    }
    #[test]
    fn rejects_domain_error() {
        assert_eq!(validate(0, &[10], 1, 9), Err(InvalidReason::Domain));
    }
}
