use crate::oracle_verdict::InvalidReason;
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct StatePair {
    pub slot: u64,
    pub left: Vec<u8>,
    pub right: Vec<u8>,
}
pub fn create(
    slot: u64,
    left: &[u8],
    right: &[u8],
    maximum_state_bytes: usize,
) -> Result<StatePair, InvalidReason> {
    if left.is_empty()
        || right.is_empty()
        || left.len() > maximum_state_bytes
        || right.len() > maximum_state_bytes
    {
        return Err(InvalidReason::Domain);
    }
    Ok(StatePair {
        slot,
        left: left.to_vec(),
        right: right.to_vec(),
    })
}
pub fn encode(v: &StatePair) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&v.slot.to_be_bytes());
    out.extend_from_slice(&(v.left.len() as u32).to_be_bytes());
    out.extend_from_slice(&v.left);
    out.extend_from_slice(&(v.right.len() as u32).to_be_bytes());
    out.extend_from_slice(&v.right);
    out
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_left_right_order() {
        let a = create(1, &[2], &[3], 4).unwrap();
        let b = create(1, &[3], &[2], 4).unwrap();
        assert_ne!(encode(&a), encode(&b))
    }
    #[test]
    fn rejects_oversize() {
        assert_eq!(create(0, &[1, 2], &[3], 1), Err(InvalidReason::Domain));
    }
}
