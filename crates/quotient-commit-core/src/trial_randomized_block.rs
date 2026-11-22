//! Deterministic hash-randomized execution order inside declared blocks.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockItem {
    pub block_digest: [u8; 32],
    pub trial_digest: [u8; 32],
}

pub fn order(seed: u64, mut items: Vec<BlockItem>) -> Vec<BlockItem> {
    items.sort_by_key(|item| {
        let mut bytes = b"noticer.quotient-trial.block-order.v1\0".to_vec();
        bytes.extend_from_slice(&seed.to_be_bytes());
        bytes.extend_from_slice(&item.block_digest);
        bytes.extend_from_slice(&item.trial_digest);
        crate::sha256::sha256(&bytes)
    });
    items
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn order_is_reproducible_and_complete() {
        let items = vec![
            BlockItem {
                block_digest: [1; 32],
                trial_digest: [2; 32],
            },
            BlockItem {
                block_digest: [1; 32],
                trial_digest: [3; 32],
            },
        ];
        let a = order(7, items.clone());
        assert_eq!(a, order(7, items));
        assert_eq!(a.len(), 2);
    }
}
