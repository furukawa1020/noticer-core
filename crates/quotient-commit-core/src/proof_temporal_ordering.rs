use crate::{proof_clock_interval::ClockInterval, receipt::hmac_sha256};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrderingCertificate {
    pub before_digest: [u8; 32],
    pub after_digest: [u8; 32],
    pub before: ClockInterval,
    pub after: ClockInterval,
    pub authenticator: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrderingError {
    Ambiguous,
    Authentication,
}
pub fn issue(
    before_digest: [u8; 32],
    after_digest: [u8; 32],
    before: ClockInterval,
    after: ClockInterval,
    key: [u8; 32],
) -> Result<OrderingCertificate, OrderingError> {
    if before.latest >= after.earliest {
        return Err(OrderingError::Ambiguous);
    }
    let mut v = OrderingCertificate {
        before_digest,
        after_digest,
        before,
        after,
        authenticator: [0; 32],
    };
    v.authenticator = auth(v, key);
    Ok(v)
}
pub fn verify(v: OrderingCertificate, key: [u8; 32]) -> Result<(), OrderingError> {
    if v.before.latest >= v.after.earliest {
        return Err(OrderingError::Ambiguous);
    }
    if v.authenticator != auth(v, key) {
        return Err(OrderingError::Authentication);
    }
    Ok(())
}
fn auth(mut v: OrderingCertificate, key: [u8; 32]) -> [u8; 32] {
    v.authenticator = [0; 32];
    let mut b = Vec::new();
    b.extend_from_slice(b"noticer.temporal-ordering.v1");
    b.extend_from_slice(&v.before_digest);
    b.extend_from_slice(&v.after_digest);
    for n in [
        v.before.earliest,
        v.before.latest,
        v.after.earliest,
        v.after.latest,
    ] {
        b.extend_from_slice(&n.to_be_bytes())
    }
    hmac_sha256(key, &b)
}
#[cfg(test)]
mod tests {
    use super::*;
    const K: [u8; 32] = [4; 32];
    #[test]
    fn certifies_order() {
        let v = issue(
            [1; 32],
            [2; 32],
            ClockInterval {
                earliest: 1,
                latest: 2,
            },
            ClockInterval {
                earliest: 3,
                latest: 4,
            },
            K,
        )
        .unwrap();
        assert_eq!(verify(v, K), Ok(()))
    }
    #[test]
    fn rejects_overlap() {
        assert_eq!(
            issue(
                [1; 32],
                [2; 32],
                ClockInterval {
                    earliest: 1,
                    latest: 3
                },
                ClockInterval {
                    earliest: 3,
                    latest: 4
                },
                K
            ),
            Err(OrderingError::Ambiguous)
        );
    }
}
