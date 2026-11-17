use crate::{proof_producer_identity::ProducerFamily, receipt::hmac_sha256};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultDomainLabel {
    pub producer: [u8; 16],
    pub region: u16,
    pub provider: u16,
    pub family: ProducerFamily,
    pub epoch: u64,
    pub authenticator: [u8; 32],
}
pub fn issue(
    producer: [u8; 16],
    region: u16,
    provider: u16,
    family: ProducerFamily,
    epoch: u64,
    key: [u8; 32],
) -> FaultDomainLabel {
    let mut v = FaultDomainLabel {
        producer,
        region,
        provider,
        family,
        epoch,
        authenticator: [0; 32],
    };
    v.authenticator = auth(v, key);
    v
}
pub fn verify(v: FaultDomainLabel, key: [u8; 32]) -> bool {
    v.authenticator == auth(v, key)
}
fn auth(mut v: FaultDomainLabel, key: [u8; 32]) -> [u8; 32] {
    v.authenticator = [0; 32];
    let mut b = Vec::new();
    b.extend_from_slice(b"noticer.fault-domain-label.v1");
    b.extend_from_slice(&v.producer);
    b.extend_from_slice(&v.region.to_be_bytes());
    b.extend_from_slice(&v.provider.to_be_bytes());
    b.push(v.family as u8);
    b.extend_from_slice(&v.epoch.to_be_bytes());
    hmac_sha256(key, &b)
}
#[cfg(test)]
mod tests {
    use super::*;
    const K: [u8; 32] = [5; 32];
    #[test]
    fn verifies_label() {
        let v = issue([1; 16], 2, 3, ProducerFamily::Native, 4, K);
        assert!(verify(v, K))
    }
    #[test]
    fn rejects_domain_tamper() {
        let mut v = issue([1; 16], 2, 3, ProducerFamily::Native, 4, K);
        v.provider = 9;
        assert!(!verify(v, K));
    }
}
