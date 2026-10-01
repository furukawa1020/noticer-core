#![forbid(unsafe_code)]

use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Digest(pub [u8; 32]);
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RequestId(pub [u8; 16]);
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ServiceId(pub [u8; 16]);
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CoalitionId(pub u64);
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReservationId(pub u64);
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MechanismId(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceEvent {
    BudgetQuote {
        request_id: RequestId,
        service_id: ServiceId,
        mechanism_id: MechanismId,
        quoted_cost_q64_64: u128,
    },
    PolicyActivate {
        generation: u64,
        policy_digest: Digest,
    },
    Reserve {
        request_id: RequestId,
        reservation_id: ReservationId,
        service_id: ServiceId,
        coalition_id: CoalitionId,
        amount_q64_64: u128,
        randomness_commitment: Digest,
        policy_generation: u64,
    },
    Release {
        reservation_id: ReservationId,
        trace_commitment: Digest,
    },
    DurableRecord {
        sequence: u64,
        chain_head: Digest,
    },
    Crash,
    Recover {
        sequence: u64,
        chain_head: Digest,
    },
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AttackStrategy {
    BudgetShopping,
    ServiceSplitting,
    CoalitionEscalation,
    SharedRandomness,
    PolicyChurn,
    CrashRollback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttackFinding {
    pub strategy: AttackStrategy,
    pub first_event_index: usize,
    pub second_event_index: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttackerConfig {
    pub maximum_events: usize,
    pub maximum_findings: usize,
}

impl AttackerConfig {
    pub const fn validate(self) -> Result<(), AttackError> {
        if self.maximum_events == 0 || self.maximum_findings == 0 {
            return Err(AttackError::InvalidConfig);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct QuoteMeta {
    index: usize,
    service_id: ServiceId,
    mechanism_id: MechanismId,
    quoted_cost_q64_64: u128,
}

#[derive(Clone, Copy, Debug)]
struct ReservationMeta {
    index: usize,
    request_id: RequestId,
    service_id: ServiceId,
    coalition_id: CoalitionId,
}

#[derive(Debug)]
pub struct AdaptiveAttacker {
    config: AttackerConfig,
}

impl AdaptiveAttacker {
    pub fn new(config: AttackerConfig) -> Result<Self, AttackError> {
        config.validate()?;
        Ok(Self { config })
    }

    pub fn analyze(&self, trace: &[TraceEvent]) -> Result<Vec<AttackFinding>, AttackError> {
        if trace.len() > self.config.maximum_events {
            return Err(AttackError::ResourceLimitExceeded);
        }
        let mut findings = Vec::new();
        let mut quotes = BTreeMap::<RequestId, QuoteMeta>::new();
        let mut reservations = BTreeMap::<ReservationId, ReservationMeta>::new();
        let mut service_coalitions = BTreeMap::<ServiceId, (usize, CoalitionId)>::new();
        let mut randomness = BTreeMap::<Digest, (usize, ReservationId)>::new();
        let mut released_requests = BTreeMap::<(RequestId, CoalitionId), (usize, ServiceId)>::new();
        let mut active_policy = None::<(usize, u64, Digest)>;
        let mut durable_heads = BTreeMap::<u64, (usize, Digest)>::new();
        let mut highest_durable = None::<(usize, u64, Digest)>;
        let mut latest_crash = None::<usize>;

        for (index, event) in trace.iter().copied().enumerate() {
            match event {
                TraceEvent::BudgetQuote {
                    request_id,
                    service_id,
                    mechanism_id,
                    quoted_cost_q64_64,
                } => {
                    if let Some(previous) = quotes.get(&request_id) {
                        if previous.service_id != service_id
                            || previous.mechanism_id != mechanism_id
                            || previous.quoted_cost_q64_64 != quoted_cost_q64_64
                        {
                            push_finding(
                                &mut findings,
                                self.config.maximum_findings,
                                AttackStrategy::BudgetShopping,
                                previous.index,
                                index,
                            )?;
                        }
                    }
                    quotes.insert(
                        request_id,
                        QuoteMeta {
                            index,
                            service_id,
                            mechanism_id,
                            quoted_cost_q64_64,
                        },
                    );
                }
                TraceEvent::PolicyActivate {
                    generation,
                    policy_digest,
                } => {
                    if let Some((previous_index, previous_generation, previous_digest)) =
                        active_policy
                    {
                        if generation <= previous_generation || policy_digest == previous_digest {
                            push_finding(
                                &mut findings,
                                self.config.maximum_findings,
                                AttackStrategy::PolicyChurn,
                                previous_index,
                                index,
                            )?;
                        }
                    }
                    active_policy = Some((index, generation, policy_digest));
                }
                TraceEvent::Reserve {
                    request_id,
                    reservation_id,
                    service_id,
                    coalition_id,
                    amount_q64_64,
                    randomness_commitment,
                    policy_generation,
                } => {
                    if reservation_id.0 == 0 || amount_q64_64 == 0 {
                        return Err(AttackError::MalformedTrace);
                    }
                    if reservations.contains_key(&reservation_id) {
                        return Err(AttackError::DuplicateReservation);
                    }
                    if let Some((previous_index, previous_coalition)) =
                        service_coalitions.get(&service_id)
                    {
                        if *previous_coalition != coalition_id {
                            push_finding(
                                &mut findings,
                                self.config.maximum_findings,
                                AttackStrategy::CoalitionEscalation,
                                *previous_index,
                                index,
                            )?;
                        }
                    }
                    service_coalitions.insert(service_id, (index, coalition_id));
                    if randomness_commitment.0 == [0; 32] {
                        return Err(AttackError::MalformedTrace);
                    }
                    if let Some((previous_index, previous_reservation)) =
                        randomness.get(&randomness_commitment)
                    {
                        if *previous_reservation != reservation_id {
                            push_finding(
                                &mut findings,
                                self.config.maximum_findings,
                                AttackStrategy::SharedRandomness,
                                *previous_index,
                                index,
                            )?;
                        }
                    }
                    randomness.insert(randomness_commitment, (index, reservation_id));
                    if let Some((policy_index, generation, _)) = active_policy {
                        if generation != policy_generation {
                            push_finding(
                                &mut findings,
                                self.config.maximum_findings,
                                AttackStrategy::PolicyChurn,
                                policy_index,
                                index,
                            )?;
                        }
                    } else {
                        return Err(AttackError::MissingPolicy);
                    }
                    reservations.insert(
                        reservation_id,
                        ReservationMeta {
                            index,
                            request_id,
                            service_id,
                            coalition_id,
                        },
                    );
                }
                TraceEvent::Release {
                    reservation_id,
                    trace_commitment,
                } => {
                    if trace_commitment.0 == [0; 32] {
                        return Err(AttackError::MalformedTrace);
                    }
                    let reservation = reservations
                        .get(&reservation_id)
                        .copied()
                        .ok_or(AttackError::ReleaseWithoutReservation)?;
                    let key = (reservation.request_id, reservation.coalition_id);
                    if let Some((previous_index, previous_service)) = released_requests.get(&key) {
                        if *previous_service != reservation.service_id {
                            push_finding(
                                &mut findings,
                                self.config.maximum_findings,
                                AttackStrategy::ServiceSplitting,
                                *previous_index,
                                index,
                            )?;
                        }
                    }
                    released_requests.insert(key, (reservation.index, reservation.service_id));
                }
                TraceEvent::DurableRecord {
                    sequence,
                    chain_head,
                } => {
                    if sequence == 0 || chain_head.0 == [0; 32] {
                        return Err(AttackError::MalformedTrace);
                    }
                    durable_heads.insert(sequence, (index, chain_head));
                    if highest_durable.is_none_or(|(_, highest, _)| sequence > highest) {
                        highest_durable = Some((index, sequence, chain_head));
                    }
                }
                TraceEvent::Crash => latest_crash = Some(index),
                TraceEvent::Recover {
                    sequence,
                    chain_head,
                } => {
                    let crash_index = latest_crash.ok_or(AttackError::RecoveryWithoutCrash)?;
                    if let Some((durable_index, highest, highest_head)) = highest_durable {
                        let rollback = sequence < highest
                            || (sequence == highest && chain_head != highest_head)
                            || durable_heads
                                .get(&sequence)
                                .is_some_and(|(_, expected)| *expected != chain_head);
                        if rollback {
                            push_finding(
                                &mut findings,
                                self.config.maximum_findings,
                                AttackStrategy::CrashRollback,
                                durable_index.max(crash_index),
                                index,
                            )?;
                        }
                    }
                    latest_crash = None;
                }
            }
        }
        Ok(findings)
    }
}

fn push_finding(
    findings: &mut Vec<AttackFinding>,
    maximum: usize,
    strategy: AttackStrategy,
    first_event_index: usize,
    second_event_index: usize,
) -> Result<(), AttackError> {
    if findings.len() >= maximum {
        return Err(AttackError::ResourceLimitExceeded);
    }
    findings.push(AttackFinding {
        strategy,
        first_event_index,
        second_event_index,
    });
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttackError {
    InvalidConfig,
    ResourceLimitExceeded,
    MalformedTrace,
    DuplicateReservation,
    MissingPolicy,
    ReleaseWithoutReservation,
    RecoveryWithoutCrash,
}

#[cfg(test)]
mod tests {
    use super::*;
    const POLICY: Digest = Digest([1; 32]);
    const RANDOM_A: Digest = Digest([2; 32]);
    const SERVICE_A: ServiceId = ServiceId([3; 16]);
    const SERVICE_B: ServiceId = ServiceId([4; 16]);
    const REQUEST: RequestId = RequestId([5; 16]);

    fn attacker() -> AdaptiveAttacker {
        AdaptiveAttacker::new(AttackerConfig {
            maximum_events: 64,
            maximum_findings: 32,
        })
        .unwrap()
    }

    #[test]
    fn detects_budget_shopping() {
        let trace = [
            TraceEvent::BudgetQuote {
                request_id: REQUEST,
                service_id: SERVICE_A,
                mechanism_id: MechanismId(1),
                quoted_cost_q64_64: 20,
            },
            TraceEvent::BudgetQuote {
                request_id: REQUEST,
                service_id: SERVICE_B,
                mechanism_id: MechanismId(2),
                quoted_cost_q64_64: 10,
            },
        ];
        assert_eq!(
            attacker().analyze(&trace).unwrap()[0].strategy,
            AttackStrategy::BudgetShopping
        );
    }

    #[test]
    fn detects_service_splitting_and_shared_randomness() {
        let trace = [
            TraceEvent::PolicyActivate {
                generation: 1,
                policy_digest: POLICY,
            },
            TraceEvent::Reserve {
                request_id: REQUEST,
                reservation_id: ReservationId(1),
                service_id: SERVICE_A,
                coalition_id: CoalitionId(1),
                amount_q64_64: 10,
                randomness_commitment: RANDOM_A,
                policy_generation: 1,
            },
            TraceEvent::Release {
                reservation_id: ReservationId(1),
                trace_commitment: Digest([7; 32]),
            },
            TraceEvent::Reserve {
                request_id: REQUEST,
                reservation_id: ReservationId(2),
                service_id: SERVICE_B,
                coalition_id: CoalitionId(1),
                amount_q64_64: 10,
                randomness_commitment: RANDOM_A,
                policy_generation: 1,
            },
            TraceEvent::Release {
                reservation_id: ReservationId(2),
                trace_commitment: Digest([8; 32]),
            },
        ];
        let strategies: Vec<_> = attacker()
            .analyze(&trace)
            .unwrap()
            .into_iter()
            .map(|finding| finding.strategy)
            .collect();
        assert!(strategies.contains(&AttackStrategy::SharedRandomness));
        assert!(strategies.contains(&AttackStrategy::ServiceSplitting));
    }

    #[test]
    fn detects_coalition_escalation_and_policy_churn() {
        let trace = [
            TraceEvent::PolicyActivate {
                generation: 2,
                policy_digest: POLICY,
            },
            TraceEvent::Reserve {
                request_id: RequestId([1; 16]),
                reservation_id: ReservationId(1),
                service_id: SERVICE_A,
                coalition_id: CoalitionId(1),
                amount_q64_64: 10,
                randomness_commitment: Digest([2; 32]),
                policy_generation: 2,
            },
            TraceEvent::PolicyActivate {
                generation: 1,
                policy_digest: Digest([9; 32]),
            },
            TraceEvent::Reserve {
                request_id: RequestId([2; 16]),
                reservation_id: ReservationId(2),
                service_id: SERVICE_A,
                coalition_id: CoalitionId(2),
                amount_q64_64: 10,
                randomness_commitment: Digest([3; 32]),
                policy_generation: 2,
            },
        ];
        let strategies: Vec<_> = attacker()
            .analyze(&trace)
            .unwrap()
            .into_iter()
            .map(|finding| finding.strategy)
            .collect();
        assert!(strategies.contains(&AttackStrategy::CoalitionEscalation));
        assert!(strategies.contains(&AttackStrategy::PolicyChurn));
    }

    #[test]
    fn detects_crash_rollback_and_forked_head() {
        for recovery in [
            TraceEvent::Recover {
                sequence: 6,
                chain_head: Digest([6; 32]),
            },
            TraceEvent::Recover {
                sequence: 7,
                chain_head: Digest([8; 32]),
            },
        ] {
            let trace = [
                TraceEvent::DurableRecord {
                    sequence: 7,
                    chain_head: Digest([7; 32]),
                },
                TraceEvent::Crash,
                recovery,
            ];
            assert_eq!(
                attacker().analyze(&trace).unwrap()[0].strategy,
                AttackStrategy::CrashRollback
            );
        }
    }

    #[test]
    fn clean_trace_has_no_findings() {
        let trace = [
            TraceEvent::PolicyActivate {
                generation: 1,
                policy_digest: POLICY,
            },
            TraceEvent::Reserve {
                request_id: REQUEST,
                reservation_id: ReservationId(1),
                service_id: SERVICE_A,
                coalition_id: CoalitionId(1),
                amount_q64_64: 10,
                randomness_commitment: RANDOM_A,
                policy_generation: 1,
            },
            TraceEvent::Release {
                reservation_id: ReservationId(1),
                trace_commitment: Digest([7; 32]),
            },
            TraceEvent::DurableRecord {
                sequence: 1,
                chain_head: Digest([7; 32]),
            },
            TraceEvent::Crash,
            TraceEvent::Recover {
                sequence: 1,
                chain_head: Digest([7; 32]),
            },
        ];
        assert!(attacker().analyze(&trace).unwrap().is_empty());
    }
}
