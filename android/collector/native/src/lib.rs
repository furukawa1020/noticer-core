use std::sync::{Mutex, OnceLock};

use jni::objects::{JIntArray, JLongArray, JObject};
use jni::sys::jint;
use jni::JNIEnv;

const ACCEPTED: jint = 0;
const COVER_REQUIRED: jint = 1;
const FAULT: jint = 2;
const PPG_RATE_HZ: i32 = 55;
const ACC_RATE_HZ: i32 = 52;
const MAX_BATCH_SAMPLES: usize = 512;
const MAX_PPG_CHANNELS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicDisposition {
    Accepted,
    CoverRequired,
    Fault,
}

impl PublicDisposition {
    const fn code(self) -> jint {
        match self {
            Self::Accepted => ACCEPTED,
            Self::CoverRequired => COVER_REQUIRED,
            Self::Fault => FAULT,
        }
    }
}

#[derive(Debug, Default)]
pub struct BridgeSession {
    active: bool,
    private_batches_seen: u64,
}

impl BridgeSession {
    pub fn reset(&mut self) -> PublicDisposition {
        self.private_batches_seen = 0;
        self.active = true;
        PublicDisposition::Accepted
    }

    pub fn ingest_ppg(
        &mut self,
        sample_rate_hz: i32,
        timestamps_ns: &[i64],
        channel_samples: &[i32],
        channel_count: usize,
    ) -> PublicDisposition {
        if !self.active
            || sample_rate_hz != PPG_RATE_HZ
            || !valid_timestamps(timestamps_ns)
            || !(1..=MAX_PPG_CHANNELS).contains(&channel_count)
            || channel_samples.len() != timestamps_ns.len().saturating_mul(channel_count)
        {
            return PublicDisposition::CoverRequired;
        }
        self.private_batches_seen = self.private_batches_seen.saturating_add(1);
        PublicDisposition::Accepted
    }

    pub fn ingest_acc(
        &mut self,
        sample_rate_hz: i32,
        timestamps_ns: &[i64],
        xyz_milli_g: &[i32],
    ) -> PublicDisposition {
        if !self.active
            || sample_rate_hz != ACC_RATE_HZ
            || !valid_timestamps(timestamps_ns)
            || xyz_milli_g.len() != timestamps_ns.len().saturating_mul(3)
        {
            return PublicDisposition::CoverRequired;
        }
        self.private_batches_seen = self.private_batches_seen.saturating_add(1);
        PublicDisposition::Accepted
    }

    pub fn purge(&mut self) {
        self.private_batches_seen = 0;
        self.active = false;
    }
}

fn valid_timestamps(timestamps_ns: &[i64]) -> bool {
    !timestamps_ns.is_empty()
        && timestamps_ns.len() <= MAX_BATCH_SAMPLES
        && timestamps_ns.windows(2).all(|pair| pair[0] < pair[1])
}

fn session() -> &'static Mutex<BridgeSession> {
    static SESSION: OnceLock<Mutex<BridgeSession>> = OnceLock::new();
    SESSION.get_or_init(|| Mutex::new(BridgeSession::default()))
}

fn read_longs(env: &mut JNIEnv<'_>, values: &JLongArray<'_>) -> Result<Vec<i64>, ()> {
    let length = usize::try_from(env.get_array_length(values).map_err(|_| ())?).map_err(|_| ())?;
    if length > MAX_BATCH_SAMPLES {
        return Err(());
    }
    let mut output = vec![0_i64; length];
    env.get_long_array_region(values, 0, &mut output)
        .map_err(|_| ())?;
    Ok(output)
}

fn read_ints(env: &mut JNIEnv<'_>, values: &JIntArray<'_>, maximum: usize) -> Result<Vec<i32>, ()> {
    let length = usize::try_from(env.get_array_length(values).map_err(|_| ())?).map_err(|_| ())?;
    if length > maximum {
        return Err(());
    }
    let mut output = vec![0_i32; length];
    env.get_int_array_region(values, 0, &mut output)
        .map_err(|_| ())?;
    Ok(output)
}

fn with_session(block: impl FnOnce(&mut BridgeSession) -> PublicDisposition) -> jint {
    match session().lock() {
        Ok(mut guard) => block(&mut guard).code(),
        Err(_) => FAULT,
    }
}

#[no_mangle]
pub extern "system" fn Java_org_noticer_collector_NativeRustSink_nativeReset(
    _env: JNIEnv<'_>,
    _object: JObject<'_>,
) -> jint {
    with_session(BridgeSession::reset)
}

#[no_mangle]
pub extern "system" fn Java_org_noticer_collector_NativeRustSink_nativeIngestPpg(
    mut env: JNIEnv<'_>,
    _object: JObject<'_>,
    sample_rate_hz: jint,
    timestamps_ns: JLongArray<'_>,
    channel_samples: JIntArray<'_>,
    channel_count: jint,
) -> jint {
    let Ok(mut timestamps) = read_longs(&mut env, &timestamps_ns) else {
        return COVER_REQUIRED;
    };
    let Ok(channel_count) = usize::try_from(channel_count) else {
        timestamps.fill(0);
        return COVER_REQUIRED;
    };
    let maximum = MAX_BATCH_SAMPLES.saturating_mul(MAX_PPG_CHANNELS);
    let Ok(mut samples) = read_ints(&mut env, &channel_samples, maximum) else {
        timestamps.fill(0);
        return COVER_REQUIRED;
    };
    let result = with_session(|state| {
        state.ingest_ppg(sample_rate_hz, &timestamps, &samples, channel_count)
    });
    timestamps.fill(0);
    samples.fill(0);
    result
}

#[no_mangle]
pub extern "system" fn Java_org_noticer_collector_NativeRustSink_nativeIngestAcc(
    mut env: JNIEnv<'_>,
    _object: JObject<'_>,
    sample_rate_hz: jint,
    timestamps_ns: JLongArray<'_>,
    xyz_milli_g: JIntArray<'_>,
) -> jint {
    let Ok(mut timestamps) = read_longs(&mut env, &timestamps_ns) else {
        return COVER_REQUIRED;
    };
    let Ok(mut samples) = read_ints(&mut env, &xyz_milli_g, MAX_BATCH_SAMPLES.saturating_mul(3))
    else {
        timestamps.fill(0);
        return COVER_REQUIRED;
    };
    let result = with_session(|state| state.ingest_acc(sample_rate_hz, &timestamps, &samples));
    timestamps.fill(0);
    samples.fill(0);
    result
}

#[no_mangle]
pub extern "system" fn Java_org_noticer_collector_NativeRustSink_nativePurge(
    _env: JNIEnv<'_>,
    _object: JObject<'_>,
) {
    if let Ok(mut guard) = session().lock() {
        guard.purge();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_bounded_preferred_streams() {
        let mut bridge = BridgeSession::default();
        assert_eq!(bridge.reset(), PublicDisposition::Accepted);
        assert_eq!(
            bridge.ingest_ppg(55, &[1, 2], &[10, 11, 12, 13, 20, 21, 22, 23], 4),
            PublicDisposition::Accepted
        );
        assert_eq!(
            bridge.ingest_acc(52, &[1, 2], &[1, 2, 3, 4, 5, 6]),
            PublicDisposition::Accepted
        );
        assert_eq!(
            bridge.ingest_ppg(135, &[1], &[1, 2, 3, 4], 4),
            PublicDisposition::CoverRequired
        );
    }

    #[test]
    fn purge_revokes_the_ingress_session() {
        let mut bridge = BridgeSession::default();
        bridge.reset();
        bridge.purge();
        assert_eq!(
            bridge.ingest_acc(52, &[1], &[1, 2, 3]),
            PublicDisposition::CoverRequired
        );
    }

    #[test]
    fn rejects_oversized_or_non_monotonic_batches() {
        let mut bridge = BridgeSession::default();
        bridge.reset();
        let too_many = vec![0_i64; MAX_BATCH_SAMPLES + 1];
        assert_eq!(
            bridge.ingest_acc(52, &too_many, &[]),
            PublicDisposition::CoverRequired
        );
        assert_eq!(
            bridge.ingest_acc(52, &[2, 1], &[1, 2, 3, 4, 5, 6]),
            PublicDisposition::CoverRequired
        );
    }
}
