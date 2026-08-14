package org.noticer.collector

class NativeRustSink : RustBatchSink {
    init {
        check(runCatching { System.loadLibrary("noticer_android_bridge") }.isSuccess) {
            "Bounded Rust bridge is unavailable"
        }
    }

    override fun reset(): BridgeDisposition = nativeReset().toDisposition()

    override fun ingestPpg(batch: PpgBatch): BridgeDisposition = nativeIngestPpg(
        batch.sampleRateHz,
        batch.timestampsNs,
        batch.channelSamples,
        batch.channelCount,
    ).toDisposition()

    override fun ingestAcc(batch: AccBatch): BridgeDisposition = nativeIngestAcc(
        batch.sampleRateHz,
        batch.timestampsNs,
        batch.xyzMilliG,
    ).toDisposition()

    override fun purge() {
        nativePurge()
    }

    private external fun nativeReset(): Int
    private external fun nativeIngestPpg(
        sampleRateHz: Int,
        timestampsNs: LongArray,
        channelSamples: IntArray,
        channelCount: Int,
    ): Int
    private external fun nativeIngestAcc(
        sampleRateHz: Int,
        timestampsNs: LongArray,
        xyzMilliG: IntArray,
    ): Int
    private external fun nativePurge()

    private fun Int.toDisposition(): BridgeDisposition = when (this) {
        0 -> BridgeDisposition.ACCEPTED
        1 -> BridgeDisposition.COVER_REQUIRED
        else -> BridgeDisposition.FAULT
    }
}

