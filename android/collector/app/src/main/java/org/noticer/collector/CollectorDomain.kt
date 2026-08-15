package org.noticer.collector

enum class StreamKind {
    PPG,
    ACC,
}

enum class SettingKey {
    SAMPLE_RATE,
    RESOLUTION,
    RANGE,
    CHANNELS,
}

data class AvailableSettings(
    val values: Map<SettingKey, Set<Int>>,
)

data class SelectedSettings(
    val values: Map<SettingKey, Int>,
) {
    val sampleRateHz: Int = requireNotNull(values[SettingKey.SAMPLE_RATE])
}

class UnsupportedStreamSettings(message: String) : IllegalArgumentException(message)

class SettingNegotiator {
    private data class Policy(
        val sampleRateHz: Int,
        val optionalChoices: Map<SettingKey, List<Int>>,
    )

    private val policies = mapOf(
        StreamKind.PPG to Policy(
            sampleRateHz = 55,
            optionalChoices = mapOf(
                SettingKey.RESOLUTION to listOf(22),
                SettingKey.CHANNELS to listOf(4),
            ),
        ),
        StreamKind.ACC to Policy(
            sampleRateHz = 52,
            optionalChoices = mapOf(
                SettingKey.RESOLUTION to listOf(16),
                SettingKey.RANGE to listOf(8, 4, 2),
                SettingKey.CHANNELS to listOf(3),
            ),
        ),
    )

    fun select(kind: StreamKind, available: AvailableSettings): SelectedSettings {
        val policy = requireNotNull(policies[kind])
        val offeredRates = available.values[SettingKey.SAMPLE_RATE].orEmpty()
        if (policy.sampleRateHz !in offeredRates) {
            throw UnsupportedStreamSettings(
                "$kind requires ${policy.sampleRateHz} Hz from the device offer",
            )
        }

        val selected = mutableMapOf(SettingKey.SAMPLE_RATE to policy.sampleRateHz)
        policy.optionalChoices.forEach { (key, approvedOrder) ->
            val offered = available.values[key] ?: return@forEach
            selected[key] = approvedOrder.firstOrNull(offered::contains)
                ?: throw UnsupportedStreamSettings("$kind offered no approved $key value")
        }
        return SelectedSettings(selected.toMap())
    }
}

enum class PublicCollectorStatus {
    IDLE,
    CONNECTING,
    NEGOTIATING,
    ACTIVE,
    COVER_REQUIRED,
    FAULT,
}

enum class CollectorEvent {
    CONNECT,
    CONNECTED,
    NEGOTIATED,
    STOP,
    STOPPED,
    FAIL,
    RESET,
}

class CollectorStateMachine {
    var status: PublicCollectorStatus = PublicCollectorStatus.IDLE
        private set

    fun apply(event: CollectorEvent): PublicCollectorStatus {
        status = when (status to event) {
            PublicCollectorStatus.IDLE to CollectorEvent.CONNECT -> PublicCollectorStatus.CONNECTING
            PublicCollectorStatus.CONNECTING to CollectorEvent.CONNECTED -> PublicCollectorStatus.NEGOTIATING
            PublicCollectorStatus.NEGOTIATING to CollectorEvent.NEGOTIATED -> PublicCollectorStatus.ACTIVE
            PublicCollectorStatus.ACTIVE to CollectorEvent.STOP -> PublicCollectorStatus.COVER_REQUIRED
            PublicCollectorStatus.COVER_REQUIRED to CollectorEvent.STOPPED -> PublicCollectorStatus.IDLE
            PublicCollectorStatus.FAULT to CollectorEvent.RESET -> PublicCollectorStatus.IDLE
            else -> if (event == CollectorEvent.FAIL) {
                PublicCollectorStatus.FAULT
            } else {
                throw IllegalStateException("Invalid public collector transition: $status + $event")
            }
        }
        return status
    }
}

data class RawPpgSample(
    val timestampNs: Long,
    val channels: List<Int>,
)

data class RawAccSample(
    val timestampNs: Long,
    val xMilliG: Int,
    val yMilliG: Int,
    val zMilliG: Int,
)

data class PpgBatch(
    val timestampsNs: LongArray,
    val channelSamples: IntArray,
    val channelCount: Int,
    val sampleRateHz: Int,
)

data class AccBatch(
    val timestampsNs: LongArray,
    val xyzMilliG: IntArray,
    val sampleRateHz: Int,
)

object BatchConverter {
    fun ppg(samples: List<RawPpgSample>, sampleRateHz: Int): PpgBatch {
        require(samples.isNotEmpty()) { "PPG batch must not be empty" }
        val channelCount = samples.first().channels.size
        require(channelCount in 1..8) { "PPG channel count is outside the bridge bound" }
        require(samples.all { it.channels.size == channelCount }) { "PPG channel count changed in batch" }
        return PpgBatch(
            timestampsNs = samples.map(RawPpgSample::timestampNs).toLongArray(),
            channelSamples = samples.flatMap(RawPpgSample::channels).toIntArray(),
            channelCount = channelCount,
            sampleRateHz = sampleRateHz,
        )
    }

    fun acc(samples: List<RawAccSample>, sampleRateHz: Int): AccBatch {
        require(samples.isNotEmpty()) { "ACC batch must not be empty" }
        return AccBatch(
            timestampsNs = samples.map(RawAccSample::timestampNs).toLongArray(),
            xyzMilliG = samples.flatMap { listOf(it.xMilliG, it.yMilliG, it.zMilliG) }.toIntArray(),
            sampleRateHz = sampleRateHz,
        )
    }
}

enum class BridgeDisposition {
    ACCEPTED,
    COVER_REQUIRED,
    FAULT,
}

interface RustBatchSink {
    fun reset(): BridgeDisposition
    fun ingestPpg(batch: PpgBatch): BridgeDisposition
    fun ingestAcc(batch: AccBatch): BridgeDisposition
    fun purge()
}

class WipingRustBridge(private val sink: RustBatchSink) {
    fun reset(): BridgeDisposition = sink.reset()

    fun ingestPpg(batch: PpgBatch): BridgeDisposition = try {
        sink.ingestPpg(batch)
    } finally {
        batch.timestampsNs.fill(0L)
        batch.channelSamples.fill(0)
    }

    fun ingestAcc(batch: AccBatch): BridgeDisposition = try {
        sink.ingestAcc(batch)
    } finally {
        batch.timestampsNs.fill(0L)
        batch.xyzMilliG.fill(0)
    }

    fun purge() = sink.purge()
}

