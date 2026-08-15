package org.noticer.collector

import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch

class PolarCollector(
    private val polar: PolarSdkPort,
    private val bridge: WipingRustBridge,
    private val negotiator: SettingNegotiator = SettingNegotiator(),
    private val publishStatus: (PublicCollectorStatus) -> Unit,
) {
    private val state = CollectorStateMachine()

    suspend fun collect(deviceId: String) {
        require(deviceId.matches(Regex("[A-Za-z0-9:-]{6,32}"))) { "Invalid Polar device identifier" }
        publish(CollectorEvent.CONNECT)
        try {
            polar.connect(deviceId)
            publish(CollectorEvent.CONNECTED)
            val ppgSettings = negotiator.select(
                StreamKind.PPG,
                polar.requestSettings(deviceId, StreamKind.PPG),
            )
            val accSettings = negotiator.select(
                StreamKind.ACC,
                polar.requestSettings(deviceId, StreamKind.ACC),
            )
            check(bridge.reset() == BridgeDisposition.ACCEPTED) { "Rust bridge reset failed" }
            publish(CollectorEvent.NEGOTIATED)

            coroutineScope {
                launch {
                    polar.ppg(deviceId, ppgSettings).collect { batch ->
                        requireAccepted(bridge.ingestPpg(batch))
                    }
                }
                launch {
                    polar.acc(deviceId, accSettings).collect { batch ->
                        requireAccepted(bridge.ingestAcc(batch))
                    }
                }
                awaitCancellation()
            }
        } catch (error: Throwable) {
            publish(CollectorEvent.FAIL)
            throw error
        } finally {
            bridge.purge()
            runCatching { polar.stop(deviceId, StreamKind.PPG) }
            runCatching { polar.stop(deviceId, StreamKind.ACC) }
            runCatching { polar.disconnect(deviceId) }
        }
    }

    fun close() = polar.close()

    private fun requireAccepted(disposition: BridgeDisposition) {
        check(disposition == BridgeDisposition.ACCEPTED) {
            "Private batch rejected; public cover is required"
        }
    }

    private fun publish(event: CollectorEvent) {
        publishStatus(state.apply(event))
    }
}

