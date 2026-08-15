package org.noticer.collector

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class BatchBridgeTest {
    @Test
    fun `converts batches and wipes temporary arrays after bridge call`() {
        val ppg = BatchConverter.ppg(
            listOf(
                RawPpgSample(1, listOf(10, 11, 12, 13)),
                RawPpgSample(2, listOf(20, 21, 22, 23)),
            ),
            55,
        )
        val acc = BatchConverter.acc(listOf(RawAccSample(1, 1, 2, 3)), 52)
        val bridge = WipingRustBridge(AcceptingSink())

        assertEquals(BridgeDisposition.ACCEPTED, bridge.ingestPpg(ppg))
        assertEquals(BridgeDisposition.ACCEPTED, bridge.ingestAcc(acc))
        assertTrue(ppg.timestampsNs.all { it == 0L })
        assertTrue(ppg.channelSamples.all { it == 0 })
        assertTrue(acc.timestampsNs.all { it == 0L })
        assertTrue(acc.xyzMilliG.all { it == 0 })
    }

    private class AcceptingSink : RustBatchSink {
        override fun reset() = BridgeDisposition.ACCEPTED
        override fun ingestPpg(batch: PpgBatch) = BridgeDisposition.ACCEPTED
        override fun ingestAcc(batch: AccBatch) = BridgeDisposition.ACCEPTED
        override fun purge() = Unit
    }
}

