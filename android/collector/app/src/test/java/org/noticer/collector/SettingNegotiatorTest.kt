package org.noticer.collector

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class SettingNegotiatorTest {
    private val negotiator = SettingNegotiator()

    @Test
    fun `selects exact preferred rates from device offers`() {
        val ppg = negotiator.select(
            StreamKind.PPG,
            AvailableSettings(
                mapOf(
                    SettingKey.SAMPLE_RATE to setOf(28, 55, 135),
                    SettingKey.RESOLUTION to setOf(22),
                    SettingKey.CHANNELS to setOf(4),
                ),
            ),
        )
        val acc = negotiator.select(
            StreamKind.ACC,
            AvailableSettings(
                mapOf(
                    SettingKey.SAMPLE_RATE to setOf(26, 52, 104),
                    SettingKey.RESOLUTION to setOf(16),
                    SettingKey.RANGE to setOf(4, 8),
                    SettingKey.CHANNELS to setOf(3),
                ),
            ),
        )

        assertEquals(55, ppg.sampleRateHz)
        assertEquals(52, acc.sampleRateHz)
        assertEquals(8, acc.values[SettingKey.RANGE])
    }

    @Test
    fun `rejects device offer without approved rate`() {
        assertThrows(UnsupportedStreamSettings::class.java) {
            negotiator.select(
                StreamKind.PPG,
                AvailableSettings(mapOf(SettingKey.SAMPLE_RATE to setOf(135))),
            )
        }
    }
}

