package org.noticer.collector

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class CollectorStateMachineTest {
    @Test
    fun `allows only the acquisition lifecycle`() {
        val state = CollectorStateMachine()
        assertEquals(PublicCollectorStatus.CONNECTING, state.apply(CollectorEvent.CONNECT))
        assertEquals(PublicCollectorStatus.NEGOTIATING, state.apply(CollectorEvent.CONNECTED))
        assertEquals(PublicCollectorStatus.ACTIVE, state.apply(CollectorEvent.NEGOTIATED))
        assertEquals(PublicCollectorStatus.COVER_REQUIRED, state.apply(CollectorEvent.STOP))
        assertEquals(PublicCollectorStatus.IDLE, state.apply(CollectorEvent.STOPPED))
    }

    @Test
    fun `fails closed on invalid transition`() {
        assertThrows(IllegalStateException::class.java) {
            CollectorStateMachine().apply(CollectorEvent.NEGOTIATED)
        }
    }
}

