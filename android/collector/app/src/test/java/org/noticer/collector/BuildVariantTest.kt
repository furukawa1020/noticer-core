package org.noticer.collector

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class BuildVariantTest {
    @Test
    fun `ordinary debug build cannot expose raw values`() {
        assertEquals("debug", BuildConfig.BUILD_TYPE)
        assertFalse(BuildConfig.ALLOW_RAW_DEBUG)
    }
}

