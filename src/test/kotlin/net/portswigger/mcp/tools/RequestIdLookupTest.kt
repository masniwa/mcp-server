package net.portswigger.mcp.tools

// >> 20261014 mniwa Test identifier separation, response pairing, stale captures and incomplete history without sending traffic.
import net.portswigger.mcp.schema.HttpService
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class RequestIdLookupTest {
    private val service = HttpService("localhost", 3000, false)
    private fun record(h: LoggerHttpHistory, message: Int) = h.recordRequest(message, "SCANNER", service, "http://localhost:3000/same", "request-$message", null)

    @Test fun `capture identifiers never substitute for message or native UI identifiers`() {
        val h = LoggerHttpHistory()
        record(h, 42)
        record(h, 1)
        val capture = h.status().captureId
        assertEquals(42, h.lookup(1, LoggerRequestIdType.MCP_CAPTURE_ID, capture).logger!!.messageId)
        assertEquals(1, h.lookup(1, LoggerRequestIdType.HTTP_MESSAGE_ID, capture).logger!!.messageId)
        assertEquals("UNSUPPORTED_UI_ID", h.lookup(1, LoggerRequestIdType.LOGGER_UI, capture).status)
        assertNull(h.lookup(1, LoggerRequestIdType.LOGGER_UI, capture).logger)
    }

    @Test fun `pending entry receives only its correlated response`() {
        val h = LoggerHttpHistory()
        record(h, 42); record(h, 1)
        val capture = h.status().captureId
        assertEquals("NO_RESPONSE_OBSERVED", h.lookup(42, LoggerRequestIdType.HTTP_MESSAGE_ID, capture).logger!!.responseState)
        h.recordResponse(1, "SCANNER", service, "http://localhost:3000/same", "request-1", "reply-1", null)
        assertNull(h.lookup(42, LoggerRequestIdType.HTTP_MESSAGE_ID, capture).logger!!.response)
        h.recordResponse(42, "SCANNER", service, "http://localhost:3000/same", "final-42", "reply-42", null)
        val result = h.lookup(42, LoggerRequestIdType.HTTP_MESSAGE_ID, capture).logger!!
        assertEquals("final-42", result.request)
        assertEquals("reply-42", result.response)
    }

    @Test fun `reload guards reject reused identifiers`() {
        val old = LoggerHttpHistory(); record(old, 1)
        val current = LoggerHttpHistory(); record(current, 1)
        assertEquals("CAPTURE_MISMATCH", current.lookup(1, LoggerRequestIdType.MCP_CAPTURE_ID, old.status().captureId).status)
        assertThrows(IllegalArgumentException::class.java) { current.lookup(1, LoggerRequestIdType.MCP_CAPTURE_ID, null) }
    }

    @Test fun `eviction and missing traffic do not masquerade as matching rows`() {
        val h = LoggerHttpHistory(maxEntries = 1); record(h, 42); record(h, 43)
        val result = h.lookup(1, LoggerRequestIdType.MCP_CAPTURE_ID, h.status().captureId)
        assertEquals("NOT_RETAINED_OR_NOT_CAPTURED", result.status)
        assertEquals(1L, result.capture!!.droppedEntries)
        assertNull(result.logger)
        assertEquals("NOT_RETAINED_OR_NOT_CAPTURED", h.lookup(Long.MAX_VALUE, LoggerRequestIdType.MCP_CAPTURE_ID, h.status().captureId).status)
    }

    @Test fun `duplicate correlation identifiers are ambiguous`() {
        val h = LoggerHttpHistory(); record(h, 42); record(h, 42)
        assertEquals("AMBIGUOUS", h.lookup(42, LoggerRequestIdType.HTTP_MESSAGE_ID, h.status().captureId).status)
    }

    @Test fun `invalid and overflowing identifiers are rejected`() {
        val h = LoggerHttpHistory()
        assertThrows(IllegalArgumentException::class.java) { h.lookup(-1, LoggerRequestIdType.MCP_CAPTURE_ID, h.status().captureId) }
        assertThrows(IllegalArgumentException::class.java) { h.lookup(Int.MAX_VALUE.toLong() + 1, LoggerRequestIdType.HTTP_MESSAGE_ID, h.status().captureId) }
    }
}
// << mniwa
