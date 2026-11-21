package net.portswigger.mcp.tools

// >> 20261009 mniwa Verify correlation, response updates, full messages, concurrency, and bounded capture loss reporting.
import net.portswigger.mcp.schema.HttpService
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.regex.Pattern

class LoggerHttpHistoryTest {
    private val service = HttpService("localhost", 3000, false)
    private fun request(h: LoggerHttpHistory, id: Int, tool: String = "EXTENSIONS", text: String = "request-$id") =
        h.recordRequest(id, tool, service, "http://localhost:3000/test/$id", text, "note-$id")
    private fun response(h: LoggerHttpHistory, id: Int, text: String = "final-$id", reply: String = "response-$id") =
        h.recordResponse(id, "EXTENSIONS", service, "http://localhost:3000/test/$id", text, reply, null)

    @Test fun `out of order responses remain paired with their originating request and tool`() {
        val h = LoggerHttpHistory()
        request(h, 1, "SCANNER", "before {{id}}")
        request(h, 2, "REPEATER")
        response(h, 2)
        response(h, 1, "after 123")
        val entries = h.snapshot()
        assertEquals(listOf(1, 2), entries.map { it.messageId })
        assertEquals(listOf("SCANNER", "REPEATER"), entries.map { it.tool })
        assertEquals("after 123", entries[0].request)
        assertEquals("response-1", entries[0].response)
        assertEquals("note-1", entries[0].notes)
        assertEquals("RESPONSE_INITIATING_REQUEST", entries[0].requestObservation)
    }

    @Test fun `pending traffic is explicit and updated rather than appended on response`() {
        val h = LoggerHttpHistory()
        request(h, 12)
        val pending = h.snapshot().single()
        assertNull(pending.response)
        assertNull(pending.responseTime)
        assertEquals("NO_RESPONSE_OBSERVED", pending.responseState)
        response(h, 12)
        val completed = h.snapshot().single()
        assertEquals(pending.id, completed.id)
        assertEquals("RESPONSE_RECEIVED", completed.responseState)
        assertNotNull(completed.responseTime)
    }

    @Test fun `regex searches full request response URL and sending tool`() {
        val h = LoggerHttpHistory()
        request(h, 1, "PROXY", "GET /first")
        request(h, 2, "SCANNER", "POST /second")
        response(h, 2, "POST /second", "HTTP/1.1 200\r\n\r\nunique-body")
        assertEquals(2, h.snapshot(Pattern.compile("unique-body")).single().messageId)
        assertEquals(2, h.snapshot(Pattern.compile("SCANNER")).single().messageId)
        assertEquals(1, h.snapshot(Pattern.compile("GET /first")).single().messageId)
        assertEquals(2, h.snapshot(Pattern.compile("/test/2$")).single().messageId)
        assertTrue(h.snapshot(Pattern.compile("no-match")).isEmpty())
    }

    @Test fun `capacity evicts oldest request id even after response arrival changes update order`() {
        val h = LoggerHttpHistory(maxEntries = 2)
        request(h, 1)
        request(h, 2)
        response(h, 1)
        request(h, 3)
        assertEquals(listOf(2, 3), h.snapshot().map { it.messageId })
        assertEquals(1, h.status().droppedEntries)
        assertEquals(2, h.status().firstRetainedId)
    }

    @Test fun `oversized entries are omitted whole and do not evict unrelated retained traffic`() {
        val h = LoggerHttpHistory(maxBytes = 1_500)
        request(h, 1)
        request(h, 2, text = "X".repeat(2_000))
        assertEquals(listOf(1), h.snapshot().map { it.messageId })
        assertEquals(1, h.status().droppedEntries)
        assertTrue(h.status().retainedBytes <= h.status().maxBytes)
    }

    @Test fun `full large HTTP text is retained without proxy truncation`() {
        val h = LoggerHttpHistory()
        val text = "POST /\r\n\r\n" + "\"😀\\n".repeat(4_000)
        request(h, 1, text = text)
        response(h, 1, text, text)
        assertEquals(text, h.snapshot().single().request)
        assertEquals(text, h.snapshot().single().response)
    }

    @Test fun `reused native message id receives a new history id`() {
        val h = LoggerHttpHistory()
        request(h, 4)
        response(h, 4)
        request(h, 4, text = "another request")
        response(h, 4, text = "another final request")
        assertEquals(listOf(1L, 2L), h.snapshot().map { it.id })
        assertEquals("another final request", h.snapshot().last().request)
    }

    @Test fun `response observed without its request has no fabricated request time`() {
        val h = LoggerHttpHistory()
        response(h, 80)
        assertNull(h.snapshot().single().requestTime)
        assertEquals("RESPONSE_RECEIVED", h.snapshot().single().responseState)
    }

    @Test fun `concurrent response capture preserves all correlations`() {
        val h = LoggerHttpHistory()
        val executor = Executors.newFixedThreadPool(4)
        (1..100).forEach { id -> executor.submit { request(h, id); response(h, id) } }
        executor.shutdown()
        assertTrue(executor.awaitTermination(10, TimeUnit.SECONDS))
        assertEquals(100, h.snapshot().size)
        h.snapshot().forEach { assertEquals("response-${it.messageId}", it.response) }
        assertEquals(0, h.status().captureErrors)
    }

    @Test fun `new extension capture has distinct identity and no pre-load records`() {
        val first = LoggerHttpHistory()
        request(first, 1)
        val second = LoggerHttpHistory()
        assertNotEquals(first.status().captureId, second.status().captureId)
        assertTrue(second.snapshot().isEmpty())
        assertEquals("MCP_HTTP_HANDLER", second.status().source)
    }
}
// << mniwa
