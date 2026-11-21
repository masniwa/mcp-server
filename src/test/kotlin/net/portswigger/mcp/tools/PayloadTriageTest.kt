package net.portswigger.mcp.tools

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.util.Base64

class PayloadTriageTest {
    private fun b64(s: String) = Base64.getEncoder().encodeToString(s.toByteArray())
    private fun item(status: Int = 200, state: String = "RESPONSE_RECEIVED") =
        PayloadExecutionItem(0, "p1", "query:x", "replace", state, statusCode = status, sendCallElapsedNanos = 9_000_000_000)
    private fun baseline(body: String = "normal") = PayloadBaselineRecord(b64("request"),
        b64("HTTP/1.1 200 OK\r\n\r\n$body"), 200, "a", "b")
    private fun evidence(item: PayloadExecutionItem, body: String, grep: List<PayloadGrepObservation> = emptyList()) =
        PayloadEvidenceRecord(item, b64("request"), b64("HTTP/1.1 ${item.statusCode} Test\r\n\r\n$body"), grep)

    @Test fun `grep negative response differences are reviewable not vulnerability verdicts`() {
        val item = item(500)
        val result = triagePayload(item, evidence(item, "SQL error"), baseline(), emptyList())
        assertEquals("REVIEW_REQUIRED", result.state)
        assertTrue(result.signals.containsAll(listOf("HTTP_SERVER_ERROR", "STATUS_CHANGED", "BODY_CHANGED", "BODY_LENGTH_CHANGED")))
        assertTrue(result.limitations.contains("NOT_A_VULNERABILITY_VERDICT"))
    }
    @Test fun `baseline grep match is identified as common not new evidence`() {
        val item = item()
        val result = triagePayload(item, evidence(item, "error", listOf(PayloadGrepObservation("sql", "replace", "MATCH"))),
            baseline("error"), listOf(ProfileGrep(mode = "replace", name = "sql", regex = "error")))
        assertEquals(listOf("GREP_MATCH_ALSO_IN_BASELINE"), result.signals)
    }
    @Test fun `long duration alone never becomes SQLi and missing controls are explicit`() {
        val item = item()
        val result = triagePayload(item, evidence(item, "normal"), baseline(), emptyList())
        assertEquals("NO_SIGNAL_IN_AVAILABLE_OBSERVATIONS", result.state)
        assertTrue(result.limitations.contains("PAIRED_TIMING_CONTROLS_NOT_COLLECTED"))
    }
    @Test fun `rate limiting and failures are review candidates without invented response`() {
        assertTrue(triagePayload(item(429), evidence(item(429), "busy"), baseline(), emptyList()).signals.contains("RATE_LIMIT_RESPONSE"))
        val failed = triagePayload(item(state = "ERROR").copy(statusCode = null), null, null, emptyList())
        assertNull(failed.response)
        assertEquals("REVIEW_REQUIRED", failed.state)
        val notSent = triagePayload(item(state = "NOT_SENT").copy(statusCode = null, sendCallElapsedNanos = null), null, null, emptyList())
        assertEquals("NOT_ASSESSED", notSent.state)
    }
    @Test fun `body metrics preserve binary bytes and exclude headers`() {
        val bytes = "HTTP/1.1 200 OK\r\nX: changed\r\n\r\n".toByteArray() + byteArrayOf(0, -1, 10)
        val metrics = payloadResponseMetrics(bytes)
        assertEquals(3, metrics.bodyBytes)
        assertEquals(sha256(byteArrayOf(0, -1, 10)), metrics.bodySha256)
        assertNull(payloadResponseMetrics(byteArrayOf(1, 2)).bodyBytes)
    }
}
