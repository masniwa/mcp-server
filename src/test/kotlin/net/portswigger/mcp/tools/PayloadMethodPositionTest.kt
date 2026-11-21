package net.portswigger.mcp.tools

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class PayloadMethodPositionTest {
    @Test fun `actual medium workbook separates all method rows from query positions`() {
        val source = System.getenv("PAYLOAD_TEST_WORKBOOK")
        val exported = System.getenv("PAYLOAD_TEST_CATALOG")
        org.junit.jupiter.api.Assumptions.assumeTrue(source != null && exported != null)
        val catalog = loadPayloadProfile(java.nio.file.Path.of(exported), java.nio.file.Path.of(source))
        val request = "GET /?x=baseline HTTP/1.1\r\nHost: test\r\n\r\n".toByteArray()
        val positions = listOf(PayloadWirePosition("query", "query", 8, 16, 6, 7), resolvePayloadMethodPosition(request))
        val plan = PayloadWirePlan.create(request, catalog, "medium", positions)
        val selected = catalog.select("medium").associateBy { it.id }
        assertEquals(458, selected.size)
        assertEquals(916, plan.candidates.size)
        assertEquals(422, plan.candidates.count { it.state == "READY" })
        assertEquals(33, plan.candidates.count { it.reason == "UNBOUND_VARIABLES" })
        assertEquals(461, plan.candidates.count { it.reason == "CONTEXT_NOT_APPLICABLE" })
        val methodRows = plan.candidates.withIndex().filter { it.value.state == "READY" && it.value.positionId!!.startsWith("METHOD:") }
        assertEquals(8, methodRows.size)
        for ((index, row) in methodRows) {
            val payload = selected.getValue(row.payloadId)
            assertEquals("METHOD", payload.category)
            assertTrue(payload.guidance.contains("HTTP method token"))
            assertEquals(payload.raw + " /?x=baseline HTTP/1.1\r\nHost: test\r\n\r\n", plan.materialize(index).toString(Charsets.UTF_8))
        }
        assertTrue(plan.candidates.filter { it.positionId == "query" && it.state == "READY" }.none { selected.getValue(it.payloadId).category == "METHOD" })
    }

    @Test fun `method payload only replaces request method and ordinary raw payload never does`() {
        val bytes = "GET /path HTTP/1.1\r\nHost: test\r\nCookie: x=abc\r\n\r\n".toByteArray()
        val rawStart = bytes.toString(Charsets.UTF_8).indexOf("abc")
        val method = resolvePayloadMethodPosition(bytes)
        val parameter = PayloadWirePosition("cookie", "raw", rawStart, rawStart + 3)
        val catalog = PayloadProfileCatalog("a".repeat(64), listOf(
            ProfilePayload("method", "replace", "light", "HEAD", listOf("raw"), "METHOD"),
            ProfilePayload("ordinary", "replace", "light", "value", listOf("raw"))))
        val plan = PayloadWirePlan.create(bytes, catalog, "light", listOf(parameter, method))
        assertEquals("CONTEXT_NOT_APPLICABLE", plan.candidates[0].reason)
        assertEquals("HEAD /path HTTP/1.1\r\nHost: test\r\nCookie: x=abc\r\n\r\n", plan.materialize(1).toString(Charsets.UTF_8))
        assertEquals("GET /path HTTP/1.1\r\nHost: test\r\nCookie: x=value\r\n\r\n", plan.materialize(2).toString(Charsets.UTF_8))
        assertEquals("CONTEXT_NOT_APPLICABLE", plan.candidates[3].reason)
    }

    @Test fun `method token rejects whitespace injection and malformed offsets`() {
        for (token in listOf("", "GET /", "GET\r\nInjected: x")) {
            val catalog = PayloadProfileCatalog("a".repeat(64), listOf(ProfilePayload("m", "replace", "light", token, listOf("raw"), "METHOD")))
            assertThrows(IllegalArgumentException::class.java) { catalog.validate() }
        }
        assertThrows(IllegalArgumentException::class.java) { resolvePayloadMethodPosition(" GET / HTTP/1.1".toByteArray()) }
        val catalog = PayloadProfileCatalog("a".repeat(64), listOf(ProfilePayload("m", "replace", "light", "POST", listOf("raw"), "METHOD")))
        assertThrows(IllegalArgumentException::class.java) {
            PayloadWirePlan.create("GET / HTTP/1.1".toByteArray(), catalog, "light", listOf(PayloadWirePosition("bad", "raw", 1, 3, target="method")))
        }
    }
}
