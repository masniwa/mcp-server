package net.portswigger.mcp.tools

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.nio.charset.StandardCharsets.UTF_8

class PayloadWirePlanTest {
    private fun catalog(vararg p: ProfilePayload) = PayloadProfileCatalog("a".repeat(64), p.toList())
    private fun p(id: String, mode: String, raw: String, context: String = "query") = ProfilePayload(id, mode, "light", raw, listOf(context))
    private fun output(plan: PayloadWirePlan, i: Int) = plan.materialize(i).toString(UTF_8)

    @Test fun `query mode bytes preserve baseline and duplicate parameter occurrences`() {
        val raw = "GET /?a=one&a=two HTTP/1.1\r\nHost: test\r\n\r\n"
        val positions = listOf(PayloadWirePosition("a-1", "query", 8, 11, 6, 7), PayloadWirePosition("a-2", "query", 14, 17, 12, 13))
        val plan = PayloadWirePlan.create(raw.toByteArray(), catalog(p("append", "append", " &日"), p("replace", "replace", "%2f"), p("array", "array", "[$" + "ne]")), "light", positions)
        assertEquals(6, plan.candidates.size)
        assertTrue(output(plan, 0).startsWith("GET /?a=one%20%26%E6%97%A5&a=two "))
        assertTrue(output(plan, 1).startsWith("GET /?a=one&a=two%20%26%E6%97%A5 "))
        assertTrue(output(plan, 2).startsWith("GET /?a=%252f&a=two "))
        assertTrue(output(plan, 4).startsWith("GET /?a%5B%24ne%5D=one&a=two "))
        assertEquals(output(plan, 0), output(plan, 0))
    }

    @Test fun `json strings escape once and numeric values retain lexical form`() {
        val raw = "{\"x\":\"日\\\"x\",\"n\":1}"
        val bytes = raw.toByteArray(UTF_8)
        val prefix = "{\"x\":\"".toByteArray().size
        val end = "{\"x\":\"日\\\"x".toByteArray(UTF_8).size
        val n = bytes.size - 2
        val positions = listOf(PayloadWirePosition("string", "json-string", prefix, end), PayloadWirePosition("number", "json-value", n, n + 1))
        val plan = PayloadWirePlan.create(bytes, catalog(p("s", "append", "\"\n", "json-string"), p("n", "replace", "-0", "json-value"), p("overflow", "replace", "1e309", "json-value")), "light", positions)
        assertEquals("{\"x\":\"日\\\"x\\\"\\n\",\"n\":1}", output(plan, 0))
        assertEquals(raw.replace("\"n\":1", "\"n\":-0"), output(plan, 3))
        assertEquals(raw.replace("\"n\":1", "\"n\":1e309"), output(plan, 5))
        assertEquals("CONTEXT_NOT_APPLICABLE", plan.candidates[1].reason)
    }

    @Test fun `unbound and incompatible candidates cannot materialize but retain every identity`() {
        val source = catalog(p("variable", "replace", "__HOST__", "raw"), p("array", "array", "[]", "raw"))
        val plan = PayloadWirePlan.create("x".toByteArray(), source, "light", listOf(PayloadWirePosition("raw", "raw", 0, 1)))
        assertEquals(listOf("variable", "array"), plan.candidates.map { it.payloadId })
        assertEquals(listOf("__HOST__"), plan.candidates[0].missingBindings)
        assertEquals("ARRAY_REQUIRES_QUERY_OR_FORM_NAME", plan.candidates[1].reason)
        assertThrows(IllegalArgumentException::class.java) { plan.materialize(0) }
        assertThrows(IllegalArgumentException::class.java) { plan.materialize(1) }
        val empty = PayloadWirePlan.create(byteArrayOf(), source, "light", emptyList())
        assertEquals(2, empty.candidates.size)
        assertTrue(empty.candidates.all { it.reason == "NO_POSITIONS" })
    }

    @Test fun `source mutation cannot change a prepared plan and literal bindings do not recurse`() {
        val bytes = "a=x".toByteArray()
        val plan = PayloadWirePlan.create(bytes, catalog(p("id", "replace", "__A__")), "light",
            listOf(PayloadWirePosition("a", "query", 2, 3, 0, 1)), mapOf("__A__" to "__B__&"))
        bytes.fill(0)
        assertEquals("a=__B__%26", output(plan, 0))
        assertEquals(sha256("a=x".toByteArray()), plan.requestSha256)
    }

    @Test fun `invalid ranges and json quotes fail before any plan can be sent`() {
        val source = catalog(p("id", "replace", "x"))
        val invalid = listOf(PayloadWirePosition("p", "query", -1, 2), PayloadWirePosition("p", "query", 2, 1),
            PayloadWirePosition("p", "query", 0, 10), PayloadWirePosition("p", "query", 0, 1, 1, null),
            PayloadWirePosition("p", "query", 0, 1, 1, 2), PayloadWirePosition("p", "json-string", 0, 1))
        invalid.forEach { assertThrows(IllegalArgumentException::class.java) { PayloadWirePlan.create("abc".toByteArray(), source, "light", listOf(it)) } }
    }
}
