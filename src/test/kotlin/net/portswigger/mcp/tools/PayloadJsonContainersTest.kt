package net.portswigger.mcp.tools

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class PayloadJsonContainersTest {
    private fun request(body: String) = ("POST /test HTTP/1.1\r\nContent-Type: application/json\r\n\r\n" + body).toByteArray()

    @Test fun `escaped pointers and unicode retain exact byte ranges`() {
        val body = """{"日本語":"é","a/b":{"~name":[{"x":1},{}]},"other":{"x":1}}"""
        val bytes = request(body)
        val positions = resolvePayloadJsonContainers(bytes, listOf("/a~1b/~0name/0", "/other", "/a~1b/~0name"))
        assertEquals(listOf("{\"x\":1}", "{\"x\":1}", "[{\"x\":1},{}]"), positions.map {
            bytes.copyOfRange(it.valueStart, it.valueEnd).toString(Charsets.UTF_8)
        })
        assertNotEquals(positions[0].valueStart, positions[1].valueStart)
        assertTrue(positions.all { it.context == "json-value" && !it.id.contains("name") })
    }

    @Test fun `whole object replacement preserves sibling and native baseline`() {
        val bytes = request("""{"value":{"name":"baseline"},"keep":true}""")
        val positions = resolvePayloadJsonContainers(bytes, listOf("/value"))
        val catalog = PayloadProfileCatalog("a".repeat(64), listOf(
            ProfilePayload("object", "replace", "light", "{\"role\":\"admin\"}", listOf("json-value"))))
        val plan = PayloadWirePlan.create(bytes, catalog, "light", positions)
        assertTrue(plan.materialize(0).toString(Charsets.UTF_8).endsWith("{\"value\":{\"role\":\"admin\"},\"keep\":true}"))
        assertTrue(bytes.toString(Charsets.UTF_8).contains("baseline"))
    }

    @Test fun `root and empty property containers are distinct`() {
        val bytes = request("""{"":[],"x":{}}""")
        val p = resolvePayloadJsonContainers(bytes, listOf("", "/"))
        assertEquals("[]", bytes.copyOfRange(p[1].valueStart, p[1].valueEnd).toString(Charsets.UTF_8))
        assertTrue(p[0].valueStart < p[1].valueStart)
    }

    @Test fun `missing scalar duplicate and malformed pointers refuse planning`() {
        for (pointer in listOf("/missing", "/x", "x", "/bad~2escape", "/a/01")) {
            assertThrows(Exception::class.java) { resolvePayloadJsonContainers(request("""{"x":1,"a":[{}]}"""), listOf(pointer)) }
        }
        assertThrows(Exception::class.java) { resolvePayloadJsonContainers(request("{}"), listOf("", "")) }
        assertThrows(Exception::class.java) { resolvePayloadJsonContainers(request("""{"x":{},"x":{}}"""), listOf("/x")) }
    }

    @Test fun `malformed input and excessive nesting refuse planning`() {
        for (body in listOf("{\"x\":{}} trailing", "{\"x\":bare}", "{\"x\":[1,]}", "[".repeat(130) + "]".repeat(130))) {
            assertThrows(Exception::class.java) { resolvePayloadJsonContainers(request(body), listOf("")) }
        }
        val invalid = request("{}") + byteArrayOf(0xff.toByte())
        assertThrows(Exception::class.java) { resolvePayloadJsonContainers(invalid, listOf("")) }
    }

    @Test fun `omitted option leaves non JSON requests untouched`() {
        assertTrue(resolvePayloadJsonContainers("GET / HTTP/1.1\r\n\r\n".toByteArray(), emptyList()).isEmpty())
    }

    @Test fun `literal control characters in JSON strings are rejected`() {
        for (control in listOf('\n', '\t', '\r', '\u0000', '\u001f')) {
            for (body in listOf("{\"key${control}\":{}}", "{\"key\":\"value${control}\"}")) {
                assertThrows(Exception::class.java) { resolvePayloadJsonContainers(request(body), listOf("")) }
            }
        }
        assertEquals(1, resolvePayloadJsonContainers(request("{\"key\":\"value\\n\\t\\r\\u0000\"}"), listOf("")).size)
    }
}
