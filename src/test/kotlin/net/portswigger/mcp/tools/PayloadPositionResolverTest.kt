package net.portswigger.mcp.tools

import burp.api.montoya.core.Range
import burp.api.montoya.http.message.params.HttpParameterType
import burp.api.montoya.http.message.params.ParsedHttpParameter
import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class PayloadPositionResolverTest {
    private fun range(start: Int, end: Int): Range = mockk {
        every { startIndexInclusive() } returns start
        every { endIndexExclusive() } returns end
    }
    private fun param(name: String, type: HttpParameterType, start: Int, end: Int, ns: Int = 0, ne: Int = 1): ParsedHttpParameter = mockk {
        every { name() } returns name
        every { type() } returns type
        every { valueOffsets() } returns range(start, end)
        every { nameOffsets() } returns range(ns, ne)
    }

    @Test fun `same name and same value use byte positions rather than text search`() {
        val raw = "a=same&a=same".toByteArray()
        val positions = resolvePayloadPositions(raw, listOf(param("a", HttpParameterType.URL, 9, 13, 7, 8), param("a", HttpParameterType.URL, 2, 6)), listOf(AuditParameterSelector("a", "URL")), false)
        assertEquals(listOf(2, 9), positions.map { it.valueStart })
        assertEquals(2, positions.map { it.id }.distinct().size)
    }

    @Test fun `selector excludes cookie without leaking its value into position identity`() {
        val points = listOf(param("x", HttpParameterType.URL, 2, 3), param("secret", HttpParameterType.COOKIE, 6, 7))
        val selected = resolvePayloadPositions("x=a;c=b".toByteArray(), points, listOf(AuditParameterSelector("x", "URL")), false)
        assertEquals(1, selected.size)
        assertEquals("query", selected.single().context)
        assertFalse(selected.single().id.contains("secret"))
        assertThrows(IllegalArgumentException::class.java) { resolvePayloadPositions("x=a;c=b".toByteArray(), points, listOf(AuditParameterSelector("missing", "URL")), false) }
    }

    @Test fun `json offsets with and without quotes resolve to same content`() {
        val bytes = "{\"x\":\"é\",\"n\":-0}".toByteArray(Charsets.UTF_8)
        val included = resolvePayloadPositions(bytes, listOf(param("x", HttpParameterType.JSON, 5, 9)), null, false).single()
        val excluded = resolvePayloadPositions(bytes, listOf(param("x", HttpParameterType.JSON, 6, 8)), null, false).single()
        assertEquals("json-string", included.context)
        assertEquals(included.valueStart, excluded.valueStart)
        assertEquals(included.valueEnd, excluded.valueEnd)
        val number = resolvePayloadPositions(bytes, listOf(param("n", HttpParameterType.JSON, 14, 16)), null, false).single()
        assertEquals("json-value", number.context)
        assertEquals("-0", bytes.copyOfRange(number.valueStart, number.valueEnd).toString(Charsets.UTF_8))
    }

    @Test fun `only urlencoded body gets form encoding and array name range`() {
        val body = listOf(param("x", HttpParameterType.BODY, 2, 3))
        val form = resolvePayloadPositions("x=v".toByteArray(), body, null, true).single()
        val other = resolvePayloadPositions("x=v".toByteArray(), body, null, false).single()
        assertEquals("form", form.context)
        assertEquals(1, form.nameEnd)
        assertEquals("raw", other.context)
        assertNull(other.nameEnd)
    }

    @Test fun `overlap and malformed native JSON are rejected rather than silently removed`() {
        assertThrows(IllegalArgumentException::class.java) {
            resolvePayloadPositions("x=abcd".toByteArray(), listOf(param("x", HttpParameterType.URL, 2, 5), param("y", HttpParameterType.URL, 3, 6)), null, false)
        }
        assertThrows(IllegalArgumentException::class.java) {
            resolvePayloadPositions("bad".toByteArray(), listOf(param("x", HttpParameterType.JSON, 0, 3)), null, false)
        }
    }
}
