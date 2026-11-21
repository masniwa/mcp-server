package net.portswigger.mcp.tools

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class PayloadGrepTest {
    @Test fun `only current mode regexes are evaluated with explicit text offsets`() {
        val result = observePayloadGrep(listOf(ProfileGrep("append", "sql", "SQL.*error"),
            ProfileGrep("replace", "other", "SQL"), ProfileGrep("append", "absent", "exception")), "append", "日SQL syntax error".toByteArray())
        assertEquals(listOf("sql", "absent"), result.map { it.name })
        assertEquals(listOf("MATCH", "NO_MATCH"), result.map { it.state })
        assertEquals(1, result.first().start)
        assertEquals(17, result.first().end)
    }
    @Test fun `no response and excessive regex work are not no match`() {
        val definitions = listOf(ProfileGrep("replace", "x", "x"))
        assertEquals("NOT_EVALUATED", observePayloadGrep(definitions, "replace", null).single().state)
        val limited = observePayloadGrep(definitions, "replace", "x".toByteArray(), 0).single()
        assertEquals("ERROR", limited.state)
        assertEquals("RegexWorkLimit", limited.reason)
    }
    @Test fun `invalid regex cannot masquerade as a clean response`() {
        val result = observePayloadGrep(listOf(ProfileGrep("array", "broken", "[")), "array", "normal".toByteArray()).single()
        assertEquals("ERROR", result.state)
    }
}
