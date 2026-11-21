package net.portswigger.mcp.tools

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.util.regex.Pattern

class HistoryRegexTest {
    @Test fun `ordinary Java expressions retain their match semantics`() {
        val texts = listOf("", "GET /path HTTP/1.1\r\nHost: example.test\r\n\r\n", "日abc123\nlast", "HTTP/1.1 200\r\n\r\nerror")
        for (expression in listOf("", "(?s)^GET.*Host:", "(?<=abc)\\d+", "(?i)ERROR", "(?m)^last$", "absent")) {
            val pattern = Pattern.compile(expression)
            val search = HistoryRegex(pattern)
            for (text in texts) assertEquals(pattern.matcher(text).find(), search.contains(text), expression)
        }
    }

    @Test fun `unanchored lookahead stops rather than returning no match`() {
        val search = HistoryRegex(Pattern.compile("(?s)(?=.*missing)(?=.*scope)"), 10_000)
        val error = assertThrows(IllegalStateException::class.java) { search.contains("x".repeat(10_000)) }
        assertTrue(error.message!!.startsWith("REGEX_WORK_LIMIT"))
    }

    @Test fun `budget is shared across individual fields and records`() {
        val search = HistoryRegex(Pattern.compile("z"), 3)
        assertFalse(search.contains("aa"))
        assertThrows(IllegalStateException::class.java) { search.contains("aa") }
    }

    @Test fun `failed logger search preserves capture and subsequent reads`() {
        val history = LoggerHttpHistory()
        history.recordRequest(1, "SCANNER", net.portswigger.mcp.schema.HttpService("localhost", 80, false),
            "http://localhost/", "x".repeat(10_000), null)
        assertThrows(IllegalStateException::class.java) {
            history.snapshot(Pattern.compile("(?s)(?=.*missing)(?=.*scope)"))
        }
        assertEquals(1, history.status().retainedEntries)
        assertEquals(1, history.snapshot().size)
        assertEquals(1, history.snapshot(Pattern.compile("^x")).size)
    }
}
