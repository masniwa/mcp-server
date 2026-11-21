package net.portswigger.mcp.tools

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class PayloadReviewReportTest {
    @Test fun `timing inventory preserves failed and pending controls separately from spreadsheet rows`() {
        val controls = listOf(
            PayloadExecutionItem(0, "CONTROL:500:0:NORMAL", "TIMING_CONTROL", "confirmation", "RESPONSE_RECEIVED", statusCode=429, sendCallElapsedNanos=1000000),
            PayloadExecutionItem(1, "CONTROL:500:0:TRUE", "TIMING_CONTROL", "confirmation", "NOT_SENT", reason="CONTROL_EXECUTION_STOPPED"))
        val comparison = TimingComparisonResult("INSUFFICIENT_EVIDENCE", listOf("MISSING_RESPONSE_OR_DURATION"), emptyList(), emptyList())
        val report = payloadReviewReport("run", "digest", emptyList(), false, controls, comparison)
        assertTrue(report.contains("予定候補：0件"))
        assertTrue(report.contains("| timing:0 |"))
        assertTrue(report.contains("| timing:1 |"))
        assertTrue(report.contains("CONTROL_EXECUTION_STOPPED"))
        assertTrue(report.contains("MISSING_RESPONSE_OR_DURATION"))
        assertTrue(report.contains("429"))
        assertFalse(report.contains("追加対照は設定されていません"))
    }

    @Test fun `a reproduced pattern reports levels and limitations without declaring SQLi`() {
        val level = TimingLevelResult(500,3,498.5,495.0,501.0,8.0,125.0)
        val comparison = TimingComparisonResult("REPRODUCIBLE_DELAY_PATTERN", emptyList(), listOf(level), emptyList())
        val item = PayloadExecutionItem(0,"<script>|[link](bad)","TIMING_CONTROL","confirmation","RESPONSE_RECEIVED")
        val report = payloadReviewReport("run", "digest", emptyList(), true, listOf(item), comparison)
        assertTrue(report.contains("498.5"))
        assertTrue(report.contains("CONTROL_SEMANTICS_REQUIRE_REVIEW"))
        assertTrue(report.contains("SQLi確定ではありません"))
        assertTrue(report.contains("診断未完了"))
        assertFalse(report.contains("<script>"))
        assertFalse(report.contains("[link]"))
    }
    @Test fun `inventory retains nonexecuted rows and never claims diagnosis complete`() {
        val rows = listOf(
            PayloadExecutionItem(0, "P-1", "q:x", "replace", "RESPONSE_RECEIVED", statusCode = 500, sendCallElapsedNanos = 1234567),
            PayloadExecutionItem(1, "P-2", null, "array", "NOT_EXECUTABLE", reason = "MISSING_BINDINGS")
        ).map { it to triagePayload(it, null, null, emptyList()) }
        val report = payloadReviewReport("run", "digest", rows, false)
        assertTrue(report.contains("P-1"))
        assertTrue(report.contains("P-2"))
        assertTrue(report.contains("MISSING_BINDINGS"))
        assertTrue(report.contains("1.234567"))
        assertTrue(report.contains("診断未完了"))
        assertTrue(report.contains("予定候補：2件"))
    }
    @Test fun `untrusted identifiers cannot inject html links or new table rows`() {
        val item = PayloadExecutionItem(0, "<script>|[click](https://bad)\nnext", "`position`", "replace", "NOT_SENT")
        val report = payloadReviewReport("run", "digest", listOf(item to triagePayload(item, null, null, emptyList())), false)
        assertFalse(report.contains("<script>"))
        assertFalse(report.contains("[click]"))
        assertFalse(report.contains("\nnext"))
        assertTrue(report.contains("&lt;script&gt;&#124;&#91;click&#93;"))
    }
}
