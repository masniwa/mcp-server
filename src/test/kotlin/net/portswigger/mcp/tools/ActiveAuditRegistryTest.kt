package net.portswigger.mcp.tools

import burp.api.montoya.scanner.audit.Audit
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.double
import kotlinx.serialization.json.int
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

// >> 20261008 mniwa Verify live audit progress, unknown states, unique identifiers, and server-lifetime isolation.
class ActiveAuditRegistryTest {
    @Test fun `submission exception retains identity and cannot become completed from an empty finished audit`() {
        val registry = ActiveAuditRegistry()
        val native = audit("finished")
        val id = registry.register(native, "localhost", 3000, "http", "/uncertain")
        var calls = 0
        val error = registry.submit(id) { calls++; throw IllegalStateException("acceptance unknown") }
        assertEquals(1, calls)
        assertNotNull(error)
        repeat(2) {
            val result = registry.snapshot(id)!!
            assertEquals(id, result["auditId"]!!.jsonPrimitive.content)
            assertEquals(JsonNull, result["completed"])
            assertEquals("true", result["nativeCompleted"]!!.jsonPrimitive.content)
            assertEquals(error, result["submissionError"]!!.jsonPrimitive.content)
            assertEquals("SUBMISSION_OUTCOME_UNKNOWN", result["timeEstimate"]!!.jsonObject["reason"]!!.jsonPrimitive.content)
        }
        assertEquals(1, calls)
        every { native.statusMessage() } throws IllegalStateException("observation unavailable")
        val failedObservation = registry.snapshot(id)!!
        assertNotNull(failedObservation["observationError"])
        assertNotNull(failedObservation["submissionError"])
        verify(exactly = 0) { native.delete() }
    }

    @Test fun `submission requires an existing handle and successful submission preserves completion semantics`() {
        val registry = ActiveAuditRegistry()
        var calls = 0
        assertThrows(IllegalArgumentException::class.java) { registry.submit("absent") { calls++ } }
        assertEquals(0, calls)
        val id = registry.register(audit("finished"), "localhost", 3000, "http", "/normal")
        assertNull(registry.submit(id) { calls++ })
        assertEquals(1, calls)
        assertEquals("true", registry.snapshot(id)!!["completed"]!!.jsonPrimitive.content)
        assertEquals("NATIVE_EXECUTION_ONLY",registry.snapshot(id)!!["completionScope"]!!.jsonPrimitive.content)
        assertEquals("false",registry.snapshot(id)!!["nativeTaskSettingsVerified"]!!.jsonPrimitive.content)
        assertEquals("NATIVE_INSERTION_POINT_REVIEW_REQUIRED",registry.snapshot(id)!!["coverageState"]!!.jsonPrimitive.content)
        assertEquals("false",registry.snapshot(id)!!["diagnosisCompleted"]!!.jsonPrimitive.content)
        assertNull(registry.snapshot(id)!!["submissionError"])
    }

    @Test fun `failed observation retains handle does not hide healthy audits and can recover`() {
        val registry = ActiveAuditRegistry()
        val broken = audit()
        every { broken.statusMessage() } throws NullPointerException("native task unavailable")
        val id = registry.register(broken, "localhost", 3000, "http", "/broken")
        val healthy = registry.register(audit("finished"), "localhost", 3000, "http", "/healthy")
        val result = registry.snapshot(id)!!
        assertEquals(id, result["auditId"]!!.jsonPrimitive.content)
        assertEquals(JsonNull, result["completed"])
        assertEquals(broken.requestCount(), result["auditRequestCount"]!!.jsonPrimitive.int)
        assertEquals("AUDIT_OBSERVATION_FAILED", result["timeEstimate"]!!.jsonObject["reason"]!!.jsonPrimitive.content)
        assertEquals(2, registry.snapshots().size)
        assertEquals("true", registry.snapshot(healthy)!!["completed"]!!.jsonPrimitive.content)
        every { broken.statusMessage() } returns "scanning"
        assertEquals("false", registry.snapshot(id)!!["completed"]!!.jsonPrimitive.content)
        every { broken.requestCount() } throws IllegalStateException("counter unavailable")
        assertEquals("false", registry.snapshot(id)!!["completed"]!!.jsonPrimitive.content)
        assertEquals(JsonNull, registry.snapshot(id)!!["auditRequestCount"])
        assertEquals(broken.insertionPointCount(), registry.snapshot(id)!!["auditInsertionPointCount"]!!.jsonPrimitive.int)
        verify(exactly = 0) { broken.addRequest(any()) }
        verify(exactly = 0) { broken.delete() }
    }
    // >> 20261014 mniwa Verify ETA integration, comparison isolation and existing completion flags without mutating audits.
    @Test fun `registry snapshots attach model estimates and isolate method and parameter shapes`() {
        var nanos = 0L
        val registry = ActiveAuditRegistry(ScanTimeEstimator({ nanos }, { java.time.Instant.EPOCH.plusNanos(nanos) }))
        repeat(3) {
            val task = audit("scanning")
            every { task.errorCount() } returns 0
            every { task.requestCount() } returns 0
            val id = registry.register(task, "localhost", 3000, "http", "/search", "fixed", "GET", "query-field")
            registry.snapshot(id)
            nanos += 50_000_000_000
            every { task.statusMessage() } returns "finished"
            every { task.requestCount() } returns 100
            registry.snapshot(id)
            registry.snapshot(id)
        }
        val task = audit("scanning")
        every { task.errorCount() } returns 0
        every { task.requestCount() } returns 0
        val id = registry.register(task, "localhost", 3000, "http", "/search", "fixed", "GET", "query-field")
        registry.snapshot(id)
        nanos += 10_000_000_000
        every { task.requestCount() } returns 20
        val estimate = registry.snapshot(id)!!["timeEstimate"]!!.jsonObject
        assertEquals("ESTIMATED", estimate["reason"]!!.jsonPrimitive.content)
        assertEquals(40.0, estimate["remainingSeconds"]!!.jsonPrimitive.double)
        assertEquals(3, estimate["comparableCompletedScans"]!!.jsonPrimitive.int)
        val other = registry.register(task, "localhost", 3000, "http", "/search", "fixed", "POST", "query-field")
        assertEquals("INSUFFICIENT_COMPARABLE_HISTORY", registry.snapshot(other)!!["timeEstimate"]!!.jsonObject["reason"]!!.jsonPrimitive.content)
        val shape = registry.register(task, "localhost", 3000, "http", "/search", "fixed", "GET", "other-field")
        assertEquals("INSUFFICIENT_COMPARABLE_HISTORY", registry.snapshot(shape)!!["timeEstimate"]!!.jsonObject["reason"]!!.jsonPrimitive.content)
        verify(exactly = 0) { task.delete() }
        verify(exactly = 0) { task.addRequest(any()) }
    }
    // << mniwa
    // >> 20261014 mniwa Use supplied workload on the first audit and retain it without creating comparison scans.
    @Test fun `first tracked audit accepts and retains a workload with no profile history`() {
        val registry = ActiveAuditRegistry()
        val task = audit("scanning")
        every { task.errorCount() } returns 0
        every { task.requestCount() } returns 0
        val id = registry.register(task, "localhost", 3000, "http", "/search")
        val model = ScanWorkload(10.0, "Observed check evidence", 2.0, 1.0)
        val initial = registry.snapshot(id, model)!!["timeEstimate"]!!.jsonObject
        assertEquals("ESTIMATED", initial["status"]!!.jsonPrimitive.content)
        assertEquals(60.0, initial["remainingSeconds"]!!.jsonPrimitive.double)
        assertEquals(0, initial["comparableCompletedScans"]!!.jsonPrimitive.int)
        val retained = registry.snapshot(id)!!["timeEstimate"]!!.jsonObject
        assertEquals(10.0, retained["requestsPerInsertionPoint"]!!.jsonPrimitive.double)
        verify(exactly = 0) { task.addRequest(any()) }
        verify(exactly = 0) { task.delete() }
    }
    // << mniwa
    private fun audit(message: String = "scanning"): Audit = mockk<Audit>().also {
        every { it.statusMessage() } returns message
        every { it.requestCount() } returns 7
        every { it.errorCount() } returns 1
        every { it.insertionPointCount() } returns 3
        every { it.issues() } returns emptyList()
    }

    @Test fun `snapshot rereads live counters and completion`() {
        val registry = ActiveAuditRegistry()
        val task = audit()
        val id = registry.register(task, "localhost", 3000, "http", "/dataadd")
        assertEquals("false", registry.snapshot(id)!!["completed"]!!.jsonPrimitive.content)
        every { task.statusMessage() } returns "finished"
        every { task.requestCount() } returns 15
        val result = registry.snapshot(id)!!
        assertEquals("true", result["completed"]!!.jsonPrimitive.content)
        assertEquals("15", result["auditRequestCount"]!!.jsonPrimitive.content)
        assertEquals("1", result["auditErrorCount"]!!.jsonPrimitive.content)
        verify(exactly = 0) { task.delete() }
        verify(exactly = 0) { task.addRequest(any()) }
    }

    @Test fun `unrecognized completion wording remains unknown`() {
        val registry = ActiveAuditRegistry()
        val id = registry.register(audit("almost completed"), "localhost", 8888, "http", "/api/v1/users/x")
        assertEquals(JsonNull, registry.snapshot(id)!!["completed"])
    }

    @Test fun `paused audit is not complete`() {
        val registry = ActiveAuditRegistry()
        val id = registry.register(audit("paused"), "localhost", 3000, "http", "/dataadd")
        assertEquals("false", registry.snapshot(id)!!["completed"]!!.jsonPrimitive.content)
    }

    @Test fun `unsupported optional metrics do not hide audit progress`() {
        val registry = ActiveAuditRegistry()
        val task = audit("finished")
        every { task.errorCount() } throws UnsupportedOperationException("Currently unsupported.")
        every { task.issues() } throws UnsupportedOperationException("Currently unsupported.")
        val id = registry.register(task, "localhost", 3000, "http", "/dataadd")
        val result = registry.snapshot(id)!!
        assertEquals("true", result["completed"]!!.jsonPrimitive.content)
        assertEquals("7", result["auditRequestCount"]!!.jsonPrimitive.content)
        assertEquals(JsonNull, result["auditErrorCount"])
        assertEquals(JsonNull, result["auditIssueCount"])
        assertTrue(result["unsupportedMetrics"].toString().contains("auditIssueCount"))
    }

    // >> 20261014 mniwa Ensure repeated polling never invokes the unsupported audit issues API or invents a zero count.
    @Test fun `polling never calls unsupported audit issues API`() {
        val registry = ActiveAuditRegistry()
        val task = audit("scanning")
        every { task.issues() } throws UnsupportedOperationException("Currently unsupported.")
        every { task.errorCount() } returns 0
        val id = registry.register(task, "localhost", 3000, "http", "/dataadd")
        repeat(5) {
            val result = registry.snapshot(id, ScanWorkload(workflowSeconds = 2.0))!!
            assertEquals(JsonNull, result["auditIssueCount"])
            assertEquals("ESTIMATED", result["timeEstimate"]!!.jsonObject["status"]!!.jsonPrimitive.content)
        }
        verify(exactly = 0) { task.issues() }
    }
    // << mniwa

    @Test fun `ids are unique and snapshots retain target identity`() {
        val registry = ActiveAuditRegistry()
        val first = registry.register(audit(), "localhost", 3000, "http", "/dataadd")
        val second = registry.register(audit(), "localhost", 8888, "http", "/api/v1/users/x")
        assertNotEquals(first, second)
        assertEquals(2, registry.snapshots().size)
        assertEquals("8888", registry.snapshot(second)!!["port"]!!.jsonPrimitive.content)
    }

    @Test fun `fresh server registry cannot resolve old ids`() {
        val registry = ActiveAuditRegistry()
        val id = registry.register(audit("done"), "localhost", 3000, "http", "/dataadd")
        assertNull(ActiveAuditRegistry().snapshot(id))
        assertNull(registry.snapshot("missing"))
        assertEquals(0, ActiveAuditRegistry().snapshots().size)
    }
}
// << mniwa
