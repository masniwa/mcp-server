package net.portswigger.mcp.tools

import burp.api.montoya.scanner.audit.Audit
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

// >> 20261008 mniwa Verify live audit progress, unknown states, unique identifiers, and server-lifetime isolation.
class ActiveAuditRegistryTest {
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
