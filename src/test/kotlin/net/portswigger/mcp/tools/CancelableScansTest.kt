package net.portswigger.mcp.tools

import burp.BurpExtender
import burp.IBurpExtenderCallbacks
import burp.IExtensionHelpers
import burp.IScanQueueItem
import io.mockk.*
import kotlinx.serialization.json.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*

class CancelableScansTest {
    private val callbacks = mockk<IBurpExtenderCallbacks>(relaxed = true)
    private val helpers = mockk<IExtensionHelpers>()
    private val queue = mockk<IScanQueueItem>(relaxed = true)
    private lateinit var bridge: BurpExtender
    private var rawState = "scanning"
    private lateinit var bridgeId: String

    @BeforeEach fun setup() {
        every { callbacks.getHelpers() } returns helpers
        every { helpers.stringToBytes(any()) } answers { firstArg<String>().toByteArray(Charsets.ISO_8859_1) }
        every { callbacks.doActiveScan(any(), any(), any(), any()) } returns queue
        every { queue.status } answers { rawState }
        bridge = BurpExtender()
        bridge.registerExtenderCallbacks(callbacks)
        bridgeId = bridge.execute(mapOf("action" to "capabilities"))["bridgeId"] as String
    }
    @AfterEach fun teardown() { bridge.extensionUnloaded() }

    private fun args(action: String, id: String? = null) = mutableMapOf<String, Any?>("action" to action, "bridgeId" to bridgeId).also { if (id != null) it["auditId"] = id }
    private fun start(operation: String = "one", request: String = "GET /test?q=normal HTTP/1.1\r\nHost: localhost\r\n\r\n"): Map<String, Any?> =
        bridge.execute(args("start") + mapOf("operationId" to operation, "host" to "localhost", "port" to 18085, "protocol" to "http", "request" to request))
    private fun id(value: Map<String, Any?>) = value["auditId"] as String

    @Test fun `loading capabilities and status send nothing`() {
        assertEquals("READY", bridge.execute(mapOf("action" to "capabilities"))["status"])
        assertEquals(emptyList<Any>(), bridge.execute(args("status"))["audits"])
        verify(exactly = 0) { callbacks.doActiveScan(any(), any(), any(), any()) }
        verify(exactly = 0) { queue.cancel() }
    }

    @Test fun `cancel only targets the returned handle and polls observed confirmation`() {
        val other = mockk<IScanQueueItem>(relaxed = true)
        every { other.status } returns "scanning"
        val one = id(start())
        every { callbacks.doActiveScan(any(), any(), any(), any()) } returns other
        val two = id(start("two"))
        val requested = bridge.execute(args("cancel", one))
        assertEquals(true, requested["cancelRequested"])
        assertEquals(false, requested["cancelConfirmed"])
        assertEquals("CANCEL_REQUESTED", requested["status"])
        bridge.execute(args("cancel", one))
        verify(exactly = 1) { queue.cancel() }
        verify(exactly = 0) { other.cancel() }
        assertEquals("OBSERVED", bridge.execute(args("status", two))["status"])
        rawState = "Cancelled."
        val confirmed = bridge.execute(args("status", one))
        assertEquals(true, confirmed["cancelConfirmed"])
        assertEquals(false, confirmed["completed"])
        assertNull(confirmed["remainingSeconds"])
        assertEquals("ALREADY_CANCELLED", bridge.execute(args("cancel", one))["status"])
    }

    @Test fun `finished and unknown IDs do not issue cancellation`() {
        val one = id(start())
        rawState = "finished"
        assertEquals("ALREADY_FINISHED", bridge.execute(args("cancel", one))["status"])
        assertEquals("AUDIT_NOT_TRACKED", bridge.execute(args("cancel", "montoya-or-ui-id"))["errorCode"])
        assertEquals("BRIDGE_MISMATCH", bridge.execute(args("cancel", one) + ("bridgeId" to "old"))["errorCode"])
        verify(exactly = 0) { queue.cancel() }
    }

    @Test fun `normal completion racing cancellation is not reported cancelled`() {
        val one = id(start())
        every { queue.cancel() } answers { rawState = "finished" }
        val result = bridge.execute(args("cancel", one))
        assertEquals(true, result["completed"])
        assertEquals(false, result["cancelConfirmed"])
        assertEquals("FINISHED", result["status"])
    }

    @Test fun `cancel exceptions remain unknown and are not blindly retried`() {
        val one = id(start())
        every { queue.cancel() } throws IllegalStateException("sensitive diagnostic detail")
        val result = bridge.execute(args("cancel", one))
        assertEquals(false, result["success"])
        assertEquals("CANCEL_OUTCOME_UNKNOWN", result["errorCode"])
        assertFalse(result.toString().contains("sensitive diagnostic"))
        bridge.execute(args("cancel", one))
        verify(exactly = 1) { queue.cancel() }
    }

    @Test fun `operation retry does not rescan and changed retry is rejected`() {
        val first = id(start())
        assertEquals(first, id(start()))
        assertEquals("OPERATION_CONFLICT", start(request = "GET /other HTTP/1.1\r\nHost: localhost\r\n\r\n")["errorCode"])
        verify(exactly = 1) { callbacks.doActiveScan(any(), any(), any(), any()) }
    }

    @Test fun `ambiguous start retains operation and prevents automatic duplication`() {
        every { callbacks.doActiveScan(any(), any(), any(), any()) } throws IllegalStateException("not returned")
        val first = start()
        assertEquals(false, first["success"])
        assertEquals("START_OUTCOME_UNKNOWN", first["status"])
        assertEquals(id(first), id(start()))
        verify(exactly = 1) { callbacks.doActiveScan(any(), any(), any(), any()) }
    }

    @Test fun `unknown status and unavailable metrics are not successful completion`() {
        rawState = "future state"
        val first = id(start())
        assertNull(bridge.execute(args("status", first))["completed"])
        every { queue.getNumRequests() } throws UnsupportedOperationException()
        assertEquals("STATE_UNAVAILABLE", bridge.execute(args("cancel", first))["status"])
        verify(exactly = 0) { queue.cancel() }
    }

    @Test fun `capacity refuses new starts without evicting handles`() {
        val first = id(start())
        repeat(255) { start("next$it") }
        assertEquals("TRACKING_CAPACITY_REACHED", start("excess")["errorCode"])
        assertEquals(first, bridge.execute(args("status", first))["auditId"])
        verify(exactly = 256) { callbacks.doActiveScan(any(), any(), any(), any()) }
    }

    @Test fun `duplicate companion never replaces an existing bridge`() {
        val duplicate = BurpExtender()
        assertThrows(IllegalStateException::class.java) { duplicate.registerExtenderCallbacks(callbacks) }
        duplicate.extensionUnloaded()
        assertEquals(bridgeId, CancelableScans().call(mapOf("action" to "capabilities"))["bridgeId"]!!.jsonPrimitive.content)
    }

    @Test fun `JMX round trip handles unavailable reload and read only state`() {
        val client = CancelableScans()
        val capabilities = client.call(mapOf("action" to "capabilities"))
        assertEquals("READY", capabilities["status"]!!.jsonPrimitive.content)
        val first = id(start())
        assertEquals(first, client.call(args("status", first))["auditId"]!!.jsonPrimitive.content)
        bridge.extensionUnloaded()
        assertEquals("BRIDGE_NOT_LOADED", client.call(args("status", first))["errorCode"]!!.jsonPrimitive.content)
        bridge = BurpExtender()
        bridge.registerExtenderCallbacks(callbacks)
        assertEquals("BRIDGE_MISMATCH", client.call(args("cancel", first))["errorCode"]!!.jsonPrimitive.content)
        verify(exactly = 0) { queue.cancel() }
    }

    @Test fun `invalid start parameters never invoke the scanner`() {
        val valid = args("start") + mapOf("operationId" to "bad", "host" to "localhost", "port" to 18085, "protocol" to "http", "request" to "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        for (change in listOf(mapOf("port" to 0), mapOf("protocol" to "ftp"), mapOf("host" to "a\nb"), mapOf("operationId" to "has spaces"))) {
            assertEquals("INVALID_ARGUMENT", bridge.execute(valid + change)["errorCode"])
        }
        verify(exactly = 0) { callbacks.doActiveScan(any(), any(), any(), any()) }
    }
}
