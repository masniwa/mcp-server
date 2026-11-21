package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import io.mockk.*
import kotlinx.serialization.json.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

class PayloadPreflightTest {
    @TempDir lateinit var root: Path

    @Test fun `preflight retains all IDs and missing values without disclosing bound secrets`() {
        val catalog = PayloadProfileCatalog("a".repeat(64), listOf(
            ProfilePayload("bound", "replace", "light", "__SECRET__", listOf("query")),
            ProfilePayload("missing", "replace", "light", "__MISSING__", listOf("query")),
            ProfilePayload("incompatible", "replace", "light", "1", listOf("json-value"))))
        val plan = PayloadWirePlan.create("a=old".toByteArray(), catalog, "light",
            listOf(PayloadWirePosition("p", "query", 2, 5, 0, 1)), mapOf("__SECRET__" to "do-not-disclose"))
        val prepared = PreparedPayloadPlan(catalog, plan, root)
        val page = payloadPlanSummary(prepared, 1, 1)
        val json = Json.parseToJsonElement(page).jsonObject
        assertEquals(3, json.getValue("selectedPayloads").jsonPrimitive.int)
        assertEquals(1, json.getValue("readyCandidates").jsonPrimitive.int)
        assertFalse(json.getValue("wirePlanReady").jsonPrimitive.boolean)
        assertEquals("missing", json.getValue("items").jsonArray.single().jsonObject.getValue("payloadId").jsonPrimitive.content)
        assertTrue(page.contains("__MISSING__"))
        assertFalse(page.contains("do-not-disclose"))
        assertFalse(page.contains("replacementBase64"))
        assertEquals(2, json.getValue("payloadsWithoutReadyPosition").jsonArray.size)
        assertTrue(Json.parseToJsonElement(payloadPlanSummary(prepared, 3, 1)).jsonObject.getValue("items").jsonArray.isEmpty())
        assertThrows(IllegalArgumentException::class.java) { payloadPlanSummary(prepared, -1, 1) }
    }

    @Test fun `actual workbook preflight writes nothing and start preparation uses identical plan`() {
        val workbook = System.getenv("PAYLOAD_TEST_WORKBOOK")
        val exported = System.getenv("PAYLOAD_TEST_CATALOG")
        assumeTrue(workbook != null && exported != null, "Workbook fixtures must be provided for full verification")
        val options = PayloadScanOptions("medium", requireNotNull(exported), requireNotNull(workbook), root.toString())
        val request = mockk<HttpRequest>(relaxed = true)
        val bytes = "GET /fixture HTTP/1.1\r\nHost: localhost\r\n\r\n".toByteArray()
        every { request.hasHeader(any<String>()) } returns false
        every { request.headerValue("Content-Type") } returns null
        every { request.toByteArray().bytes } returns bytes
        every { request.parameters() } returns emptyList()
        every { request.withAddedHeader(PAYLOAD_RUN_HEADER, any()) } returns request
        val prepared = preparePayloadPlan(request, null, options)
        val direct = preparePayloadPlan(request, null, options.copy(catalogPath = null))
        assertEquals(prepared.catalog, direct.catalog)
        assertEquals(prepared.plan.candidates, direct.plan.candidates)
        assertEquals(prepared.plan.sourceSha256, direct.plan.sourceSha256)
        val decoded = Json.decodeFromString<PayloadScanOptions>("""{"tier":"medium","workbookPath":"source.xlsx","evidenceRoot":"evidence"}""")
        assertNull(decoded.catalogPath)
        assertEquals(458, prepared.plan.candidates.size)
        assertEquals(8, prepared.plan.candidates.count { it.state == "READY" })
        Files.list(root).use { assertEquals(0L, it.count()) }
        val api = mockk<MontoyaApi>(relaxed = true)
        val scanner = mockk<burp.api.montoya.scanner.Scanner>(relaxed = true)
        every { api.scanner() } returns scanner
        val run = PayloadRunRegistry(api).prepare(request, null, options)
        assertEquals(prepared.plan.candidates, run.plan.candidates)
        assertEquals(prepared.plan.requestSha256, run.plan.requestSha256)
        assertEquals(prepared.plan.sourceSha256, run.plan.sourceSha256)
        Files.list(root).use { assertEquals(1L, it.count()) }
        verify(exactly = 0) { scanner.startAudit(any()) }
        verify(exactly = 0) { api.http() }
        run.close()
    }
}
