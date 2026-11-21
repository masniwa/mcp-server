package net.portswigger.mcp.tools

import kotlinx.serialization.json.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.net.URLDecoder
import java.nio.file.Path

/** Actual Hard-only definitions exercise additional execution paths, not just tier selection. */
class PayloadHardWorkbookTest {
    @TempDir lateinit var root: Path

    private fun source(): PayloadProfileCatalog {
        val workbook = System.getenv("PAYLOAD_TEST_WORKBOOK")
        val exported = System.getenv("PAYLOAD_TEST_CATALOG")
        assumeTrue(workbook != null && exported != null, "Actual workbook fixtures are required")
        return loadPayloadProfile(Path.of(exported), Path.of(workbook))
    }

    private val original = ("POST /check?probe=baseline HTTP/1.1\r\nHost: fixture\r\n" +
        "Content-Type: application/json\r\n\r\n" + """{"value":{"display_name":"baseline"}}""").toByteArray()

    private fun positions(): List<PayloadWirePosition> {
        val text = original.toString(Charsets.UTF_8)
        val query = text.indexOf("baseline")
        val leaf = text.lastIndexOf("baseline")
        return listOf(PayloadWirePosition("query", "query", query, query + 8, query - 6, query - 1),
            PayloadWirePosition("leaf", "json-string", leaf, leaf + 8)) +
            resolvePayloadJsonContainers(original, listOf("/value"))
    }

    @Test fun `actual Hard includes all modes and preserves Medium plans byte for byte`() {
        val catalog = source()
        assertTrue(PAYLOAD_SCAN_DESCRIPTION.contains("payloadProfile.tier=hard"))
        val medium = catalog.select("medium")
        val hard = catalog.select("hard")
        assertEquals(670, hard.size)
        assertEquals(458, medium.size)
        assertEquals(mapOf("append" to 280, "replace" to 354, "array" to 36), hard.groupingBy { it.mode }.eachCount())
        assertEquals(212, hard.count { it.minimumTier == "hard" })
        val p = positions() + resolvePayloadMethodPosition(original)
        val mediumPlan = PayloadWirePlan.create(original, catalog, "medium", p)
        val hardPlan = PayloadWirePlan.create(original, catalog, "hard", p)
        val mediumIds = medium.map { it.id }.toSet()
        assertEquals(mediumPlan.candidates, hardPlan.candidates.filter { it.payloadId in mediumIds })
        val hardOffsets = hardPlan.candidates.withIndex().filter { it.value.payloadId in mediumIds }
        mediumPlan.candidates.forEachIndexed { index, row ->
            if (row.state == "READY") assertArrayEquals(mediumPlan.materialize(index), hardPlan.materialize(hardOffsets[index].index))
        }
        assertEquals(2680, hardPlan.candidates.size)
        assertArrayEquals(original, ("POST /check?probe=baseline HTTP/1.1\r\nHost: fixture\r\n" +
            "Content-Type: application/json\r\n\r\n" + """{"value":{"display_name":"baseline"}}""").toByteArray())
    }

    @Test fun `every actual Hard row executes at all compatible query leaf and container positions`() {
        val catalog = source().let { it.copy(payloads = it.payloads.filter { p -> p.minimumTier == "hard" }) }
        val definitions = catalog.payloads.associateBy { it.id }
        val p = positions()
        val plan = PayloadWirePlan.create(original, catalog, "hard", p)
        assertEquals(636, plan.candidates.size)
        assertEquals(508, plan.candidates.count { it.state == "READY" })
        assertEquals(128, plan.candidates.count { it.reason == "CONTEXT_NOT_APPLICABLE" })
        val execution = PayloadExecution(plan)
        val store = PayloadEvidenceStore.create(root.resolve("hard"), plan)
        var sent = 0
        execution.execute({ true }, { bytes ->
            val row = plan.candidates.withIndex().filter { it.value.state == "READY" }[sent++].value
            val payload = definitions.getValue(row.payloadId)
            val text = bytes.toString(Charsets.UTF_8)
            val uri = text.substringBefore(" HTTP/1.1").substringAfter(' ')
            val body = text.substringAfter("\r\n\r\n")
            val value = if (payload.mode == "append") "baseline" + payload.raw else payload.raw
            when (row.positionId) {
                "query" -> {
                    val pair = uri.substringAfter('?').split('=', limit = 2)
                    assertEquals(if (payload.mode == "array") "probe" + payload.raw else "probe", URLDecoder.decode(pair[0], Charsets.UTF_8))
                    assertEquals(if (payload.mode == "array") "baseline" else value, URLDecoder.decode(pair[1], Charsets.UTF_8))
                    assertEquals("""{"value":{"display_name":"baseline"}}""", body)
                }
                "leaf" -> {
                    assertEquals("/check?probe=baseline", uri)
                    assertEquals(value, Json.parseToJsonElement(body).jsonObject.getValue("value").jsonObject.getValue("display_name").jsonPrimitive.content)
                }
                else -> {
                    assertEquals("replace", payload.mode)
                    assertEquals("/check?probe=baseline", uri)
                    assertEquals("{\"value\":" + payload.raw + "}", body)
                }
            }
            PayloadExchange(bytes, "HTTP/1.1 200 OK\r\n\r\nrecorded".toByteArray(), 200, bytes)
        }, store::record)
        assertEquals(508, sent)
        assertTrue(execution.allCandidatesRecorded())
        assertEquals(definitions.keys, execution.snapshot().filter { it.state == "RESPONSE_RECEIVED" }.map { it.payloadId }.toSet())
        for (row in execution.snapshot().filter { it.state == "RESPONSE_RECEIVED" }) {
            assertArrayEquals(plan.materialize(row.index), java.util.Base64.getDecoder().decode(store.read(row.index).submittedRequestBase64))
        }
    }

    @Test fun `actual Hard special values retain lengths double encoding and nested array names`() {
        val catalog = source()
        val definitions = catalog.payloads.associateBy { it.id }
        val plan = PayloadWirePlan.create(original, catalog, "hard", positions())
        fun wire(id: String): String {
            val index = plan.candidates.indexOfFirst { it.payloadId == id && it.positionId == "query" }
            assertTrue(index >= 0)
            return plan.materialize(index).toString(Charsets.UTF_8).substringBefore(" HTTP/1.1")
        }
        assertTrue(wire("P-0279").endsWith("probe=baseline%252527"))
        assertTrue(wire("P-0633").endsWith("probe=%252527"))
        assertTrue(wire("P-0666").endsWith("probe%5Bconstructor%5D%5Bprototype%5D%5B__ap_probe__%5D=baseline"))
        assertTrue(wire("P-0669").endsWith("probe.key=baseline"))
        assertEquals(1024, definitions.getValue("P-0561").raw.length)
        assertEquals("A".repeat(1021) + "1!z", definitions.getValue("P-0561").raw)
        assertEquals("A".repeat(1021) + "1!z", URLDecoder.decode(wire("P-0561").substringAfter("probe="), Charsets.UTF_8))
        assertEquals(520, URLDecoder.decode(wire("P-0253").substringAfter("probe="), Charsets.UTF_8).length)
        assertEquals(0, plan.candidates.count { it.payloadId in definitions.values.filter { d -> d.minimumTier == "hard" }.map { d -> d.id } && it.reason == "UNBOUND_VARIABLES" })
    }
}
