package net.portswigger.mcp.tools

import burp.api.montoya.scanner.audit.Audit
import io.mockk.*
import kotlinx.serialization.json.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path

class PayloadDeferralTest {
    @TempDir lateinit var root: Path
    private val catalog = PayloadProfileCatalog("a".repeat(64), listOf(
        ProfilePayload("normal", "replace", "light", "ok", listOf("query")),
        ProfilePayload("deferred", "replace", "light", "__UNBOUND__", listOf("query"))))
    private val positions = listOf(PayloadWirePosition("q", "query", 2, 3, 0, 1), PayloadWirePosition("form", "form", 2, 3, 0, 1))
    private fun plan(deferrals: Map<String, String> = mapOf("deferred" to "ユーザー指定で保留")) =
        PayloadWirePlan.create("x=1".toByteArray(), catalog, "light", positions, deferredPayloads = deferrals)

    @Test fun `deferred identities survive every position and cannot be materialized or sent`() {
        val plan = plan()
        assertEquals(4, plan.candidates.size)
        assertEquals(listOf("q", "form"), plan.candidates.filter { it.payloadId == "deferred" }.map { it.positionId })
        for (index in listOf(2, 3)) {
            assertEquals("USER_DEFERRED:ユーザー指定で保留", plan.candidates[index].reason)
            assertThrows(IllegalArgumentException::class.java) { plan.materialize(index) }
        }
        val execution = PayloadExecution(plan)
        val sent = mutableListOf<String>()
        execution.execute({true}, { sent += it.decodeToString(); PayloadExchange(it, "ok".toByteArray(), 200) }, {_, _ ->})
        assertEquals(listOf("x=ok"), sent)
        assertFalse(execution.allCandidatesRecorded())
        assertTrue(execution.allNonDeferredCandidatesRecorded())
        assertTrue(execution.snapshot().filter { it.payloadId == "deferred" }.all { it.attemptedAt == null && it.requestSha256 == null })
    }

    @Test fun `unknown IDs modes and missing reasons are rejected and defaults preserve unbound failure`() {
        for (invalid in listOf(mapOf("typo" to "reason"), mapOf("deferred" to " "), mapOf("deferred" to "x".repeat(501)))) {
            assertThrows(IllegalArgumentException::class.java) { plan(invalid) }
        }
        assertThrows(IllegalArgumentException::class.java) {
            PayloadWirePlan.create("x=1".toByteArray(), catalog, "light", positions, modes=listOf("append"), deferredPayloads=mapOf("deferred" to "reason"))
        }
        assertEquals("UNBOUND_VARIABLES", plan(emptyMap()).candidates[2].reason)
    }

    @Test fun `preflight distinguishes full coverage scoped readiness and all deferred scope`() {
        val summary = Json.parseToJsonElement(payloadPlanSummary(PreparedPayloadPlan(catalog, plan(), root), 0, 100)).jsonObject
        assertFalse(summary.getValue("wirePlanReady").jsonPrimitive.boolean)
        assertTrue(summary.getValue("nonDeferredWirePlanReady").jsonPrimitive.boolean)
        assertEquals(listOf("deferred"), summary.getValue("deferredPayloadIds").jsonArray.map { it.jsonPrimitive.content })
        val all = plan(mapOf("normal" to "reason", "deferred" to "reason"))
        val execution = PayloadExecution(all)
        execution.execute({error("No send gate should be called")}, {error("No sends")}, {_, _ ->})
        assertFalse(execution.allNonDeferredCandidatesRecorded())
        assertTrue(all.candidates.all { it.reason?.startsWith("USER_DEFERRED:") == true })
    }

    @Test fun `results retain full incomplete state report reasons and independent scoped completion`() {
        val plan = plan()
        val store = PayloadEvidenceStore.create(root.resolve("run"), plan)
        val execution = PayloadExecution(plan)
        val run = PayloadRunRegistry.Run("id", plan, execution, store, root.resolve("run"), mockk())
        val audit = mockk<Audit>(); every { audit.statusMessage() } returns "finished"; run.audit = audit
        execution.execute({true}, {PayloadExchange(it, "HTTP/1.1 200 OK\r\n\r\nok".toByteArray(), 200)}, store::record)
        val result = Json.parseToJsonElement(PayloadRunRegistry(mockk()).results(run, 0, 100, false, true)).jsonObject
        assertFalse(result.getValue("completed").jsonPrimitive.boolean)
        assertFalse(result.getValue("allCandidatesRecorded").jsonPrimitive.boolean)
        assertFalse(result.getValue("diagnosisCompleted").jsonPrimitive.boolean)
        assertTrue(result.getValue("nonDeferredExecutionCompleted").jsonPrimitive.boolean)
        assertTrue(result.getValue("reviewReportMarkdown").jsonPrimitive.content.contains("USER_DEFERRED:ユーザー指定で保留"))
        java.nio.file.Files.writeString(root.resolve("run/0.json"), "corrupt")
        assertThrows(Exception::class.java) { PayloadRunRegistry(mockk()).results(run, 0, 100, false, true) }
    }

    @Test fun `scoped progress cannot hide no callback stopped sends or missing positions`() {
        val execution = PayloadExecution(plan())
        assertFalse(execution.allNonDeferredCandidatesRecorded())
        execution.execute({false}, {error("No sends")}, {_, _ ->})
        assertFalse(execution.allNonDeferredCandidatesRecorded())
        val empty = PayloadWirePlan.create(byteArrayOf(), catalog, "light", emptyList(), deferredPayloads=mapOf("deferred" to "reason"))
        val noPositions = PayloadExecution(empty)
        noPositions.execute({true}, {error("No sends")}, {_, _ ->})
        assertFalse(noPositions.allNonDeferredCandidatesRecorded())
        assertEquals("USER_DEFERRED:reason", empty.candidates[1].reason)
    }
}
