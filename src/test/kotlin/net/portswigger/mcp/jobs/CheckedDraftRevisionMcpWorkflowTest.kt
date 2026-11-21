package net.portswigger.mcp.jobs

import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.server.mcp
import io.modelcontextprotocol.kotlin.sdk.types.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.*
import net.portswigger.diagnosis.runner.*
import net.portswigger.mcp.TestSseMcpClient
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.net.ServerSocket
import java.nio.file.Path

/** Runs only a local MCP server and a counted mock Burp port; no diagnostic target is contacted. */
class CheckedDraftRevisionMcpWorkflowTest {
    @TempDir lateinit var directory: Path

    private fun CallToolResult?.body(): JsonObject {
        requireNotNull(this)
        assertFalse(isError == true, content.toString())
        return jobJson.parseToJsonElement((content.single() as TextContent).text).jsonObject
    }

    private fun JsonObject.task(): JsonObject = getValue("states").jsonArray.single().jsonObject

    private fun targets(proposal: JobProposal): String {
        val request = proposal.variants.single().request
        val material = proposal.materials.single { it.id == request.sourceId }
        return buildJsonArray {
            add(buildJsonObject {
                put("taskId", "next-login")
                put("jobId", proposal.jobId)
                put("endpoint", jobJson.encodeToJsonElement(material.endpoint))
                put("sourceId", request.sourceId)
                put("sourceRequestSha256", request.sourceRequestSha256)
            })
        }.toString()
    }

    private fun correctedSerials(original: JobProposal): JobProposal {
        val serials = original.variants.single().settings.macros.associate {
            val old = it.jsonObject.getValue("serial_number").jsonPrimitive.long
            old to old + 100L
        }
        fun remap(value: JsonElement): JsonElement = when (value) {
            is JsonObject -> JsonObject(value.mapValues { (name, child) ->
                val serial = (child as? JsonPrimitive)?.takeUnless { it.isString }?.longOrNull
                if (name in setOf("serial_number", "macro_serial_number") && serial in serials)
                    JsonPrimitive(serials.getValue(serial!!)) else remap(child)
            })
            is JsonArray -> JsonArray(value.map(::remap))
            else -> value
        }
        return original.copy(revision = original.revision + 1, variants = original.variants.map { variant ->
            variant.copy(settings = variant.settings.copy(
                macros = remap(variant.settings.macros).jsonArray,
                rules = remap(variant.settings.rules).jsonArray,
                macroPreparations = variant.settings.macroPreparations.map {
                    it.copy(macroSerialNumber = serials[it.macroSerialNumber] ?: it.macroSerialNumber)
                }
            ))
        })
    }

    private fun addFreshCollision(port: DraftTestFixture.Port, proposal: JobProposal) {
        val project = port.current.project
        val root = project.getValue("project_options").jsonObject
        val sessions = root.getValue("sessions").jsonObject
        val macros = sessions["macros"] as? JsonObject ?: JsonObject(emptyMap())
        val changed = JsonObject(macros + ("macros" to JsonArray(listOf(proposal.variants.single().settings.macros.first()))))
        port.current = port.current.copy(project = JsonObject(project + ("project_options" to JsonObject(root +
            ("sessions" to JsonObject(sessions + ("macros" to changed)))))))
    }

    private suspend fun operation(
        client: TestSseMcpClient,
        service: DiagnosticJobService,
        arguments: Map<String, Any>
    ): JsonObject {
        val reply = client.callTool("diagnostic_job", arguments).body()
        return DraftTestFixture.await(service, reply.getValue("operationId").jsonPrimitive.content,
            arguments.getValue("executionId") as String)
    }

    @Test fun `successful next draft can be corrected after fresh baseline collision and only the revised binding is promoted`() = runBlocking {
        val port = DraftTestFixture.Port().apply { current = LoginPreparationFixture.baseline }
        val approvals = mutableListOf<Pair<String, ApprovalStage>>()
        JobStore(directory.resolve("revised-checked-draft")).use { store ->
            val worker = GuardedWorker(port, store, HumanApprover { plan, stage, _ ->
                approvals += plan.proposal.jobId to stage
                "mock-human"
            })
            DraftTestFixture.start(worker)
            DiagnosticJobService(worker, store, false).use { service ->
                val mcp = Server(serverInfo = Implementation("mock-checked-draft-revision", "1"),
                    options = ServerOptions(capabilities = ServerCapabilities(tools = ServerCapabilities.Tools(listChanged = false))))
                ToolDispatch.attach(mcp, ToolDispatch(true))
                mcp.registerDiagnosticJobTool(service)
                val number = ServerSocket(0).use { it.localPort }
                val server = embeddedServer(Netty, host = "127.0.0.1", port = number) { mcp { mcp } }.start(wait = false)
                val client = TestSseMcpClient()
                try {
                    client.connectToServer("http://127.0.0.1:$number")
                    val original = LoginPreparationFixture.proposal()
                    client.callTool("diagnostic_job", mapOf(
                        "action" to "plan_next", "executionId" to "current", "nextTargetsJson" to targets(original)
                    )).body()
                    val calls = port.calls()
                    val fence = store.get("fence")
                    val parent = worker.record("current")
                    client.callTool("diagnostic_draft", mapOf(
                        "action" to "submit_next", "baselineExecutionId" to "current", "nextTargetId" to "next-login",
                        "draftId" to "checked-v1", "proposalJson" to jobJson.encodeToString(original)
                    )).body()
                    withTimeout(8000) {
                        while (service.lookAhead.report("current").task()["state"] != JsonPrimitive("STATIC_CHECKED")) delay(10)
                    }
                    val first = service.drafts.load("checked-v1")
                    assertEquals(calls, port.calls())
                    assertEquals(fence, store.get("fence"))
                    assertEquals(parent, worker.record("current"))
                    assertEquals(JsonPrimitive(true), service.lookAhead.report("current").task()["checkedDuringScan"])

                    port.completed = true
                    worker.poll("current")
                    assertEquals("EXECUTION_FINISHED", worker.record("current").state)
                    addFreshCollision(port, original)
                    val fresh = port.current
                    val failed = operation(client, service, mapOf(
                        "action" to "propose", "executionId" to "next-execution", "draftId" to "checked-v1",
                        "draftDigest" to first.draftDigest, "operationId" to "fresh-collision"
                    ))
                    assertEquals(JsonPrimitive("FAILED"), failed["state"])
                    assertEquals(JsonPrimitive("MACRO_ID_COLLISION"), failed["errorCode"])
                    assertNull(store.get("execution:next-execution"))
                    assertNull(store.get("draft-origin:next-execution"))
                    assertFalse(service.lookAhead.report("current").task().containsKey("promotedExecutionId"))
                    assertNativeSnapshotEquals(fresh, port.current)
                    assertEquals(1, port.starts.get())

                    val corrected = correctedSerials(original)
                    assertEquals(original.materials, corrected.materials)
                    assertEquals(original.variants.single().request, corrected.variants.single().request)
                    assertNotEquals(original.variants.single().settings.macros, corrected.variants.single().settings.macros)
                    val beforeCorrection = port.calls()
                    val afterParentFence = store.get("fence")
                    val checked = client.callTool("diagnostic_draft", mapOf(
                        "action" to "validate", "baselineExecutionId" to "current", "draftId" to "checked-v2",
                        "proposalJson" to jobJson.encodeToString(corrected)
                    )).body()
                    val rebound = client.callTool("diagnostic_draft", mapOf(
                        "action" to "submit_next", "baselineExecutionId" to "current", "nextTargetId" to "next-login",
                        "draftId" to "checked-v2", "proposalJson" to jobJson.encodeToString(corrected)
                    )).body().task()
                    assertEquals(JsonPrimitive("STATIC_CHECKED"), rebound["state"])
                    assertEquals(checked["draftDigest"], rebound["draftDigest"])
                    assertEquals(JsonPrimitive(false), rebound["checkedDuringScan"])
                    assertEquals(JsonPrimitive(true), rebound["windowMissed"])
                    val historical = rebound.getValue("priorAttempts").jsonArray.single().jsonObject
                    assertEquals(JsonPrimitive("checked-v1"), historical["draftId"])
                    assertEquals(JsonPrimitive("STATIC_CHECKED"), historical["state"])
                    assertEquals(JsonPrimitive(first.draftDigest), historical["draftDigest"])
                    assertEquals(JsonPrimitive(first.plan.proposalDigest), historical["proposalDigest"])
                    assertEquals(first, service.drafts.load("checked-v1"))
                    assertEquals(beforeCorrection, port.calls())
                    assertEquals(afterParentFence, store.get("fence"))

                    val stale = operation(client, service, mapOf(
                        "action" to "propose", "executionId" to "old-attempt", "draftId" to "checked-v1",
                        "draftDigest" to first.draftDigest, "operationId" to "obsolete-binding"
                    ))
                    assertEquals(JsonPrimitive("LOOKAHEAD_BOUND_DRAFT_REQUIRED"), stale["errorCode"])
                    val wrongDigest = operation(client, service, mapOf(
                        "action" to "propose", "executionId" to "wrong-digest", "draftId" to "checked-v2",
                        "draftDigest" to "0".repeat(64), "operationId" to "revised-wrong-digest"
                    ))
                    assertEquals(JsonPrimitive("DRAFT_DIGEST_MISMATCH"), wrongDigest["errorCode"])
                    assertEquals(beforeCorrection, port.calls())
                    assertEquals(afterParentFence, store.get("fence"))

                    val promoted = operation(client, service, mapOf(
                        "action" to "propose", "executionId" to "next-execution", "draftId" to "checked-v2",
                        "draftDigest" to checked.getValue("draftDigest").jsonPrimitive.content,
                        "operationId" to "corrected-promotion"
                    ))
                    assertEquals(JsonPrimitive("SUCCEEDED"), promoted["state"])
                    assertEquals(fresh, worker.plan("next-execution").baseline)
                    assertEquals(corrected, worker.plan("next-execution").proposal)
                    assertEquals(JsonPrimitive("next-execution"), service.lookAhead.report("current").task()["promotedExecutionId"])
                    assertTrue(approvals.none { it.first == original.jobId })
                    assertNull(store.get("approval:next-execution:PREPARATION"))
                    assertNull(store.get("validation:next-execution"))
                    val probes = port.probes.get()
                    val prepared = operation(client, service, mapOf(
                        "action" to "prepare", "executionId" to "next-execution", "operationId" to "prepare-revised-next"
                    ))
                    assertEquals(JsonPrimitive("SUCCEEDED"), prepared["state"])
                    assertEquals(probes + 5, port.probes.get())
                    assertEquals(listOf(original.jobId to ApprovalStage.PREPARATION), approvals.filter { it.first == original.jobId })
                    assertNull(store.get("approval:next-execution:EXECUTION"))
                    assertEquals(1, port.starts.get())
                    assertNativeSnapshotEquals(fresh, port.current)
                } finally {
                    if (client.isConnected()) client.close()
                    server.stop(100, 2000)
                }
            }
        }
    }
}
