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
import java.nio.file.Files
import java.nio.file.Path

/** Exercises the existing-agent handoff over MCP; no language-model service or target HTTP is used. */
class LookAheadMcpWorkflowTest {
    @TempDir lateinit var directory: Path

    private fun CallToolResult?.body(): JsonObject {
        requireNotNull(this)
        assertFalse(isError == true, content.toString())
        return jobJson.parseToJsonElement((content.single() as TextContent).text).jsonObject
    }

    private fun CallToolResult?.rejects(code: String) {
        requireNotNull(this)
        assertTrue(isError == true, content.toString())
        assertTrue(content.toString().contains(code), content.toString())
    }

    private fun targets(proposal: JobProposal, taskId: String = "next-login"): String {
        val request = proposal.variants.single { it.kind == "REFLECTION" }.request
        return buildJsonArray {
            add(buildJsonObject {
                put("taskId", taskId)
                put("jobId", proposal.jobId)
                put("endpoint", jobJson.encodeToJsonElement(request.endpoint))
                put("sourceId", request.sourceId)
                put("sourceRequestSha256", request.sourceRequestSha256)
            })
        }.toString()
    }

    private fun JsonObject.planning(): JsonObject = getValue("lookAheadPlanning").jsonObject
    private fun JsonObject.task(): JsonObject = getValue("states").jsonArray.single().jsonObject

    private suspend fun rejectsJob(
        client: TestSseMcpClient,
        service: DiagnosticJobService,
        arguments: Map<String, Any>,
        code: String
    ) {
        val reply = client.callTool("diagnostic_job", arguments)
        if (reply?.isError == true) {
            reply.rejects(code)
        } else {
            val queued = reply.body()
            val operation = queued["operationId"]!!.jsonPrimitive.content
            val execution = arguments.getValue("executionId") as String
            val failed = DraftTestFixture.await(service, operation, execution)
            assertEquals(JsonPrimitive("FAILED"), failed["state"])
            assertEquals(JsonPrimitive(code), failed["errorCode"])
        }
    }

    private suspend fun withRunningMcp(
        block: suspend (TestSseMcpClient, DiagnosticJobService, GuardedWorker, JobStore, DraftTestFixture.Port) -> Unit
    ) {
        val port = DraftTestFixture.Port().apply { current = LoginPreparationFixture.baseline }
        JobStore(Files.createTempDirectory(directory, "lookahead-mcp-")).use { store ->
            val worker = GuardedWorker(port, store, HumanApprover { _, _, _ -> "mock-human" })
            // A retained RUNNING execution must remain observable even before the new declaration exists.
            DraftTestFixture.start(worker)
            DiagnosticJobService(worker, store, false).use { service ->
                val mcp = Server(
                    serverInfo = Implementation("mock-lookahead-workflow", "1"),
                    options = ServerOptions(capabilities = ServerCapabilities(tools = ServerCapabilities.Tools(listChanged = false)))
                )
                ToolDispatch.attach(mcp, ToolDispatch(true))
                mcp.registerDiagnosticJobTool(service)
                val number = ServerSocket(0).use { it.localPort }
                val server = embeddedServer(Netty, host = "127.0.0.1", port = number) { mcp { mcp } }.start(wait = false)
                val client = TestSseMcpClient()
                try {
                    client.connectToServer("http://127.0.0.1:$number")
                    block(client, service, worker, store, port)
                } finally {
                    if (client.isConnected()) client.close()
                    server.stop(100, 2000)
                }
            }
        }
    }

    @Test fun `MCP exposes unfinished next configuration then automatically statically checks the agent submission during the same audit`() = runBlocking {
        withRunningMcp { client, service, worker, store, port ->
            val proposal = LoginPreparationFixture.proposal()
            client.callTool("diagnostic_job", mapOf(
                "action" to "plan_next", "executionId" to "current", "nextTargetsJson" to targets(proposal)
            )).body()
            val waiting = client.callTool("diagnostic_job", mapOf("action" to "status", "executionId" to "current")).body()
            assertEquals("RUNNING", waiting["execution"]!!.jsonObject["state"]!!.jsonPrimitive.content)
            assertEquals("CONFIGURATION_REQUIRED", waiting.planning().task()["state"]!!.jsonPrimitive.content)
            assertEquals("CREATE_NEXT_CONFIGURATION_AND_SUBMIT_DIAGNOSTIC_DRAFT", waiting["agentNextAction"]!!.jsonPrimitive.content)
            assertEquals(JsonPrimitive(false), waiting.planning()["automaticConfigurationGeneration"])
            assertEquals(JsonPrimitive(false), waiting.planning()["targetTrafficSent"])

            val calls = port.calls()
            val fence = store.get("fence")
            val active = store.get("active")
            val current = port.current
            // This represents the existing AI acting on agentNextAction. The server checks it automatically.
            client.callTool("diagnostic_draft", mapOf(
                "action" to "submit_next", "baselineExecutionId" to "current", "nextTargetId" to "next-login",
                "draftId" to "next-login-draft", "proposalJson" to jobJson.encodeToString(proposal)
            )).body()
            var statusReads = 0
            val checked = withTimeout(8000) {
                var value: JsonObject
                do {
                    value = client.callTool("diagnostic_job", mapOf("action" to "status", "executionId" to "current")).body()
                    statusReads++
                    if (value.planning().task()["state"] != JsonPrimitive("STATIC_CHECKED")) delay(10)
                } while (value.planning().task()["state"] != JsonPrimitive("STATIC_CHECKED"))
                value
            }
            val task = checked.planning().task()
            val saved = service.drafts.load("next-login-draft")
            assertEquals(JsonPrimitive(saved.draftDigest), task["draftDigest"])
            assertEquals(JsonPrimitive("next-login-draft"), task["draftId"])
            assertEquals(JsonPrimitive(true), task["checkedDuringScan"])
            assertEquals(JsonPrimitive(worker.record("current").auditId), task["checkedAuditId"])
            assertEquals(JsonPrimitive(worker.epoch), task["checkedEpoch"])
            assertEquals(proposal, saved.plan.proposal)
            assertEquals(LoginPreparationFixture.baseline, saved.plan.baseline)
            assertEquals("RUNNING", worker.record("current").state)
            assertEquals(current, port.current)
            assertEquals(fence, store.get("fence"))
            assertEquals(active, store.get("active"))
            assertNull(store.get("execution:next-login-draft"))
            assertTrue(store.keys("approval:next-login-draft").isEmpty())
            assertNull(store.get("validation:next-login-draft"))
            // Status explicitly observes the native handle. Automatic static work contributes no port calls.
            assertEquals(calls.filterIndexed { i, _ -> i != 6 }, port.calls().filterIndexed { i, _ -> i != 6 })
            assertEquals(calls[6] + statusReads, port.polls.get())
            assertFalse(checked.toString().contains("fixture-secret"))
            assertFalse(checked.toString().contains("POST /login HTTP"))
            val repeated = client.callTool("diagnostic_draft", mapOf(
                "action" to "submit_next", "baselineExecutionId" to "current", "nextTargetId" to "next-login",
                "draftId" to "next-login-draft", "proposalJson" to jobJson.encodeToString(proposal)
            )).body()
            assertEquals(JsonPrimitive(saved.draftDigest), repeated.task()["draftDigest"])
            assertEquals(JsonPrimitive(true), repeated.task()["checkedDuringScan"])
            assertEquals(calls.filterIndexed { i, _ -> i != 6 }, port.calls().filterIndexed { i, _ -> i != 6 })

            client.callTool("diagnostic_job", mapOf(
                "action" to "propose", "executionId" to "next-execution", "draftId" to "next-login-draft",
                "draftDigest" to saved.draftDigest, "operationId" to "busy-lookahead-promotion"
            )).body()
            assertEquals(JsonPrimitive("BURP_CONTEXT_BUSY"), DraftTestFixture.await(service, "busy-lookahead-promotion")["errorCode"])
            assertEquals("RUNNING", worker.record("current").state)

            port.completed = true
            worker.poll("current")
            port.current = port.current.copy(project = JsonObject(port.current.project + ("unrelated" to JsonPrimitive("keep-current"))))
            val fresh = port.current
            val beforeUnbound = port.calls()
            rejectsJob(client, service, mapOf(
                "action" to "propose", "executionId" to "without-bound-draft",
                "proposalJson" to jobJson.encodeToString(proposal), "operationId" to "unbound-lookahead-promotion"
            ), "LOOKAHEAD_BOUND_DRAFT_REQUIRED")
            assertEquals(beforeUnbound, port.calls())
            assertNull(store.get("execution:without-bound-draft"))
            client.callTool("diagnostic_job", mapOf(
                "action" to "propose", "executionId" to "next-execution", "draftId" to "next-login-draft",
                "draftDigest" to saved.draftDigest, "operationId" to "idle-lookahead-promotion"
            )).body()
            assertEquals(JsonPrimitive("SUCCEEDED"), DraftTestFixture.await(service, "idle-lookahead-promotion")["state"])
            assertEquals(fresh, worker.plan("next-execution").baseline)
            assertNull(store.get("approval:next-execution:PREPARATION"))
            assertNull(store.get("approval:next-execution:EXECUTION"))
            assertNull(store.get("validation:next-execution"))
            val probes = port.probes.get()
            client.callTool("diagnostic_job", mapOf(
                "action" to "prepare", "executionId" to "next-execution", "operationId" to "prepare-lookahead-next"
            )).body()
            assertEquals(JsonPrimitive("SUCCEEDED"), DraftTestFixture.await(service, "prepare-lookahead-next")["state"])
            assertEquals(probes + 5, port.probes.get())
            assertEquals(1, port.starts.get())
            assertNativeSnapshotEquals(fresh, port.current)
        }
    }

    @Test fun `missing next information remains unfinished through status polling and rejects substituted target while legacy draft stays separate`() = runBlocking {
        withRunningMcp { client, service, _, store, port ->
            val proposal = LoginPreparationFixture.proposal()
            client.callTool("diagnostic_job", mapOf(
                "action" to "plan_next", "executionId" to "current", "nextTargetsJson" to targets(proposal)
            )).body()
            client.callTool("diagnostic_draft", mapOf(
                "action" to "needs_information", "baselineExecutionId" to "current", "nextTargetId" to "next-login",
                "informationNeeded" to listOf("Current attribute baseline is not observed")
            )).body()
            val effects = port.calls().filterIndexed { i, _ -> i != 6 }
            repeat(3) {
                val status = client.callTool("diagnostic_job", mapOf("action" to "status", "executionId" to "current")).body()
                assertEquals("INFORMATION_REQUIRED", status.planning().task()["state"]!!.jsonPrimitive.content)
                assertTrue(status.toString().contains("Current attribute baseline is not observed"))
                assertFalse(status.planning().task().containsKey("draftDigest"))
            }
            assertEquals(effects, port.calls().filterIndexed { i, _ -> i != 6 })
            assertNull(store.get("draft:next-login-draft"))

            client.callTool("diagnostic_draft", mapOf(
                "action" to "submit_next", "baselineExecutionId" to "current", "nextTargetId" to "next-login",
                "draftId" to "wrong-job", "proposalJson" to jobJson.encodeToString(proposal.copy(jobId = "another-job"))
            )).rejects("LOOKAHEAD_TARGET_MISMATCH")
            val request = proposal.variants.single().request
            val wrongHash = proposal.copy(variants = listOf(proposal.variants.single().copy(
                request = request.copy(sourceRequestSha256 = "0".repeat(64))
            )))
            client.callTool("diagnostic_draft", mapOf(
                "action" to "submit_next", "baselineExecutionId" to "current", "nextTargetId" to "next-login",
                "draftId" to "wrong-source", "proposalJson" to jobJson.encodeToString(wrongHash)
            )).rejects("LOOKAHEAD_TARGET_MISMATCH")
            assertNull(store.get("draft:wrong-job"))
            assertNull(store.get("draft:wrong-source"))

            val legacy = client.callTool("diagnostic_draft", mapOf(
                "action" to "validate", "draftId" to "independent-legacy", "baselineExecutionId" to "current",
                "proposalJson" to jobJson.encodeToString(DraftTestFixture.proposal())
            )).body()
            assertEquals(JsonPrimitive("STATIC_CHECKED"), legacy["state"])
            assertEquals(legacy, client.callTool("diagnostic_draft", mapOf("action" to "get", "draftId" to "independent-legacy")).body())
            assertEquals(DraftTestFixture.proposal(), service.drafts.load("independent-legacy").plan.proposal)
            val unfinished = client.callTool("diagnostic_job", mapOf("action" to "status", "executionId" to "current")).body()
            assertEquals(JsonPrimitive("INFORMATION_REQUIRED"), unfinished.planning().task()["state"])
            assertFalse(unfinished.planning().task().containsKey("draftDigest"))
        }
    }

    @Test fun `new execution requires explicit next-target declaration while an explicit empty last-target declaration remains valid`() = runBlocking {
        withRunningMcp { client, service, worker, store, port ->
            port.completed = true
            worker.poll("current")
            worker.register("new-execution", DraftTestFixture.proposal("final-target"))
            worker.approve("new-execution", ApprovalStage.PREPARATION)
            worker.prepare("new-execution")
            val before = port.calls()
            rejectsJob(client, service, mapOf(
                "action" to "execute", "executionId" to "new-execution",
                "validationDigest" to fingerprint(worker.validation("new-execution")), "operationId" to "missing-next-declaration"
            ), "LOOKAHEAD_TARGETS_DECLARATION_REQUIRED")
            assertEquals(before, port.calls())
            assertEquals("VALIDATED", worker.record("new-execution").state)
            assertNull(store.get("approval:new-execution:EXECUTION"))

            client.callTool("diagnostic_job", mapOf(
                "action" to "plan_next", "executionId" to "new-execution", "nextTargetsJson" to "[]"
            )).body()
            val status = client.callTool("diagnostic_job", mapOf("action" to "status", "executionId" to "new-execution")).body()
            assertEquals(JsonPrimitive(true), status.planning()["declared"])
            assertEquals(JsonPrimitive(true), status.planning()["lastTarget"])
            assertEquals(emptyList<JsonElement>(), status.planning()["states"]!!.jsonArray.toList())
            assertEquals(before, port.calls())
        }
    }
}
