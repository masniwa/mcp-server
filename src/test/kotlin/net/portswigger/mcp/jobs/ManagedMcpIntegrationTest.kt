package net.portswigger.mcp.jobs

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.persistence.PersistedObject
import io.mockk.*
import kotlinx.coroutines.*
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import net.portswigger.mcp.*
import net.portswigger.mcp.config.McpConfig
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import java.net.ServerSocket
import java.net.URI
import java.net.http.*
import java.nio.file.*

class ManagedMcpIntegrationTest {
    @Test fun `real MCP transport rejects direct sends and worker endpoint rejects missing role token`()= runBlocking {
        val api=mockk<MontoyaApi>(relaxed=true)
        val nativeHttp=api.http();val nativeScanner=api.scanner();val suite=api.burpSuite()
        every { api.burpSuite().version().edition() } returns BurpSuiteEdition.PROFESSIONAL
        val port=ServerSocket(0).use { it.localPort }
        val storage=mockk<PersistedObject>(relaxed=true)
        every { storage.getString(any()) } returns "127.0.0.1"
        every { storage.getInteger("port") } returns port
        every { storage.getBoolean(any()) } returns true
        val config=McpConfig(storage,api.logging())
        val temp=Path.of("..","temp").toAbsolutePath().normalize();Files.createDirectories(temp)
        val settings=ManagedSettings(true,"worker-token-".repeat(4),"cph-token-".repeat(4),Files.createTempDirectory(temp,"managed-mcp-"),emptySet())
        val manager=KtorServerManager(api,settings)
        val started=CompletableDeferred<Unit>()
        val client=TestSseMcpClient()
        try {
            manager.start(config) { state ->
                if(state is ServerState.Running) started.complete(Unit)
                if(state is ServerState.Failed) started.completeExceptionally(state.exception)
            }
            withTimeout(20000) { started.await() }
            client.connectToServer("http://127.0.0.1:$port")
            val toolList=client.listTools()
            val descriptions=toolList.associate { it.name to it.description.orEmpty() }
            val recoveryTool=toolList.single { it.name=="diagnostic_job" }
            assertEquals(setOf("action","executionId"),recoveryTool.inputSchema.required.orEmpty().toSet())
            assertEquals(JsonPrimitive("string"),recoveryTool.inputSchema.properties!!.getValue("recoverySelectionJson").jsonObject["type"])
            assertTrue(recoveryTool.description.orEmpty().contains("Common settings recovery"))
            assertTrue(recoveryTool.description.orEmpty().contains("both before/after scopes"))
            assertTrue(recoveryTool.description.orEmpty().contains("lastKnownNativeMetrics"))
            assertTrue(recoveryTool.description.orEmpty().contains("producer-confirmed pre-Audit rejection"))
            assertTrue(recoveryTool.description.orEmpty().contains("Non-owned logging-only verbosity changes"))
            assertTrue(recoveryTool.description.orEmpty().contains("START_RESULT_METADATA_SAVE_FAILED"))
            assertTrue(recoveryTool.description.orEmpty().contains("UNCOMMITTED_START_RESPONSE/UNVERIFIED"))
            assertTrue(recoveryTool.description.orEmpty().contains("completionRecordPersisted=false"))
            assertTrue(recoveryTool.description.orEmpty().contains("verificationState=UNAVAILABLE"))
            assertTrue(recoveryTool.description.orEmpty().contains("Actual uncertain submission remains SUBMISSION_UNKNOWN"))
            assertTrue(recoveryTool.description.orEmpty().contains("recoverySelectionJson as a JSON STRING"))
            assertTrue(recoveryTool.description.orEmpty().contains("resumeOperationId"))
            assertTrue(recoveryTool.description.orEmpty().contains("recovery_replan"))
            assertFalse(descriptions.getValue("review_workflow_evidence").startsWith("MANAGED MODE:"))
            assertTrue(descriptions.getValue("review_workflow_evidence").contains("Sends no HTTP"))
            for(name in listOf("get_proxy_http_history","get_proxy_http_history_regex")) {
                assertFalse(descriptions.getValue(name).startsWith("MANAGED MODE:"))
                assertTrue(toolList.single { it.name==name }.inputSchema.toString().contains("includeRequestIds"),name)
                val schema=toolList.single { it.name==name }.inputSchema
                assertFalse("includeRequestIds" in schema.required.orEmpty(),name)
                assertTrue(schema.required.orEmpty().containsAll(listOf("count","offset")),name)
                if(name.endsWith("_regex")) assertTrue("regex" in schema.required.orEmpty(),name)
            }
            assertTrue(descriptions.getValue("send_http1_request").startsWith("MANAGED MODE:"))
            assertTrue(descriptions.getValue("set_project_options").contains("diagnostic_job"))
            assertFalse(descriptions.getValue("get_cph_config").startsWith("MANAGED MODE:"))
            assertTrue(descriptions.getValue("diagnostic_job").contains("BRANCH_SCAN_OPTIONS_FORBIDDEN"))
            assertTrue(descriptions.getValue("diagnostic_job").contains("SessionPlan="))
            assertTrue(descriptions.getValue("diagnostic_job").contains("settings.serialScannerRequests=true"))
            assertTrue(descriptions.getValue("diagnostic_job").contains("restores the complete original pool"))
            for(name in listOf("diagnostic_job","set_project_options","start_active_scan","generate_session_validation_action")) {
                val description=descriptions.getValue(name)
                assertTrue(description.contains("Five repetitions mean five complete checks"),name)
                assertTrue(description.contains("requiredBranches=[\"normal\"] with branchSetup={}"),name)
                assertTrue(description.contains("Do not automatically add invalid-password"),name)
                assertTrue(description.contains("Invalid means a missing/expired owned session"),name)
                assertTrue(description.contains("prerequisite logout -> diagnostic login -> post-request logout"),name)
                assertFalse(description.contains("testing.md"),name)
            }
            assertFalse(descriptions.getValue("diagnostic_job").contains("Required branches must cover valid/no-login and invalid/recovery"))
            assertTrue(descriptions.getValue("diagnostic_stint").contains("review_preparation"))
            val missingStint=client.callTool("diagnostic_stint",mapOf("action" to "status","stintId" to "absent"))
            assertTrue(missingStint.toString().contains("STINT_NOT_FOUND"))
            val jobStatus=client.callTool("diagnostic_job",mapOf("action" to "status","executionId" to "absent"))
            assertTrue(jobStatus!!.isError==true)
            assertTrue(jobStatus.content.toString().contains("NOT_FOUND"))
            assertFalse(jobStatus.content.toString().contains("MANAGED_MODE_JOB_REQUIRED"))
            val denied=client.callTool("send_http1_request",mapOf("targetHostname" to "never-contact.invalid","targetPort" to 80,"usesHttps" to false,"content" to "GET / HTTP/1.1\r\nHost: never-contact.invalid\r\n\r\n"))
            assertTrue(denied!!.isError==true)
            val deniedConfig=client.callTool("set_project_options",mapOf("json" to "{}"))
            assertTrue(deniedConfig!!.isError==true)
            val http=HttpClient.newHttpClient()
            val url=URI("http://127.0.0.1:$port/diagnosis/worker")
            val body="""{"action":"status","executionId":"absent","body":{}}"""
            val noToken=HttpRequest.newBuilder(url).POST(HttpRequest.BodyPublishers.ofString(body)).build()
            assertEquals(403,http.send(noToken,HttpResponse.BodyHandlers.ofString()).statusCode())
            val withToken=HttpRequest.newBuilder(url).header("Authorization","Bearer ${settings.workerToken}").POST(HttpRequest.BodyPublishers.ofString(body)).build()
            val reply=http.send(withToken,HttpResponse.BodyHandlers.ofString())
            assertEquals(200,reply.statusCode());assertTrue(reply.body().contains("NOT_FOUND"))
            val oversized=HttpRequest.newBuilder(url).header("Authorization","Bearer ${settings.workerToken}")
                .POST(HttpRequest.BodyPublishers.ofString("x".repeat(16*1024*1024+1))).build()
            assertEquals(413,http.send(oversized,HttpResponse.BodyHandlers.ofString()).statusCode())
            verify(exactly=0) { nativeHttp.sendRequest(any()) }
            verify(exactly=0) { nativeScanner.startAudit(any()) }
            verify(exactly=0) { suite.importProjectOptionsFromJson(any()) }
            client.close()
            val stopped=CompletableDeferred<Unit>()
            manager.stop { if(it==ServerState.Stopped) stopped.complete(Unit) }
            withTimeout(20000) { stopped.await() }
            every { storage.getString("host") } returns "0.0.0.0"
            val rejected=CompletableDeferred<ServerState>()
            manager.start(config) { if(it is ServerState.Failed || it==ServerState.Running) rejected.complete(it) }
            assertTrue(withTimeout(20000) { rejected.await() } is ServerState.Failed)
        } finally { if(client.isConnected()) client.close();manager.shutdown() }
    }
}
