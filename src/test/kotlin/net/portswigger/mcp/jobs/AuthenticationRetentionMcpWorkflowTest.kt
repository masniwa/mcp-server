package net.portswigger.mcp.jobs

import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.modelcontextprotocol.kotlin.sdk.server.*
import io.modelcontextprotocol.kotlin.sdk.types.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.*
import net.portswigger.diagnosis.runner.*
import net.portswigger.mcp.TestSseMcpClient
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.net.ServerSocket
import java.nio.file.Path

class AuthenticationRetentionMcpWorkflowTest {
    @TempDir lateinit var directory:Path
    private fun proposal():JobProposal {
        val base=DraftTestFixture.proposal("reusable");val source=base.materials.single()
        val macro=buildJsonObject {
            put("description","job:reusable:recovery");put("serial_number",101)
            putJsonArray("items") { add(buildJsonObject {
                put("url",source.endpoint.url());put("request",source.request);put("response",source.response)
                put("method","GET");put("status_code",200);put("accept_response_cookies",true);put("use_request_cookies",true)
                put("custom_parameters",JsonArray(emptyList()));put("request_parameters",JsonArray(emptyList()))
            }) }
        }
        val rule=buildJsonObject {
            put("description","job:reusable:authentication");put("enabled",true)
            put("exclude_from_scope",JsonArray(emptyList()));put("named_params",JsonArray(emptyList()));put("restrict_scope_to_named_params",false)
            put("tools_scope",JsonArray(listOf(JsonPrimitive("Scanner"),JsonPrimitive("Extensions"))))
            put("url_scope","custom");put("url_scope_advanced_mode",false)
            putJsonArray("include_in_scope") { add(buildJsonObject { put("prefix",source.endpoint.url());put("enabled",true);put("include_subdomains",false) }) }
            putJsonArray("actions") { add(buildJsonObject {
                put("type","validate_session");put("enabled",true);put("validation_action","issue_current_request")
                put("action","run_macro");put("stop_if_valid",false);put("match_expression","observed")
                putJsonObject("run_macro_action") { put("macro_serial_number",101);put("update_with_params",false);put("update_with_cookies",true) }
            }) }
        }
        val cph=buildJsonObject {
            putJsonObject("job:reusable:token") { put("enabled",true);put("dynamic_checkbox",false) }
            putJsonObject(digest("options")) { put("chkbox_scanner",true);put("chkbox_extender",true) }
        }
        val request=base.variants.single().request
        return base.copy(session=SessionPlan(true,"USE","observed read-only session validation","fixture",validationSourceId=source.id),
            variants=listOf(base.variants.single().copy(settings=SettingsPlan(macros=JsonArray(listOf(macro)),rules=JsonArray(listOf(rule)),cph=cph,cphOrder=cph.keys.toList()),
                requiredBranches=listOf("normal","invalid"),branchSetup=mapOf("invalid" to listOf(request)))),
            authenticationRetention=AuthenticationRetention(listOf("job:reusable:authentication"),listOf("job:reusable:token")))
    }
    private fun CallToolResult?.body():JsonObject {
        requireNotNull(this);assertFalse(isError==true,content.toString())
        return jobJson.parseToJsonElement((content.single() as TextContent).text).jsonObject
    }
    @Test fun `public SSE plan keeps authentication in Burp and AI next target switches existing definitions`()=runBlocking {
        val port=DraftTestFixture.Port();port.completed=true
        port.current=port.current.copy(cph=buildJsonObject { putJsonObject(digest("options")) { put("chkbox_scanner",false);put("chkbox_extender",true) } },cphOrder=listOf(digest("options")))
        val checkedPort=object:BurpExecutionPort by port {
            private fun checkTools() {
                val options=port.current.cph[digest("options")]!!.jsonObject
                assertEquals(JsonPrimitive(true),options["chkbox_scanner"])
                assertEquals(JsonPrimitive(true),options["chkbox_extender"])
            }
            override fun probe(variant:ScanVariant,branch:String):Pair<String,JsonObject> { checkTools();return port.probe(variant,branch) }
            override fun start(variant:ScanVariant):JsonObject { checkTools();return port.start(variant) }
        }
        val reviews=mutableListOf<ApprovalStage>()
        JobStore(directory.resolve("jobs")).use { store ->
            val worker=GuardedWorker(checkedPort,store,HumanApprover { plan,stage,_ ->
                reviews.add(stage)
                if(stage==ApprovalStage.PREPARATION && reviews.size==1) {
                    assertEquals(0,port.applies.get());assertEquals(0,port.probes.get());assertEquals(0,port.starts.get())
                }
                if(plan.proposal.authenticationRetention!=null) {
                    val text=reviewAuthenticationSummary(plan)
                    assertTrue(text.contains("Check session is valid"));assertTrue(text.contains("無効化"))
                }
                "mock-human"
            })
            DiagnosticJobService(worker,store,false).use { service ->
                val mcp=Server(serverInfo=Implementation("retention-workflow","1"),options=ServerOptions(capabilities=ServerCapabilities(tools=ServerCapabilities.Tools(listChanged=false))))
                ToolDispatch.attach(mcp,ToolDispatch(true));mcp.registerDiagnosticJobTool(service)
                val number=ServerSocket(0).use { it.localPort }
                val server=embeddedServer(Netty,host="127.0.0.1",port=number) { mcp { mcp } }.start(wait=false)
                val client=TestSseMcpClient()
                try {
                    client.connectToServer("http://127.0.0.1:$number")
                    val description=client.listTools().single { it.name=="diagnostic_job" }.description.orEmpty()
                    assertTrue(description.contains("authenticationRetention"));assertTrue(description.contains("authenticationStates"))
                    val first=proposal()
                    client.callTool("diagnostic_job",mapOf("action" to "propose","executionId" to "first","operationId" to "proposal-first","proposalJson" to jobJson.encodeToString(first))).body()
                    assertEquals(JsonPrimitive("SUCCEEDED"),DraftTestFixture.await(service,"proposal-first","first")["state"])
                    client.callTool("diagnostic_job",mapOf("action" to "prepare","executionId" to "first","operationId" to "prepare-first")).body()
                    assertEquals(JsonPrimitive("SUCCEEDED"),DraftTestFixture.await(service,"prepare-first","first")["state"])
                    val validation=client.callTool("diagnostic_job",mapOf("action" to "validation","executionId" to "first")).body()
                    assertEquals(JsonPrimitive(10),validation["totalProbes"])
                    val retained=worker.plan("first").restorationBaseline!!
                    assertEquals(retained,port.current)
                    assertEquals(JsonPrimitive(false),port.current.cph["job:reusable:token"]!!.jsonObject["enabled"])
                    client.callTool("diagnostic_job",mapOf("action" to "plan_next","executionId" to "first","nextTargetsJson" to "[]")).body()
                    val execute=mapOf("action" to "execute","executionId" to "first","operationId" to "execute-first","validationDigest" to fingerprint(worker.validation("first")))
                    client.callTool("diagnostic_job",execute).body()
                    assertEquals(JsonPrimitive("SUCCEEDED"),DraftTestFixture.await(service,"execute-first","first")["state"])
                    assertEquals("EXECUTION_FINISHED",worker.record("first").state);assertEquals(retained,port.current)
                    val before=port.calls();client.callTool("diagnostic_job",execute).body();assertEquals(before,port.calls())
                    val states=AuthenticationStates(mapOf("job:reusable:authentication" to true),mapOf("job:reusable:token" to true),listOf("Scanner","Extender"))
                    val next=first.copy(jobId="next",authenticationRetention=null,variants=listOf(first.variants.single().copy(settings=SettingsPlan(authenticationStates=states))))
                    client.callTool("diagnostic_job",mapOf("action" to "propose","executionId" to "next","operationId" to "proposal-next","proposalJson" to jobJson.encodeToString(next))).body()
                    assertEquals(JsonPrimitive("SUCCEEDED"),DraftTestFixture.await(service,"proposal-next","next")["state"])
                    assertTrue(reviewAuthenticationSummary(worker.plan("next")).contains("job:reusable:authentication=true"))
                    client.callTool("diagnostic_job",mapOf("action" to "prepare","executionId" to "next","operationId" to "prepare-next")).body()
                    assertEquals(JsonPrimitive("SUCCEEDED"),DraftTestFixture.await(service,"prepare-next","next")["state"])
                    assertEquals(retained,port.current);assertEquals(21,port.probes.get());assertEquals(1,port.starts.get())
                    assertEquals(listOf(ApprovalStage.PREPARATION,ApprovalStage.EXECUTION,ApprovalStage.PREPARATION),reviews)
                } finally { if(client.isConnected()) client.close();server.stop(100,2000) }
            }
        }
    }
}
