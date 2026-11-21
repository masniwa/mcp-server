package net.portswigger.mcp.jobs

import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.server.mcp
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

class DraftMcpWorkflowTest {
    @TempDir lateinit var directory:Path
    private fun CallToolResult?.body():JsonObject {
        requireNotNull(this);assertFalse(isError==true,content.toString())
        return jobJson.parseToJsonElement((content.single() as TextContent).text).jsonObject
    }
    @Test fun `real managed MCP drafts next login settings during scan then promotes without bypassing preparation`() = runBlocking {
        val port=DraftTestFixture.Port();port.current=LoginPreparationFixture.baseline
        JobStore(directory.resolve("sse")).use { store ->
            val worker=GuardedWorker(port,store,HumanApprover { _,_,_ -> "mock-human" })
            DraftTestFixture.start(worker)
            DiagnosticJobService(worker,store,false).use { service ->
                val mcp=Server(serverInfo=Implementation("mock-draft-workflow","1"),options=ServerOptions(capabilities=ServerCapabilities(tools=ServerCapabilities.Tools(listChanged=false))))
                ToolDispatch.attach(mcp,ToolDispatch(true));mcp.registerDiagnosticJobTool(service)
                val number=ServerSocket(0).use { it.localPort }
                val server=embeddedServer(Netty,host="127.0.0.1",port=number) { mcp { mcp } }.start(wait=false)
                val client=TestSseMcpClient()
                try {
                    client.connectToServer("http://127.0.0.1:$number")
                    val descriptions=client.listTools().associate { it.name to it.description.orEmpty() }
                    assertFalse(descriptions.getValue("diagnostic_draft").startsWith("MANAGED MODE:"))
                    assertTrue(descriptions.getValue("diagnostic_draft").contains("JobProposal="))
                    assertTrue(descriptions.getValue("diagnostic_draft").contains("does not acquire the Burp context"))
                    val before=port.calls();val fence=store.get("fence")
                    val draft=client.callTool("diagnostic_draft",mapOf("action" to "validate","draftId" to "next-login",
                        "baselineExecutionId" to "current","proposalJson" to jobJson.encodeToString(LoginPreparationFixture.proposal()))).body()
                    assertEquals("STATIC_CHECKED",draft["state"]!!.jsonPrimitive.content)
                    assertEquals(before,port.calls());assertEquals(fence,store.get("fence"))
                    assertNull(store.get("execution:next-login"));assertTrue(store.keys("approval:next-login").isEmpty())
                    assertEquals(draft,client.callTool("diagnostic_draft",mapOf("action" to "get","draftId" to "next-login")).body())
                    val digest=draft["draftDigest"]!!.jsonPrimitive.content
                    val early=DiagnosticJob("propose","next-execution",draftId="next-login",draftDigest=digest,operationId="busy-promotion")
                    client.callTool("diagnostic_job",mapOf("action" to early.action,"executionId" to early.executionId,
                        "draftId" to requireNotNull(early.draftId),"draftDigest" to requireNotNull(early.draftDigest),"operationId" to requireNotNull(early.operationId))).body()
                    assertEquals(JsonPrimitive("BURP_CONTEXT_BUSY"),DraftTestFixture.await(service,"busy-promotion")["errorCode"])
                    assertEquals(before,port.calls());assertEquals("RUNNING",worker.record("current").state)
                    port.completed=true;worker.poll("current")
                    val fresh=port.current
                    val args=mapOf("action" to "propose","executionId" to "next-execution","draftId" to "next-login",
                        "draftDigest" to digest,"operationId" to "idle-promotion")
                    client.callTool("diagnostic_job",args).body()
                    val promoted=DraftTestFixture.await(service,"idle-promotion")
                    assertEquals(JsonPrimitive("SUCCEEDED"),promoted["state"])
                    assertEquals(fresh,worker.plan("next-execution").baseline)
                    assertEquals(JsonPrimitive("next-login"),service.status("next-execution")["draftOrigin"]!!.jsonObject["draftId"])
                    val calls=port.calls();client.callTool("diagnostic_job",args).body();assertEquals(calls,port.calls())
                    assertNull(store.get("validation:next-execution"));assertNull(store.get("approval:next-execution:EXECUTION"))
                    client.callTool("diagnostic_job",mapOf("action" to "prepare","executionId" to "next-execution","operationId" to "prepare-next")).body()
                    assertEquals(JsonPrimitive("SUCCEEDED"),DraftTestFixture.await(service,"prepare-next")["state"])
                    val validation=client.callTool("diagnostic_job",mapOf("action" to "validation","executionId" to "next-execution")).body()
                    assertEquals(5,validation["totalProbes"]!!.jsonPrimitive.int)
                    assertEquals(1,port.starts.get());assertNativeSnapshotEquals(fresh,port.current)
                    val malformed=client.callTool("diagnostic_draft",mapOf("action" to "validate","draftId" to "no-approval",
                        "baselineExecutionId" to "current","proposalJson" to (jobJson.encodeToString(DraftTestFixture.proposal()).dropLast(1)+",\"approved\":true}")))
                    assertTrue(malformed!!.isError==true);assertNull(store.get("draft:no-approval"))
                } finally { if(client.isConnected()) client.close();server.stop(100,2000) }
            }
        }
    }

    @Test fun `promotion arguments and digest errors never create formal plans and legacy operation encoding is unchanged`() {
        val port=DraftTestFixture.Port()
        JobStore(directory.resolve("arguments")).use { store ->
            val worker=GuardedWorker(port,store,HumanApprover { _,_,_ -> "mock-human" })
            DiagnosticJobService(worker,store,false).use { service ->
                val p=DraftTestFixture.proposal();val draft=service.drafts.validate("draft",p,null)
                for(input in listOf(
                    DiagnosticJob("propose","next-execution",draftId="draft"),
                    DiagnosticJob("propose","next-execution",draftDigest=draft.draftDigest),
                    DiagnosticJob("propose","next-execution",draftId="draft",draftDigest=draft.draftDigest,proposalJson=jobJson.encodeToString(p)),
                    DiagnosticJob("execute","next-execution",draftId="draft",draftDigest=draft.draftDigest))) {
                    assertEquals("DRAFT_PROMOTION_ARGUMENTS_REQUIRED",assertThrows(JobRejected::class.java) { service.call(input) }.code)
                }
                val calls=port.calls()
                service.call(DiagnosticJob("propose","next-execution",draftId="draft",draftDigest="changed",operationId="wrong-digest"))
                assertEquals(JsonPrimitive("DRAFT_DIGEST_MISMATCH"),DraftTestFixture.await(service,"wrong-digest")["errorCode"])
                assertEquals(calls,port.calls());assertNull(store.get("execution:next-execution"))
                val encoded=jobJson.encodeToJsonElement(DiagnosticJob("propose","legacy",proposalJson="{}",operationId="stable")).jsonObject
                assertFalse("draftId" in encoded);assertFalse("draftDigest" in encoded)
                val old=jobJson.parseToJsonElement("""{"action":"propose","executionId":"legacy","proposalJson":"{}","operationId":"stable","validationDigest":null,"evidenceRef":null,"index":0,"offset":0,"count":20}""")
                assertEquals(old,encoded)
            }
        }
    }
}
