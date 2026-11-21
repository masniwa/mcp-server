package net.portswigger.mcp.jobs

import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.modelcontextprotocol.kotlin.sdk.server.*
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
import java.time.Instant

/** Two actual MCP transports, one server-owned execution; no Burp or target HTTP. */
class ScanSessionHandoffMcpTest {
    @TempDir lateinit var directory:Path

    private suspend fun TestSseMcpClient.job(action:String,arguments:Map<String,Any> = emptyMap()):JsonObject {
        val reply=requireNotNull(callTool("diagnostic_job",mapOf("action" to action,"executionId" to "scan-handoff")+arguments))
        assertFalse(reply.isError==true,reply.content.toString())
        return jobJson.parseToJsonElement((reply.content.single() as TextContent).text).jsonObject
    }

    private suspend fun TestSseMcpClient.finished(operationId:String):JsonObject = withTimeout(10000) {
        var result=job("operation",mapOf("operationId" to operationId))
        while(result["state"]==JsonPrimitive("RUNNING")) {
            delay(25);result=job("operation",mapOf("operationId" to operationId))
        }
        assertEquals(JsonPrimitive("SUCCEEDED"),result["state"],result.toString())
        result
    }

    @Test fun runningAuditSurvivesClientDisconnectAndNewClientResumesSameOperationWithoutReplay()=runBlocking {
        val port=DraftTestFixture.Port()
        JobStore(directory.resolve("jobs")).use { store ->
            val worker=GuardedWorker(port,store,HumanApprover { _,_,_ -> "mock-human" })
            DiagnosticJobService(worker,store,false).use { service ->
                val mcp=Server(serverInfo=Implementation("scan-handoff-fixture","1"),
                    options=ServerOptions(capabilities=ServerCapabilities(tools=ServerCapabilities.Tools(listChanged=false))))
                ToolDispatch.attach(mcp,ToolDispatch(true));mcp.registerDiagnosticJobTool(service)
                val number=ServerSocket(0).use { it.localPort }
                val server=embeddedServer(Netty,host="127.0.0.1",port=number) { mcp { mcp } }.start(wait=false)
                val first=TestSseMcpClient();val second=TestSseMcpClient()
                try {
                    first.connectToServer("http://127.0.0.1:$number")
                    first.job("propose",mapOf("operationId" to "propose-handoff",
                        "proposalJson" to jobJson.encodeToString(DraftTestFixture.proposal("handoff"))))
                    first.finished("propose-handoff")
                    first.job("prepare",mapOf("operationId" to "prepare-handoff"));first.finished("prepare-handoff")
                    first.job("plan_next",mapOf("nextTargetsJson" to "[]"))
                    val execution=mapOf<String,Any>("operationId" to "execute-handoff",
                        "validationDigest" to fingerprint(worker.validation("scan-handoff")))
                    first.job("execute",execution)
                    val before=withTimeout(10000) {
                        var status=first.job("status")
                        while(status["execution"]!!.jsonObject["state"]!=JsonPrimitive("RUNNING")) {
                            delay(25);status=first.job("status")
                        }
                        status
                    }
                    val auditId=before.getValue("execution").jsonObject.getValue("auditId")
                    assertEquals(JsonPrimitive("audit-1"),auditId)
                    assertEquals(auditId,before.getValue("native").jsonObject["auditId"])
                    assertEquals(JsonPrimitive(false),before.getValue("native").jsonObject["completed"])
                    assertEquals(JsonPrimitive("scan-handoff"),before.getValue("context").jsonObject["ownerExecutionId"])
                    assertEquals(JsonPrimitive("RUNNING"),before.getValue("operation").jsonObject["state"])
                    val plan=store.get("plan:scan-handoff");val validation=store.get("validation:scan-handoff")
                    val settings=port.current;val probes=port.probes.get();val restores=port.restores.get()
                    val handoff=buildJsonObject {
                        put("executionId","scan-handoff");put("operationId","execute-handoff");put("auditId",auditId)
                        put("observedAt",Instant.now().toString());put("status",before)
                        put("nextAction","READ_SAME_STATUS_AND_OPERATION_NEVER_EXECUTE_AGAIN")
                    }
                    val saved=directory.resolve("handoff.json")
                    Files.writeString(saved,handoff.toString())
                    first.close()
                    assertFalse(first.isConnected(),"The first client must actually close before checking disconnected execution")
                    val pollsWhileDisconnected=port.polls.get()
                    withTimeout(8000) { while(port.polls.get()==pollsWhileDisconnected) delay(25) }
                    assertEquals("RUNNING",worker.record("scan-handoff").state)
                    assertEquals(1,port.starts.get());assertEquals(probes,port.probes.get())
                    assertEquals(restores,port.restores.get());assertEquals(settings,port.current)

                    second.connectToServer("http://127.0.0.1:$number")
                    val metadata=second.listTools().single { it.name=="diagnostic_job" }
                    assertEquals(JsonPrimitive("string"),metadata.inputSchema.properties!!.getValue("recoverySelectionJson").jsonObject["type"])
                    val loaded=jobJson.parseToJsonElement(Files.readString(saved)).jsonObject
                    val executionReference=mapOf<String,Any>("executionId" to loaded.getValue("executionId").jsonPrimitive.content)
                    val resumed=second.job("status",executionReference)
                    val operation=second.job("operation",executionReference+("operationId" to loaded.getValue("operationId").jsonPrimitive.content))
                    assertEquals(loaded["auditId"],resumed.getValue("execution").jsonObject["auditId"])
                    assertEquals(loaded["auditId"],resumed.getValue("native").jsonObject["auditId"])
                    assertEquals(JsonPrimitive("RUNNING"),operation["state"])
                    assertEquals(JsonPrimitive("scan-handoff"),resumed.getValue("context").jsonObject["ownerExecutionId"])
                    assertEquals(1,port.starts.get());assertEquals(probes,port.probes.get());assertEquals(restores,port.restores.get())
                    assertEquals(plan,store.get("plan:scan-handoff"));assertEquals(validation,store.get("validation:scan-handoff"))

                    port.completed=true // Complete only the fake native audit, without a second execute/advance call.
                    second.finished("execute-handoff")
                    assertEquals("EXECUTION_FINISHED",worker.record("scan-handoff").state)
                    assertEquals(JsonNull,store.get("active"));assertEquals(1,port.starts.get())
                    assertEquals(probes+1,port.probes.get());assertEquals(restores+1,port.restores.get())
                    assertEquals(DraftTestFixture.baseline,port.current)
                    assertEquals(plan,store.get("plan:scan-handoff"));assertEquals(validation,store.get("validation:scan-handoff"))
                    assertEquals(handoff,jobJson.parseToJsonElement(Files.readString(saved)))
                } finally {
                    port.completed=true
                    if(first.isConnected()) first.close()
                    if(second.isConnected()) second.close()
                    server.stop(100,2000)
                }
            }
        }
    }
}
