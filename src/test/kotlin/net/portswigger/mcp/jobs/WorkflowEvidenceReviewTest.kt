package net.portswigger.mcp.jobs

import io.mockk.mockk
import io.mockk.Called
import io.mockk.every
import io.mockk.confirmVerified
import io.mockk.verify
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.types.*
import kotlinx.serialization.json.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path

class WorkflowEvidenceReviewTest {
    private val json=Json
    private val service=json.parseToJsonElement("""{"host":"app.example.test","port":9443,"secure":true}""")
    private fun row(id:Int,method:String,path:String,body:String="",response:String="HTTP/1.1 200 OK\r\n\r\n{}"):JsonObject=buildJsonObject {
        put("id",id);put("captureId","capture-a");put("tool","EXTENSIONS");put("httpService",service);put("requestTime","time-$id")
        put("request","$method $path HTTP/1.1\r\nHost: app.example.test\r\nCookie: sid=private-session; csrf=private-csrf\r\nX-CSRFToken: private-csrf\r\n\r\n$body")
        put("response",response);put("responseState","RESPONSE_RECEIVED")
    }
    private fun entries()=listOf(
        row(1,"POST","/sign-in",response="HTTP/1.1 302 Found\r\nSet-Cookie: sid=private-session; HttpOnly\r\nSet-Cookie: csrf=private-csrf\r\n\r\n"),
        row(2,"GET","/identity",response="HTTP/1.1 200 OK\r\n\r\n{\"user\":{\"id\":42}}"),
        row(3,"PATCH","/account","{\"name\":\"診断入力'<>\"}"),
        row(4,"PATCH","/restore",response="HTTP/1.1 200 OK\r\n\r\n{\"name\":\"original\"}"),
        row(5,"POST","/sign-out"),row(6,"GET","/invalid",response="HTTP/1.1 401 Unauthorized\r\n\r\n{}"))
    private fun flows(rows:List<JsonObject> = entries(),n:Int=5)=JsonArray((1..n).map { index -> buildJsonObject { put("id","flow-$index");put("entries",JsonArray(rows.map { JsonObject(it+("id" to JsonPrimitive(it["id"]!!.jsonPrimitive.int+(index-1)*100))) })) } })
    private fun plan()=WorkflowEvidenceReview.parse("""{
      "expectedFlows":5,"httpService":$service,
      "stages":[{"id":"login","method":"POST","path":"/sign-in","tool":"EXTENSIONS"},
        {"id":"identity","method":"GET","path":"/identity","tool":"EXTENSIONS"},
        {"id":"target","method":"PATCH","path":"/account","tool":"EXTENSIONS"},
        {"id":"restore","method":"PATCH","path":"/restore","tool":"EXTENSIONS"},
        {"id":"logout","method":"POST","path":"/sign-out","tool":"EXTENSIONS"},
        {"id":"invalid","method":"GET","path":"/invalid","tool":"EXTENSIONS"}],
      "checks":[
        {"id":"auth","category":"AUTHENTICATION","left":{"stage":"identity","side":"response","field":"json","pointer":"/user/id"},"expected":42},
        {"id":"csrf","category":"CSRF","left":{"stage":"target","side":"request","field":"header","name":"X-CSRFToken"},"right":{"stage":"login","side":"response","field":"setCookie","name":"csrf"}},
        {"id":"own-sid","category":"SESSION_LOGOUT","left":{"stage":"login","side":"response","field":"setCookie","name":"sid"},"right":{"stage":"logout","side":"request","field":"cookie","name":"sid"}},
        {"id":"verify-sid","category":"SESSION_LOGOUT","left":{"stage":"logout","side":"request","field":"cookie","name":"sid"},"right":{"stage":"invalid","side":"request","field":"cookie","name":"sid"}},
        {"id":"expired","category":"SESSION_LOGOUT","left":{"stage":"invalid","side":"response","field":"status"},"expected":401},
        {"id":"input","category":"INPUT_PRESERVATION","left":{"stage":"target","side":"request","field":"json","pointer":"/name"},"expected":"診断入力'<>"},
        {"id":"restored","category":"ATTRIBUTE_RESTORATION","left":{"stage":"restore","side":"response","field":"json","pointer":"/name"},"expected":"original"}]
    }""")
    private fun result(rows:List<JsonObject> = entries(),p:JsonObject=plan(),n:Int=5)=WorkflowEvidenceReview.review(p,flows(rows,n))
    @Test fun `all five categories and repeated flows pass with redacted evidence references`() {
        val report=result();assertEquals(JsonPrimitive("PASS"),report["reviewState"]);assertEquals(JsonPrimitive(35),report["assertionsPassed"])
        assertTrue(report.toString().contains("capture-a"));listOf("private-session","private-csrf","original","診断入力","app.example").forEach { assertFalse(report.toString().contains(it)) }
    }
    @Test fun `wrong logout SID and changed attack payload fail rather than count as cleanup`() {
        val rows=entries().toMutableList();rows[4]=JsonObject(rows[4]+("request" to JsonPrimitive(rows[4]["request"]!!.jsonPrimitive.content.replace("private-session","wrong"))))
        rows[2]=row(3,"PATCH","/account","{\"name\":\"overwritten\"}")
        assertEquals(JsonPrimitive("FAIL"),result(rows)["reviewState"])
    }
    @Test fun `pending overlapping rows merge with completed response without double counting`() {
        val rows=entries();val pending=JsonObject(rows[0]+mapOf("response" to JsonNull,"responseState" to JsonPrimitive("NO_RESPONSE_OBSERVED")))
        val report=result(listOf(pending)+rows);assertEquals(JsonPrimitive("PASS"),report["reviewState"])
        assertEquals(JsonPrimitive(6),report["flows"]!!.jsonArray[0].jsonObject["uniqueEntries"])
    }
    @Test fun `conflicting completed responses or immutable requests remain unresolved`() {
        for(key in listOf("request","response")) {
            val rows=entries();val conflict=JsonObject(rows[0]+(key to JsonPrimitive("conflicting evidence")))
            assertEquals(JsonPrimitive("INDETERMINATE"),result(rows+conflict)["reviewState"])
        }
    }
    @Test fun `missing response despite send return cannot prove expiry`() {
        val rows=entries().toMutableList();rows[5]=JsonObject(rows[5]+mapOf("response" to JsonNull,"responseState" to JsonPrimitive("NO_RESPONSE_OBSERVED"),"sendCompletionState" to JsonPrimitive("SEND_RETURNED")))
        assertEquals(JsonPrimitive("INDETERMINATE"),result(rows)["reviewState"])
    }
    @Test fun `duplicate endpoints ambiguous order cross capture and flow count do not pass`() {
        assertEquals(JsonPrimitive("INDETERMINATE"),result(entries()+row(7,"POST","/sign-out"))["reviewState"])
        val rows=entries().toMutableList();rows[5]=JsonObject(rows[5]+("captureId" to JsonPrimitive("other-capture")))
        assertEquals(JsonPrimitive("INDETERMINATE"),result(rows)["reviewState"])
        assertEquals(JsonPrimitive("INDETERMINATE"),result(n=4)["reviewState"])
    }
    @Test fun `duplicate JSON keys and missing fields cannot prove authentication`() {
        for(body in listOf("{\"user\":{\"id\":0,\"id\":42}}","{}")) {
            val rows=entries().toMutableList();rows[1]=row(2,"GET","/identity",response="HTTP/1.1 200 OK\r\n\r\n$body")
            assertEquals(JsonPrimitive("INDETERMINATE"),result(rows)["reviewState"])
        }
    }
    @Test fun `host port scheme are generic and unrelated service records excluded`() {
        val other=json.parseToJsonElement("""{"host":"different.internal","port":8081,"secure":false}""")
        val rows=entries().map { JsonObject(it+("httpService" to other)) }
        assertEquals(JsonPrimitive("INDETERMINATE"),result(rows)["reviewState"])
        assertEquals(JsonPrimitive("PASS"),result(rows,JsonObject(plan()+("httpService" to other)))["reviewState"])
    }
    @Test fun `unconfigured categories remain indeterminate and empty evidence never passes`() {
        val p=plan();val partial=JsonObject(p+("checks" to JsonArray(p["checks"]!!.jsonArray.take(1))))
        assertEquals(JsonPrimitive("INDETERMINATE"),result(p=partial)["reviewState"])
        assertEquals(JsonPrimitive("INDETERMINATE"),result(n=0)["reviewState"])
    }
    @Test fun `public managed tool compares exports without contacting worker or changing state`() {
        val service=mockk<DiagnosticJobService>()
        val server=Server(Implementation("offline-review","1"),ServerOptions(ServerCapabilities(tools=ServerCapabilities.Tools(listChanged=false))))
        val dispatch=ToolDispatch(true);ToolDispatch.attach(server,dispatch);server.registerWorkflowEvidenceReview(service)
        val args=buildJsonObject { put("planJson",plan().toString());put("evidenceJson",buildJsonObject { put("flows",flows()) }.toString()) }
        val content=dispatch.publicCall("review_workflow_evidence",args)
        assertEquals(JsonPrimitive("PASS"),json.parseToJsonElement((content.single() as TextContent).text).jsonObject["reviewState"])
        verify { service wasNot Called }
    }
    @Test fun `saved probes are filtered to their windows and use the same public reviewer`() {
        val rows=entries()
        val probes=(1..5).map { index -> buildJsonObject {
            put("variantId","reflection");put("branch","normal")
            put("logger",buildJsonObject {
                put("before",buildJsonObject { put("latestId",(index-1)*100) });put("after",buildJsonObject { put("latestId",(index-1)*100+6) })
                put("pages",JsonArray(listOf(JsonPrimitive((rows+row(7,"GET","/outside")).map { JsonObject(it+("id" to JsonPrimitive(it["id"]!!.jsonPrimitive.int+(index-1)*100))) }.joinToString("\n")))))
            })
        } }
        val flows=WorkflowEvidenceReview.probeFlows(probes)
        assertTrue(flows.all { it.jsonObject["entries"]!!.jsonArray.size==6 })
        val service=mockk<DiagnosticJobService>();every { service.savedReviewFlows("existing") } returns flows
        val server=Server(Implementation("offline-review","1"),ServerOptions(ServerCapabilities(tools=ServerCapabilities.Tools(listChanged=false))))
        val dispatch=ToolDispatch(true);ToolDispatch.attach(server,dispatch);server.registerWorkflowEvidenceReview(service)
        val result=dispatch.publicCall("review_workflow_evidence",buildJsonObject { put("executionId","existing");put("planJson",plan().toString()) })
        assertEquals(JsonPrimitive("PASS"),json.parseToJsonElement((result.single() as TextContent).text).jsonObject["reviewState"])
        verify(exactly=1) { service.savedReviewFlows("existing") };confirmVerified(service)
    }
    @Test fun `unexpected owned traffic is retained and prevents overall pass`() {
        val report=result(entries()+row(7,"POST","/extra"))
        assertEquals(JsonPrimitive("INDETERMINATE"),report["reviewState"])
        assertEquals(1,report["flows"]!!.jsonArray[0].jsonObject["unexpectedEntries"]!!.jsonArray.size)
    }
    @Test fun `one recorded workflow cannot be relabeled as five independent repetitions`() {
        val reused=JsonArray((1..5).map { buildJsonObject { put("id","copy-$it");put("entries",JsonArray(entries())) } })
        assertEquals(JsonPrimitive("INDETERMINATE"),WorkflowEvidenceReview.review(plan(),reused)["reviewState"])
    }
    @Test fun `UTF8 form fields can be compared without logging credentials and duplicates are ambiguous`() {
        val p=plan();val checks=p["checks"]!!.jsonArray.toMutableList()
        checks.add(WorkflowEvidenceReview.parse("""{"id":"form-input","category":"INPUT_PRESERVATION","left":{"stage":"target","side":"request","field":"form","name":"name"},"expected":"日 a+b"}"""))
        val newPlan=JsonObject(p+("checks" to JsonArray(checks)))
        for((body,expected) in listOf("name=%E6%97%A5+a%2Bb" to "PASS","name=a&name=b" to "INDETERMINATE","name=%FF" to "INDETERMINATE")) {
            val rows=entries().toMutableList()
            rows[2]=JsonObject(rows[2]+("request" to JsonPrimitive("PATCH /account HTTP/1.1\r\nHost: app.example.test\r\nCookie: sid=private-session; csrf=private-csrf\r\nX-CSRFToken: private-csrf\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n$body")))
            // This form replaces the JSON request, so replace that one original assertion.
            val formPlan=JsonObject(newPlan+("checks" to JsonArray(checks.filter { it.jsonObject["id"]!=JsonPrimitive("input") })))
            assertEquals(JsonPrimitive(expected),result(rows,formPlan)["reviewState"])
        }
    }
    @Test fun `archived evidence replay when supplied uses identical reviewer and writes only report`() {
        val source=System.getenv("WORKFLOW_REVIEW_REPLAY") ?: return
        val directory=Path.of(source)
        val report=WorkflowEvidenceReview.review(WorkflowEvidenceReview.parse(Files.readString(directory.resolve("plan.json"))),
            WorkflowEvidenceReview.parse(Files.readString(directory.resolve("evidence.json")))["flows"]!!.jsonArray)
        Files.writeString(directory.resolve("report.json"),report.toString())
        assertEquals(JsonPrimitive(5),report["observedFlows"])
        assertEquals(JsonPrimitive("PASS"),report["reviewState"],report.toString())
    }
}
