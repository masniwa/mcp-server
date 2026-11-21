package net.portswigger.mcp.jobs

import io.mockk.*
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.types.*
import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class RateLimitObservationsTest {
    private val service=buildJsonObject { put("host","rate.fixture.invalid");put("port",8647);put("secure",true) }
    private fun row(id:Long,status:Int,startSecond:Int=id.toInt(),endSecond:Int=startSecond):JsonObject=buildJsonObject {
        put("captureId","capture");put("id",id);put("tool","SCANNER");put("httpService",service)
        put("request","POST /auth?step=normal HTTP/1.1\r\nHost: rate.fixture.invalid:8647\r\nCookie: owned=fixture-secret\r\n\r\npassword=fixture-password")
        put("response","HTTP/1.1 $status Response\r\n\r\nfixture-body");put("responseState","RESPONSE_RECEIVED")
        put("requestTime","2026-11-12T16:28:${startSecond.toString().padStart(2,'0')}Z")
        put("responseTime","2026-11-12T16:28:${endSecond.toString().padStart(2,'0')}Z")
    }
    private fun flows(vararg rows:JsonObject)=buildJsonArray { add(buildJsonObject { put("id","flow");put("entries",JsonArray(rows.toList())) }) }
    private fun summarize(vararg rows:JsonObject)=RateLimitObservations.summarize(flows(*rows))!!
    private fun plan(expectedStatus:Int=429)=buildJsonObject {
        put("expectedFlows",1);put("httpService",service)
        putJsonArray("stages") { add(buildJsonObject {
            put("id","observed");put("method","POST");put("path","/auth?step=normal");put("tool","SCANNER")
        }) }
        put("checks",JsonArray(WorkflowEvidenceReview.categories.map { category -> buildJsonObject {
            put("id",category.lowercase());put("category",category)
            putJsonObject("left") { put("stage","observed");put("side","response");put("field","status") };put("expected",expectedStatus)
        } }))
    }
    @Test fun `429 observations count once and later matching responses never prove recovery backoff or retry`() {
        val rejected=row(1,429);val pending=JsonObject(rejected+mapOf("response" to JsonNull,"responseState" to JsonPrimitive("NO_RESPONSE_OBSERVED")))
        val report=summarize(pending,rejected,row(2,302),row(3,200))
        assertEquals(JsonPrimitive(1),report["observed429Count"])
        val observation=report.getValue("observations").jsonArray.single().jsonObject
        assertEquals(JsonPrimitive(2),observation.getValue("later2xx3xxEvidence").jsonObject["id"])
        assertEquals(JsonPrimitive(302),observation["laterStatusCode"])
        assertEquals(JsonPrimitive(false),report["sameFailedCheckRetryProven"])
        assertEquals(JsonPrimitive(false),report["authenticationOrApplicationRecoveryProven"])
        assertEquals(JsonPrimitive(false),report["actualTaskPoolAssignmentVerified"]);assertEquals(JsonNull,report["automaticBackoffObserved"])
        assertEquals(JsonPrimitive("NOT_PROVIDED"),report["configurationSource"])
        listOf("rate.fixture.invalid","fixture-secret","fixture-password","fixture-body","/auth").forEach { assertFalse(report.toString().contains(it)) }
    }
    @Test fun `different captures services tools methods or exact query paths do not prove later matching responses`() {
        val success=row(2,302)
        val alternatives=listOf(
            JsonObject(success+("captureId" to JsonPrimitive("another"))),
            JsonObject(success+("httpService" to JsonObject(service+("port" to JsonPrimitive(9647))))),
            JsonObject(success+("tool" to JsonPrimitive("EXTENSIONS"))),
            JsonObject(success+("request" to JsonPrimitive(success.getValue("request").jsonPrimitive.content.replace("POST ","GET ")))),
            JsonObject(success+("request" to JsonPrimitive(success.getValue("request").jsonPrimitive.content.replace("step=normal","step=attack"))))
        )
        alternatives.forEach { candidate ->
            assertEquals(JsonNull,summarize(row(1,429),candidate).getValue("observations").jsonArray.single().jsonObject["later2xx3xxEvidence"])
        }
    }
    @Test fun `missing conflicting reversed or overlapping timestamps never become proven recovery`() {
        val rejected=row(1,429,startSecond=1,endSecond=4)
        val alternatives=listOf(JsonObject(row(2,302)-"requestTime"),row(2,302,startSecond=2,endSecond=3),row(2,302,startSecond=5,endSecond=4))
        alternatives.forEach { candidate ->
            assertEquals(JsonNull,summarize(rejected,candidate).getValue("observations").jsonArray.single().jsonObject["later2xx3xxEvidence"])
        }
        val report=summarize(JsonObject(rejected-"responseTime"),row(2,302))
        assertEquals(JsonPrimitive(false),report.getValue("observations").jsonArray.single().jsonObject["timestampOrderAvailable"])
        val conflicting=JsonObject(row(2,302)+("responseTime" to JsonPrimitive("2026-11-12T16:28:50Z")))
        assertEquals(JsonPrimitive(1),summarize(row(1,429),row(2,302),conflicting)["unresolvedEvidenceEntries"])
    }
    @Test fun `no observed 429 leaves existing output unchanged and 429 never changes configured assertion state`() {
        assertNull(RateLimitObservations.summarize(flows(row(1,403))))
        assertFalse(WorkflowEvidenceReview.review(plan(403),flows(row(1,403))).containsKey("rateLimitObservations"))
        val report=WorkflowEvidenceReview.review(plan(),flows(row(1,429)))
        assertEquals(JsonPrimitive("PASS"),report["reviewState"]);assertEquals(JsonPrimitive(false),report["diagnosisCompleted"])
        assertEquals(JsonPrimitive(1),report.getValue("rateLimitObservations").jsonObject["observed429Count"])
        val rejected=WorkflowEvidenceReview.review(plan(302),flows(row(1,429)))
        assertEquals(JsonPrimitive("FAIL"),rejected["reviewState"])
    }
    @Test fun `saved default pool fields keep their provenance without inventing missing settings or task assignment`() {
        val request=RequestPlan(Endpoint("https","rate.fixture.invalid",8647,"/"),"request","observed","source-hash")
        val variant=ScanVariant("reflection","REFLECTION",request=request,settings=SettingsPlan())
        val project=WorkflowEvidenceReview.parse("""{"project_options":{"resource_pools":{"default_resource_pool":{"auto_backoff":true,"auto_backoff_after_429_status_returned":true,"concurrent_request_limit_enabled":true,"concurrent_request_limit":1,"private-field":"never expose"}}}}""")
        val compiled=mockk<CompiledPlan>();every { compiled.variants } returns listOf(
            CompiledVariant(variant,project,JsonObject(emptyMap()),emptyList(),"saved-settings"),
            CompiledVariant(variant.copy(id="missing"),JsonObject(emptyMap()),JsonObject(emptyMap()),emptyList(),"missing-settings"))
        val settings=RateLimitObservations.savedDefaultPools(compiled)
        assertEquals(JsonPrimitive(true),settings[0].jsonObject["auto_backoff_after_429_status_returned"])
        assertEquals(JsonPrimitive(1),settings[0].jsonObject["concurrent_request_limit"])
        assertEquals(JsonPrimitive(false),settings[1].jsonObject["defaultPoolPresent"])
        assertFalse(settings[1].jsonObject.containsKey("auto_backoff"));assertFalse(settings.toString().contains("never expose"))
    }
    @Test fun `public evidence export route does not contact worker and saved route only reads flows and plan settings`() {
        val jobs=mockk<DiagnosticJobService>()
        val server=Server(Implementation("offline-rate-review","1"),ServerOptions(ServerCapabilities(tools=ServerCapabilities.Tools(listChanged=false))))
        val dispatch=ToolDispatch(true);ToolDispatch.attach(server,dispatch);server.registerWorkflowEvidenceReview(jobs)
        val args=buildJsonObject { put("planJson",plan().toString());put("evidenceJson",buildJsonObject { put("flows",flows(row(1,429))) }.toString()) }
        val direct=dispatch.publicCall("review_workflow_evidence",args)
        val directReport=Json.parseToJsonElement((direct.single() as TextContent).text).jsonObject
        assertEquals(JsonPrimitive("NOT_PROVIDED"),directReport.getValue("rateLimitObservations").jsonObject["configurationSource"])
        verify { jobs wasNot Called }
        every { jobs.savedReviewFlows("existing") } returns flows(row(1,429))
        every { jobs.savedRateLimitConfigurations("existing") } returns JsonArray(emptyList())
        val saved=dispatch.publicCall("review_workflow_evidence",buildJsonObject { put("executionId","existing");put("planJson",plan().toString()) })
        val savedReport=Json.parseToJsonElement((saved.single() as TextContent).text).jsonObject
        assertEquals(JsonPrimitive("SAVED_COMPILED_PLAN_DEFAULT_POOLS"),savedReport.getValue("rateLimitObservations").jsonObject["configurationSource"])
        assertEquals(JsonPrimitive(false),savedReport.getValue("rateLimitObservations").jsonObject["actualTaskPoolAssignmentVerified"])
        verify(exactly=1) { jobs.savedReviewFlows("existing") };verify(exactly=1) { jobs.savedRateLimitConfigurations("existing") };confirmVerified(jobs)
    }
    @Test fun `sanitized recorded fixture preserves thirteen 429 observations and six prerequisite later responses`() {
        val resource=javaClass.getResourceAsStream("/workflow-evidence/sanitized-rate-limit-sequence.json")
        assertNotNull(resource,"Portable sanitized recorded fixture is required")
        val fixture=resource!!.bufferedReader().use { Json.parseToJsonElement(it.readText()).jsonObject }
        val expected=fixture.getValue("expected").jsonObject
        val rows=fixture.getValue("entries").jsonArray.map { it.jsonObject }
        rows.forEach { row ->
            assertTrue(row.getValue("request").jsonPrimitive.content.matches(Regex("[A-Z]+ /fixture/path-[0-9]+ HTTP/1\\.1\\r\\nHost: archive\\.fixture\\.invalid:8443\\r\\n\\r\\n")))
            assertTrue(row.getValue("response").jsonPrimitive.content.matches(Regex("HTTP/1\\.1 [0-9]{3} Observed\\r\\n\\r\\n")))
            assertEquals(JsonPrimitive("archive.fixture.invalid"),row.getValue("httpService").jsonObject["host"])
        }
        assertEquals(expected.getValue("totalRows").jsonPrimitive.int,rows.size)
        val report=summarize(*rows.toTypedArray())
        assertEquals(expected["observed429Count"],report["observed429Count"])
        val prerequisites=expected.getValue("normalPrerequisite429Ids").jsonArray.toSet()
        val observations=report.getValue("observations").jsonArray.map { it.jsonObject }.filter {
            it.getValue("response429Evidence").jsonObject.getValue("id") in prerequisites
        }
        assertEquals(6,observations.size)
        observations.forEach { observation ->
            assertEquals(expected["firstLaterPrerequisiteResponseId"],observation.getValue("later2xx3xxEvidence").jsonObject["id"])
            assertEquals(expected["laterPrerequisiteStatus"],observation["laterStatusCode"])
        }
        assertEquals(JsonPrimitive(false),report["sameFailedCheckRetryProven"])
        assertEquals(JsonPrimitive(false),report["authenticationOrApplicationRecoveryProven"])
    }
}
