package net.portswigger.diagnosis.contract

import kotlinx.serialization.json.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class InputCoverageCompilerTest {
    private val body="csrfmiddlewaretoken=normal-token&login=reader&password=valid-password"
    private val raw="POST /login?loggedout=1 HTTP/1.1\r\nHost: contract.invalid:8080\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: ${body.length}\r\n\r\n$body"
    private val e=Endpoint("http","contract.invalid",8080,"/login?loggedout=1")
    private val response="HTTP/1.1 200 OK\r\n\r\nnormal"
    private val parameters=listOf(InputParameter("loggedout","URL"),InputParameter("csrfmiddlewaretoken","BODY"),InputParameter("login","BODY"),InputParameter("password","BODY"))
    private val capabilities=setOf("SCANNER_WORKFLOW","EXCLUSIVE_CONTEXT")
    private fun options(selected:List<InputParameter>)=buildJsonObject { put("insertionPointParameters",jobJson.encodeToJsonElement(selected)) }
    private fun job(selected:List<InputParameter>?=parameters):JobProposal {
        val source=HttpMaterial("source",e,raw,response,digest(raw),digest(response))
        return JobProposal(jobId="coverage",revision=1,objective="Review every observed input",targetPolicy=listOf(TargetPermit(e)),materials=listOf(source),
            session=SessionPlan(false,"OMIT","No authentication in this structural fixture","fixture"),
            variants=listOf(ScanVariant("reflection","REFLECTION",request=RequestPlan(e,raw,source.id,source.requestSha256,selected?.let(::options) ?: JsonObject(emptyMap())),settings=SettingsPlan())),
            requiredCapabilities=capabilities,cleanupPolicy="Review owned state",requestedInputParameters=selected.orEmpty())
    }
    private fun action()=jobJson.parseToJsonElement("""{"type":"run_macro","enabled":true,"macro_serial_number":41,"match_params":"specified","specified_params":["csrfmiddlewaretoken"],"update_with_params":true}""").jsonObject
    private fun baseline(action:JsonObject?=null):BurpSnapshot {
        val project=buildJsonObject { putJsonObject("project_options") { putJsonObject("sessions") {
            putJsonObject("macros") { putJsonArray("macros") { if(action!=null) add(buildJsonObject {
                put("serial_number",41);putJsonArray("items") { add(buildJsonObject { put("request",raw);put("response",response);put("url",e.url()) }) }
            }) } }
            putJsonObject("session_handling_rules") { putJsonArray("rules") { if(action!=null) add(buildJsonObject {
                put("enabled",true);putJsonArray("tools_scope") { add("Scanner") };put("url_scope","custom");put("url_scope_advanced_mode",false)
                putJsonArray("include_in_scope") { add(buildJsonObject { put("prefix",e.url());put("enabled",true) }) }
                putJsonArray("actions") { add(action) }
            }) } }
        } } }
        return BurpSnapshot("instance",project,JsonObject(emptyMap()),emptyList(),capabilities)
    }
    @Test fun `compiler rejects inherited prerequisite overwrites before native execution`() {
        assertEquals("MACRO_OVERWRITES_DIAGNOSTIC_INPUT",assertThrows(JobRejected::class.java) { JobCompiler().compile(job(),baseline(action())) }.code)
        val excluded=InputExclusion("csrfmiddlewaretoken","BODY","Reviewed separate token diagnosis")
        val selected=job(parameters.filterNot { it.name==excluded.name })
        val safe=selected.copy(variants=listOf(selected.variants.single().copy(inputExclusions=listOf(excluded))))
        val plan=JobCompiler().compile(safe,baseline(action()))
        assertEquals(listOf(excluded),plan.variants.single().variant.inputExclusions)
        assertEquals(options(parameters.filterNot { it.name==excluded.name }),plan.variants.single().variant.request.startOptions)
        assertEquals(raw,plan.variants.single().variant.request.request)
    }
    @Test fun `compiler checks nested conditional recovery and conservatively applicable native rules`() {
        val recovery=buildJsonObject {
            put("type","validate_session");put("enabled",true);put("action","run_macro");put("perform_action_if_invalid",true)
            put("run_macro_action",JsonObject(action()-"type"))
        }
        assertEquals("MACRO_OVERWRITES_DIAGNOSTIC_INPUT",assertThrows(JobRejected::class.java) { JobCompiler().compile(job(),baseline(recovery)) }.code)
        val original=baseline(action());val root=original.project["project_options"]!!.jsonObject
        val sessions=root["sessions"]!!.jsonObject;val handling=sessions["session_handling_rules"]!!.jsonObject
        val unrelated=JsonObject(handling["rules"]!!.jsonArray.single().jsonObject+("tools_scope" to JsonArray(listOf(JsonPrimitive("Proxy")))))
        val changedHandling=JsonObject(handling+("rules" to JsonArray(listOf(unrelated))))
        val changedSessions=JsonObject(sessions+("session_handling_rules" to changedHandling))
        val outside=original.copy(project=buildJsonObject { put("project_options",JsonObject(root+("sessions" to changedSessions))) })
        JobCompiler().compile(job(),outside)
    }
    @Test fun `new safeguards omit defaults and preserve persisted legacy plan fingerprints`() {
        val legacy=job(null)
        val serialized=jobJson.encodeToJsonElement(legacy)
        assertFalse(serialized.toString().contains("inputExclusions"));assertFalse(serialized.toString().contains("preparationOnce"))
        assertFalse(serialized.toString().contains("requestedInputParameters"))
        val restored=jobJson.decodeFromJsonElement<JobProposal>(serialized)
        assertEquals(fingerprint(legacy),fingerprint(restored))
        val plan=JobCompiler().compile(legacy,baseline())
        val saved=jobJson.encodeToJsonElement(plan)
        assertEquals(saved,jobJson.encodeToJsonElement(jobJson.decodeFromJsonElement<CompiledPlan>(saved)))
        assertEquals(plan.planDigest,JobCompiler().compile(restored,baseline()).planDigest)
        // Deserializing a previously saved plan never invokes the new proposal guard.
        val historical=plan.copy(proposal=job(),baseline=baseline(action()))
        assertEquals(historical,jobJson.decodeFromJsonElement<CompiledPlan>(jobJson.encodeToJsonElement(historical)))
    }
    @Test fun `exclusion reasons are bound to the plan and blank explanations are rejected`() {
        val selected=job(parameters.drop(1));val variant=selected.variants.single()
        val first=selected.copy(variants=listOf(variant.copy(inputExclusions=listOf(InputExclusion("loggedout","URL","Reviewed reason one")))))
        val second=first.copy(variants=listOf(first.variants.single().copy(inputExclusions=listOf(InputExclusion("loggedout","URL","Reviewed reason two")))))
        assertNotEquals(JobCompiler().compile(first,baseline()).planDigest,JobCompiler().compile(second,baseline()).planDigest)
        val blank=first.copy(variants=listOf(variant.copy(inputExclusions=listOf(InputExclusion("loggedout","URL","")))))
        assertEquals("INPUT_EXCLUSION_REASON_REQUIRED",assertThrows(JobRejected::class.java) { JobCompiler().compile(blank,baseline()) }.code)
    }
    @Test fun `once preparation rejects unobserved changed out of scope and scan option inputs in pure compilation`() {
        val original=job(null);val variant=original.variants.single()
        val preparation=variant.request.copy(startOptions=JsonObject(emptyMap()))
        fun proposal(request:RequestPlan)=original.copy(variants=listOf(variant.copy(preparationOnce=listOf(request))))
        val valid=JobCompiler().compile(proposal(preparation),baseline())
        assertEquals(listOf(preparation),valid.variants.single().variant.preparationOnce)
        val outside=e.copy(host="outside.invalid")
        val cases=listOf(
            preparation.copy(sourceId="unobserved") to "ONCE_PREPARATION_SOURCE_NOT_OBSERVED",
            preparation.copy(sourceId="") to "ONCE_PREPARATION_SOURCE_NOT_OBSERVED",
            preparation.copy(sourceRequestSha256="0".repeat(64)) to "ONCE_PREPARATION_SOURCE_NOT_OBSERVED",
            preparation.copy(endpoint=outside,request=raw.replace("Host: contract.invalid:8080","Host: outside.invalid:8080")) to "OUT_OF_SCOPE",
            preparation.copy(startOptions=options(parameters)) to "ONCE_PREPARATION_SCAN_OPTIONS_FORBIDDEN"
        )
        cases.forEach { (request,code) ->
            assertEquals(code,assertThrows(JobRejected::class.java) { JobCompiler().compile(proposal(request),baseline()) }.code)
        }
    }
}
