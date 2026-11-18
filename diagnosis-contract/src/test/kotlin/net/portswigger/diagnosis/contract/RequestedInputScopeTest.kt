package net.portswigger.diagnosis.contract

import kotlinx.serialization.json.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class RequestedInputScopeTest {
    private val fields=listOf(InputParameter("mode","URL"),InputParameter("state","BODY"),InputParameter("identity","BODY"),InputParameter("credential","BODY"))
    private val target=Endpoint("http","scope-fixture.invalid",8080,"/submit?mode=1")
    private val raw="POST ${target.path} HTTP/1.1\r\nHost: ${target.host}:${target.port}\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nstate=sample&identity=reader&credential=fixture"
    private val response="HTTP/1.1 200 OK\r\n\r\nnormal"
    private val source=HttpMaterial("observed",target,raw,response,digest(raw),digest(response))
    private val capabilities=setOf("SCANNER_WORKFLOW","EXCLUSIVE_CONTEXT")
    private val baseline=BurpSnapshot("fixture",JsonObject(emptyMap()),JsonObject(emptyMap()),emptyList(),capabilities)
    private fun options(selected:List<InputParameter>)=buildJsonObject { put("insertionPointParameters",jobJson.encodeToJsonElement(selected)) }
    private fun proposal(selected:List<InputParameter>?=fields,requested:List<InputParameter> = fields):JobProposal = JobProposal(
        jobId="requested-scope",revision=1,objective="Diagnose the independently requested inputs",targetPolicy=listOf(TargetPermit(target)),
        materials=listOf(source),session=SessionPlan(false,"OMIT","Fixture requires no session","fixture"),
        variants=listOf(ScanVariant("reflection","REFLECTION",request=RequestPlan(target,raw,source.id,source.requestSha256,selected?.let(::options) ?: JsonObject(emptyMap())),settings=SettingsPlan())),
        requiredCapabilities=capabilities,cleanupPolicy="Review owned fixture state",requestedInputParameters=requested)
    private fun reject(code:String,proposal:JobProposal) {
        assertEquals(code,assertThrows(JobRejected::class.java) { JobCompiler().compile(proposal,baseline) }.code)
    }
    @Test fun `explicit selection requires an independent requested declaration for every new compilation`() {
        reject("REQUESTED_INPUT_PARAMETERS_REQUIRED",proposal(requested=emptyList()))
        val old=jobJson.encodeToJsonElement(proposal(requested=emptyList()))
        assertFalse(old.toString().contains("requestedInputParameters"))
        val restored=jobJson.decodeFromJsonElement<JobProposal>(old)
        assertEquals(old,jobJson.encodeToJsonElement(restored))
        reject("REQUESTED_INPUT_PARAMETERS_REQUIRED",restored)
    }
    @Test fun `a future separate Scan reason cannot remove one of four requested inputs`() {
        val narrower=proposal(selected=fields.filterNot { it.name=="state" })
        val excluded=narrower.copy(variants=listOf(narrower.variants.single().copy(
            inputExclusions=listOf(InputExclusion("state","BODY","This input will be diagnosed in a separate future Scan")))))
        reject("REQUESTED_INPUT_COVERAGE_MISMATCH",excluded)
        reject("REQUESTED_INPUT_COVERAGE_MISMATCH",excluded.copy(limitations=listOf("A future job may test state separately")))
    }
    @Test fun `an independently requested subset is accepted as its own explicitly declared scope`() {
        val subset=fields.filterNot { it.name=="state" }
        val proposal=proposal(subset,subset)
        val explicit=proposal.copy(variants=listOf(proposal.variants.single().copy(
            inputExclusions=listOf(InputExclusion("state","BODY","Observed context outside this independently requested subset")))))
        val compiled=JobCompiler().compile(explicit,baseline)
        assertEquals(subset,compiled.proposal.requestedInputParameters)
        assertEquals(subset.toSet(),InputCoverage.selected(compiled.variants.single().variant.request.startOptions)!!.toSet())
    }
    @Test fun `requested identities preserve exact names native type and case with no duplicate claims`() {
        reject("DUPLICATE_REQUESTED_INPUT_PARAMETER",proposal(requested=fields+fields.first()))
        for(invalid in listOf(InputParameter(" ","BODY"),InputParameter("state"," ")))
            reject("INVALID_REQUESTED_INPUT_PARAMETERS",proposal(requested=listOf(invalid)))
        reject("INVALID_REQUESTED_INPUT_PARAMETERS",proposal(requested=List(129) { InputParameter("field$it","BODY") }))
        reject("REQUESTED_INPUT_COVERAGE_MISMATCH",proposal(requested=fields.map { if(it.name=="state") it.copy(name="State") else it }))
        reject("REQUESTED_INPUT_COVERAGE_MISMATCH",proposal(requested=fields.map { if(it.name=="state") it.copy(type="body") else it }))
        // Declared order does not change the selected identity set.
        JobCompiler().compile(proposal(selected=fields.reversed()),baseline)
    }
    private fun withStored(proposal:JobProposal):JobProposal {
        val macro=buildJsonObject {
            put("serial_number",41);put("description","job:requested-scope:stored-response")
            putJsonArray("items") { add(buildJsonObject {
                put("url",target.url());put("request",raw);put("response",response);put("method","POST");put("status_code",200)
                put("accept_response_cookies",true);put("use_request_cookies",true)
                putJsonArray("custom_parameters") {};putJsonArray("request_parameters") {}
            }) }
        }
        val rule=buildJsonObject {
            put("description","job:requested-scope:stored-rule");put("enabled",true)
            putJsonArray("actions") { add(buildJsonObject {
                put("type","run_post_request_macro");put("enabled",true);put("macro_serial_number",41);put("pass_back","final_response")
            }) }
            putJsonArray("exclude_from_scope") {};putJsonArray("named_params") {};put("restrict_scope_to_named_params",false)
            putJsonArray("tools_scope") { add("Scanner");add("Extensions") }
            put("url_scope","custom");put("url_scope_advanced_mode",false)
            putJsonArray("include_in_scope") { add(buildJsonObject { put("prefix",target.url());put("enabled",true) }) }
        }
        val stored=proposal.variants.single().copy(id="stored",kind="STORED",verificationSourceId=source.id,
            settings=SettingsPlan(macros=JsonArray(listOf(macro)),rules=JsonArray(listOf(rule))))
        return proposal.copy(variants=proposal.variants+stored,storedVerificationSourceIds=listOf(source.id))
    }
    @Test fun `every reflection and stored variant must retain the whole requested set`() {
        val both=withStored(proposal())
        val compiled=JobCompiler().compile(both,baseline)
        assertEquals(2,compiled.variants.size)
        assertTrue(compiled.variants.all { InputCoverage.selected(it.variant.request.startOptions)!!.toSet()==fields.toSet() })
        val stored=both.variants.last()
        val narrowed=stored.copy(request=stored.request.copy(startOptions=options(fields.drop(1))))
        reject("REQUESTED_INPUT_COVERAGE_MISMATCH",both.copy(variants=listOf(both.variants.first(),narrowed)))
        val automatic=stored.copy(request=stored.request.copy(startOptions=JsonObject(emptyMap())))
        reject("REQUESTED_INPUT_SELECTION_REQUIRED",both.copy(variants=listOf(both.variants.first(),automatic)))
    }
    @Test fun `automatic calls and saved legacy digests retain their old default serialization`() {
        val automatic=proposal(selected=null,requested=emptyList())
        val encoded=jobJson.encodeToJsonElement(automatic)
        assertFalse(encoded.toString().contains("requestedInputParameters"))
        assertEquals(fingerprint(automatic),fingerprint(jobJson.decodeFromJsonElement<JobProposal>(encoded)))
        val compiled=JobCompiler().compile(automatic,baseline)
        val saved=jobJson.encodeToJsonElement(compiled)
        assertEquals(compiled,jobJson.decodeFromJsonElement<CompiledPlan>(saved))
        assertEquals(compiled.planDigest,JobCompiler().compile(jobJson.decodeFromJsonElement<JobProposal>(encoded),baseline).planDigest)
        // A pre-existing explicit plan can still be deserialized for evidence and recovery without recompiling it.
        val historical=compiled.copy(proposal=proposal(requested=emptyList()))
        val oldSaved=jobJson.encodeToJsonElement(historical)
        assertEquals(oldSaved,jobJson.encodeToJsonElement(jobJson.decodeFromJsonElement<CompiledPlan>(oldSaved)))
        assertNotEquals(compiled.proposalDigest,JobCompiler().compile(proposal(),baseline).proposalDigest)
    }
}
