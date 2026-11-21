package net.portswigger.diagnosis.contract

import kotlinx.serialization.json.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class AuthenticationRetentionTest {
    private val endpoint=Endpoint("http","fixture.invalid",8080,"/items")
    private val raw="GET /items HTTP/1.1\r\nHost: fixture.invalid:8080\r\n\r\n"
    private val response="HTTP/1.1 200 OK\r\n\r\nnormal"
    private val material=HttpMaterial("observed",endpoint,raw,response,digest(raw),digest(response))
    private val caps=setOf("SCANNER_WORKFLOW","EXCLUSIVE_CONTEXT","DYNAMIC_WORKFLOW_VERIFIED")
    private val baseline=BurpSnapshot("instance",jobJson.parseToJsonElement("""{"project_options":{"sessions":{},"resource_pools":{"default_resource_pool":{"concurrent_request_limit_enabled":false,"concurrent_request_limit":8,"keep":"original"}}},"proxy":{"keep":true}}""").jsonObject,
        buildJsonObject { putJsonObject(digest("options")) { put("chkbox_scanner",false);put("chkbox_extender",true) } },listOf(digest("options")),caps)
    private fun macro(id:Int)=buildJsonObject {
        put("serial_number",id);put("description","job:auth:macro-$id")
        putJsonArray("items") { add(buildJsonObject {
            put("url",endpoint.url());put("request",raw);put("response",response);put("method","GET");put("status_code",200)
            put("accept_response_cookies",true);put("use_request_cookies",true)
            put("custom_parameters",JsonArray(emptyList()));put("request_parameters",JsonArray(emptyList()))
        }) }
    }
    private fun rule(name:String,validation:Boolean=true)=buildJsonObject {
        put("description","job:auth:$name");put("enabled",true)
        put("exclude_from_scope",JsonArray(emptyList()));put("named_params",JsonArray(emptyList()));put("restrict_scope_to_named_params",false)
        put("tools_scope",JsonArray(listOf(JsonPrimitive("Scanner"),JsonPrimitive("Extensions"))))
        put("url_scope","custom");put("url_scope_advanced_mode",false)
        putJsonArray("include_in_scope") { add(buildJsonObject { put("enabled",true);put("include_subdomains",false);put("prefix",endpoint.url()) }) }
        putJsonArray("actions") { add(buildJsonObject {
            put("type",if(validation) "validate_session" else "run_macro");put("enabled",true)
            put("macro_serial_number",if(validation) 101 else 103)
            if(validation) {
                put("validation_action","run_macro");put("action","run_macro");put("stop_if_valid",false)
                put("response_location","body");put("match_type","literal");put("match_expression","normal")
                putJsonObject("run_macro_action") { put("macro_serial_number",102);put("update_with_params",false);put("update_with_cookies",true) }
            }
        }) }
    }
    private fun proposal():JobProposal {
        val settings=SettingsPlan(macros=JsonArray((101..103).map(::macro)),rules=JsonArray(listOf(rule("login"),rule("temporary",false))),
            cph=buildJsonObject {
                putJsonObject("job:auth:source") { put("enabled",true) }
                putJsonObject("job:auth:destination") { put("enabled",true);put("dynamic_checkbox",true);put("extract_choice_index",2);put("cached_selection","job:auth:source") }
                putJsonObject("job:auth:temporary") { put("enabled",true) }
                putJsonObject(digest("options")) { put("chkbox_scanner",true);put("chkbox_extender",true) }
            },cphOrder=listOf("job:auth:source","job:auth:destination","job:auth:temporary",digest("options")),serialScannerRequests=true)
        return JobProposal(jobId="auth",revision=1,objective="review auth retention",targetPolicy=listOf(TargetPermit(endpoint)),materials=listOf(material),
            session=SessionPlan(true,"USE","conditional recovery","account",validationSourceId=material.id),
            variants=listOf(ScanVariant("reflection","REFLECTION",request=RequestPlan(endpoint,raw,material.id,material.requestSha256),settings=settings)),
            requiredCapabilities=caps,cleanupPolicy="owned only",authenticationRetention=AuthenticationRetention(listOf("job:auth:login"),listOf("job:auth:destination")))
    }
    private fun list(project:JsonObject,container:String,key:String)=project["project_options"]!!.jsonObject["sessions"]!!.jsonObject[container]!!.jsonObject[key]!!.jsonArray
    private fun rejected(code:String,p:JobProposal) {
        assertEquals(code,assertThrows(JobRejected::class.java) { JobCompiler().compile(p,baseline) }.code)
    }
    @Test fun `retains validation and recovery macros and cache closure disabled at rest without temporary settings`() {
        val proposal=proposal();val plan=JobCompiler().compile(proposal,baseline);val kept=plan.restorationBaseline!!
        val rules=list(kept.project,"session_handling_rules","rules")
        assertEquals(1,rules.size);assertEquals(JsonPrimitive(false),rules.single().jsonObject["enabled"])
        assertEquals(proposal.variants.single().settings.rules.first().jsonObject["actions"],rules.single().jsonObject["actions"])
        assertEquals(setOf(101,102),list(kept.project,"macros","macros").map { it.jsonObject["serial_number"]!!.jsonPrimitive.int }.toSet())
        assertEquals(listOf("job:auth:source","job:auth:destination",digest("options")),kept.cphOrder)
        assertEquals(JsonPrimitive(false),kept.cph["job:auth:source"]!!.jsonObject["enabled"])
        assertEquals(JsonPrimitive(false),kept.cph["job:auth:destination"]!!.jsonObject["enabled"])
        assertFalse("job:auth:temporary" in kept.cph)
        assertEquals(baseline.cph[digest("options")],kept.cph[digest("options")])
        assertEquals(baseline.project["proxy"],kept.project["proxy"])
        assertEquals(baseline.project["project_options"]!!.jsonObject["resource_pools"],kept.project["project_options"]!!.jsonObject["resource_pools"])
        val active=plan.variants.single()
        assertEquals(JsonPrimitive(true),list(active.project,"session_handling_rules","rules").first().jsonObject["enabled"])
        assertEquals(JsonPrimitive(true),active.cph["job:auth:destination"]!!.jsonObject["enabled"])
        checkRecoveryOwnership(plan,kept)
        assertEquals(plan,JobCompiler().compile(proposal,baseline))
    }
    @Test fun `next target reuses existing definitions and switches only enabled flags then restores disabled idle baseline`() {
        val first=JobCompiler().compile(proposal(),baseline);val kept=first.restorationBaseline!!
        val states=AuthenticationStates(mapOf("job:auth:login" to true),mapOf("job:auth:source" to true,"job:auth:destination" to true),listOf("Scanner","Extender"))
        val next=proposal().copy(jobId="next",authenticationRetention=null,variants=listOf(proposal().variants.single().copy(settings=SettingsPlan(authenticationStates=states))))
        val plan=JobCompiler().compile(next,kept);val active=plan.variants.single()
        assertEquals(1,list(active.project,"session_handling_rules","rules").size)
        assertEquals(JsonPrimitive(true),list(active.project,"session_handling_rules","rules").single().jsonObject["enabled"])
        assertEquals(JsonPrimitive(true),active.cph[digest("options")]!!.jsonObject["chkbox_scanner"])
        validateAuthenticationToolScopes(plan)
        assertEquals(kept.cph["job:auth:destination"]!!.jsonObject-"enabled",active.cph["job:auth:destination"]!!.jsonObject-"enabled")
        checkRecoveryOwnership(plan,kept.copy(project=active.project,cph=active.cph,cphOrder=active.cphOrder))
        val changed=JsonObject(active.cph+mapOf("job:auth:source" to JsonObject(active.cph["job:auth:source"]!!.jsonObject+("static_expression" to JsonPrimitive("tampered")))))
        assertEquals("UNRELATED_CPH_CHANGED",assertThrows(JobRejected::class.java) { checkRecoveryOwnership(plan,kept.copy(project=active.project,cph=changed,cphOrder=active.cphOrder)) }.code)
        val inactive=next.copy(session=next.session.copy(authenticationRequired=false,validationDecision="OMIT"),variants=listOf(next.variants.single().copy(settings=SettingsPlan())))
        assertEquals(JsonPrimitive(false),list(JobCompiler().compile(inactive,kept).variants.single().project,"session_handling_rules","rules").single().jsonObject["enabled"])
    }
    @Test fun `selectors refuse missing unowned nonvalidation or conflicting authentication definitions`() {
        val p=proposal()
        rejected("INVALID_AUTHENTICATION_RETENTION",p.copy(authenticationRetention=AuthenticationRetention(listOf("other"))))
        rejected("RETAINED_AUTHENTICATION_RULE_MISSING",p.copy(authenticationRetention=AuthenticationRetention(listOf("job:auth:missing"))))
        rejected("RETAINED_AUTHENTICATION_VALIDATION_REQUIRED",p.copy(authenticationRetention=AuthenticationRetention(listOf("job:auth:temporary"))))
        rejected("RETAINED_CPH_MISSING_OR_UNOWNED",p.copy(authenticationRetention=AuthenticationRetention(listOf("job:auth:login"),listOf("job:auth:missing"))))
        val variant=p.variants.single()
        rejected("AUTHENTICATION_RULE_STATE_REFERENCE_REQUIRED",p.copy(authenticationRetention=null,variants=listOf(variant.copy(settings=variant.settings.copy(authenticationStates=AuthenticationStates(mapOf("absent" to true)))))))
        rejected("AUTHENTICATION_CPH_STATE_REFERENCE_REQUIRED",p.copy(authenticationRetention=null,variants=listOf(variant.copy(settings=variant.settings.copy(authenticationStates=AuthenticationStates(cph=mapOf(digest("options") to false)))))))
    }
    @Test fun `scope retention is explicit and preserves original scope and unrelated project fields`() {
        val p=proposal();val v=p.variants.single()
        val scope=buildJsonObject { putJsonArray("include") { add(buildJsonObject { put("prefix",endpoint.url());put("enabled",true) }) } }
        val scoped=p.copy(variants=listOf(v.copy(settings=v.settings.copy(targetScope=scope))))
        rejected("RETAINED_CPH_TARGET_SCOPE_REQUIRED",scoped)
        val plan=JobCompiler().compile(scoped.copy(authenticationRetention=p.authenticationRetention!!.copy(retainTargetScope=true)),baseline)
        val retained=plan.restorationBaseline!!
        assertTrue(retained.project.toString().contains(endpoint.url()))
        assertEquals(baseline.project["proxy"],retained.project["proxy"])
        checkRecoveryOwnership(plan,retained)
    }
    @Test fun `recovery ownership also accepts approved newly added Options with an initially empty CPH snapshot`() {
        val empty=baseline.copy(cph=JsonObject(emptyMap()),cphOrder=emptyList())
        val plan=JobCompiler().compile(proposal(),empty)
        val kept=plan.restorationBaseline!!
        assertEquals(proposal().variants.single().settings.cph[digest("options")],kept.cph[digest("options")])
        checkRecoveryOwnership(plan,kept)
        val changed=kept.copy(cph=JsonObject(kept.cph+(digest("options") to buildJsonObject { put("verbosity",99) })))
        assertEquals("UNRELATED_CPH_OPTIONS_CHANGED",assertThrows(JobRejected::class.java) { checkRecoveryOwnership(plan,changed) }.code)
    }
    @Test fun `legacy plan digest and wire form are unchanged when retention and switching are omitted`() {
        val oldStates=jobJson.parseToJsonElement("""{"rules":{},"cph":{}}""")
        assertEquals(oldStates,jobJson.encodeToJsonElement(jobJson.decodeFromJsonElement<AuthenticationStates>(oldStates)))
        val p=proposal().copy(authenticationRetention=null)
        val encoded=jobJson.encodeToJsonElement(p).jsonObject
        assertFalse("authenticationRetention" in encoded)
        assertFalse("authenticationStates" in encoded["variants"]!!.jsonArray.first().jsonObject["settings"]!!.jsonObject)
        val compiled=JobCompiler().compile(p,baseline)
        assertNull(compiled.restorationBaseline)
        assertFalse("restorationBaseline" in jobJson.encodeToJsonElement(compiled).jsonObject)
        val seed=buildJsonObject { put("proposal",compiled.proposalDigest);put("baseline",fingerprint(baseline));put("variants",jobJson.encodeToJsonElement(compiled.variants)) }
        assertEquals(fingerprint(seed),compiled.planDigest)
        assertEquals(compiled,jobJson.decodeFromJsonElement<CompiledPlan>(jobJson.encodeToJsonElement(compiled)))
    }
    @Test fun `retention preserves temporary and authentication Rule order in either direction`() {
        val p=proposal();val v=p.variants.single()
        for(order in listOf(v.settings.rules,v.settings.rules.reversed().let(::JsonArray))) {
            val submitted=p.copy(variants=listOf(v.copy(settings=v.settings.copy(rules=order))))
            val ordinary=JobCompiler().compile(submitted.copy(authenticationRetention=null),baseline)
            val retained=JobCompiler().compile(submitted,baseline)
            assertEquals(list(ordinary.variants.single().project,"session_handling_rules","rules"),
                list(retained.variants.single().project,"session_handling_rules","rules"))
        }
    }
    @Test fun `reused CPH requires declared tools and enables precisely those tools before send`() {
        val p=proposal();val idle=JobCompiler().compile(p,baseline).restorationBaseline!!
        fun next(states:AuthenticationStates)=p.copy(jobId="next",authenticationRetention=null,
            variants=listOf(p.variants.single().copy(settings=SettingsPlan(authenticationStates=states))))
        val missing=AuthenticationStates(mapOf("job:auth:login" to true),mapOf("job:auth:destination" to true))
        assertEquals("CPH_TOOL_SCOPE_REQUIRED",assertThrows(JobRejected::class.java) { JobCompiler().compile(next(missing),idle) }.code)
        for(tools in listOf(listOf("Scanner"),listOf("Extender"),listOf("Scanner","Extender"))) {
            val plan=JobCompiler().compile(next(missing.copy(cphTools=tools)),idle)
            validateAuthenticationToolScopes(plan)
            val options=plan.variants.single().cph[digest("options")]!!.jsonObject
            assertEquals(JsonPrimitive("Scanner" in tools),options["chkbox_scanner"])
            assertEquals(JsonPrimitive(true),options["chkbox_extender"]) // preserve unrelated original flags
            assertEquals(baseline.cph[digest("options")],plan.baseline.cph[digest("options")])
            checkRecoveryOwnership(plan,idle.copy(project=plan.variants.single().project,cph=plan.variants.single().cph,cphOrder=plan.variants.single().cphOrder))
        }
        assertEquals("INVALID_CPH_TOOL_SCOPE",assertThrows(JobRejected::class.java) { JobCompiler().compile(next(missing.copy(cphTools=listOf("Scannre"))),idle) }.code)
        val plan=JobCompiler().compile(next(missing.copy(cphTools=listOf("Scanner"))),idle)
        val variant=plan.variants.single()
        val disabled=JsonObject(variant.cph+(digest("options") to JsonObject(variant.cph[digest("options")]!!.jsonObject+("chkbox_scanner" to JsonPrimitive(false)))))
        assertEquals("CPH_TOOL_SCOPE_DISABLED",assertThrows(JobRejected::class.java) {
            validateAuthenticationToolScopes(plan.copy(variants=listOf(variant.copy(cph=disabled))))
        }.code)
        val old=plan.copy(variants=listOf(variant.copy(variant=variant.variant.copy(settings=variant.variant.settings.copy(authenticationStates=missing)))))
        assertEquals("CPH_TOOL_SCOPE_REQUIRED",assertThrows(JobRejected::class.java) { validateAuthenticationToolScopes(old) }.code)
    }
    @Test fun `multiple variants share retained authentication but retain independent temporary workflows`() {
        val p=proposal();val reflection=p.variants.single();val original=reflection.settings
        val post=rule("stored",false).let { template ->
            val action=buildJsonObject { put("type","run_post_request_macro");put("enabled",true);put("macro_serial_number",103);put("pass_back","final_response");put("update_with_params",false) }
            JsonObject(template+("actions" to JsonArray(listOf(action))))
        }
        val temporary=JsonObject(original.macros.last().jsonObject+("description" to JsonPrimitive("job:auth:other-temporary")))
        val stored=reflection.copy(id="stored",kind="STORED",verificationSourceId=material.id,
            settings=original.copy(macros=JsonArray(original.macros.dropLast(1)+temporary),rules=JsonArray(listOf(original.rules.first(),post)),
                cph=JsonObject(original.cph+(digest("options") to JsonObject(original.cph.getValue(digest("options")).jsonObject+("verbosity" to JsonPrimitive(1)))))))
        val multi=p.copy(variants=listOf(reflection,stored),storedVerificationSourceIds=listOf(material.id))
        val plan=JobCompiler().compile(multi,baseline)
        assertEquals(2,plan.variants.size)
        plan.variants.forEach { variant ->
            val auth=list(variant.project,"session_handling_rules","rules").single { it.jsonObject["description"]==JsonPrimitive("job:auth:login") }
            assertEquals(JsonPrimitive(true),auth.jsonObject["enabled"])
        }
        assertEquals(1,list(plan.restorationBaseline!!.project,"session_handling_rules","rules").size)
        val changed=JsonObject(original.rules.first().jsonObject+("tools_scope" to JsonArray(listOf(JsonPrimitive("Scanner")))))
        rejected("RETAINED_AUTHENTICATION_CONFLICT",multi.copy(variants=listOf(reflection,stored.copy(settings=stored.settings.copy(rules=JsonArray(listOf(changed,post)))))))
    }
}
