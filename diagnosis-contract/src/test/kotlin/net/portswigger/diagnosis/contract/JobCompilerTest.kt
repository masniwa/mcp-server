package net.portswigger.diagnosis.contract

import kotlinx.serialization.json.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*

class JobCompilerTest {
    @Test fun `execution approval duration is opt in bounded and part of the reviewed digest`() {
        val original=job()
        assertFalse(jobJson.encodeToJsonElement(original).toString().contains("executionApprovalMaxAgeSeconds"))
        assertEquals(fingerprint(original),fingerprint(jobJson.decodeFromJsonElement<JobProposal>(jobJson.encodeToJsonElement(original))))
        val long=original.copy(executionApprovalMaxAgeSeconds=86400)
        assertNotEquals(fingerprint(original),fingerprint(long))
        JobCompiler().compile(long,baseline)
        for(duration in listOf(-1L,0L,86401L,Long.MAX_VALUE))
            reject("INVALID_EXECUTION_APPROVAL_DURATION",original.copy(executionApprovalMaxAgeSeconds=duration))
    }
    @Test fun `nested native recovery macro omission is equivalent without hiding real changes`() {
        val recovery=jobJson.parseToJsonElement("""{"macro_serial_number":123,"match_params":"specified","specified_params":[],"update_with_params":false,"update_with_cookies":true}""").jsonObject
        val action=buildJsonObject { put("type","validate_session");put("action","run_macro");put("run_macro_action",recovery) }
        val omitted=JsonObject(action+("run_macro_action" to JsonObject(recovery-"specified_params")))
        for(wrapped in listOf(true,false)) {
            fun project(a:JsonObject)=projectAction(a).let { if(wrapped) it else it["project_options"]!!.jsonObject }
            assertEquals(projectDefinitions(project(action)),projectDefinitions(project(omitted)))
            assertTrue(project(action).toString().contains("specified_params"))
            val changes=listOf(
                "specified_params" to JsonArray(listOf(JsonPrimitive("csrf"))),
                "update_with_params" to JsonPrimitive(true),
                "future_field" to JsonPrimitive(true))
            for(change in changes) {
                val changed=JsonObject(recovery+change)
                assertNotEquals(projectDefinitions(project(omitted)),projectDefinitions(project(JsonObject(action+("run_macro_action" to changed)))))
            }
            val differentMode=JsonObject(action+("action" to JsonPrimitive("prompt")))
            assertNotEquals(projectDefinitions(project(differentMode)),projectDefinitions(project(JsonObject(differentMode+("run_macro_action" to JsonObject(recovery-"specified_params"))))))
        }
    }
    @Test fun `serial scanner opt in preserves legacy serialized definitions and digests`() {
        val legacy=jobJson.encodeToJsonElement(job())
        assertFalse(legacy.toString().contains("serialScannerRequests"))
        val decoded=jobJson.decodeFromJsonElement<JobProposal>(legacy)
        assertEquals(fingerprint(job()),fingerprint(decoded))
        val v=job().variants.single()
        val opted=job().copy(variants=listOf(v.copy(settings=v.settings.copy(serialScannerRequests=true))))
        assertNotEquals(fingerprint(job()),fingerprint(opted))
        assertTrue(jobJson.encodeToJsonElement(opted).toString().contains("\"serialScannerRequests\":true"))
    }
    private fun poolBaseline(wrapped:Boolean=true):BurpSnapshot {
        val pool=jobJson.parseToJsonElement("""{"default_resource_pool":{"name":"operator pool","concurrent_request_limit_enabled":false,"concurrent_request_limit":10,"throttle_interval_millis":19,"future_setting":{"keep":true}},"custom_resource_pools":[{"name":"other","concurrent_request_limit":3}]}""")
        val root=JsonObject(baseline.project["project_options"]!!.jsonObject+("resource_pools" to pool))
        return baseline.copy(project=if(wrapped) JsonObject(baseline.project+("project_options" to root)) else root)
    }
    @Test fun `approved serial pool changes only the limit and enabled flag in either native root layout`() {
        val v=job().variants.single();val j=job().copy(variants=listOf(v.copy(settings=v.settings.copy(serialScannerRequests=true))))
        for(wrapped in listOf(true,false)) {
            val before=poolBaseline(wrapped);val plan=JobCompiler().compile(j,before)
            val root=(plan.variants.single().project["project_options"] as? JsonObject) ?: plan.variants.single().project
            val original=(before.project["project_options"] as? JsonObject) ?: before.project
            val pools=root["resource_pools"]!!.jsonObject;val pool=pools["default_resource_pool"]!!.jsonObject
            assertEquals(1,pool["concurrent_request_limit"]!!.jsonPrimitive.int)
            assertTrue(pool["concurrent_request_limit_enabled"]!!.jsonPrimitive.boolean)
            assertEquals(original["resource_pools"]!!.jsonObject["default_resource_pool"]!!.jsonObject- setOf("concurrent_request_limit","concurrent_request_limit_enabled"),pool- setOf("concurrent_request_limit","concurrent_request_limit_enabled"))
            assertEquals(original["resource_pools"]!!.jsonObject["custom_resource_pools"],pools["custom_resource_pools"])
            assertEquals(before,plan.baseline)
            assertEquals(original- setOf("sessions","resource_pools"),root- setOf("sessions","resource_pools"))
            val ordinary=JobCompiler().compile(job(),before).variants.single().project
            assertEquals(original["resource_pools"],((ordinary["project_options"] as? JsonObject) ?: ordinary)["resource_pools"])
        }
    }
    @Test fun `serial pool request rejects missing native pool configuration before apply`() {
        val v=job().variants.single()
        reject("RESOURCE_POOL_CONFIGURATION_REQUIRED",job().copy(variants=listOf(v.copy(settings=v.settings.copy(serialScannerRequests=true)))))
    }
    @Test fun `scope changes cannot discard the approved serial pool`() {
        val v=job().variants.single();val scope=buildJsonObject { putJsonArray("include") { add(buildJsonObject { put("prefix",target.url()) }) } }
        val j=job().copy(variants=listOf(v.copy(settings=v.settings.copy(serialScannerRequests=true,targetScope=scope))))
        val root=JobCompiler().compile(j,poolBaseline()).variants.single().project["project_options"]!!.jsonObject
        assertEquals(1,root["resource_pools"]!!.jsonObject["default_resource_pool"]!!.jsonObject["concurrent_request_limit"]!!.jsonPrimitive.int)
        assertEquals(target.url(),root["target"]!!.jsonObject["scope"]!!.jsonObject["include"]!!.jsonArray.single().jsonObject["prefix"]!!.jsonPrimitive.content)
    }
    private fun projectAction(action:JsonObject)=buildJsonObject { putJsonObject("project_options") { putJsonObject("sessions") {
        putJsonObject("session_handling_rules") { putJsonArray("rules") { add(buildJsonObject { put("actions",JsonArray(listOf(action))) }) } }
    } } }
    @Test fun `native omission of an empty specified macro parameter list preserves its definition digest`() {
        val action=buildJsonObject { put("type","run_macro");put("match_params","specified");put("specified_params",JsonArray(emptyList())) }
        val withEmpty=projectAction(action);val omitted=projectAction(JsonObject(action-"specified_params"))
        assertEquals(projectDefinitions(withEmpty),projectDefinitions(omitted))
        assertEquals(settingsDigest(withEmpty,JsonObject(emptyMap()),emptyList()),settingsDigest(omitted,JsonObject(emptyMap()),emptyList()))
        assertTrue(withEmpty.toString().contains("specified_params"))
    }
    @Test fun `native normalization cannot hide selected parameters unknown fields or another action mode`() {
        val base=buildJsonObject { put("type","run_macro");put("match_params","specified") }
        val normal=projectDefinitions(projectAction(base))
        assertNotEquals(normal,projectDefinitions(projectAction(JsonObject(base+("specified_params" to JsonArray(listOf(JsonPrimitive("csrf"))))))))
        assertNotEquals(normal,projectDefinitions(projectAction(JsonObject(base+("unknown" to JsonArray(emptyList()))))))
        for(modified in listOf(JsonObject(base+("type" to JsonPrimitive("run_post_request_macro"))),JsonObject(base+("match_params" to JsonPrimitive("all_except"))))) {
            assertNotEquals(projectDefinitions(projectAction(modified)),projectDefinitions(projectAction(JsonObject(modified+("specified_params" to JsonArray(emptyList()))))))
        }
    }
    private val target=Endpoint("http","test.invalid",8080,"/api/items")
    private val raw="POST /api/items HTTP/1.1\r\nHost: test.invalid:8080\r\nContent-Length: 12\r\n\r\nname=normal"
    private val material=HttpMaterial("observed",target,raw,"HTTP/1.1 200 OK\r\n\r\nnormal",digest(raw),digest("HTTP/1.1 200 OK\r\n\r\nnormal"))
    private val capabilities=setOf("SCANNER_WORKFLOW","EXCLUSIVE_CONTEXT","DYNAMIC_WORKFLOW_VERIFIED")
    private fun job():JobProposal=JobProposal(jobId="demo",revision=1,objective="Review observed item creation",
        targetPolicy=listOf(TargetPermit(target)),materials=listOf(material),session=SessionPlan(true,"OMIT","Normal authentication is performed on each attempt","reader"),
        variants=listOf(ScanVariant("reflection","REFLECTION",request=RequestPlan(target,raw,"observed",material.requestSha256),settings=SettingsPlan())),
        requiredCapabilities=capabilities,cleanupPolicy="Owned diagnostic records only")
    private val baseline=BurpSnapshot("instance",jobJson.parseToJsonElement("""{"project_options":{"sessions":{"macros":{"macros":[]},"session_handling_rules":{"rules":[]}}},"proxy":{"unchanged":true}}""").jsonObject,JsonObject(emptyMap()),emptyList(),capabilities)
    private fun reject(code:String,job:JobProposal,base:BurpSnapshot=baseline) {
        assertEquals(code,assertThrows(JobRejected::class.java) { JobCompiler().compile(job,base) }.code)
    }
    private fun nativeItem(request:String,response:String,url:String=target.url())=buildJsonObject {
        put("url",url);put("request",request);put("response",response);put("method",request.substringBefore(' '));put("status_code",200)
        put("accept_response_cookies",true);put("use_request_cookies",true);put("custom_parameters",JsonArray(emptyList()));put("request_parameters",JsonArray(emptyList()))
    }
    @Test fun `JSON body cannot be declared as a native Macro request parameter`() {
        val request="POST /api/items HTTP/1.1\r\nHost: test.invalid:8080\r\nContent-Type: application/json\r\n\r\n{\"id\":123}"
        val observed=material.copy(request=request,requestSha256=digest(request))
        val parameter=buildJsonObject { put("name","id");put("type","body_url_encoded");put("original_value","123")
            put("preset_value","123");put("parameter_handling","derive_from_prior_response") }
        val item=JsonObject(nativeItem(request,material.response)+("request_parameters" to JsonArray(listOf(parameter))))
        val macro=buildJsonObject { put("description","job:demo:cleanup");put("serial_number",321L)
            put("items",JsonArray(listOf(item))) }
        val variant=job().variants.single()
        val proposal=job().copy(materials=listOf(observed),variants=listOf(variant.copy(
            request=variant.request.copy(request=request,sourceRequestSha256=observed.requestSha256),
            settings=SettingsPlan(macros=JsonArray(listOf(macro))))))
        reject("MACRO_PARAMETER_LOCATION_UNSUPPORTED",proposal)
    }
    @Test fun `native Macro URL and form parameter locations remain valid`() {
        val url=buildJsonObject { put("name","id");put("type","url") }
        val form=buildJsonObject { put("name","token");put("type","body_url_encoded") }
        validateNativeMacroParameters("macro",0,
            "POST /api/items?id=42 HTTP/1.1\r\nHost: test.invalid:8080\r\nContent-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n\r\ntoken=abc",
            JsonArray(listOf(url,form)))
    }
    private fun nativeRule(name:String,actions:JsonArray)=buildJsonObject {
        put("description","job:demo:$name");put("enabled",true);put("actions",actions)
        put("exclude_from_scope",JsonArray(emptyList()));put("named_params",JsonArray(emptyList()));put("restrict_scope_to_named_params",false)
        put("tools_scope",JsonArray(listOf(JsonPrimitive("Scanner"),JsonPrimitive("Extensions"))))
        put("url_scope","custom");put("url_scope_advanced_mode",false)
        putJsonArray("include_in_scope") { add(buildJsonObject { put("enabled",true);put("include_subdomains",false);put("prefix",target.url()) }) }
    }
    @Test fun `compiler is deterministic and preserves native roots`() {
        val one=JobCompiler().compile(job(),baseline)
        assertEquals(one,JobCompiler().compile(job(),baseline))
        assertEquals(baseline.project["proxy"],one.variants.single().project["proxy"])
    }
    @Test fun `unknown schema and self approval fields are rejected`() {
        reject("INVALID_JOB_VERSION",job().copy(schemaVersion=2))
        val input=JsonObject(jobJson.encodeToJsonElement(job()).jsonObject+("approved" to JsonPrimitive(true)))
        assertThrows(Exception::class.java) { jobJson.decodeFromJsonElement<JobProposal>(input) }
    }
    @Test fun `prefix boundaries do not allow sibling APIs or other ports`() {
        val permit=TargetPermit(target.copy(path="/api"),true)
        assertTrue(permit.allows(target));assertFalse(permit.allows(target.copy(path="/api-evil")))
        assertFalse(permit.allows(target.copy(port=9090)))
    }
    @Test fun `out of scope observed material rejects before compilation`() {
        reject("OUT_OF_SCOPE",job().copy(targetPolicy=listOf(TargetPermit(target.copy(path="/different")))))
    }
    @Test fun `changing material and host is detected`() {
        reject("MATERIAL_CHANGED",job().copy(materials=listOf(material.copy(response="modified"))))
        val v=job().variants.single()
        reject("HOST_MISMATCH",job().copy(variants=listOf(v.copy(request=v.request.copy(request=raw.replace("Host: test.invalid:8080","Host: other.invalid"))))))
    }
    @Test fun `unsupported capabilities are explicit`() {
        reject("UNSUPPORTED_CAPABILITY",job(),baseline.copy(capabilities=emptySet()))
    }
    @Test fun `dynamic dependencies must be topological`() {
        val binding=DynamicBinding("id","response","request","regex","path","before","reject",listOf("missing"))
        reject("BINDING_ORDER_OR_CYCLE",job().copy(dynamicBindings=listOf(binding)))
        reject("DYNAMIC_CAPABILITY_REQUIRED",job().copy(dynamicBindings=listOf(binding.copy(dependsOn=emptyList())),requiredCapabilities=capabilities-"DYNAMIC_WORKFLOW_VERIFIED"))
    }
    @Test fun `stored destinations cannot be silently omitted`() {
        reject("STORED_COVERAGE_MISMATCH",job().copy(storedVerificationSourceIds=listOf("observed")))
    }
    @Test fun `legacy ignored config is not accepted as an applied job configuration`() {
        val v=job().variants.single()
        reject("UNSUPPORTED_START_OPTION",job().copy(variants=listOf(v.copy(request=v.request.copy(startOptions=buildJsonObject { putJsonObject("config") { put("audit",true) } })))))
    }
    @Test fun `unobserved macro requests are not invented`() {
        val macro=buildJsonObject { put("description","job:demo:login");put("serial_number",9007199254740993L);putJsonArray("items") {
            add(buildJsonObject { put("url",target.url());put("request",raw);put("response","unobserved response") })
        } }
        val v=job().variants.single()
        val proposal=job().copy(variants=listOf(v.copy(settings=SettingsPlan(macros=JsonArray(listOf(macro))))))
        reject("MACRO_NOT_OBSERVED",proposal)
    }
    @Test fun `large native integer identifiers and existing macros are preserved losslessly`() {
        val macro=buildJsonObject { put("description","job:demo:login");put("serial_number",9007199254740993L);putJsonArray("items") {
            add(nativeItem(raw,material.response))
        } }
        val v=job().variants.single()
        val plan=JobCompiler().compile(job().copy(variants=listOf(v.copy(settings=SettingsPlan(macros=JsonArray(listOf(macro)))))),baseline)
        assertTrue(plan.variants.single().project.toString().contains("9007199254740993"))
    }
    @Test fun `CPH source ordering and array socket shape follow the existing implementation`() {
        val source="job:demo:source";val dest="job:demo:dest"
        val tab=buildJsonObject { put("enabled",true);put("single_request",raw);putJsonArray("issuer") { add(false);add(target.host);add(target.port) } }
        val targetTab=buildJsonObject { put("enabled",true);put("dynamic_checkbox",true);put("cached_selection",source);put("extract_choice_index",2) }
        val settings=SettingsPlan(cph=JsonObject(linkedMapOf(source to tab,dest to targetTab)),cphOrder=listOf(source,dest))
        val v=job().variants.single()
        val p=job().copy(variants=listOf(v.copy(settings=settings)))
        assertEquals(listOf(source,dest),JobCompiler().compile(p,baseline).variants.single().cphOrder)
        reject("CPH_CACHE_REFERENCE_ORDER",p.copy(variants=listOf(v.copy(settings=settings.copy(cphOrder=listOf(dest,source))))))
    }
    @Test fun `CPH expression shape and single line controls fail before native apply with safe field details`() {
        val name="job:demo:fourth"
        val v=job().variants.single()
        fun proposed(value:JsonElement):JobProposal=job().copy(variants=listOf(v.copy(settings=SettingsPlan(
            cph=JsonObject(mapOf(name to buildJsonObject { put("enabled",true);put("static_expression",value) })),
            cphOrder=listOf(name)))))
        val malformed=assertThrows(JobRejected::class.java) { JobCompiler().compile(proposed(JsonPrimitive("secret-value")),baseline) }
        assertEquals("CPH_FIELD_SHAPE_INVALID",malformed.code)
        assertEquals(mapOf("tabName" to name,"fieldName" to "static_expression"),malformed.safeDetails)
        assertFalse(malformed.message!!.contains("secret-value"))
        reject("CPH_SINGLE_LINE_CONTROL_CHARACTER",proposed(buildJsonArray { add(true);add("value\r\n") }))
        JobCompiler().compile(proposed(buildJsonArray { add(true);add("\\r\\n") }),baseline)
    }
    @Test fun `forwarder host is checked even if target request is allowed`() {
        val tab=buildJsonObject { put("enabled",true);put("enable_forwarder",true);putJsonArray("forwarder") { add(false);add("outside.invalid");add(80) } }
        val v=job().variants.single()
        reject("CPH_SOCKET_OUT_OF_SCOPE",job().copy(variants=listOf(v.copy(settings=SettingsPlan(cph=buildJsonObject { put("job:demo:forward",tab) },cphOrder=listOf("job:demo:forward"))))))
    }
    @Test fun `dynamic single-request response changes do not change definitions`() {
        fun cph(index:Int,response:String)=buildJsonObject { putJsonObject("job:demo:tab") {
            put("dynamic_checkbox",true);put("extract_choice_index",index);put("single_response",response);put("match_expression","literal")
        } }
        assertEquals(cphDefinitions(cph(0,"old")),cphDefinitions(cph(0,"new")))
        assertNotEquals(cphDefinitions(cph(2,"old")),cphDefinitions(cph(2,"new")))
        assertNotEquals(settingsDigest(baseline.project,cph(0,"new"),listOf("a","b")),settingsDigest(baseline.project,cph(0,"new"),listOf("b","a")))
    }
    @Test fun `alternate native root layout is preserved`() {
        val native=baseline.project["project_options"]!!.jsonObject
        val plan=JobCompiler().compile(job(),baseline.copy(project=native))
        assertFalse("project_options" in plan.variants.single().project)
    }
    @Test fun `session validation decision cannot silently omit its native action`() {
        reject("SESSION_VALIDATION_SOURCE_REQUIRED",job().copy(session=job().session.copy(validationDecision="USE")))
        val get="GET /api/items HTTP/1.1\r\nHost: test.invalid:8080\r\n\r\n"
        val probe=material.copy(id="probe",request=get,requestSha256=digest(get))
        val p=job().copy(materials=job().materials+probe,session=job().session.copy(validationDecision="USE",validationSourceId="probe"))
        reject("SESSION_VALIDATION_ACTION_REQUIRED",p)
    }
    @Test fun `unsupported CPH fields fail before native import rather than silently disappearing`() {
        val v=job().variants.single()
        val settings=SettingsPlan(cph=buildJsonObject { putJsonObject("job:demo:tab") { put("invented_setting",true) } },cphOrder=listOf("job:demo:tab"))
        reject("UNSUPPORTED_CPH_FIELD",job().copy(variants=listOf(v.copy(settings=settings))))
    }
    @Test fun `a later CPH tab with a string expression is rejected before any import`() {
        val source="job:demo:source";val destination="job:demo:destination"
        val wrong=buildJsonObject {
            putJsonObject(source) { put("enabled",true);putJsonArray("static_expression") { add(true);add("source") } }
            putJsonObject(destination) {
                put("enabled",true);put("dynamic_checkbox",true);put("extract_choice_index",2);put("cached_selection",source)
                put("static_expression","Cookie: PHPSESSID=sample\\r\\n")
            }
        }
        val v=job().variants.single()
        fun proposal(cph:JsonObject)=job().copy(variants=listOf(v.copy(settings=SettingsPlan(cph=cph,cphOrder=listOf(source,destination)))))
        reject("CPH_FIELD_SHAPE_INVALID",proposal(wrong))
        val fixed=JsonObject(wrong+(destination to JsonObject(wrong.getValue(destination).jsonObject+
            ("static_expression" to JsonArray(listOf(JsonPrimitive(true),wrong.getValue(destination).jsonObject.getValue("static_expression")))))))
        assertEquals(listOf(source,destination),JobCompiler().compile(proposal(fixed),baseline).variants.single().cphOrder)
    }
    @Test fun `a new CPH handler can reuse an observed existing source without copying its definition`() {
        val old=buildJsonObject { putJsonObject("existing-source") { put("enabled",true) } }
        val settings=SettingsPlan(cph=buildJsonObject { putJsonObject("job:demo:dest") { put("enabled",true);put("dynamic_checkbox",true);put("extract_choice_index",2);put("cached_selection","existing-source") } },
            cphOrder=listOf("existing-source","job:demo:dest"))
        val v=job().variants.single()
        val plan=JobCompiler().compile(job().copy(variants=listOf(v.copy(settings=settings))),baseline.copy(cph=old,cphOrder=listOf("existing-source")))
        assertEquals(old["existing-source"],plan.variants.single().cph["existing-source"])
        assertEquals(settings.cphOrder,plan.variants.single().cphOrder)
    }
    @Test fun `merging native CPH options keeps them last after new and existing tabs`() {
        val options=digest("options")
        val old=buildJsonObject {
            putJsonObject("existing-source") { put("enabled",false) }
            putJsonObject("existing-dest") { put("enabled",false);put("dynamic_checkbox",true);put("extract_choice_index",2);put("cached_selection","existing-source") }
            putJsonObject(options) { put("verbosity",3) }
        }
        val settings=SettingsPlan(cph=buildJsonObject {
            putJsonObject("job:demo:new") { put("enabled",false) };put(options,old.getValue(options))
        },cphOrder=listOf("job:demo:new",options))
        val v=job().variants.single()
        val compiled=JobCompiler().compile(job().copy(variants=listOf(v.copy(settings=settings))),baseline.copy(cph=old,cphOrder=old.keys.toList())).variants.single()
        assertEquals(listOf("job:demo:new","existing-source","existing-dest",options),compiled.cphOrder)
        assertEquals(old["existing-dest"],compiled.cph["existing-dest"])
        assertEquals(listOf("job:demo:new",options),settings.cphOrder)
    }
    @Test fun `native options positioning never hides an invalid cache dependency order`() {
        val options=digest("options")
        val settings=SettingsPlan(cph=buildJsonObject {
            putJsonObject(options) { put("verbosity",3) }
            putJsonObject("job:demo:dest") { put("enabled",true);put("dynamic_checkbox",true);put("extract_choice_index",2);put("cached_selection","job:demo:source") }
            putJsonObject("job:demo:source") { put("enabled",false) }
        },cphOrder=listOf(options,"job:demo:dest","job:demo:source"))
        reject("CPH_CACHE_REFERENCE_ORDER",job().copy(variants=listOf(job().variants.single().copy(settings=settings))))
    }
    @Test fun `new Target scope entries preserve unrelated existing include and exclude arrays`() {
        val base=jobJson.parseToJsonElement("""{"project_options":{"sessions":{}},"target":{"scope":{"include":[{"prefix":"http://existing.invalid/","enabled":true}],"exclude":[{"prefix":"http://existing.invalid/private","enabled":true}]}}}""").jsonObject
        val scope=buildJsonObject { putJsonArray("include") { add(buildJsonObject { put("prefix",target.url());put("enabled",true) }) } }
        val v=job().variants.single()
        val plan=JobCompiler().compile(job().copy(variants=listOf(v.copy(settings=SettingsPlan(targetScope=scope)))),baseline.copy(project=base))
        val result=plan.variants.single().project["target"]!!.jsonObject["scope"]!!.jsonObject
        assertEquals(2,result["include"]!!.jsonArray.size);assertEquals(1,result["exclude"]!!.jsonArray.size)
    }
    @Test fun `reused active CPH issuer cannot introduce an unapproved destination`() {
        val old=buildJsonObject { putJsonObject("existing-dynamic") {
            put("enabled",true);put("dynamic_checkbox",true);put("extract_choice_index",0)
            putJsonArray("issuer") { add(false);add("outside.invalid");add(80) }
            put("single_request","GET /login HTTP/1.1\r\nHost: outside.invalid\r\n\r\n")
        } }
        reject("CPH_SOCKET_OUT_OF_SCOPE",job(),baseline.copy(cph=old,cphOrder=old.keys.toList()))
    }
    private fun reusedMacroBaseline(prefix:String):BurpSnapshot {
        val native=buildJsonObject { putJsonObject("project_options") { putJsonObject("sessions") {
            putJsonObject("macros") { putJsonArray("macros") { add(buildJsonObject {
                put("description","existing login");put("serial_number",101)
                putJsonArray("items") { add(buildJsonObject { put("url","http://outside.invalid/login");put("request","GET /login HTTP/1.1\r\nHost: outside.invalid\r\n\r\n");put("response",material.response) }) }
            }) } }
            putJsonObject("session_handling_rules") { putJsonArray("rules") { add(buildJsonObject {
                put("description","existing rule");put("enabled",true);put("url_scope","custom");put("url_scope_advanced_mode",false)
                putJsonArray("include_in_scope") { add(buildJsonObject { put("enabled",true);put("include_subdomains",false);put("prefix",prefix) }) }
                putJsonArray("actions") { add(buildJsonObject { put("type","run_macro");put("enabled",true);put("macro_serial_number",101) }) }
            }) } }
        } } }
        return baseline.copy(project=native)
    }
    @Test fun `referenced inherited macro is included in target scope validation`() {
        reject("OUT_OF_SCOPE",job(),reusedMacroBaseline(target.url()))
    }
    @Test fun `unrelated inherited rule does not unnecessarily broaden the job allowlist`() {
        assertNotNull(JobCompiler().compile(job(),reusedMacroBaseline("http://unrelated.invalid/")))
    }
    @Test fun `native dynamic settings require capability even without binding metadata`() {
        val tab=buildJsonObject { put("enabled",true);put("dynamic_checkbox",true);put("extract_choice_index",0)
            putJsonArray("issuer") { add(false);add(target.host);add(target.port) };put("single_request",raw)
        }
        val v=job().variants.single().copy(settings=SettingsPlan(cph=buildJsonObject { put("job:demo:dynamic",tab) },cphOrder=listOf("job:demo:dynamic")))
        reject("DYNAMIC_CAPABILITY_REQUIRED",job().copy(variants=listOf(v),requiredCapabilities=capabilities-"DYNAMIC_WORKFLOW_VERIFIED"))
    }
    @Test fun `stored verification can use a separate preprocessing rule`() {
        val get="GET /api/items HTTP/1.1\r\nHost: test.invalid:8080\r\n\r\n"
        val view=material.copy(id="view",request=get,requestSha256=digest(get))
        val macro=buildJsonObject { put("description","job:demo:view");put("serial_number",201);putJsonArray("items") {
            add(nativeItem(get,view.response))
        } }
        fun rule(name:String,type:String)=nativeRule(name,JsonArray(listOf(buildJsonObject {
            put("type",type);put("enabled",true);put("macro_serial_number",201);put("update_with_params",true)
            if(type=="run_post_request_macro") { put("pass_back","final_response");put("match_params","all_except") }
            else { put("match_params","specified");put("specified_params",JsonArray(emptyList()));put("invoke_extension_action",false);put("match_cookies","all_except");put("tolerate_url_mismatch",false);put("update_with_cookies",true) }
        })))
        val stored=job().variants.single().copy(id="stored",kind="STORED",verificationSourceId="view",settings=SettingsPlan(macros=JsonArray(listOf(macro)),rules=JsonArray(listOf(rule("pre","run_macro"),rule("stored","run_post_request_macro")))))
        assertNotNull(JobCompiler().compile(job().copy(materials=listOf(material,view),variants=job().variants+stored,storedVerificationSourceIds=listOf("view")),baseline))
    }
    @Test fun `encoded traversal cannot bypass a permitted path prefix`() {
        val e=target.copy(path="/api/%2e%2e/admin");val request="GET ${e.path} HTTP/1.1\r\nHost: test.invalid:8080\r\n\r\n"
        val input=material.copy(endpoint=e,request=request,requestSha256=digest(request))
        val v=job().variants.single().copy(request=RequestPlan(e,request,input.id,input.requestSha256))
        reject("AMBIGUOUS_PATH",job().copy(targetPolicy=listOf(TargetPermit(target.copy(path="/api"),true)),materials=listOf(input),variants=listOf(v)))
    }
    @Test fun `an encoded literal percent in a legitimate path remains supported`() {
        target.copy(path="/api/discount%25.txt").validate()
        assertThrows(JobRejected::class.java) { target.copy(path="/api/%252e%252e/admin").validate() }
    }
    @Test fun `native macro defaults cannot be supplied by a permissive mock instead of the proposal`() {
        val item=buildJsonObject { put("url",target.url());put("request",raw);put("response",material.response) }
        val macro=buildJsonObject { put("description","job:demo:incomplete");put("serial_number",301);put("items",JsonArray(listOf(item))) }
        val v=job().variants.single().copy(settings=SettingsPlan(macros=JsonArray(listOf(macro))))
        reject("MACRO_NATIVE_FIELDS_REQUIRED",job().copy(variants=listOf(v)))
    }
    @Test fun `observed macro request can be explicitly prepared with dynamic path and CPH trigger`() {
        val e=target.copy(path="/api/items/17")
        val get="GET ${e.path} HTTP/1.1\r\nHost: test.invalid:8080\r\n\r\n"
        val observed=material.copy(id="view",endpoint=e,request=get,requestSha256=digest(get))
        val prepared=get.replace("/items/17","/items/{{id}}").replace("\r\n\r\n","\r\nX-cphtarget: view-flow\r\n\r\n")
        val preparedEndpoint=e.copy(path="/api/items/{{id}}")
        val macro=buildJsonObject { put("description","job:demo:view");put("serial_number",302);put("items",JsonArray(listOf(nativeItem(prepared,observed.response,preparedEndpoint.url())))) }
        val preparation=MacroPreparation(302,0,observed.id,observed.requestSha256,listOf(LiteralSubstitution("/items/17","/items/{{id}}")),"view-flow")
        val stored=job().variants.single().copy(id="stored",kind="STORED",verificationSourceId=observed.id,settings=SettingsPlan(
            macros=JsonArray(listOf(macro)),macroPreparations=listOf(preparation),rules=JsonArray(listOf(nativeRule("stored",JsonArray(listOf(buildJsonObject {
                put("type","run_post_request_macro");put("enabled",true);put("macro_serial_number",302);put("pass_back","final_response");put("match_params","all_except");put("update_with_params",true)
            })))))))
        val proposal=job().copy(targetPolicy=listOf(TargetPermit(target,true)),materials=listOf(material,observed),variants=job().variants+stored,storedVerificationSourceIds=listOf(observed.id))
        val plan=JobCompiler().compile(proposal,baseline)
        assertTrue(plan.variants.last().project.toString().contains("{{id}}"))
        reject("MACRO_NOT_OBSERVED",proposal.copy(variants=job().variants+stored.copy(settings=stored.settings.copy(macroPreparations=emptyList()))))
        val changedPreparation=preparation.copy(sourceRequestSha256="changed")
        val changedVariant=stored.copy(settings=stored.settings.copy(macroPreparations=listOf(changedPreparation)))
        reject("MACRO_PREPARATION_SOURCE_CHANGED",proposal.copy(variants=job().variants+changedVariant))
    }
}
