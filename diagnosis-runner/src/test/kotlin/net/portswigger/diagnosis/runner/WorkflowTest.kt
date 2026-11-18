package net.portswigger.diagnosis.runner

import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import java.nio.file.Files
import java.nio.file.Path
import java.time.*

class WorkflowTest {
    private fun retainedAuthenticationJob():JobProposal {
        val j=storedJob();val stored=j.variants.last();val template=stored.settings.rules.single().jsonObject
        val auth=JsonObject(template+mapOf("description" to JsonPrimitive("job:sample:authentication"),"actions" to JsonArray(listOf(buildJsonObject {
            put("type","validate_session");put("enabled",true);put("validation_action","run_macro")
            put("macro_serial_number",9007199254740993L);put("stop_if_valid",false);put("action","run_macro")
            putJsonObject("run_macro_action") { put("macro_serial_number",9007199254740993L);put("update_with_params",false);put("update_with_cookies",true) }
        }))))
        val cph=JsonObject(stored.settings.cph+(digest("options") to buildJsonObject { put("chkbox_scanner",true);put("chkbox_extender",true) }))
        val reflection=j.variants.first().copy(settings=stored.settings.copy(rules=JsonArray(listOf(auth)),cph=cph,cphOrder=cph.keys.toList()))
        return j.copy(variants=listOf(reflection),storedVerificationSourceIds=emptyList(),
            authenticationRetention=AuthenticationRetention(listOf("job:sample:authentication"),listOf("job:sample:token")))
    }
    @Test fun `preparation execution and next job reuse keep authentication definitions in Burp with target selected states`():Unit=store().use { s ->
        val port=retentionPort();val worker=GuardedWorker(port,s,HumanApprover { _,_,_ -> "human" })
        val job=retainedAuthenticationJob();ready(worker,job)
        val retained=worker.plan("execution").restorationBaseline!!
        fun rules()=port.current.project["project_options"]!!.jsonObject["sessions"]!!.jsonObject["session_handling_rules"]!!.jsonObject["rules"]!!.jsonArray
        assertEquals(JsonPrimitive(false),rules().single().jsonObject["enabled"])
        assertEquals(JsonPrimitive(false),port.current.cph["job:sample:token"]!!.jsonObject["enabled"])
        start(worker);assertEquals(JsonPrimitive(true),rules().single().jsonObject["enabled"])
        val live=port.current;val beforeDraft=port.probes
        assertEquals(retained,worker.draftBaseline("execution"))
        assertEquals(live,port.current);assertEquals(beforeDraft,port.probes)
        assertEquals("EXECUTION_FINISHED",worker.poll("execution").state)
        assertEquals(retained.project,port.current.project)
        assertEquals(JsonPrimitive(false),rules().single().jsonObject["enabled"])
        val base=job.variants.single()
        val states=AuthenticationStates(mapOf("job:sample:authentication" to true),mapOf("job:sample:token" to true),listOf("Scanner","Extender"))
        val next=job.copy(jobId="next",authenticationRetention=null,variants=listOf(base.copy(settings=SettingsPlan(authenticationStates=states))))
        worker.register("next",next);worker.approve("next",ApprovalStage.PREPARATION);worker.prepare("next")
        assertEquals(retained.project,port.current.project)
        assertEquals(1,port.starts);assertEquals(11,port.probes)
        assertEquals(JsonPrimitive(false),port.current.cph["job:sample:token"]!!.jsonObject["enabled"])
    }
    @Test fun `approved stop recovery after validation retains authentication after worker restart without replay`():Unit=store().use { s ->
        val port=retentionPort();val worker=GuardedWorker(port,s,HumanApprover { _,_,_ -> "human" })
        ready(worker,retainedAuthenticationJob());val baseline=worker.plan("execution").restorationBaseline!!
        start(worker);port.state="cancelled"
        val probes=port.probes
        val restarted=GuardedWorker(port,s,HumanApprover { _,_,_ -> "human" })
        assertEquals("FAILED_RECONCILED",restarted.recover("execution","operator confirmed cancellation").state)
        assertEquals(baseline.project,port.current.project);assertEquals(probes,port.probes)
        assertEquals(JsonPrimitive(false),port.current.cph["job:sample:token"]!!.jsonObject["enabled"])
    }
    @Test fun `failed preparation recovers original settings without promoting unvalidated authentication`():Unit=store().use { s ->
        val port=retentionPort();val worker=GuardedWorker(port,s,HumanApprover { _,_,_ -> "human" });val original=port.current
        worker.register("execution",retainedAuthenticationJob());worker.approve("execution",ApprovalStage.PREPARATION);port.failApply=true
        assertThrows(Exception::class.java) { worker.prepare("execution") };port.failApply=false
        assertNull(s.get("validation:execution"))
        worker.recover("execution","operator confirmed no audit and quiescence")
        assertEquals(original.project,port.current.project)
        assertEquals(JsonPrimitive(false),port.current.cph["job:sample:token"]!!.jsonObject["enabled"])
        assertEquals(0,port.probes);assertEquals(0,port.starts)
    }
    @Test fun `saved unsafe CPH scope is refused before preparation or a new Scan can change settings`():Unit=store().use { s ->
        val port=retentionPort();val source=retainedAuthenticationJob()
        port.current=JobCompiler().compile(source,port.current).restorationBaseline!!
        val states=AuthenticationStates(mapOf("job:sample:authentication" to true),mapOf("job:sample:token" to true),listOf("Scanner","Extender"))
        val next=source.copy(jobId="next",authenticationRetention=null,variants=listOf(source.variants.single().copy(settings=SettingsPlan(authenticationStates=states))))
        val worker=GuardedWorker(port,s,HumanApprover { _,_,_ -> "human" })
        val plan=worker.register("execution",next);worker.approve("execution",ApprovalStage.PREPARATION)
        val variant=plan.variants.single()
        val old=variant.copy(variant=variant.variant.copy(settings=variant.variant.settings.copy(authenticationStates=states.copy(cphTools=emptyList()))))
        s.put("plan:execution",jobJson.encodeToJsonElement(plan.copy(variants=listOf(old)))) // synthetic legacy saved plan only
        val before=Triple(port.applies,port.probes,port.starts)
        assertEquals("CPH_TOOL_SCOPE_REQUIRED",assertThrows(JobRejected::class.java) { worker.prepare("execution") }.code)
        assertEquals(before,Triple(port.applies,port.probes,port.starts))
        s.put("plan:execution",jobJson.encodeToJsonElement(plan));worker.prepare("execution");worker.approve("execution",ApprovalStage.EXECUTION)
        val changed=JsonObject(variant.cph+(digest("options") to JsonObject(variant.cph[digest("options")]!!.jsonObject+("chkbox_scanner" to JsonPrimitive(false)))))
        s.put("plan:execution",jobJson.encodeToJsonElement(plan.copy(variants=listOf(variant.copy(cph=changed)))))
        val after=Triple(port.applies,port.probes,port.starts)
        assertEquals("CPH_TOOL_SCOPE_DISABLED",assertThrows(JobRejected::class.java) { start(worker) }.code)
        assertEquals(after,Triple(port.applies,port.probes,port.starts))
    }
    private fun maintenanceApprover(onReview:()->Unit={}):HumanApprover=object:HumanApprover {
        override fun review(plan:CompiledPlan,stage:ApprovalStage,report:ValidationReport?)="human"
        override fun reviewRetirement(plan:CompiledPlan,record:ExecutionRecord,evidenceRef:String,currentDigest:String):String {
            assertTrue(currentDigest.matches(Regex("[0-9a-f]{64}")));onReview();return "human"
        }
    }
    @Test fun `retired legacy owner preserves unknown results and current settings then allows fresh preparation`():Unit=store().use { s ->
        val p=MockPort();val old=GuardedWorker(p,s,maintenanceApprover());ready(old);start(old)
        p.pollThrows=true;p.retirementReady=true
        p.current=p.current.copy(project=buildJsonObject { put("current-project","preserve-me") })
        val before=p.current;val sends=p.probes;val starts=p.starts;val restores=p.restores
        val replacement=GuardedWorker(p,s,maintenanceApprover())
        assertEquals(JsonPrimitive("execution"),replacement.contextStatus()["ownerExecutionId"])
        val retired=replacement.retire("execution","operator checked current Dashboard and detached Project")
        assertEquals("RETIRED_UNVERIFIED",retired.state);assertEquals("INCOMPLETE",retired.diagnosisState)
        assertEquals("NOT_RESTORED_OLD_CONTEXT_RETIRED",retired.cleanupState)
        assertEquals(before,p.current);assertEquals(sends,p.probes);assertEquals(starts,p.starts);assertEquals(restores,p.restores)
        val proof=s.get("retirement:execution")!!.jsonObject
        assertEquals(JsonPrimitive(false),proof["oldTerminationVerified"]);assertEquals(JsonPrimitive(false),proof["oldSettingsRestored"])
        assertEquals("RUNNING",jobJson.decodeFromJsonElement<ExecutionRecord>(proof["previous"]!!).state)
        assertEquals(JsonNull,replacement.contextStatus()["ownerExecutionId"])
        replacement.register("fresh",job().copy(jobId="fresh"));replacement.approve("fresh",ApprovalStage.PREPARATION);replacement.prepare("fresh")
        assertEquals("VALIDATED",replacement.record("fresh").state)
        replacement.retire("execution","same operation after completion")
        replacement.revoke("execution");assertEquals("RETIRED_UNVERIFIED",replacement.record("execution").state)
        assertEquals("RETIRED_EXECUTION_INCOMPLETE",assertThrows(JobRejected::class.java) { replacement.recover("execution","old proof") }.code)
    }
    @Test fun `retirement requires explicit maintenance review even when old generic approver accepts`():Unit=store().use { s ->
        val p=MockPort();val old=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" });ready(old);start(old)
        p.retirementReady=true;p.pollThrows=true
        val replacement=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" })
        assertEquals("HUMAN_DENIED",assertThrows(JobRejected::class.java) { replacement.retire("execution","operator evidence") }.code)
        assertEquals(JsonPrimitive("execution"),s.get("active"));assertNull(s.get("retirement:execution"));assertEquals(1,p.starts)
    }
    @Test fun `retirement refuses live epoch present or unknown handles helper traffic and other owners`():Unit=store().use { s ->
        val p=MockPort();val old=GuardedWorker(p,s,maintenanceApprover());ready(old);start(old)
        assertEquals("LIVE_CONTEXT_CANNOT_RETIRE",assertThrows(JobRejected::class.java) { old.retire("execution","proof") }.code)
        val replacement=GuardedWorker(p,s,maintenanceApprover())
        assertEquals("CURRENT_AUDIT_ACTIVITY_OR_HANDLE_PRESENT",assertThrows(JobRejected::class.java) { replacement.retire("execution","proof") }.code)
        p.retirementReady=true;p.recoveryReady=false
        assertEquals("HELPER_TRAFFIC_NOT_QUIESCENT",assertThrows(JobRejected::class.java) { replacement.retire("execution","proof") }.code)
        p.recoveryReady=true;s.put("active",JsonPrimitive("other"))
        assertEquals("EXECUTION_DOES_NOT_OWN_CONTEXT",assertThrows(JobRejected::class.java) { replacement.retire("execution","proof") }.code)
        assertEquals(JsonPrimitive("other"),s.get("active"));assertNull(s.get("retirement:execution"))
    }
    @Test fun `retirement binds the exact current snapshot across human review`():Unit=store().use { s ->
        val p=MockPort();val old=GuardedWorker(p,s,maintenanceApprover());ready(old);start(old);p.retirementReady=true
        val replacement=GuardedWorker(p,s,maintenanceApprover { p.current=p.current.copy(project=buildJsonObject { put("manual-change",true) }) })
        assertEquals("CURRENT_CONTEXT_CHANGED",assertThrows(JobRejected::class.java) { replacement.retire("execution","proof") }.code)
        assertEquals(JsonPrimitive("execution"),s.get("active"));assertNull(s.get("retirement:execution"))
    }
    @Test fun `disabled owned definitions renamed serials and nested rule references prohibit retirement`():Unit=store().use { s ->
        val p=MockPort();val old=GuardedWorker(p,s,maintenanceApprover())
        validated(old,storedJob());old.approve("execution",ApprovalStage.EXECUTION);start(old)
        val plan=old.plan("execution");val baseline=plan.baseline
        val macro=plan.variants.last().variant.settings.macros.single().jsonObject
        val renamed=JsonObject(macro+("description" to JsonPrimitive("renamed")))
        val nested=buildJsonObject { put("description","unrelated");putJsonArray("actions") { add(buildJsonObject {
            putJsonObject("run_macro_action") { put("macro_serial_number",macro.getValue("serial_number")) }
        }) } }
        fun snapshot(macros:JsonArray=JsonArray(emptyList()),rules:JsonArray=JsonArray(emptyList()))=baseline.copy(project=buildJsonObject {
            putJsonObject("project_options") { putJsonObject("sessions") {
                putJsonObject("macros") { put("macros",macros) };putJsonObject("session_handling_rules") { put("rules",rules) }
            } }
        })
        listOf(snapshot(JsonArray(listOf(macro))),snapshot(JsonArray(listOf(renamed))),snapshot(rules=JsonArray(listOf(nested))),
            baseline.copy(cph=buildJsonObject { putJsonObject("job:sample:disabled") { put("enabled",false) } }),
            baseline.copy(cph=buildJsonObject { putJsonObject("other") { put("cached_selection","job:sample:missing") } })).forEach { current ->
            assertEquals("JOB_SETTINGS_STILL_PRESENT",assertThrows(JobRejected::class.java) { checkRetirementSettingsAbsent(plan,current) }.code)
        }
        checkRetirementSettingsAbsent(plan,baseline)
    }
    @Test fun `active and failed apply do not retain the preparation restored label`():Unit=store().use { s ->
        val p=MockPort();val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" })
        ready(w);start(w)
        assertEquals("SETTINGS_APPLIED",w.record("execution").cleanupState)
        assertEquals("EXECUTION_FINISHED",w.poll("execution").state)
        assertEquals("SETTINGS_RESTORED_BUSINESS_REVIEW_REQUIRED",w.record("execution").cleanupState)
    }
    @Test fun `failed execution apply has unverified cleanup until recovery`():Unit=store().use { s ->
        val p=MockPort();val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" })
        ready(w);p.failApply=true
        assertThrows(Exception::class.java) { start(w) }
        assertEquals("SETTINGS_APPLY_OUTCOME_PENDING",w.record("execution").cleanupState)
        assertEquals("RECOVERY_REQUIRED",w.record("execution").state)
        assertEquals(0,p.starts)
    }
    @Test fun `long approval cannot bypass validation freshness for the next variant`():Unit=store().use { s ->
        val p=MockPort();val clock=TestClock();val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" },clock)
        validated(w,storedJob().copy(executionApprovalMaxAgeSeconds=14400))
        w.approve("execution",ApprovalStage.EXECUTION);start(w);clock.seconds+=7200
        assertEquals("EXECUTION_APPROVED",w.poll("execution").state)
        assertEquals("VALIDATION_EXPIRED",assertThrows(JobRejected::class.java) { start(w) }.code)
        assertEquals(1,p.starts)
    }
    @Test fun `nested recovery native omission survives the guarded workflow`():Unit=store().use { s ->
        val p=MockPort();p.omitEmptySpecifiedParams=true
        p.current=p.current.copy(project=jobJson.parseToJsonElement("""{"project_options":{"sessions":{"session_handling_rules":{"rules":[{"enabled":false,"actions":[{"type":"validate_session","action":"run_macro","run_macro_action":{"match_params":"specified","specified_params":[],"update_with_params":false}}]}]}}}}""").jsonObject)
        val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" })
        ready(w);start(w)
        assertEquals("EXECUTION_FINISHED",w.poll("execution").state)
        assertEquals(6,p.probes);assertEquals(2,p.restores)
    }
    @Test fun `reviewed long approval keeps same audit valid beyond one hour but not after expiry`():Unit=store().use { s ->
        val p=MockPort();val clock=TestClock();val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" },clock)
        validated(w,job().copy(executionApprovalMaxAgeSeconds=14400))
        w.approve("execution",ApprovalStage.EXECUTION);start(w)
        p.completed=false;p.state="scanning";clock.seconds+=7200
        assertEquals("RUNNING",w.poll("execution").state)
        assertEquals(1,p.starts);assertEquals(5,p.probes)
        clock.seconds+=7200
        assertEquals("CONTROL_REQUIRED",w.poll("execution").state)
        assertEquals(1,p.starts);assertEquals(5,p.probes)
        w.renewContinuation("execution")
        val approval=jobJson.decodeFromJsonElement<ApprovalRecord>(s.get("approval:execution:EXECUTION")!!)
        assertEquals(14400L,approval.expiresAt-approval.approvedAt)
        clock.seconds+=7200
        assertEquals("RUNNING",w.poll("execution").state)
        w.revoke("execution")
        assertEquals("CONTROL_REQUIRED",w.record("execution").state)
        assertEquals(1,p.starts);assertEquals(5,p.probes)
    }
    private val caps=setOf("SCANNER_WORKFLOW","EXCLUSIVE_CONTEXT","DYNAMIC_WORKFLOW_VERIFIED")
    private val target=Endpoint("http","fixture.invalid",8080,"/items")
    private val raw="POST /items HTTP/1.1\r\nHost: fixture.invalid:8080\r\nContent-Length: 10\r\n\r\nname=probe"
    private val response="HTTP/1.1 200 OK\r\n\r\ncreated"
    private fun job(dynamic:Boolean=false):JobProposal {
        val source=HttpMaterial("observed",target,raw,response,digest(raw),digest(response))
        val cph=if(dynamic) buildJsonObject { putJsonObject("job:sample:token") {
            put("enabled",true);put("dynamic_checkbox",true);put("extract_choice_index",0);put("single_response","initial")
            putJsonArray("issuer") { add(false);add(target.host);add(target.port) };put("single_request",raw)
        } } else JsonObject(emptyMap())
        return JobProposal(jobId="sample",revision=1,objective="Diagnose observed request",targetPolicy=listOf(TargetPermit(target)),materials=listOf(source),
            session=SessionPlan(true,"OMIT","Authentication is performed for each diagnostic attempt by the reviewed workflow","tester"),
            dynamicBindings=if(dynamic) listOf(DynamicBinding("token","observed","Authorization","regex","header","before request","reject")) else emptyList(),
            variants=listOf(ScanVariant("reflection","REFLECTION",request=RequestPlan(target,raw,source.id,source.requestSha256),settings=SettingsPlan(cph=cph,cphOrder=cph.keys.toList()))),
            requiredCapabilities=caps,cleanupPolicy="Only records owned by this execution")
    }
    private fun storedJob():JobProposal {
        val j=job(true)
        val get="GET /items HTTP/1.1\r\nHost: fixture.invalid:8080\r\n\r\n"
        val view=HttpMaterial("view",target,get,"HTTP/1.1 200 OK\r\n\r\nsaved item",digest(get),digest("HTTP/1.1 200 OK\r\n\r\nsaved item"))
        val macro=buildJsonObject {
            put("description","job:sample:view");put("serial_number",9007199254740993L)
            putJsonArray("items") { add(buildJsonObject {
                put("url",target.url());put("request",get);put("response",view.response);put("method","GET");put("status_code",200)
                put("accept_response_cookies",true);put("use_request_cookies",true);put("custom_parameters",JsonArray(emptyList()));put("request_parameters",JsonArray(emptyList()))
            }) }
        }
        val rule=buildJsonObject {
            put("description","job:sample:stored-rule");put("enabled",true);put("exclude_from_scope",JsonArray(emptyList()));put("named_params",JsonArray(emptyList()));put("restrict_scope_to_named_params",false)
            put("tools_scope",JsonArray(listOf(JsonPrimitive("Scanner"),JsonPrimitive("Extensions"))));put("url_scope","custom");put("url_scope_advanced_mode",false)
            putJsonArray("include_in_scope") { add(buildJsonObject { put("enabled",true);put("include_subdomains",false);put("prefix",target.url()) }) }
            putJsonArray("actions") {
            add(buildJsonObject { put("type","run_post_request_macro");put("enabled",true);put("macro_serial_number",9007199254740993L);put("pass_back","final_response");put("match_params","all_except");put("update_with_params",true) })
        } }
        val stored=j.variants.single().copy(id="stored-list",kind="STORED",verificationSourceId="view",
            settings=j.variants.single().settings.copy(macros=JsonArray(listOf(macro)),rules=JsonArray(listOf(rule))))
        return j.copy(materials=j.materials+view,variants=j.variants+stored,storedVerificationSourceIds=listOf("view"))
    }
    private class TestClock(var seconds:Long=1000):Clock() {
        override fun getZone():ZoneId=ZoneOffset.UTC
        override fun withZone(zone:ZoneId):Clock=this
        override fun instant():Instant=Instant.ofEpochSecond(seconds)
    }
    private fun retentionPort()=MockPort().also { port ->
        port.current=port.current.copy(cph=buildJsonObject { putJsonObject(digest("options")) { put("chkbox_scanner",false);put("chkbox_extender",true) } },cphOrder=listOf(digest("options")))
        port.checkAuthenticationTools=true
    }
    private inner class MockPort:BurpExecutionPort {
        var current=BurpSnapshot("burp-1",jobJson.parseToJsonElement("""{"project_options":{"sessions":{}},"proxy":{"preserve":true}}""").jsonObject,JsonObject(emptyMap()),emptyList(),caps)
        var applies=0;var probes=0;var starts=0;var restores=0;var polls=0
        var failApply=false;var failStart=false;var pollThrows=false;var completed=true;var collectComplete=true;var changedInput=false
        var state="finished"
        var onCollect:()->Unit = {}
        var quiescent=true
        var recoveryReady=true
        var retirementReady=false
        override fun retirementReadiness(auditId:String)=retirementReady
        var savedTerminalProof=false
        override fun recoveryReadiness(endpoints:List<Endpoint>)=recoveryReady
        var omitEmptySpecifiedParams=false
        var expectedScannerLimit:Int?=null
        var checkAuthenticationTools=false
        private fun checkScannerLimit() {
            if(checkAuthenticationTools) {
                val options=current.cph[digest("options")]!!.jsonObject
                assertEquals(JsonPrimitive(true),options["chkbox_scanner"])
                assertEquals(JsonPrimitive(true),options["chkbox_extender"])
            }
            expectedScannerLimit?.let { limit ->
            val pool=current.project["project_options"]!!.jsonObject["resource_pools"]!!.jsonObject["default_resource_pool"]!!.jsonObject
            assertEquals(limit,pool["concurrent_request_limit"]!!.jsonPrimitive.int)
            assertTrue(pool["concurrent_request_limit_enabled"]!!.jsonPrimitive.boolean)
        } }
        override fun snapshot()=current
        override fun verifyInputs(job:JobProposal) { requireJob(!changedInput,"APPROVED_INPUT_CHANGED") }
        override fun apply(variant:CompiledVariant) {
            applies++;current=current.copy(project=variant.project,cph=variant.cph,cphOrder=variant.cphOrder)
            if(omitEmptySpecifiedParams) current=current.copy(project=projectDefinitions(current.project))
            if(failApply) throw IllegalStateException("simulated failure after native settings changed")
        }
        override fun restore(baseline:BurpSnapshot,ownedCphNames:Set<String>) {
            restores++
            val residue=current.cph.filterKeys { it !in baseline.cph }.mapValues { (_,v) -> JsonObject(v.jsonObject+("enabled" to JsonPrimitive(false))) }
            current=baseline.copy(cph=JsonObject(baseline.cph+residue),cphOrder=baseline.cphOrder+residue.keys)
            if(omitEmptySpecifiedParams) current=current.copy(project=projectDefinitions(current.project))
        }
        override fun probe(variant:ScanVariant,branch:String):Pair<String,JsonObject> {
            checkScannerLimit()
            probes++
            current=current.copy(cph=JsonObject(current.cph.mapValues { (name,v) ->
                if(name==digest("options")) v else JsonObject(v.jsonObject+("single_response" to JsonPrimitive("fresh-token-$probes")))
            }))
            return response to buildJsonObject { put("captureId","mock-capture");put("droppedEntries",0);put("captureErrors",0);put("branch",branch) }
        }
        override fun start(variant:ScanVariant):JsonObject {
            checkScannerLimit()
            starts++;if(failStart) throw IllegalStateException("acceptance is unknown")
            return buildJsonObject { put("status","started");put("auditId","audit-$starts") }
        }
        override fun poll(auditId:String):JsonObject {
            polls++;if(pollThrows) throw IllegalStateException("observation temporarily unavailable")
            return buildJsonObject { put("completed",completed);put("auditStatusMessage",state);put("auditIssueCount",JsonNull) }
        }
        override fun collect(auditId:String,payloadRunId:String?)=buildJsonObject {
            onCollect()
            if(savedTerminalProof) {
                put("auditId",auditId);put("native",poll(auditId))
                put("loggerStatus",buildJsonObject { put("droppedEntries",0);put("captureErrors",0) })
                put("loggerPages",JsonArray(emptyList()))
            }
            put("quiescent",quiescent)
            put("complete",collectComplete);put("auditIssueCount",JsonNull);put("issueAttribution","SITE_MAP_NOT_AUDIT_SPECIFIC");put("diagnosisCompleted",false)
        }
    }
    private fun store():JobStore {
        val temp=Path.of("..","..","temp").toAbsolutePath().normalize();Files.createDirectories(temp)
        return JobStore(Files.createTempDirectory(temp,"diagnosis-mock-"))
    }
    private fun validated(w:GuardedWorker,j:JobProposal=job()) {
        w.register("execution",j);w.approve("execution",ApprovalStage.PREPARATION);w.prepare("execution")
    }
    private fun ready(w:GuardedWorker,j:JobProposal=job()) { validated(w,j);w.approve("execution",ApprovalStage.EXECUTION) }
    private fun start(w:GuardedWorker):ExecutionRecord { val r=w.record("execution");return w.start("execution",r.fence,w.epoch) }

    private fun serialJob():JobProposal {
        val j=job();return j.copy(variants=j.variants.map { it.copy(settings=it.settings.copy(serialScannerRequests=true)) })
    }
    private fun MockPort.installPool() {
        val root=current.project["project_options"]!!.jsonObject
        current=current.copy(project=JsonObject(current.project+("project_options" to JsonObject(root+("resource_pools" to
            jobJson.parseToJsonElement("""{"default_resource_pool":{"concurrent_request_limit_enabled":true,"concurrent_request_limit":10,"throttle_interval_millis":37},"custom_resource_pools":[]}"""))))))
    }
    @Test fun `serial scanner preparation audit and control use one and restore the entire original pool`():Unit=store().use { s ->
        val p=MockPort();p.installPool();val original=p.current.project;p.expectedScannerLimit=1
        val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" })
        validated(w,serialJob());assertEquals(original,p.current.project);assertEquals(5,p.probes)
        w.approve("execution",ApprovalStage.EXECUTION);start(w)
        assertEquals("EXECUTION_FINISHED",w.poll("execution").state)
        assertEquals(original,p.current.project);assertEquals(6,p.probes);assertEquals(1,p.starts)
    }
    @Test fun `manual pool edits after validation refuse a new audit instead of overwriting the operator`():Unit=store().use { s ->
        val p=MockPort();p.installPool();val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" })
        ready(w,serialJob());val root=p.current.project["project_options"]!!.jsonObject
        p.current=p.current.copy(project=JsonObject(p.current.project+("project_options" to JsonObject(root+("resource_pools" to buildJsonObject { put("operatorEdit",true) })))))
        val modified=p.current.project
        assertEquals("PROJECT_SETTINGS_CHANGED",assertThrows(JobRejected::class.java) { start(w) }.code)
        assertEquals(modified,p.current.project);assertEquals(0,p.starts)
    }
    @Test fun `serial pool recovery restores a partial apply without sending any diagnostic traffic`():Unit=store().use { s ->
        val p=MockPort();p.installPool();val original=p.current.project
        val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" })
        w.register("execution",serialJob());w.approve("execution",ApprovalStage.PREPARATION);p.failApply=true
        assertThrows(Exception::class.java) { w.prepare("execution") }
        assertEquals("RECOVERY_REQUIRED",w.record("execution").state)
        assertEquals("FAILED_RECONCILED",w.recover("execution","failed apply before any probe or audit").state)
        assertEquals(original,p.current.project);assertEquals(0,p.probes);assertEquals(0,p.starts);assertEquals(1,p.restores)
    }
    @Test fun `serial pool recovery after cancellation rejects an unrelated throttle edit`():Unit=store().use { s ->
        val p=MockPort();p.installPool();val original=p.current.project
        val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" });ready(w,serialJob());start(w)
        p.completed=false;p.state="cancelled";val approved=p.current.project
        val r=approved["project_options"]!!.jsonObject;val pools=r["resource_pools"]!!.jsonObject
        val pool=JsonObject(pools["default_resource_pool"]!!.jsonObject+("throttle_interval_millis" to JsonPrimitive(99)))
        p.current=p.current.copy(project=JsonObject(approved+("project_options" to JsonObject(r+("resource_pools" to JsonObject(pools+("default_resource_pool" to pool)))))))
        val modified=p.current.project;val sends=p.probes;val starts=p.starts;val restores=p.restores
        assertThrows(JobRejected::class.java) { w.recover("execution","cancelled but manually edited") }
        assertEquals(modified,p.current.project);assertEquals(restores,p.restores)
        p.current=p.current.copy(project=approved)
        assertEquals("FAILED_RECONCILED",w.recover("execution","same cancelled audit with approved pool").state)
        assertEquals(original,p.current.project);assertEquals(sends,p.probes);assertEquals(starts,p.starts)
    }

    @Test fun `MCP recovery restores cancelled job without any target replay and is idempotent`():Unit=store().use { s ->
        val p=MockPort();val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" })
        ready(w,job(true));start(w);val probes=p.probes;val starts=p.starts;val restores=p.restores
        p.completed=false;p.state="scanning"
        assertEquals("NATIVE_TERMINATION_UNPROVEN",assertThrows(JobRejected::class.java) { w.recover("execution","cancel evidence") }.code)
        assertEquals(restores,p.restores)
        p.state="cancelled"
        val recovered=w.recover("execution","native cancelled audit-1")
        assertEquals("FAILED_RECONCILED",recovered.state);assertEquals(probes,p.probes);assertEquals(starts,p.starts)
        assertEquals(restores+1,p.restores);assertEquals(JsonNull,s.get("active"))
        w.recover("execution","same terminal execution");assertEquals(restores+1,p.restores)
        assertEquals("SETTINGS_RESTORED_BUSINESS_REVIEW_REQUIRED",recovered.cleanupState)
    }
    @Test fun `recovery refuses unfinished helpers and unrelated project edits`():Unit=store().use { s ->
        val p=MockPort();val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" })
        ready(w);start(w);p.state="cancelled";p.completed=false;val before=p.restores
        p.recoveryReady=false
        assertEquals("HELPER_TRAFFIC_NOT_QUIESCENT",assertThrows(JobRejected::class.java) { w.recover("execution","cancelled") }.code)
        p.recoveryReady=true
        p.current=p.current.copy(project=JsonObject(p.current.project+("proxy" to buildJsonObject { put("preserve",false) })))
        assertEquals("UNRELATED_PROJECT_SETTINGS_CHANGED",assertThrows(JobRejected::class.java) { w.recover("execution","cancelled") }.code)
        assertEquals(before,p.restores)
    }
    @Test fun `recovery handles owned partial apply without manual config imports`():Unit=store().use { s ->
        val p=MockPort();val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" })
        w.register("execution",job(true));w.approve("execution",ApprovalStage.PREPARATION);p.failApply=true
        assertThrows(Exception::class.java) { w.prepare("execution") }
        assertEquals("RECOVERY_REQUIRED",w.record("execution").state)
        assertEquals("FAILED_RECONCILED",w.recover("execution","apply failed before sends").state)
        assertEquals(0,p.probes);assertEquals(0,p.starts)
    }
    @Test fun `installation recovery uses committed cancelled proof after handle loss without replay`():Unit=store().use { s ->
        val p=MockPort();val old=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" })
        ready(old);start(old);p.state="cancelled";p.completed=false;p.savedTerminalProof=true
        old.capturePartialResults("execution")
        val replacement=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" });p.pollThrows=true
        val count=p.probes
        assertEquals("FAILED_RECONCILED",replacement.recover("execution","persisted terminal evidence").state)
        assertEquals(count,p.probes);assertEquals(1,p.starts)
    }
    @Test fun `handle loss without durable terminal evidence refuses automatic recovery`():Unit=store().use { s ->
        val p=MockPort();val old=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" })
        ready(old);start(old);p.pollThrows=true
        val replacement=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" })
        assertEquals("NATIVE_TERMINATION_UNPROVEN",assertThrows(JobRejected::class.java) { replacement.recover("execution","chat says stopped") }.code)
    }
    @Test fun `recovery never releases another executions ownership or overwrites an unrelated CPH tab`():Unit=store().use { s ->
        val p=MockPort();val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" })
        ready(w);start(w);p.state="cancelled";p.completed=false
        val restores=p.restores;val probes=p.probes
        s.put("active",JsonPrimitive("another-execution"))
        assertEquals("ANOTHER_EXECUTION_OWNS_CONTEXT",assertThrows(JobRejected::class.java) { w.recover("execution","cancelled") }.code)
        assertEquals(JsonPrimitive("another-execution"),s.get("active"))
        s.put("active",JsonPrimitive("execution"))
        p.current=p.current.copy(cph=buildJsonObject { putJsonObject("unrelated-tab") { put("enabled",false) } },cphOrder=listOf("unrelated-tab"))
        assertEquals("UNOWNED_CPH_TAB_DURING_RECOVERY",assertThrows(JobRejected::class.java) { w.recover("execution","cancelled") }.code)
        assertEquals(restores,p.restores);assertEquals(probes,p.probes);assertEquals(1,p.starts)
    }
    @Test fun `corrupted saved termination cannot authorize recovery after handle loss`():Unit=store().use { s ->
        val p=MockPort();val old=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" })
        ready(old);start(old);p.state="cancelled";p.completed=false;p.savedTerminalProof=true
        old.capturePartialResults("execution")
        val reference=s.get("result-index:execution")!!.jsonArray.last().jsonObject["key"]!!.jsonPrimitive.content
        s.put(reference,JsonObject(s.get(reference)!!.jsonObject+("tampered" to JsonPrimitive(true))))
        val replacement=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" });p.pollThrows=true
        val restores=p.restores
        assertEquals("NATIVE_TERMINATION_UNPROVEN",assertThrows(JobRejected::class.java) { replacement.recover("execution","untrusted proof") }.code)
        assertEquals(restores,p.restores);assertEquals(1,p.starts)
    }

    @Test fun `native empty parameter omission is accepted through preparation execution and restore`():Unit=store().use { s ->
        val p=MockPort();p.omitEmptySpecifiedParams=true
        val project=jobJson.parseToJsonElement("""{"project_options":{"sessions":{"session_handling_rules":{"rules":[{"enabled":false,"actions":[{"type":"run_macro","match_params":"specified","specified_params":[]}]}]}}}}""").jsonObject
        p.current=p.current.copy(project=project)
        val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" })
        ready(w);start(w)
        assertEquals("EXECUTION_FINISHED",w.poll("execution").state)
        assertEquals(6,p.probes);assertEquals(2,p.restores)
    }

    @Test fun `unapproved proposal and auto-allowed host cannot cause side effects`():Unit=store().use { s ->
        val p=MockPort();val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" })
        w.register("execution",job())
        assertThrows(JobRejected::class.java) { w.prepare("execution") }
        assertThrows(JobRejected::class.java) { start(w) }
        assertEquals(0,p.applies+p.probes+p.starts)
    }
    @Test fun `human denial leaves preparation unapplied`():Unit=store().use { s ->
        val p=MockPort();val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> null })
        w.register("execution",job());assertThrows(JobRejected::class.java) { w.approve("execution",ApprovalStage.PREPARATION) }
        assertEquals(0,p.applies)
    }
    @Test fun `dynamic preparation sends five workflows preserves settings and reports CPH residue`():Unit=store().use { s ->
        val p=MockPort();val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "operator" })
        validated(w,job(true))
        assertEquals(5,p.probes);assertEquals(1,p.restores);assertEquals("VALIDATED",w.record("execution").state)
        assertFalse(p.current.cph["job:sample:token"]!!.jsonObject["enabled"]!!.jsonPrimitive.boolean)
        w.approve("execution",ApprovalStage.EXECUTION);start(w)
        assertEquals("EXECUTION_FINISHED",w.poll("execution").state)
        assertEquals(6,p.probes);assertEquals("NOT_REVIEWED",w.record("execution").diagnosisState)
    }
    @Test fun `same id with different proposal is rejected`():Unit=store().use { s ->
        val w=GuardedWorker(MockPort(),s,HumanApprover { _,_,_ -> "human" });val j=job()
        val p=w.register("execution",j)
        assertEquals(p,w.register("execution",j))
        assertThrows(JobRejected::class.java) { w.register("execution",j.copy(revision=2)) }
    }
    @Test fun `approved scan starts once and duplicate command returns the same audit`():Unit=store().use { s ->
        val p=MockPort();val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" });ready(w)
        val first=start(w);assertEquals(first,start(w));assertEquals(1,p.starts)
    }
    @Test fun `start throws after possible acceptance and is never retried`():Unit=store().use { s ->
        val p=MockPort();val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" });ready(w);p.failStart=true
        assertThrows(Exception::class.java) { start(w) }
        assertEquals("SUBMISSION_UNKNOWN",w.record("execution").state)
        assertThrows(JobRejected::class.java) { start(w) };assertEquals(1,p.starts)
    }
    @Test fun `apply failure does not start scanner or automatically restore unknown state`():Unit=store().use { s ->
        val p=MockPort();val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" })
        w.register("execution",job());w.approve("execution",ApprovalStage.PREPARATION);p.failApply=true
        assertThrows(Exception::class.java) { w.prepare("execution") }
        assertEquals("RECOVERY_REQUIRED",w.record("execution").state);assertEquals(0,p.starts+p.restores)
    }
    @Test fun `approval expiry never pretends to stop native audit`():Unit=store().use { s ->
        val p=MockPort();val clock=TestClock();val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" },clock)
        ready(w);start(w);clock.seconds+=3601
        val r=w.poll("execution");assertEquals("CONTROL_REQUIRED",r.state)
        assertEquals(0,p.polls);assertEquals(1,p.starts)
    }
    @Test fun `validation expiry blocks execution before a new scan`():Unit=store().use { s ->
        val p=MockPort();val clock=TestClock();val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" },clock)
        validated(w);clock.seconds+=3601
        assertThrows(JobRejected::class.java) { w.approve("execution",ApprovalStage.EXECUTION) };assertEquals(0,p.starts)
    }
    @Test fun `manual project change does not get overwritten`():Unit=store().use { s ->
        val p=MockPort();val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" });ready(w)
        p.current=p.current.copy(project=buildJsonObject { put("manual",true) })
        val applies=p.applies;assertThrows(JobRejected::class.java) { start(w) }
        assertEquals(applies,p.applies);assertEquals(0,p.starts)
    }
    @Test fun `workbook snapshot generation change invalidates approval`():Unit=store().use { s ->
        val p=MockPort();val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" });ready(w);p.changedInput=true
        assertThrows(JobRejected::class.java) { start(w) };assertEquals(0,p.starts)
    }
    @Test fun `fencing token prevents stale runner writes`():Unit=store().use { s ->
        val p=MockPort();val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" });ready(w)
        assertThrows(JobRejected::class.java) { w.start("execution",0,w.epoch) }
        assertThrows(JobRejected::class.java) { w.start("execution",w.record("execution").fence,"old-epoch") };assertEquals(0,p.starts)
    }
    @Test fun `second job cannot change settings of a running audit`():Unit=store().use { s ->
        val p=MockPort();val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" });ready(w);start(w)
        val before=p.current;val applies=p.applies;val probes=p.probes
        assertEquals("BURP_CONTEXT_BUSY",assertThrows(JobRejected::class.java) {
            w.register("second",job().copy(jobId="other"))
        }.code)
        assertEquals(before,p.current);assertEquals(applies,p.applies);assertEquals(probes,p.probes)
        assertNull(s.get("execution:second"));assertEquals(1,p.starts)
    }
    @Test fun `observation failure can recover by polling the same audit without restart`():Unit=store().use { s ->
        val p=MockPort();val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" });ready(w);start(w);p.pollThrows=true
        assertEquals("OBSERVATION_UNKNOWN",w.poll("execution").state);p.pollThrows=false
        assertEquals("EXECUTION_FINISHED",w.poll("execution").state);assertEquals(1,p.starts)
    }
    @Test fun `cancelled audit is partial and does not release shared state as successful completion`():Unit=store().use { s ->
        val p=MockPort();val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" });ready(w);start(w);p.state="cancelled";p.completed=false
        assertEquals("CONTROL_REQUIRED",w.poll("execution").state);assertEquals(1,p.restores)
    }
    @Test fun `incomplete evidence and null native metrics are retained`():Unit=store().use { s ->
        val p=MockPort();val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" });ready(w);start(w);p.collectComplete=false
        assertEquals("INCOMPLETE",w.poll("execution").evidenceState)
        val saved=w.savedResults("execution")
        assertFalse(saved["diagnosisCompleted"]!!.jsonPrimitive.boolean)
        assertEquals(JsonNull,saved["records"]!!.jsonArray.first().jsonObject["auditIssueCount"])
    }
    @Test fun `restart can read saved results but cannot invent a live native handle`() {
        val s=store();val dir=s.directory;val p=MockPort()
        val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" });ready(w);start(w);w.poll("execution");s.close()
        JobStore(dir).use { reopened ->
            val newWorker=GuardedWorker(p,reopened,HumanApprover { _,_,_ -> "human" })
            assertTrue(newWorker.savedResults("execution")["records"]!!.jsonArray.isNotEmpty())
            assertThrows(JobRejected::class.java) { newWorker.poll("execution") };assertEquals(1,p.starts)
        }
    }
    @Test fun `missing or modified committed evidence is an error`():Unit=store().use { s ->
        val w=GuardedWorker(MockPort(),s,HumanApprover { _,_,_ -> "human" });ready(w);start(w);w.poll("execution")
        s.put("result:execution:0",JsonObject(emptyMap()))
        assertThrows(JobRejected::class.java) { w.savedResults("execution") }
    }
    @Test fun `write ahead intent survives failure and cannot replay across reopen`() {
        val s=store();val dir=s.directory;var calls=0
        assertThrows(Exception::class.java) { s.onceJson("op","input") { calls++;throw IllegalStateException("after send") } };s.close()
        JobStore(dir).use { reopened ->
            assertThrows(JobRejected::class.java) { reopened.onceJson("op","input") { calls++;JsonNull } }
            assertThrows(JobRejected::class.java) { reopened.onceJson("op","changed") { calls++;JsonNull } }
        };assertEquals(1,calls)
    }
    @Test fun `runner protocol executes the workflow against a mock without Burp or target sockets`():Unit=store().use { workerStore ->
        store().use { clientStore ->
            val p=MockPort();val w=GuardedWorker(p,workerStore,HumanApprover { _,_,_ -> "human" });val protocol=WorkerProtocol(w)
            val runner=JobRunner(WorkerConnection(protocol::handle),clientStore)
            runner.prepare("execution",job(true));runner.start("execution")
            assertEquals("EXECUTION_FINISHED",jobJson.decodeFromJsonElement<ExecutionRecord>(runner.call("poll","execution")).state)
            assertEquals(1,p.starts);assertEquals(6,p.probes)
        }
    }
    @Test fun `protocol has no arbitrary execution or self approval operation`():Unit=store().use { s ->
        val protocol=WorkerProtocol(GuardedWorker(MockPort(),s,HumanApprover { _,_,_ -> "human" }))
        assertEquals("UNSUPPORTED_WORKER_OPERATION",protocol.handle(WorkerRequest("approve","execution")).errorCode)
        assertEquals("UNSUPPORTED_WORKER_OPERATION",protocol.handle(WorkerRequest("invoke_tool","execution")).errorCode)
    }
    @Test fun `revoke requires UI control without cancelling other jobs`():Unit=store().use { s ->
        val p=MockPort();val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" });ready(w);start(w);w.revoke("execution")
        assertEquals("CONTROL_REQUIRED",w.record("execution").state);assertEquals(1,p.starts)
    }
    @Test fun `runner executes reflection plus stored variants independently under one reviewed plan`():Unit=store().use { s ->
        store().use { client ->
            val p=MockPort();val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" })
            val runner=JobRunner(WorkerConnection(WorkerProtocol(w)::handle),client)
            runner.prepare("execution",storedJob())
            assertEquals(10,p.probes)
            assertEquals("EXECUTION_FINISHED",runner.run("execution",pause={}).state)
            assertEquals(2,p.starts);assertEquals(12,p.probes);assertEquals(4,p.restores)
            assertEquals(4,w.savedResults("execution")["records"]!!.jsonArray.size)
        }
    }
    @Test fun `valid and recovery branches need five probes each`():Unit=store().use { s ->
        val p=MockPort();val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" })
        val j=job();val v=j.variants.single()
        val branch=v.copy(requiredBranches=listOf("normal","expired"),branchSetup=mapOf("expired" to listOf(v.request)))
        validated(w,j.copy(variants=listOf(branch)))
        assertEquals(10,p.probes)
        w.approve("execution",ApprovalStage.EXECUTION)
    }
    @Test fun `recovery acknowledgment requires human and an actually restored baseline`():Unit=store().use { s ->
        val p=MockPort();val baseline=p.current;val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" })
        ready(w);start(w);w.revoke("execution")
        assertThrows(JobRejected::class.java) { w.reconcileRestored("execution","UI evidence") }
        p.current=baseline
        assertEquals("FAILED_RECONCILED",w.reconcileRestored("execution","UI audit match, ended traffic and restored settings").state)
        assertEquals(1,p.starts)
    }
    @Test fun `HTTP client and serialized worker protocol run against a loopback mock only`():Unit=store().use { s ->
        store().use { clientStore ->
            val p=MockPort();val protocol=WorkerProtocol(GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" }))
            val token="local-mock-token";val server=com.sun.net.httpserver.HttpServer.create(java.net.InetSocketAddress("127.0.0.1",0),0)
            server.createContext("/diagnosis/worker") { exchange ->
                if(exchange.requestHeaders.getFirst("Authorization")!="Bearer $token") { exchange.sendResponseHeaders(403,-1);exchange.close() } else {
                    val request=jobJson.decodeFromString<WorkerRequest>(exchange.requestBody.bufferedReader().readText())
                    val bytes=jobJson.encodeToString(protocol.handle(request)).toByteArray()
                    exchange.sendResponseHeaders(200,bytes.size.toLong());exchange.responseBody.use { it.write(bytes) }
                }
            }
            server.start()
            try {
                val uri=java.net.URI("http://127.0.0.1:${server.address.port}/diagnosis/worker")
                val runner=JobRunner(HttpWorkerConnection(uri,token),clientStore)
                runner.prepare("execution",job(true))
                assertEquals("EXECUTION_FINISHED",runner.run("execution",pause={}).state)
                assertEquals(1,p.starts)
                assertThrows(JobRejected::class.java) { HttpWorkerConnection(uri,"wrong").call(WorkerRequest("status","execution")) }
            } finally { server.stop(0) }
        }
    }
    @Test fun `partial results remain available without resending a diagnostic request`():Unit=store().use { s ->
        val p=MockPort();val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" });ready(w);start(w);p.completed=false;p.state="scanning"
        val saved=w.savedResults("execution")
        assertEquals("PARTIAL_OBSERVATION",saved["records"]!!.jsonArray.single().jsonObject["observationKind"]!!.jsonPrimitive.content)
        assertEquals(1,p.starts);assertEquals(5,p.probes);assertEquals("RUNNING",w.record("execution").state)
    }
    @Test fun `modified validation evidence cannot reuse execution approval`():Unit=store().use { s ->
        val p=MockPort();val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" });ready(w)
        val report=jobJson.decodeFromJsonElement<ValidationReport>(s.get("validation:execution")!!)
        s.put("validation:execution",jobJson.encodeToJsonElement(report.copy(probes=emptyList())))
        assertEquals("APPROVED_VALIDATION_CHANGED",assertThrows(JobRejected::class.java) { start(w) }.code)
        assertEquals(0,p.starts)
    }
    @Test fun `human can inspect immutable native plan and validation files before approving`():Unit=store().use { s ->
        val w=GuardedWorker(MockPort(),s,HumanApprover { _,_,_ -> "human" });validated(w,job(true))
        val original=jobJson.encodeToJsonElement(w.plan("execution"))
        val artifacts=ReviewArtifacts(s.directory);val file=artifacts.write(original,"plan")
        assertEquals(original,jobJson.parseToJsonElement(Files.readString(file)))
        val projected=reviewProjection(original).toString()
        assertFalse(projected.contains("name=probe"));assertTrue(projected.contains("protectedValueSha256"))
        Files.writeString(file,"modified")
        assertThrows(JobRejected::class.java) { artifacts.write(original,"plan") }
    }
    @Test fun `published JSON example completes the serialized mock workflow`():Unit=store().use { s ->
        val example=jobJson.decodeFromString<JobProposal>(Files.readString(Path.of("examples","mock-job.json")))
        val w=GuardedWorker(MockPort(),s,HumanApprover { _,_,_ -> "human" });ready(w,example);start(w)
        assertEquals("EXECUTION_FINISHED",w.poll("execution").state)
    }
    @Test fun `long running audit can be reapproved without a new submission or new validation sends`():Unit=store().use { s ->
        val clock=TestClock();val p=MockPort();val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" },clock)
        ready(w);val original=start(w);clock.seconds+=3601
        assertEquals("CONTROL_REQUIRED",w.poll("execution").state)
        val renewed=w.renewContinuation("execution")
        assertEquals(original.auditId,renewed.auditId);assertEquals(1,p.starts);assertEquals(5,p.probes)
        assertEquals("EXECUTION_FINISHED",w.poll("execution").state);assertEquals(1,p.starts)
    }
    @Test fun `approval expiry during result collection prevents normal resend and restore`():Unit=store().use { s ->
        val clock=TestClock();val p=MockPort();val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" },clock)
        ready(w);start(w);p.onCollect={clock.seconds+=3601}
        assertEquals("CONTROL_REQUIRED",w.poll("execution").state)
        assertEquals(5,p.probes);assertEquals(1,p.restores)
    }
    @Test fun `manual configuration change during collection prevents any later diagnostic send`():Unit=store().use { s ->
        val p=MockPort();val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" });ready(w);start(w)
        p.onCollect={p.current=p.current.copy(project=buildJsonObject { put("manual",true) })}
        assertEquals("RECOVERY_REQUIRED",w.poll("execution").state)
        assertEquals(5,p.probes);assertEquals(1,p.restores)
    }
    @Test fun `unfinished callback retains settings and does not advance the scan variant`():Unit=store().use { s ->
        val p=MockPort();val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" });ready(w);start(w);p.quiescent=false
        assertEquals("RUNNING",w.poll("execution").state)
        assertEquals(5,p.probes);assertEquals(1,p.restores)
    }
    @Test fun `continuation checks configuration again after human dialog`():Unit=store().use { s ->
        val p=MockPort();val clock=TestClock()
        val reviewer=object:HumanApprover {
            override fun review(plan:CompiledPlan,stage:ApprovalStage,report:ValidationReport?)="human"
            override fun reviewContinuation(plan:CompiledPlan,record:ExecutionRecord,report:ValidationReport):String {
                p.current=p.current.copy(project=buildJsonObject { put("changedWhileDialogOpen",true) });return "human"
            }
        }
        val w=GuardedWorker(p,s,reviewer,clock);ready(w);start(w);clock.seconds+=3601;w.poll("execution")
        assertThrows(JobRejected::class.java) { w.renewContinuation("execution") }
        assertEquals("CONTROL_REQUIRED",w.record("execution").state)
    }
    @Test fun `committed operation result corruption is detected before replaying its stored identity`():Unit=store().use { s ->
        s.onceJson("operation","input") { buildJsonObject { put("auditId","original") } }
        java.sql.DriverManager.getConnection("jdbc:sqlite:${s.directory.resolve("jobs.sqlite")}").use { db ->
            db.createStatement().use { it.executeUpdate("UPDATE operations SET result='{}' WHERE id='operation'") }
        }
        assertThrows(JobRejected::class.java) { s.onceJson("operation","input") { fail("Must never resend") } }
    }
    @Test fun `metadata transaction rolls back both execution and context lock together`():Unit=store().use { s ->
        assertThrows(IllegalStateException::class.java) { s.transaction {
            s.put("active",JsonPrimitive("new-execution"))
            s.put("execution:new-execution",buildJsonObject { put("state","PREPARING") })
            throw IllegalStateException("injected failure before metadata commit")
        } }
        assertNull(s.get("active"));assertNull(s.get("execution:new-execution"))
    }
    @Test fun `side effects cannot run inside an uncommitted metadata transaction`():Unit=store().use { s ->
        var calls=0
        val error=assertThrows(JobRejected::class.java) { s.transaction { s.onceJson("op","input") { calls++;JsonNull } } }
        assertEquals("SIDE_EFFECT_INSIDE_METADATA_TRANSACTION",error.code);assertEquals(0,calls)
    }
    @Test fun `legacy operation rows without independent digests are not silently trusted`() {
        val initial=store();val path=initial.directory;initial.close()
        java.sql.DriverManager.getConnection("jdbc:sqlite:${path.resolve("jobs.sqlite")}").use { db -> db.createStatement().use {
            it.execute("DROP TABLE operations")
            it.execute("CREATE TABLE operations(id TEXT PRIMARY KEY,input TEXT NOT NULL,state TEXT NOT NULL,result TEXT)")
            it.execute("INSERT INTO operations VALUES('old','input','COMMITTED','{}')")
        } }
        JobStore(path).use { reopened ->
            val error=assertThrows(JobRejected::class.java) { reopened.onceJson("old","input") { fail("Must never replay") } }
            assertEquals("OPERATION_RESULT_UNVERIFIABLE",error.code)
        }
    }
    @Test fun `callback waiting snapshots remain immutable when later collection completes`():Unit=store().use { s ->
        val p=MockPort();val w=GuardedWorker(p,s,HumanApprover { _,_,_ -> "human" });ready(w);start(w)
        p.quiescent=false;w.poll("execution");val first=w.savedResults("execution")["records"]!!.jsonArray.first()
        p.quiescent=true;assertEquals("EXECUTION_FINISHED",w.poll("execution").state)
        val records=w.savedResults("execution")["records"]!!.jsonArray
        assertEquals(first,records.first());assertEquals(3,records.size)
    }
    @Test fun `protected review projection masks mixed-case Logger pages and canonicalizes object keys`():Unit=store().use { s ->
        val value=buildJsonObject { putJsonArray("loggerPages") { add("Authorization: Bearer example-secret") };put("other",true) }
        assertFalse(reviewProjection(value).toString().contains("example-secret"))
        val artifacts=ReviewArtifacts(s.directory);val first=artifacts.write(value,"plan")
        assertEquals(first,artifacts.write(JsonObject(value.toList().reversed().toMap()),"plan"))
    }
}
