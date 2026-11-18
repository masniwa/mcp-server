package net.portswigger.diagnosis.runner

import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path
import java.sql.DriverManager

class OncePreparationWorkflowTest {
    private val capabilities=setOf("SCANNER_WORKFLOW","EXCLUSIVE_CONTEXT")
    private val response="HTTP/1.1 200 OK\r\n\r\nobserved result"
    private fun material(id:String,path:String):HttpMaterial {
        val e=Endpoint("http","once.fixture.invalid",8193,path)
        val raw="POST $path HTTP/1.1\r\nHost: once.fixture.invalid:8193\r\nContent-Length: 0\r\n\r\n"
        return HttpMaterial(id,e,raw,response,digest(raw),digest(response))
    }
    private fun HttpMaterial.requestPlan()=RequestPlan(endpoint,request,id,requestSha256)
    private fun job(branches:Boolean=true):JobProposal {
        val diagnostic=material("diagnostic","/records")
        val preparations=(0 until 3).map { material("owned-key-$it","/owned-key/revoke/$it") }
        val branch=material("branch-state","/branch/prepare")
        return JobProposal(jobId="once",revision=1,objective="Prepare owned state once, then verify the repeating workflow",
            targetPolicy=listOf(TargetPermit(Endpoint("http","once.fixture.invalid",8193,"/"),true)),
            materials=listOf(diagnostic,branch)+preparations,
            session=SessionPlan(false,"OMIT","The observed diagnostic is unauthenticated","test-account"),
            variants=listOf(ScanVariant("reflection","REFLECTION",request=diagnostic.requestPlan(),settings=SettingsPlan(),
                requiredBranches=if(branches) listOf("normal","other-state") else listOf("normal"),
                branchSetup=if(branches) mapOf("other-state" to listOf(branch.requestPlan())) else emptyMap(),
                preparationOnce=preparations.map { it.requestPlan() })),
            requiredCapabilities=capabilities,cleanupPolicy="Only owned test state")
    }
    private fun storedJob():JobProposal {
        val job=job(false);val view=material("saved-result","/records/view")
        val macro=buildJsonObject {
            put("description","job:once:saved-result");put("serial_number",501)
            putJsonArray("items") { add(buildJsonObject {
                put("url",view.endpoint.url());put("request",view.request);put("response",view.response);put("method","POST");put("status_code",200)
                put("accept_response_cookies",true);put("use_request_cookies",true)
                put("custom_parameters",JsonArray(emptyList()));put("request_parameters",JsonArray(emptyList()))
            }) }
        }
        val rule=buildJsonObject {
            put("description","job:once:saved-result-rule");put("enabled",true)
            put("exclude_from_scope",JsonArray(emptyList()));put("named_params",JsonArray(emptyList()));put("restrict_scope_to_named_params",false)
            put("tools_scope",JsonArray(listOf(JsonPrimitive("Scanner"),JsonPrimitive("Extensions"))))
            put("url_scope","custom");put("url_scope_advanced_mode",false)
            putJsonArray("include_in_scope") { add(buildJsonObject {
                put("enabled",true);put("include_subdomains",false);put("prefix",job.variants.single().request.endpoint.url())
            }) }
            putJsonArray("actions") { add(buildJsonObject {
                put("type","run_post_request_macro");put("enabled",true);put("macro_serial_number",501)
                put("pass_back","final_response");put("match_params","all_except");put("update_with_params",true)
            }) }
        }
        val stored=job.variants.single().copy(id="stored",kind="STORED",verificationSourceId=view.id,
            settings=SettingsPlan(macros=JsonArray(listOf(macro)),rules=JsonArray(listOf(rule))),
            preparationOnce=job.variants.single().preparationOnce.take(1))
        return job.copy(materials=job.materials+view,variants=job.variants+stored,storedVerificationSourceIds=listOf(view.id))
    }
    private class Port(capabilities:Set<String>):BurpExecutionPort {
        var current=BurpSnapshot("instance",JsonObject(emptyMap()),JsonObject(emptyMap()),emptyList(),capabilities)
        val events=mutableListOf<String>()
        var onceCalls=0;var probeCalls=0;var starts=0;var restoreCalls=0;var failOnceAt:Int?=null
        var rejectCoverage=false
        override fun validateInputCoverage(plan:CompiledPlan) { requireJob(!rejectCoverage,"INPUT_COVERAGE_GAP") }
        override fun snapshot()=current
        override fun apply(variant:CompiledVariant) {
            events.add("apply:${variant.variant.id}");current=current.copy(project=variant.project,cph=variant.cph,cphOrder=variant.cphOrder)
        }
        override fun restore(baseline:BurpSnapshot,ownedCphNames:Set<String>) {
            restoreCalls++;events.add("restore");current=baseline
        }
        override fun oncePreparation(request:RequestPlan):Pair<String,JsonObject> {
            onceCalls++;events.add("once:${request.sourceId}")
            if(onceCalls==failOnceAt) error("transport outcome is unknown")
            return "HTTP/1.1 204 No Content\r\n\r\n" to buildJsonObject { put("window","once-$onceCalls") }
        }
        override fun probe(variant:ScanVariant,branch:String):Pair<String,JsonObject> {
            probeCalls++;events.add("probe:$branch")
            return "HTTP/1.1 200 OK\r\n\r\nworkflow" to buildJsonObject { put("window","probe-$probeCalls") }
        }
        override fun start(variant:ScanVariant):JsonObject {
            starts++;events.add("start")
            return buildJsonObject { put("status","started");put("auditId","audit-$starts") }
        }
        override fun poll(auditId:String)=buildJsonObject { put("completed",true);put("auditStatusMessage","finished") }
        override fun collect(auditId:String,payloadRunId:String?)=buildJsonObject { put("quiescent",true);put("complete",true) }
        override fun recoveryReadiness(endpoints:List<Endpoint>)=true
    }
    private fun store():JobStore {
        val root=Path.of("..","..","temp","approval-input-lifecycle-20261113","once-tests").toAbsolutePath().normalize()
        Files.createDirectories(root);return JobStore(Files.createTempDirectory(root,"worker-"))
    }
    private fun prepared(worker:GuardedWorker,proposal:JobProposal=job()):ValidationReport {
        worker.register("execution",proposal);worker.approve("execution",ApprovalStage.PREPARATION)
        return worker.prepare("execution")
    }
    private fun start(worker:GuardedWorker):ExecutionRecord {
        val record=worker.record("execution");return worker.start("execution",record.fence,worker.epoch)
    }

    @Test fun `once-only preparation precedes every branch but never enters five probes scan or control`():Unit=store().use { store ->
        val port=Port(capabilities);val worker=GuardedWorker(port,store,HumanApprover { _,_,_ -> "human" })
        val report=prepared(worker)
        assertEquals(listOf("apply:reflection","once:owned-key-0","once:owned-key-1","once:owned-key-2"),port.events.take(4))
        assertEquals(3,port.onceCalls);assertEquals(10,port.probeCalls)
        assertEquals(3,report.preparationOnce.size);assertEquals(10,report.probes.size)
        assertEquals(setOf("once-1","once-2","once-3"),report.preparationOnce.map { it.logger.getValue("window").jsonPrimitive.content }.toSet())
        assertEquals(5,report.probes.count { it.branch=="normal" });assertEquals(5,report.probes.count { it.branch=="other-state" })
        assertEquals(report,worker.prepare("execution"));assertEquals(3,port.onceCalls);assertEquals(10,port.probeCalls)
        worker.approve("execution",ApprovalStage.EXECUTION);start(worker)
        assertEquals("EXECUTION_FINISHED",worker.poll("execution").state)
        assertEquals(1,port.starts);assertEquals(3,port.onceCalls);assertEquals(11,port.probeCalls);assertEquals(2,port.restoreCalls)
    }
    @Test fun `uncertain once-only request stops before probes retains partial evidence and cannot replay after restart`():Unit=store().use { store ->
        val port=Port(capabilities);port.failOnceAt=2
        val worker=GuardedWorker(port,store,HumanApprover { _,_,_ -> "human" })
        assertThrows(IllegalStateException::class.java) { prepared(worker) }
        assertEquals("RECOVERY_REQUIRED",worker.record("execution").state)
        assertEquals(2,port.onceCalls);assertEquals(0,port.probeCalls);assertEquals(0,port.starts)
        val partial=jobJson.decodeFromJsonElement<List<PreparationEvidence>>(store.get("partial-preparation-once:execution")!!)
        assertEquals(1,partial.size);assertEquals(0,partial.single().index)
        assertEquals("INVALID_STATE",assertThrows(JobRejected::class.java) { worker.prepare("execution") }.code)
        val replacement=GuardedWorker(port,store,HumanApprover { _,_,_ -> "human" })
        assertEquals("WORKER_EPOCH_CHANGED_RECONCILIATION_REQUIRED",assertThrows(JobRejected::class.java) { replacement.prepare("execution") }.code)
        DriverManager.getConnection("jdbc:sqlite:${store.directory.resolve("jobs.sqlite")}").use { db ->
            db.createStatement().use { statement ->
                statement.executeQuery("SELECT state FROM operations WHERE id='execution:preparation-once:reflection:1'").use { result ->
                    assertTrue(result.next());assertEquals("INTENT",result.getString(1))
                }
            }
        }
        val recovered=worker.recover("execution","operator checked that helper traffic ended")
        assertEquals("FAILED_RECONCILED",recovered.state);assertEquals(1,port.restoreCalls)
        assertEquals(2,port.onceCalls);assertEquals(0,port.probeCalls);assertEquals(0,port.starts)
    }
    @Test fun `separate reflection and stored variants each run their approved once-only list once`():Unit=store().use { store ->
        val port=Port(capabilities);val worker=GuardedWorker(port,store,HumanApprover { _,_,_ -> "human" })
        val report=prepared(worker,storedJob())
        assertEquals(4,port.onceCalls);assertEquals(10,port.probeCalls);assertEquals(2,port.restoreCalls)
        assertEquals(3,report.preparationOnce.count { it.variantId=="reflection" })
        assertEquals(1,report.preparationOnce.count { it.variantId=="stored" })
        val storedApply=port.events.indexOf("apply:stored")
        assertEquals("once:owned-key-0",port.events[storedApply+1]);assertEquals("probe:normal",port.events[storedApply+2])
        assertEquals(report,worker.prepare("execution"));assertEquals(4,port.onceCalls)
        worker.approve("execution",ApprovalStage.EXECUTION);start(worker);worker.poll("execution")
        start(worker);assertEquals("EXECUTION_FINISHED",worker.poll("execution").state)
        assertEquals(2,port.starts);assertEquals(4,port.onceCalls);assertEquals(12,port.probeCalls)
    }
    @Test fun `once-only evidence is shown to the execution approver and bound to approved validation digest`():Unit=store().use { store ->
        val port=Port(capabilities);var reviewed:ValidationReport?=null
        val worker=GuardedWorker(port,store,HumanApprover { _,stage,report -> if(stage==ApprovalStage.EXECUTION) reviewed=report;"human" })
        val report=prepared(worker);worker.approve("execution",ApprovalStage.EXECUTION)
        assertEquals(report,reviewed)
        val changed=report.copy(preparationOnce=report.preparationOnce.mapIndexed { index,evidence ->
            if(index==0) evidence.copy(response="HTTP/1.1 200 OK\r\n\r\nchanged") else evidence
        })
        assertNotEquals(fingerprint(report),fingerprint(changed))
        store.put("validation:execution",jobJson.encodeToJsonElement(changed))
        assertEquals("APPROVED_VALIDATION_CHANGED",assertThrows(JobRejected::class.java) { start(worker) }.code)
        assertEquals(0,port.starts);assertEquals(3,port.onceCalls)
    }
    @Test fun `once-only evidence cannot replace five workflow probes or disappear before approval`():Unit=store().use { store ->
        val port=Port(capabilities);val worker=GuardedWorker(port,store,HumanApprover { _,_,_ -> "human" })
        val report=prepared(worker,job(false))
        store.put("validation:execution",jobJson.encodeToJsonElement(report.copy(probes=report.probes.take(4))))
        assertEquals("FIVE_PROBES_REQUIRED",assertThrows(JobRejected::class.java) { worker.approve("execution",ApprovalStage.EXECUTION) }.code)
        store.put("validation:execution",jobJson.encodeToJsonElement(report.copy(preparationOnce=emptyList())))
        assertEquals("PREPARATION_ONCE_EVIDENCE_REQUIRED",assertThrows(JobRejected::class.java) { worker.approve("execution",ApprovalStage.EXECUTION) }.code)
        assertEquals(5,port.probeCalls);assertEquals(3,port.onceCalls);assertEquals(0,port.starts)
    }
    @Test fun `once-only evidence must retain unique exact per-variant identities`():Unit=store().use { store ->
        val port=Port(capabilities);val worker=GuardedWorker(port,store,HumanApprover { _,_,_ -> "human" })
        val report=prepared(worker,job(false))
        val changed=report.copy(preparationOnce=listOf(report.preparationOnce.first(),report.preparationOnce.first(),report.preparationOnce.last()))
        store.put("validation:execution",jobJson.encodeToJsonElement(changed))
        assertEquals("PREPARATION_ONCE_EVIDENCE_REQUIRED",assertThrows(JobRejected::class.java) { worker.approve("execution",ApprovalStage.EXECUTION) }.code)
    }
    @Test fun `input coverage validation rejects before formal registration approval or target effects`():Unit=store().use { store ->
        val port=Port(capabilities);port.rejectCoverage=true;var approvals=0
        val worker=GuardedWorker(port,store,HumanApprover { _,_,_ -> approvals++;"human" })
        assertEquals("INPUT_COVERAGE_GAP",assertThrows(JobRejected::class.java) { worker.register("execution",job()) }.code)
        assertNull(store.get("plan:execution"));assertNull(store.get("execution:execution"));assertNull(store.get("active"))
        assertEquals(0,approvals);assertTrue(port.events.isEmpty())
    }
}
