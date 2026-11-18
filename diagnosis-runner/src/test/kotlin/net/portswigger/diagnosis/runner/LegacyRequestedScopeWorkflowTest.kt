package net.portswigger.diagnosis.runner

import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

class LegacyRequestedScopeWorkflowTest {
    private val time=1_800_000_000L
    private val clock=Clock.fixed(Instant.ofEpochSecond(time),ZoneOffset.UTC)
    private val capabilities=setOf("SCANNER_WORKFLOW","EXCLUSIVE_CONTEXT")
    private val baseline=BurpSnapshot("fixture",JsonObject(emptyMap()),JsonObject(emptyMap()),emptyList(),capabilities)
    private fun legacyPlan():CompiledPlan {
        val endpoint=Endpoint("http","legacy-scope.invalid",8080,"/submit?mode=1")
        val raw="POST ${endpoint.path} HTTP/1.1\r\nHost: ${endpoint.host}:8080\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\ncsrf=sample&identity=reader&credential=fixture"
        val response="HTTP/1.1 200 OK\r\n\r\nnormal"
        val material=HttpMaterial("observed",endpoint,raw,response,digest(raw),digest(response))
        val automatic=JobProposal(jobId="legacy-scope",revision=1,objective="Preserve legacy evidence without authorizing new sends",
            targetPolicy=listOf(TargetPermit(endpoint)),materials=listOf(material),session=SessionPlan(false,"OMIT","Fixture","fixture"),
            variants=listOf(ScanVariant("reflection","REFLECTION",request=RequestPlan(endpoint,raw,material.id,material.requestSha256),settings=SettingsPlan())),
            requiredCapabilities=capabilities,cleanupPolicy="Review owned state")
        val parameters=listOf(InputParameter("mode","URL"),InputParameter("csrf","BODY"),InputParameter("identity","BODY"),InputParameter("credential","BODY"))
        val explicit=automatic.variants.single().copy(request=automatic.variants.single().request.copy(startOptions=buildJsonObject {
            put("insertionPointParameters",jobJson.encodeToJsonElement(parameters))
        }))
        val proposal=automatic.copy(variants=listOf(explicit)) // A pre-upgrade proposal has no independent requested declaration.
        val old=JobCompiler().compile(automatic,baseline)
        val variants=listOf(old.variants.single().copy(variant=explicit))
        val proposalDigest=fingerprint(proposal)
        val seed=buildJsonObject { put("proposal",proposalDigest);put("baseline",fingerprint(baseline));put("variants",jobJson.encodeToJsonElement(variants)) }
        return old.copy(proposal=proposal,proposalDigest=proposalDigest,planDigest=fingerprint(seed),variants=variants)
    }
    private class Port(private val baseline:BurpSnapshot):BurpExecutionPort {
        var current=baseline
        var snapshots=0;var verifies=0;var applies=0;var probes=0;var onceSends=0;var starts=0;var restores=0;var polls=0;var collections=0
        var nativeState="cancelled"
        override fun verifyInputs(job:JobProposal) { verifies++ }
        override fun snapshot():BurpSnapshot { snapshots++;return current }
        override fun apply(variant:CompiledVariant) { applies++;current=current.copy(project=variant.project,cph=variant.cph,cphOrder=variant.cphOrder) }
        override fun restore(baseline:BurpSnapshot,ownedCphNames:Set<String>) { restores++;current=baseline }
        override fun oncePreparation(request:RequestPlan):Pair<String,JsonObject> { onceSends++;return "HTTP/1.1 200 OK\r\n\r\n" to JsonObject(emptyMap()) }
        override fun probe(variant:ScanVariant,branch:String):Pair<String,JsonObject> { probes++;return "HTTP/1.1 200 OK\r\n\r\n" to JsonObject(emptyMap()) }
        override fun start(variant:ScanVariant):JsonObject { starts++;return buildJsonObject { put("status","started");put("auditId","new-audit") } }
        override fun poll(auditId:String):JsonObject { polls++;return buildJsonObject { put("auditStatusMessage",nativeState);put("completed",false) } }
        override fun collect(auditId:String,payloadRunId:String?):JsonObject {
            collections++;return buildJsonObject {
                put("auditId",auditId);put("native",buildJsonObject { put("auditStatusMessage",nativeState);put("completed",false) })
                put("quiescent",true);put("complete",false);putJsonObject("loggerStatus") { put("droppedEntries",0);put("captureErrors",0) };putJsonArray("loggerPages") {}
            }
        }
        override fun recoveryReadiness(endpoints:List<Endpoint>)=true
    }
    private fun store():JobStore {
        val root=Path.of("..","..","temp","requested-input-and-throttling-20261113","legacy-scope-tests").toAbsolutePath().normalize()
        Files.createDirectories(root);return JobStore(Files.createTempDirectory(root,"worker-"))
    }
    private fun persist(store:JobStore,worker:GuardedWorker,state:String,audit:String?=null):CompiledPlan {
        val plan=legacyPlan()
        store.put("plan:execution",jobJson.encodeToJsonElement(plan))
        store.put("execution:execution",jobJson.encodeToJsonElement(ExecutionRecord("execution",plan.planDigest,worker.epoch,1,state=state,auditId=audit)))
        val variant=plan.variants.single()
        val report=ValidationReport(plan.planDigest,List(5) { ProbeEvidence("reflection","normal",it,variant.settingsDigest,"HTTP/1.1 200 OK\r\n\r\n",JsonObject(emptyMap()),time) },time,true,emptyList())
        store.put("validation:execution",jobJson.encodeToJsonElement(report));store.put("prepared-baseline:execution",jobJson.encodeToJsonElement(baseline))
        for(stage in listOf(ApprovalStage.PREPARATION,ApprovalStage.EXECUTION))
            store.put("approval:execution:${stage.name}",jobJson.encodeToJsonElement(ApprovalRecord("old-${stage.name}","execution",plan.planDigest,stage,time-1,time+3600,"old-human",if(stage==ApprovalStage.EXECUTION) fingerprint(report) else null)))
        return plan
    }
    private fun assertNoNewWork(port:Port,store:JobStore) {
        assertEquals(0,port.snapshots+port.verifies+port.applies+port.probes+port.onceSends+port.starts)
        assertNull(store.get("active"))
    }
    @Test fun `legacy explicit scope cannot obtain new preparation or execution approval`():Unit=store().use { store ->
        val port=Port(baseline);var reviews=0
        val worker=GuardedWorker(port,store,HumanApprover { _,_,_ -> reviews++;"human" },clock)
        for((stage,state) in listOf(ApprovalStage.PREPARATION to "STATIC_VALIDATED",ApprovalStage.EXECUTION to "VALIDATED")) {
            persist(store,worker,state)
            val approval=store.get("approval:execution:${stage.name}")
            assertEquals("REQUESTED_INPUT_PARAMETERS_REQUIRED",assertThrows(JobRejected::class.java) { worker.approve("execution",stage) }.code)
            assertEquals(approval,store.get("approval:execution:${stage.name}"));assertEquals(state,worker.record("execution").state)
            assertNoNewWork(port,store)
        }
        assertEquals(0,reviews)
    }
    @Test fun `legacy previously approved preparation cannot apply settings capture context or send probes`():Unit=store().use { store ->
        val port=Port(baseline);val worker=GuardedWorker(port,store,HumanApprover { _,_,_ -> fail("Must refuse before asking for approval") },clock)
        val old=persist(store,worker,"PREPARATION_APPROVED")
        val saved=store.get("plan:execution")
        assertEquals("REQUESTED_INPUT_PARAMETERS_REQUIRED",assertThrows(JobRejected::class.java) { worker.prepare("execution") }.code)
        assertEquals(old,worker.plan("execution"));assertEquals(saved,store.get("plan:execution"));assertEquals("PREPARATION_APPROVED",worker.record("execution").state)
        assertNoNewWork(port,store)
    }
    @Test fun `legacy validated and execution approved plan cannot start a new audit`():Unit=store().use { store ->
        val port=Port(baseline);val worker=GuardedWorker(port,store,HumanApprover { _,_,_ -> fail("Must refuse before asking for approval") },clock)
        val old=persist(store,worker,"EXECUTION_APPROVED")
        assertEquals("REQUESTED_INPUT_PARAMETERS_REQUIRED",assertThrows(JobRejected::class.java) { worker.start("execution",1,worker.epoch) }.code)
        assertEquals(old,worker.plan("execution"));assertEquals("EXECUTION_APPROVED",worker.record("execution").state)
        assertNoNewWork(port,store)
    }
    @Test fun `legacy plan remains readable capturable and recoverable without scope recompilation`():Unit=store().use { store ->
        val port=Port(baseline);var reviews=0
        val worker=GuardedWorker(port,store,HumanApprover { _,_,_ -> reviews++;"human" },clock)
        val old=persist(store,worker,"CONTROL_REQUIRED","old-audit")
        val encoded=store.get("plan:execution")!!
        assertFalse(encoded.toString().contains("requestedInputParameters"));assertEquals(old,worker.plan("execution"))
        port.current=baseline.copy(project=old.variants.single().project)
        store.put("active",JsonPrimitive("execution"))
        assertEquals(1,worker.capturePartialResults("execution")["records"]!!.jsonArray.size)
        assertEquals("FAILED_RECONCILED",worker.recover("execution","saved cancelled audit and quiescent helper evidence").state)
        assertEquals(old,worker.plan("execution"));assertEquals(encoded,store.get("plan:execution"))
        assertEquals(baseline,port.current);assertEquals(1,port.restores);assertEquals(1,port.collections);assertEquals(1,reviews)
        assertEquals(0,port.applies+port.probes+port.onceSends+port.starts);assertEquals(JsonNull,store.get("active"))
    }
    @Test fun `existing legacy audit start idempotence observation and renewal never resubmit it`():Unit=store().use { store ->
        val port=Port(baseline);port.nativeState="auditing"
        val worker=GuardedWorker(port,store,HumanApprover { _,_,_ -> "human" },clock)
        val old=persist(store,worker,"RUNNING","old-audit")
        port.current=baseline.copy(project=old.variants.single().project)
        store.put("active",JsonPrimitive("execution"))
        assertEquals("old-audit",worker.start("execution",1,worker.epoch).auditId)
        assertEquals("RUNNING",worker.poll("execution").state)
        assertEquals("old-audit",worker.renewContinuation("execution").auditId)
        assertEquals(0,port.applies+port.probes+port.onceSends+port.starts)
    }
}
