package net.portswigger.mcp.jobs

import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.*
import net.portswigger.diagnosis.runner.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

internal object DraftTestFixture {
    val caps = setOf("SCANNER_WORKFLOW", "EXCLUSIVE_CONTEXT", "DYNAMIC_WORKFLOW_VERIFIED")
    val endpoint = Endpoint("http", "fixture.invalid", 8080, "/items")
    val raw = "GET /items HTTP/1.1\r\nHost: fixture.invalid:8080\r\n\r\n"
    val response = "HTTP/1.1 200 OK\r\n\r\nobserved"
    val baseline = BurpSnapshot("fixture", jobJson.parseToJsonElement("""
        {"project_options":{"sessions":{"macros":{"macros":[]},"session_handling_rules":{"rules":[]}},
        "resource_pools":{"default_resource_pool":{"concurrent_request_limit_enabled":true,"concurrent_request_limit":10}}}}
    """).jsonObject, JsonObject(emptyMap()), emptyList(), caps)
    fun proposal(id: String = "next"): JobProposal {
        val material = HttpMaterial("observed", endpoint, raw, response, digest(raw), digest(response))
        return JobProposal(jobId=id, revision=1, objective="Observed next request", targetPolicy=listOf(TargetPermit(endpoint)),
            materials=listOf(material), session=SessionPlan(false,"OMIT","Observed public endpoint","fixture-owned"),
            variants=listOf(ScanVariant("reflection","REFLECTION",request=RequestPlan(endpoint,raw,material.id,material.requestSha256),
                settings=SettingsPlan())), requiredCapabilities=caps, cleanupPolicy="No created application records")
    }
    class Port: BurpExecutionPort {
        @Volatile var current = baseline
        @Volatile var completed = false
        @Volatile var inputChanged = false
        @Volatile var secretChanged = false
        var gate: Pair<CountDownLatch,CountDownLatch>? = null
        val snapshots=AtomicInteger(); val freezes=AtomicInteger(); val verifies=AtomicInteger()
        val applies=AtomicInteger(); val probes=AtomicInteger(); val starts=AtomicInteger(); val polls=AtomicInteger()
        val collects=AtomicInteger(); val restores=AtomicInteger()
        fun calls() = listOf(snapshots,freezes,verifies,applies,probes,starts,polls,collects,restores).map { it.get() }
        override fun snapshot():BurpSnapshot { snapshots.incrementAndGet();return current }
        override fun freezeInputs(job:JobProposal):JobProposal { freezes.incrementAndGet();return job }
        override fun verifyInputs(job:JobProposal) {
            verifies.incrementAndGet()
            requireJob(!inputChanged,"APPROVED_INPUT_CHANGED");requireJob(!secretChanged,"SECRET_GENERATION_CHANGED_OR_UNAVAILABLE")
        }
        override fun apply(variant:CompiledVariant) { applies.incrementAndGet();current=current.copy(project=variant.project,cph=variant.cph,cphOrder=variant.cphOrder) }
        override fun restore(baseline:BurpSnapshot,ownedCphNames:Set<String>) { restores.incrementAndGet();current=baseline }
        override fun probe(variant:ScanVariant,branch:String):Pair<String,JsonObject> {
            probes.incrementAndGet()
            gate?.let { (entered,release) -> entered.countDown();check(release.await(8,TimeUnit.SECONDS)) }
            return response to JsonObject(emptyMap())
        }
        override fun start(variant:ScanVariant):JsonObject { val count=starts.incrementAndGet();return buildJsonObject { put("status","started");put("auditId","audit-$count") } }
        override fun poll(auditId:String):JsonObject { polls.incrementAndGet();return buildJsonObject {
            put("auditId",auditId);put("completed",completed);put("auditStatusMessage",if(completed) "finished" else "scanning")
        } }
        override fun collect(auditId:String,payloadRunId:String?):JsonObject { collects.incrementAndGet();return buildJsonObject {
            put("auditId",auditId);put("complete",true);put("quiescent",true)
        } }
    }
    fun start(worker:GuardedWorker) {
        worker.register("current",proposal("current"));worker.approve("current",ApprovalStage.PREPARATION);worker.prepare("current")
        worker.approve("current",ApprovalStage.EXECUTION)
        val record=worker.record("current");worker.start("current",record.fence,worker.epoch)
    }
    fun await(service:DiagnosticJobService,id:String,execution:String="next-execution"):JsonObject {
        val deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(8)
        while(System.nanoTime()<deadline) {
            val result=service.call(DiagnosticJob("operation",execution,operationId=id))
            if(result["state"]!=JsonPrimitive("RUNNING")) return result
            Thread.sleep(10)
        }
        error("Specific operation $id did not finish")
    }
}
