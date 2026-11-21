package net.portswigger.mcp.jobs

import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.*
import net.portswigger.diagnosis.runner.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class ColdCphRecoveryMcpTest {
    @TempDir lateinit var directory:Path
    private fun factory()=buildJsonObject { putJsonObject(digest("options")) {
        listOf("repeater","scanner","extender","spider","intruder","sequencer","target","proxy").forEach {
            put("chkbox_$it",it in setOf("repeater","proxy"))
        };put("verbosity",3)
    } }
    private fun await(service:DiagnosticJobService,id:String):JsonObject {
        repeat(500) {
            val result=service.call(DiagnosticJob("operation","execution",operationId=id))
            if(result["state"]?.jsonPrimitive?.content in setOf("SUCCEEDED","FAILED")) return result
            Thread.sleep(10)
        };error("operation did not finish")
    }
    @Test fun `public recovery operation waits for cold CPH review restores only saved settings and is idempotent`() {
        val source=DraftTestFixture.proposal("sample")
        var current=DraftTestFixture.baseline.copy(instanceId="before",cph=JsonObject(factory()+
            ("preserved-auth" to buildJsonObject { put("enabled",false) })),cphOrder=listOf("preserved-auth",digest("options")))
        val baseline=current;var restores=0;var sends=0
        val port=object:BurpExecutionPort {
            override fun snapshot()=current
            override fun apply(variant:CompiledVariant) { current=current.copy(project=variant.project,cph=variant.cph,cphOrder=variant.cphOrder);throw JobRejected("FIXTURE_AFTER_APPLY") }
            override fun restore(value:BurpSnapshot,ownedCphNames:Set<String>) { restores++;current=value }
            override fun probe(variant:ScanVariant,branch:String):Pair<String,JsonObject> { sends++;error("must not send") }
            override fun start(variant:ScanVariant):JsonObject { sends++;error("must not start") }
            override fun poll(auditId:String):JsonObject=error("no audit was created")
            override fun collect(auditId:String,payloadRunId:String?):JsonObject=error("no audit was created")
            override fun recoveryReadiness(endpoints:List<Endpoint>)=true
            override fun retirementReadiness(auditId:String)=true
        }
        JobStore(directory).use { store ->
            val old=GuardedWorker(port,store,HumanApprover { _,_,_ -> "human" })
            old.register("execution",source);old.approve("execution",ApprovalStage.PREPARATION)
            assertThrows(JobRejected::class.java) { old.prepare("execution") }
            current=current.copy(instanceId="after",cph=factory(),cphOrder=listOf(digest("options")))
            val entered=CountDownLatch(1);val release=CountDownLatch(1);var reviews=0
            lateinit var service:DiagnosticJobService
            val reviewer=object:HumanApprover {
                override fun review(plan:CompiledPlan,stage:ApprovalStage,report:ValidationReport?):String=error("must use the dedicated review")
                override fun reviewColdCphRestore(plan:CompiledPlan,record:ExecutionRecord,evidenceRef:String,currentDigest:String):String {
                    reviews++;service.approvalPhase("AWAITING_RECOVERY_APPROVAL");entered.countDown()
                    check(release.await(5,TimeUnit.SECONDS));service.approvalPhase("RUNNING");return "human"
                }
            }
            val worker=GuardedWorker(port,store,reviewer)
            DiagnosticJobService(worker,store,false).use { live ->
                service=live
                val input=DiagnosticJob("recover","execution",operationId="recover-cold",evidenceRef="saved same Project and process termination")
                live.call(input);assertTrue(entered.await(3,TimeUnit.SECONDS));assertEquals(0,restores)
                assertEquals(JsonPrimitive("APPROVE_STAGE_IN_BURP_THEN_POLL_SAME_OPERATION"),live.status("execution")["nextAction"])
                release.countDown();assertEquals(JsonPrimitive("SUCCEEDED"),await(live,"recover-cold")["state"])
                assertEquals(baseline.project,current.project);assertEquals(baseline.cph,current.cph);assertEquals(baseline.cphOrder,current.cphOrder)
                assertEquals("FAILED_RECONCILED",worker.record("execution").state);assertEquals(0,sends)
                assertEquals(JsonNull,live.status("execution")["context"]!!.jsonObject["ownerExecutionId"])
                live.call(input);assertEquals(1,reviews);assertEquals(1,restores)
            }
        }
    }
}
