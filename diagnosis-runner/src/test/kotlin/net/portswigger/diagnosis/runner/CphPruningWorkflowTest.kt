package net.portswigger.diagnosis.runner

import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.nio.file.Files

class CphPruningWorkflowTest {
    private fun handler(enabled:Boolean)=buildJsonObject { put("enabled",enabled);put("single_request","") }
    private class Port(var current:BurpSnapshot):BurpExecutionPort {
        var replacements=0
        var auditReady=true
        var trafficReady=true
        override fun snapshot()=current
        override fun retirementReadiness(auditId:String)=auditReady
        override fun allTrafficQuiescent()=trafficReady
        override fun apply(variant:CompiledVariant)=error("unused")
        override fun restore(baseline:BurpSnapshot,ownedCphNames:Set<String>)=error("unused")
        override fun replaceCph(config:JsonObject,order:List<String>) {
            replacements++
            current=current.copy(cph=config,cphOrder=order)
        }
        override fun probe(variant:ScanVariant,branch:String)=error("unused")
        override fun start(variant:ScanVariant)=error("unused")
        override fun poll(auditId:String)=error("unused")
        override fun collect(auditId:String,payloadRunId:String?)=error("unused")
    }
    private fun snapshot(enabled:Boolean=false)=BurpSnapshot("instance",buildJsonObject { put("project_options",buildJsonObject {}) },
        buildJsonObject {
            put("job:done:a",handler(enabled));put("job:done:b",handler(false));put("job:keep:c",handler(false))
            put("options",buildJsonObject { put("chkbox_scanner",false) })
        },listOf("job:done:a","job:done:b","job:keep:c","options"),emptySet())
    private fun approver(decision:String?="operator")=object:HumanApprover {
        override fun review(plan:CompiledPlan,stage:ApprovalStage,report:ValidationReport?)=null
        override fun reviewCphPrune(names:List<String>,evidenceRef:String,currentDigest:String,targetDigest:String):String?=decision
    }
    private fun store()=JobStore(Files.createTempDirectory(java.nio.file.Path.of("..","..","temp").toAbsolutePath().normalize(),"cph-prune-"))

    @Test fun `explicit disabled job handlers are removed with exact readback and a durable record`()=store().use { store ->
        val port=Port(snapshot());val worker=GuardedWorker(port,store,approver())
        val result=worker.pruneCph("maintenance-1",listOf("job:done:a","job:done:b"),"completed jobs are no longer used")
        assertEquals(2,result["removedCount"]!!.jsonPrimitive.int)
        assertEquals(setOf("job:keep:c","options"),port.current.cph.keys)
        assertEquals(listOf("job:keep:c","options"),port.current.cphOrder)
        assertEquals(1,port.replacements)
        assertNotNull(store.get("cph-prune:maintenance-1"))
        assertTrue(result["projectUnchanged"]!!.jsonPrimitive.boolean)
        assertFalse(result["httpTrafficSent"]!!.jsonPrimitive.boolean)
    }

    @Test fun `enabled unknown non-job and denied handlers are never removed`()=store().use { store ->
        val enabled=Port(snapshot(true));val worker=GuardedWorker(enabled,store,approver())
        assertEquals("CPH_PRUNE_REQUIRES_DISABLED_EXISTING_HANDLERS",
            assertThrows<JobRejected> { worker.pruneCph("maintenance-2",listOf("job:done:a"),"evidence") }.code)
        assertEquals("CPH_PRUNE_JOB_OWNERSHIP_REQUIRED",
            assertThrows<JobRejected> { worker.pruneCph("maintenance-3",listOf("options"),"evidence") }.code)
        val denied=GuardedWorker(Port(snapshot()),store,approver(null))
        assertEquals("HUMAN_DENIED",assertThrows<JobRejected> {
            denied.pruneCph("maintenance-4",listOf("job:done:b"),"evidence")
        }.code)
        assertEquals(0,enabled.replacements)
    }
    @Test fun `prune refuses active native audit or helper traffic before human review`()=store().use { store ->
        for(kind in listOf("audit","traffic")) {
            val port=Port(snapshot())
            if(kind=="audit") port.auditReady=false else port.trafficReady=false
            val worker=GuardedWorker(port,store,approver())
            assertThrows<JobRejected> { worker.pruneCph("maintenance-$kind",listOf("job:done:a"),"evidence") }
            assertEquals(0,port.replacements)
        }
    }
}
