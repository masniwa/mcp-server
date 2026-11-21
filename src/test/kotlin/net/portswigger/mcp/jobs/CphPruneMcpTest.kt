package net.portswigger.mcp.jobs

import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.*
import net.portswigger.diagnosis.runner.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.util.concurrent.TimeUnit

class CphPruneMcpTest {
    private class Port:BurpExecutionPort {
        var current=BurpSnapshot("instance",buildJsonObject { put("project_options",buildJsonObject {}) },buildJsonObject {
            put("job:done:a",buildJsonObject { put("enabled",false) })
            put("job:keep:b",buildJsonObject { put("enabled",false) })
            put("options",buildJsonObject { put("verbosity",3) })
        },listOf("job:done:a","job:keep:b","options"),emptySet())
        override fun snapshot()=current
        override fun retirementReadiness(auditId:String)=true
        override fun allTrafficQuiescent()=true
        override fun apply(variant:CompiledVariant)=error("unused")
        override fun restore(baseline:BurpSnapshot,ownedCphNames:Set<String>)=error("unused")
        override fun replaceCph(config:JsonObject,order:List<String>) { current=current.copy(cph=config,cphOrder=order) }
        override fun probe(variant:ScanVariant,branch:String)=error("unused")
        override fun start(variant:ScanVariant)=error("unused")
        override fun poll(auditId:String)=error("unused")
        override fun collect(auditId:String,payloadRunId:String?)=error("unused")
    }
    private fun await(service:DiagnosticJobService,id:String):JsonObject {
        val limit=System.nanoTime()+TimeUnit.SECONDS.toNanos(10)
        while(System.nanoTime()<limit) {
            val result=service.call(DiagnosticJob("operation","maintenance-prune",operationId=id))
            if(result["state"]!=JsonPrimitive("RUNNING")) return result
            Thread.sleep(10)
        }
        error("operation did not finish")
    }
    @Test fun `review action prunes only named CPH handlers and returns a nonblocking operation`() {
        val temp=java.nio.file.Path.of("..","temp").toAbsolutePath().normalize().also(Files::createDirectories)
        val directory=Files.createTempDirectory(temp,"cph-prune-mcp-")
        JobStore(directory).use { store ->
            val port=Port()
            val approver=object:HumanApprover {
                override fun review(plan:CompiledPlan,stage:ApprovalStage,report:ValidationReport?)=null
                override fun reviewCphPrune(names:List<String>,evidenceRef:String,currentDigest:String,targetDigest:String)="operator"
            }
            DiagnosticJobService(GuardedWorker(port,store,approver),store,false).use { service ->
                val start=service.call(DiagnosticJob("prune_cph","maintenance-prune",operationId="prune-1",
                    evidenceRef="completed scan and no future reference",cphNamesJson="[\"job:done:a\"]"))
                assertEquals(JsonPrimitive("RUNNING"),start["state"])
                val done=await(service,"prune-1")
                assertEquals(JsonPrimitive("SUCCEEDED"),done["state"])
                assertEquals(setOf("job:keep:b","options"),port.current.cph.keys)
                assertEquals(1,done["result"]!!.jsonObject["removedCount"]!!.jsonPrimitive.int)
            }
        }
    }
}
