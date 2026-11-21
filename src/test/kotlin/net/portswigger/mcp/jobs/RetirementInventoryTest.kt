package net.portswigger.mcp.jobs

import kotlinx.serialization.json.*
import net.portswigger.mcp.execution.retirementInventoryReady
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class RetirementInventoryTest {
    private fun inventory(vararg audits:JsonElement)=buildJsonObject { put("success",true);put("audits",JsonArray(audits.toList())) }
    private fun audit(status:String,completed:JsonElement,id:String="other")=buildJsonObject {
        put("auditId",id);put("auditStatusMessage",status);put("completed",completed)
    }
    @Test fun `only absent old handle and known terminal current inventory permit maintenance review`() {
        assertTrue(retirementInventoryReady(inventory(),"old")) // Inventory absence is not old termination proof.
        val finished=audit("finished",JsonPrimitive(true))
        assertTrue(retirementInventoryReady(inventory(finished,audit("cancelled",JsonNull,"cancelled-other")),"old"))
        listOf(audit("scanning",JsonPrimitive(false)),audit("paused",JsonPrimitive(false)),audit("unknown",JsonNull),
            audit("unknown",JsonPrimitive(true)),audit("finished",JsonPrimitive(true),"old"),audit("finished",JsonPrimitive(true),""),
            JsonObject(finished+("observationError" to JsonPrimitive("transient"))),JsonObject(finished+("submissionError" to JsonPrimitive("unknown"))),
            JsonPrimitive("invalid")).forEach { assertFalse(retirementInventoryReady(inventory(it),"old"),it.toString()) }
        assertFalse(retirementInventoryReady(buildJsonObject { put("success",false);put("audits",JsonArray(emptyList())) },"old"))
        assertFalse(retirementInventoryReady(buildJsonObject { put("success",true) },"old"))
    }
}
