package net.portswigger.mcp.jobs

import io.mockk.every
import io.mockk.spyk
import kotlinx.serialization.json.*
import net.portswigger.mcp.execution.CphClient
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path

class CphConnectionTest {
    @TempDir lateinit var root:Path
    private val secret="test-credential-must-not-appear-".repeat(3)
    private fun client(source:String="file"):CphClient {
        val managed=ManagedSettings(true,"worker-$secret",secret,root.resolve("worker-store"),emptySet(),
            profileFile=if(source=="file") root.resolve("settings.json") else null)
        return spyk(CphClient(secret,managed.connectionMetadata()))
    }
    private fun response(client:CphClient,status:Int,body:JsonObject):JsonObject {
        every { client.exchange("/cph/export",host="127.0.0.1",port=17866) } returns (status to body.toString())
        val result=client.readConfiguration()
        assertFalse(result.contains(secret))
        return Json.parseToJsonElement(result).jsonObject
    }
    private fun exported(directory:Path=root,source:String="file")=buildJsonObject {
        put("success",true);put("managed",true);put("config",buildJsonObject { put("Options",buildJsonObject { put("Scanner",false) }) })
        put("connection",buildJsonObject { put("source",source);put("runtimeDirectory",directory.toString()) })
    }
    @Test fun `startup metadata contains source runtime and mode but no credentials`() {
        val managed=ManagedSettings.forExtension(emptyMap(),root)
        val result=managed.connectionMetadata()
        assertEquals("file",result["source"]!!.jsonPrimitive.content)
        assertEquals(root.resolve("runtime").toString(),result["runtimeDirectory"]!!.jsonPrimitive.content)
        assertEquals("REVIEW",result["authorizationMode"]!!.jsonPrimitive.content)
        assertFalse(result.toString().contains(managed.cphToken!!))
        assertFalse(result.toString().contains(managed.workerToken!!))
    }
    @Test fun `matching live file selection preserves exported configuration`() {
        val body=exported()
        val result=response(client(),200,body)
        assertEquals(body["config"],result["config"])
        assertTrue(result["success"]!!.jsonPrimitive.boolean)
        assertTrue(result["connectionDiagnostics"]!!.jsonObject["runtimeMatches"]!!.jsonPrimitive.boolean)
    }
    @Test fun `different live runtime is reported even with matching authentication`() {
        val client=client()
        val result=response(client,200,exported(root.resolve("other-clone")))
        assertFalse(result["connectionDiagnostics"]!!.jsonObject["runtimeMatches"]!!.jsonPrimitive.boolean)
        assertEquals("CPH_RUNTIME_MISMATCH",assertThrows(net.portswigger.diagnosis.contract.JobRejected::class.java) { client.export() }.message)
    }
    @Test fun `environment or older CPH cannot be claimed to have a matching runtime`() {
        val older=buildJsonObject { put("success",true);put("managed",true);put("config",JsonObject(emptyMap())) }
        assertEquals(JsonNull,response(client(),200,older)["connectionDiagnostics"]!!.jsonObject["runtimeMatches"])
        assertEquals(JsonNull,response(client("environment"),200,exported())["connectionDiagnostics"]!!.jsonObject["runtimeMatches"])
        assertEquals(JsonNull,response(client(),200,exported(source="environment"))["connectionDiagnostics"]!!.jsonObject["runtimeMatches"])
    }
    @Test fun `403 gives stopped maintenance guidance without guessing the CPH runtime`() {
        val result=response(client(),403,buildJsonObject { put("success",false);put("message","CPH_AUTH_REQUIRED") })
        assertFalse(result["success"]!!.jsonPrimitive.boolean)
        assertEquals(403,result["status"]!!.jsonPrimitive.int)
        val diagnostics=result["connectionDiagnostics"]!!.jsonObject
        assertEquals("CPH_AUTH_REQUIRED",diagnostics["code"]!!.jsonPrimitive.content)
        assertEquals(JsonNull,diagnostics["runtimeMatches"])
        assertTrue(diagnostics["guidance"]!!.jsonPrimitive.content.contains("Do not reload during diagnosis"))
    }
    @Test fun `non authentication failure is not labelled as credential mismatch`() {
        val result=response(client(),500,buildJsonObject { put("success",false);put("message","CPH_API_FAILED") })
        assertNull(result["connectionDiagnostics"]!!.jsonObject["code"])
    }
}
