package net.portswigger.mcp.jobs

import io.mockk.every
import io.mockk.spyk
import io.mockk.slot
import io.mockk.verify
import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.JobRejected
import net.portswigger.mcp.execution.CphClient
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.net.SocketTimeoutException
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
    @Test fun `CPH import and prune have longer bounded read timeouts than ordinary reads`() {
        val server=com.sun.net.httpserver.HttpServer.create(java.net.InetSocketAddress("127.0.0.1",0),0)
        server.createContext("/cph/export") { exchange ->
            Thread.sleep(200)
            runCatching { exchange.sendResponseHeaders(200,-1) }
            exchange.close()
        }
        server.createContext("/cph/import") { exchange ->
            exchange.requestBody.use { it.readBytes() }
            val body="""{"success":true}""".toByteArray()
            exchange.sendResponseHeaders(200,body.size.toLong())
            exchange.responseBody.use { it.write(body) }
        }
        server.createContext("/cph/prune") { exchange ->
            exchange.requestBody.use { it.readBytes() }
            Thread.sleep(200)
            val body="""{"success":true,"removedCount":1}""".toByteArray()
            exchange.sendResponseHeaders(200,body.size.toLong())
            exchange.responseBody.use { it.write(body) }
        }
        server.start()
        try {
            val client=CphClient(null,null,50,1000)
            assertThrows(SocketTimeoutException::class.java) { client.exchange("/cph/export",port=server.address.port) }
            val (status,body)=client.exchange("/cph/import","{}",port=server.address.port)
            assertEquals(200,status)
            assertTrue(body.contains("\"success\":true"))
            val (pruneStatus,pruneBody)=client.exchange("/cph/prune","{}",port=server.address.port)
            assertEquals(200,pruneStatus)
            assertTrue(pruneBody.contains("\"removedCount\":1"))
        } finally { server.stop(0) }
    }
    @Test fun `managed CPH apply sends exact baseline and operation to atomic endpoint without legacy fallback`() {
        val client=client();val body=slot<String>()
        val config=buildJsonObject { putJsonObject("job:demo:tab") { put("enabled",true) } }
        val expected=buildJsonObject { putJsonObject("job:old:tab") { put("enabled",false) } }
        every { client.exchange("/cph/import-atomic",capture(body),"127.0.0.1",17866) } returns
            (500 to """{"success":false,"code":"CPH_FIELD_SHAPE_INVALID","tabName":"job:demo:tab","fieldName":"static_expression","message":"CPH_API_FAILED"}""")
        val error=assertThrows(JobRejected::class.java) { client.apply(config,listOf("job:demo:tab"),expected,"demo:prepare-apply:reflection") }
        assertEquals("CPH_FIELD_SHAPE_INVALID",error.code)
        assertEquals("static_expression",error.safeDetails["fieldName"])
        val sent=Json.parseToJsonElement(body.captured).jsonObject
        assertEquals(expected,sent["expected"])
        assertEquals(config,sent["config"])
        assertEquals("demo:prepare-apply:reflection",sent["operationId"]!!.jsonPrimitive.content)
        verify(exactly=0) { client.exchange("/cph/import",any(),any(),any()) }
    }

    @Test fun cacheDependencyErrorsPreserveSafeCodeFieldAndStageWithoutLegacyImport() {
        val client=client()
        val config=buildJsonObject { putJsonObject("job:demo:tab") { put("enabled",true) } }
        for(code in listOf("CPH_CACHE_REFERENCE_REQUIRED","CPH_CACHE_REFERENCE_ORDER","CPH_CACHE_REFERENCE_CYCLE",
            "CPH_CACHE_REFERENCE_CONFLICT","CPH_CACHE_REFERENCE_NOT_RESTORED","CPH_IMPORT_READBACK_MISMATCH")) {
            val response=buildJsonObject {
                put("success",false);put("code",code);put("stage","preflight")
                put("tabName","job:demo:tab");put("fieldName","cached_selection");put("message",secret)
            }
            every { client.exchange("/cph/import-atomic",any(),"127.0.0.1",17866) } returns (500 to response.toString())
            val error=assertThrows(JobRejected::class.java) {
                client.apply(config,listOf("job:demo:tab"),JsonObject(emptyMap()),"demo:cache-error")
            }
            assertEquals(code,error.code)
            assertEquals(mapOf("tabName" to "job:demo:tab","fieldName" to "cached_selection","stage" to "preflight"),error.safeDetails)
            assertFalse(error.toString().contains(secret));assertFalse(error.safeDetails.toString().contains(secret))
        }
        verify(exactly=0) { client.exchange("/cph/import",any(),any(),any()) }
    }
}
