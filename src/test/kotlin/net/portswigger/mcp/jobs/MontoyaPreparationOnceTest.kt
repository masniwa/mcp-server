package net.portswigger.mcp.jobs

import burp.api.montoya.MontoyaApi
import io.mockk.*
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.*
import net.portswigger.mcp.execution.*
import net.portswigger.mcp.schema.HttpService
import net.portswigger.mcp.tools.LoggerHistoryStatus
import net.portswigger.mcp.tools.LoggerHttpHistory
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path

class MontoyaPreparationOnceTest {
    private val api=mockk<MontoyaApi>(relaxed=true)
    private val cph=mockk<CphClient>(relaxed=true)
    private val dispatch=ToolDispatch(true)
    private val endpoint=Endpoint("https","preparation.fixture.invalid",8447,"/owned-state/revoke")
    private val raw="POST /owned-state/revoke HTTP/1.1\r\nHost: preparation.fixture.invalid:8447\r\nCookie: OwnedKey=observed-owned-value\r\nContent-Length: 0\r\n\r\n"
    private fun request()=RequestPlan(endpoint,raw,"observed",digest(raw))
    private fun port(logger:LoggerHttpHistory?=null):MontoyaJobPort {
        val root=Path.of("..","temp","approval-input-lifecycle-20261113","once-tests").toAbsolutePath().normalize()
        Files.createDirectories(root)
        return MontoyaJobPort(api,dispatch,cph,"instance",emptySet(),Files.createTempDirectory(root,"adapter-"),listOf(root),loggerHistory=logger)
    }
    private fun completeStatus()="""{"captureId":"capture","retainedEntries":0,"latestId":0,"droppedEntries":0,"captureErrors":0}"""

    @Test fun `once-only preparation uses existing approved HTTP sender preserving exact destination and bytes`() {
        var sent:JsonObject?=null;var starts=0
        dispatch.registerWorkerHttp1 { sent=it;"HTTP/1.1 204 No Content\r\n\r\n" }
        dispatch.register("get_logger_history_status") { listOf(TextContent(completeStatus())) }
        dispatch.register("start_active_scan") { starts++;error("preparation must never start a scan") }
        val result=port().oncePreparation(request())
        assertTrue(result.first.startsWith("HTTP/1.1 204"));assertEquals(JsonPrimitive(true),result.second["semanticReviewRequired"])
        assertEquals(raw,sent!!.getValue("content").jsonPrimitive.content)
        assertEquals(endpoint.host,sent!!.getValue("targetHostname").jsonPrimitive.content)
        assertEquals(endpoint.port,sent!!.getValue("targetPort").jsonPrimitive.int)
        assertTrue(sent!!.getValue("usesHttps").jsonPrimitive.boolean);assertEquals(0,starts)
        verify(exactly=0) { api.burpSuite().importProjectOptionsFromJson(any()) }
    }
    @Test fun `scan options and incomplete capture refuse once-only transport before any send`() {
        var sends=0
        dispatch.registerWorkerHttp1 { sends++;"HTTP/1.1 200 OK\r\n\r\n" }
        val port=port()
        val request=request().copy(startOptions=buildJsonObject { put("workload",JsonObject(emptyMap())) })
        assertEquals("PREPARATION_ONCE_SCAN_OPTIONS_FORBIDDEN",assertThrows(JobRejected::class.java) { port.oncePreparation(request) }.code)
        dispatch.register("get_logger_history_status") { listOf(TextContent(completeStatus().replace("\"captureErrors\":0","\"captureErrors\":null"))) }
        assertEquals("LOGGER_INCOMPLETE",assertThrows(JobRejected::class.java) { port.oncePreparation(request()) }.code)
        assertEquals(0,sends)
    }
    @Test fun historicalLossDoesNotPreventNewOnceOnlyEvidenceAndMissingPageMetadataRefusesBeforeSend() {
        var sends=0
        dispatch.registerWorkerHttp1 { sends++;"HTTP/1.1 200 OK\r\n\r\n" }
        val metadata=completeStatus().replace("\"captureErrors\":0","\"captureErrors\":1")
        dispatch.register("get_logger_history_status") { listOf(TextContent(metadata)) }
        assertTrue(port().oncePreparation(request()).first.startsWith("HTTP/1.1 200"));assertEquals(1,sends)
        dispatch.register("get_logger_history_status") { listOf(TextContent("""{"captureId":"capture","latestId":0,"droppedEntries":0,"captureErrors":0}""")) }
        assertEquals("LOGGER_METADATA_MISSING",assertThrows(JobRejected::class.java) { port().oncePreparation(request()) }.code)
        assertEquals(1,sends)
    }
    @Test fun `once-only capture window stays separate from the five-probe evidence window`() {
        LoggerHttpHistory().use { history ->
            val service=HttpService(endpoint.host,endpoint.port,true)
            history.recordRequest(1,"EXTENSIONS",service,endpoint.url(),"old request",null)
            history.recordResponse(1,"EXTENSIONS",service,endpoint.url(),"old request","old response",null)
            dispatch.register("get_logger_history_status") { listOf(TextContent(Json.encodeToString(LoggerHistoryStatus.serializer(),history.status()))) }
            var id=1
            dispatch.registerWorkerHttp1 { args ->
                id++;val request=args.getValue("content").jsonPrimitive.content
                val response="HTTP/1.1 200 OK\r\n\r\nresponse-$id"
                history.recordRequest(id,"EXTENSIONS",service,endpoint.url(),request,null)
                history.recordResponse(id,"EXTENSIONS",service,endpoint.url(),request,response,null)
                response
            }
            val port=port(history)
            val once=port.oncePreparation(request()).second.getValue("pages").jsonArray.single().jsonPrimitive.content
            val variant=ScanVariant("reflection","REFLECTION",request=request(),settings=SettingsPlan())
            val probe=port.probe(variant,"normal").second.getValue("pages").jsonArray.single().jsonPrimitive.content
            assertTrue(once.contains("response-2"));assertFalse(once.contains("old response"));assertFalse(once.contains("response-3"))
            assertTrue(probe.contains("response-3"));assertFalse(probe.contains("response-2"))
        }
    }
    @Test fun `no response or capture changed after once-only send remains failed evidence`() {
        var sends=0
        dispatch.register("get_logger_history_status") { listOf(TextContent(completeStatus())) }
        dispatch.registerWorkerHttp1 { sends++;"No response received" }
        val port=port()
        assertEquals("HTTP_PROBE_DENIED_OR_NO_RESPONSE",assertThrows(JobRejected::class.java) { port.oncePreparation(request()) }.code)
        var statusReads=0
        dispatch.registerWorkerHttp1 { sends++;"HTTP/1.1 200 OK\r\n\r\n" }
        dispatch.register("get_logger_history_status") {
            statusReads++;listOf(TextContent(completeStatus().replace("capture\"","capture-$statusReads\"")))
        }
        assertEquals("LOGGER_INCOMPLETE",assertThrows(JobRejected::class.java) { port.oncePreparation(request()) }.code)
        assertEquals(2,sends)
    }
}
