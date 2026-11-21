package net.portswigger.mcp.jobs

import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.JobRejected
import net.portswigger.mcp.execution.CphClient
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*

class ManagedBoundaryTest {
    @Test fun `all known mutating tool entry points are blocked in managed mode`() {
        val dispatch=ToolDispatch(true);var calls=0
        val mutations=listOf("send_http1_request","send_http2_request","start_active_scan","set_project_options","set_user_options",
            "import_cph_config","send_to_intruder","create_repeater_tab","create_repeater_tab_http2","set_proxy_intercept_state",
            "set_task_execution_engine_state","set_active_editor_contents","generate_collaborator_payload","get_collaborator_interactions")
        mutations.forEach { tool ->
            dispatch.register(tool) { calls++;listOf(TextContent("side effect")) }
            assertThrows(JobRejected::class.java) { dispatch.publicCall(tool,JsonObject(emptyMap())) }
        }
        assertEquals(0,calls)
    }
    @Test fun `worker and legacy share the exact same registered implementation`() {
        val managed=ToolDispatch(true);var calls=0
        managed.register("send_http1_request") { args -> calls++;listOf(TextContent(args["content"]!!.jsonPrimitive.content)) }
        assertEquals("raw",(managed.workerCall("send_http1_request",buildJsonObject { put("content","raw") }).single() as TextContent).text)
        assertEquals(1,calls)
        val legacy=ToolDispatch(false);legacy.register("set_project_options") { listOf(TextContent("legacy preserved")) }
        assertEquals("legacy preserved",(legacy.publicCall("set_project_options",JsonObject(emptyMap())).single() as TextContent).text)
    }
    @Test fun `read permission boundaries are not replaced by an execution role`() {
        val managed=ToolDispatch(true)
        managed.register("get_logger_http_history") { throw JobRejected("EXISTING_DATA_ACCESS_DENIED") }
        assertEquals("EXISTING_DATA_ACCESS_DENIED",assertThrows(JobRejected::class.java) { managed.publicCall("get_logger_http_history",JsonObject(emptyMap())) }.code)
    }
    @Test fun `management opt in requires separate strong secrets and absolute storage`() {
        assertFalse(ManagedSettings.environment(emptyMap()).enabled)
        assertThrows(JobRejected::class.java) { ManagedSettings.environment(mapOf("BURP_DIAG_MANAGED" to "1")) }
        val env=mapOf("BURP_DIAG_MANAGED" to "1","BURP_DIAG_WORKER_TOKEN" to "a".repeat(32),"BURP_DIAG_CPH_TOKEN" to "b".repeat(32),"BURP_DIAG_STORE" to System.getProperty("user.dir"))
        val settings=ManagedSettings.environment(env)
        assertTrue(settings.authorized("Bearer ${"a".repeat(32)}"));assertFalse(settings.authorized(null));assertFalse(settings.authorized("Bearer wrong"))
        assertThrows(JobRejected::class.java) { ManagedSettings.environment(env+("BURP_DIAG_CPH_TOKEN" to "a".repeat(32))) }
    }
    @Test fun `CPH credential cannot be sent to an arbitrary readback host`() {
        val client=CphClient("secret".repeat(8))
        assertEquals("CPH_TOKEN_DESTINATION_FORBIDDEN",assertThrows(JobRejected::class.java) { client.exchange("/cph/export",host="attacker.invalid",port=17866) }.code)
    }
}
