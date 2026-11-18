package net.portswigger.mcp.jobs

import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.ContentBlock
import kotlinx.serialization.json.JsonObject
import java.util.Collections
import java.util.WeakHashMap
import java.util.concurrent.ConcurrentHashMap
import net.portswigger.diagnosis.contract.requireJob

/** Both the legacy MCP facade and the approved worker invoke the same handlers. */
class ToolDispatch(val managed: Boolean) {
    private val handlers=ConcurrentHashMap<String,(JsonObject)->List<ContentBlock>>()
    private var http1Response:((JsonObject)->String)?=null
    fun registerWorkerHttp1(handler:(JsonObject)->String) { http1Response=handler }
    /** Internal typed response projection, never registered as a public MCP tool. */
    fun workerHttp1(args:JsonObject):String = (http1Response ?: error("Worker HTTP sender not registered"))(args)
    fun register(name:String, handler:(JsonObject)->List<ContentBlock>) { handlers[name]=handler }
    fun publicDescription(name:String,description:String):String =
        if(managed && name !in READ_TOOLS && name !in MANAGED_TOOLS)
            "MANAGED MODE: direct calls to this mutation tool are disabled (MANAGED_MODE_JOB_REQUIRED). Use diagnostic_job with a validated plan for configuration, import, sending, scan execution and stopped-job recovery. The following describes the legacy handler only.\n\n$description"
        else description
    fun publicCall(name:String, arguments:JsonObject):List<ContentBlock> {
        requireJob(!managed || name in READ_TOOLS || name in MANAGED_TOOLS,"MANAGED_MODE_JOB_REQUIRED")
        return workerCall(name,arguments)
    }
    /** Only the authenticated worker adapter calls this; it is never exposed as an MCP tool. */
    fun workerCall(name:String,arguments:JsonObject):List<ContentBlock> =
        (handlers[name] ?: error("Unsupported worker tool"))(arguments)
    companion object {
        private val MANAGED_TOOLS=setOf("diagnostic_job","diagnostic_stint")
        val READ_TOOLS=setOf("output_project_options","output_user_options","get_cph_config","get_macros","get_macro_detail",
            "get_session_handling_rules","get_active_scan_status","get_payload_scan_results","plan_payload_scan",
            "get_scanner_issues","get_proxy_http_history","get_proxy_http_history_regex","get_proxy_http_request_by_id",
            "get_logger_history_status","get_logger_http_history","get_logger_http_history_regex","get_logger_http_request_by_id",
            "get_proxy_websocket_history","get_proxy_websocket_history_regex","get_organizer_items","get_organizer_items_regex",
            "base64_encode","base64_decode","url_encode","url_decode","generate_random_string",
            "generate_cph_import_config","generate_session_validation_action","generate_invoke_extension_action","get_active_editor_contents","diagnostic_draft","review_workflow_evidence")
        private val servers=Collections.synchronizedMap(WeakHashMap<Server,ToolDispatch>())
        fun attach(server:Server,dispatch:ToolDispatch) { servers[server]=dispatch }
        fun forServer(server:Server):ToolDispatch = servers.getOrPut(server) { ToolDispatch(false) }
    }
}
