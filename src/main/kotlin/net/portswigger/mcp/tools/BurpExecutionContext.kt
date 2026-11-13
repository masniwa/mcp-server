package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import net.portswigger.mcp.execution.CphClient

/** Native handles outlive MCP transport stop/start, but never pretend to survive extension/Burp reload. */
class BurpExecutionContext(api:MontoyaApi,val cph:CphClient=CphClient()) {
    val http1=net.portswigger.mcp.execution.Http1Sender(api)
    internal val activeAudits=ActiveAuditRegistry()
    internal val payloadRuns=PayloadRunRegistry(api)
    private val scanService=net.portswigger.mcp.execution.ActiveScanService(api,activeAudits,payloadRuns)
    fun start(input:StartActiveScan,config:net.portswigger.mcp.config.McpConfig):String=scanService.start(input,config)
}
