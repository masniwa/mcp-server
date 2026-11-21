package net.portswigger.mcp.tools

import burp.api.montoya.core.ByteArray as BurpBytes
import burp.api.montoya.http.Http
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.scanner.AuditResult
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint
import burp.api.montoya.scanner.scancheck.ActiveScanCheck

internal const val PAYLOAD_RUN_HEADER = "X-MCP-Payload-Run"

/** Register PER_REQUEST. The random marker isolates this run from other native audits.
 * The calling integration owns registration/unload and supplies the native audit gate.
 */
internal class PayloadActiveScanCheck(
    private val runToken: String,
    private val service: HttpService,
    private val method: String,
    private val path: String,
    private val execution: PayloadExecution,
    private val evidence: PayloadEvidenceStore,
    private val maySend: () -> Boolean,
    private val cancelled: () -> Boolean,
    private val timing: PayloadTimingCollection? = null,
    private val timingStore: PayloadEvidenceStore? = null
) : ActiveScanCheck {
    override fun checkName(): String = "MCP spreadsheet payloads"

    override fun doCheck(base: HttpRequestResponse, insertionPoint: AuditInsertionPoint, http: Http): AuditResult {
        val request = base.request()
        val incoming = request.httpService()
        if (request.headerValue(PAYLOAD_RUN_HEADER) != runToken ||
            incoming.host() != service.host() || incoming.port() != service.port() || incoming.secure() != service.secure() ||
            request.method() != method || request.path() != path) return AuditResult.auditResult()
        evidence.recordBaseline(PayloadExchange(request.toByteArray().bytes,
            if (base.hasResponse()) base.response().toByteArray().bytes else null,
            if (base.hasResponse()) base.response().statusCode().toInt() else null))
        val send: (ByteArray) -> PayloadExchange = { bytes ->
            val parsed = HttpRequest.httpRequest(service, BurpBytes.byteArray(*bytes))
            // Chunk framing needs a dedicated implementation; never rewrite it as a length body.
            require(!parsed.hasHeader("Transfer-Encoding")) { "Transfer-Encoding is not supported by the payload byte adapter" }
            val unmarked = parsed.withRemovedHeader(PAYLOAD_RUN_HEADER)
            val outgoing = if (unmarked.hasHeader("Content-Length") || unmarked.body().length() > 0)
                unmarked.withBody(unmarked.body()) else unmarked
            val submitted = outgoing.toByteArray().bytes.copyOf()
            val response = http.sendRequest(outgoing)
            PayloadExchange(response.request().toByteArray().bytes,
                if (response.hasResponse()) response.response().toByteArray().bytes else null,
                if (response.hasResponse()) response.response().statusCode().toInt() else null, submitted)
        }
        PayloadCancellationWatch(cancelled).during {
            val first=execution.execute(maySend,send,evidence::record)
            if(first && timing!=null) {
                if(execution.snapshot().any { it.state in setOf("ERROR","NO_RESPONSE","NOT_SENT") }) timing.stop()
                timing.execute(maySend,send,requireNotNull(timingStore)::record)
            }
        }
        // Grep matches are candidates for review, never fabricated native vulnerability issues.
        return AuditResult.auditResult()
    }
}
