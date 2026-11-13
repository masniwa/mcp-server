package net.portswigger.mcp.execution
import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.scanner.AuditConfiguration
import burp.api.montoya.scanner.BuiltInAuditConfiguration
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.*
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.HttpRequestSecurity
import net.portswigger.mcp.tools.*

/** Shared native start implementation; legacy and approved job paths retain the same callback engine. */
internal class ActiveScanService(private val api:MontoyaApi, private val activeAudits:ActiveAuditRegistry,
    private val payloadRuns:PayloadRunRegistry) {
    fun start(input:StartActiveScan,config:McpConfig):String = with(input) {
            require(input.config==null) { "UNSUPPORTED_ACTIVE_SCAN_CONFIG: native Task insertion-point strategy and resource-pool assignment cannot be set by this API; verify them in Burp before submitting. No audit was created." }
            workload?.validate()
            // << mniwa
            require(etaProfile == null || etaProfile.matches(Regex("[A-Za-z0-9_.-]{1,128}"))) { "etaProfile must be a non-secret label of 1..128 letters, digits, underscore, period or hyphen" }
            // << mniwa
            val usesHttps = protocol.equals("https", ignoreCase = true)

            val allowed = runBlocking {
                HttpRequestSecurity.checkHttpRequestPermission(host, port, config, request, api)
            }
            if (!allowed) {
                api.logging().logToOutput("MCP Active Scan denied: $host:$port")
                return@with "Start active scan denied by Burp Suite"
            }

            val fixedContent = normalizeHttpContent(request)
            validateRawHttpRequest(fixedContent)
            val service = HttpService.httpService(host, port, usesHttps)
            val httpRequest = HttpRequest.httpRequest(service, fixedContent)

            val selectedOffsets = insertionPointParameters?.let { selectAuditParameters(httpRequest.parameters(), it, httpRequest.toByteArray().length()) }

            val auditConfiguration = AuditConfiguration.auditConfiguration(
                BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS
            )

            val payloadRun = payloadProfile?.let { payloadRuns.prepare(httpRequest, insertionPointParameters, it) }
            val scanRequest = payloadRun?.scanRequest ?: httpRequest
            // The marker header shifts body offsets. Resolve explicit native ranges again.
            val scanOffsets = if (payloadRun == null) selectedOffsets else insertionPointParameters?.let {
                selectAuditParameters(scanRequest.parameters(), it, scanRequest.toByteArray().length())
            }
            val audit = try { api.scanner().startAudit(auditConfiguration) } catch (error: Exception) {
                payloadRun?.close(); throw error
            }
            payloadRun?.audit = audit
            val auditId = activeAudits.register(audit, host, port, protocol, fixedContent.lineSequence().first().split(' ').getOrElse(1) { "" }, etaProfile, httpRequest.method(), buildJsonArray { httpRequest.parameters().map { it.type().name + ":" + it.name() }.sorted().forEach { add(it) } }.toString())
            payloadRun?.auditId = auditId
            val submissionError = activeAudits.submit(auditId) { addSelectedAuditRequest(audit, scanRequest, scanOffsets) }
            if (submissionError != null) {
                payloadRun?.submissionError = submissionError
                // Stop additional payload work, retain its ledger and native handle for investigation.
                runCatching { payloadRun?.close() }
            }

            api.logging().logToOutput(
                "MCP Active Scan submission ${if (submissionError == null) "returned" else "uncertain"}: auditId=$auditId host=$host port=$port protocol=$protocol requestLength=${fixedContent.length}"
            )
            payloadRun?.auditId = auditId

            val initialSnapshot = activeAudits.snapshot(auditId, workload)

            // << mniwa
            buildJsonObject {
                put("status", when {
                    submissionError != null -> "submission_outcome_unknown"
                    initialSnapshot?.containsKey("observationError") == true -> "submitted_status_unavailable"
                    else -> "started"
                })
                submissionError?.let { put("submissionError", it) }
                put("auditId", auditId)
                initialSnapshot?.get("observationError")?.let { put("observationError", it) }
                payloadRun?.let {
                    put("payloadRunId", it.id)
                    put("payloadCandidates", it.plan.candidates.size)
                    put("payloadReady", it.plan.candidates.count { c -> c.state == "READY" })
                    put("payloadEvidenceDirectory", it.directory.toString())
                }
                // >> 20261014 mniwa Include the initial estimate as soon as detected insertion points are exposed.
                put("timeEstimate", initialSnapshot?.get("timeEstimate") ?: JsonNull)
                // << mniwa
                put("host", host)
                put("port", port)
                put("protocol", protocol)
                put("requestLength", fixedContent.length)
                put("insertionPointMode", if (selectedOffsets == null) "AUTOMATIC" else "EXPLICIT_PARAMETER_VALUES")
                put("nativeTaskSettingsVerified",false)
                put("nativeTaskSettingsSource","BURP_TASK_NOT_CONTROLLED_BY_API")
                put("coverageState","NATIVE_INSERTION_POINT_REVIEW_REQUIRED")
                insertionPointParameters?.let { selectors -> put("selectedParameters", buildJsonArray { selectors.forEach { selector -> add(buildJsonObject { put("name", selector.name); put("type", selector.type) }) } }) }
                put("auditRequestCount", initialSnapshot?.get("auditRequestCount") ?: JsonNull)
                put("auditInsertionPointCount", initialSnapshot?.get("auditInsertionPointCount") ?: JsonNull)
                put("auditStatusMessage", initialSnapshot?.get("auditStatusMessage") ?: JsonNull)
            }.toString()
    }
}
