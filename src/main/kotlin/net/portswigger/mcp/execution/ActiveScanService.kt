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
import net.portswigger.diagnosis.contract.*

/** Shared native start implementation; legacy and approved job paths retain the same callback engine. */
internal class ActiveScanService(private val api:MontoyaApi, private val activeAudits:ActiveAuditRegistry,
    private val payloadRuns:PayloadRunRegistry) {
    private class Progress {
        var stage="PRECHECK"
        var nativeAttempted=false
        var nativeCreated=false
        var auditId:String?=null
        var payloadRunId:String?=null
        var accepted=false
        var rejectionCode:String?=null
        var observation:JsonObject?=null
        var cleanupErrorClass:String?=null
        var cleanup:(()->Unit)?=null
    }
    private sealed interface Outcome {
        data object Denied:Outcome
        data class Started(val body:JsonObject,val observation:JsonObject?):Outcome
    }
    fun start(input:StartActiveScan,config:McpConfig):String {
        val progress=Progress()
        return try { when(val outcome=perform(input,config,progress)) {
            Outcome.Denied -> LEGACY_SCAN_START_DENIED
            is Outcome.Started -> outcome.body.toString()
        } } catch(error:Exception) {
            if(!progress.nativeAttempted) runCatching { progress.cleanup?.invoke() }
            throw error
        }
    }
    /** Internal managed projection shares all native execution with the legacy facade. */
    fun startManaged(input:StartActiveScan,config:McpConfig):JsonObject {
        val p=Progress()
        return try { when(val outcome=perform(input,config,p)) {
            Outcome.Denied -> scanStartNotSubmitted("SCAN_START_PERMISSION_DENIED","PERMISSION_CHECK")
            is Outcome.Started -> JsonObject(outcome.body+outcome.observation.orEmpty().filterKeys {
                it in setOf("auditRequestCount","auditErrorCount","auditInsertionPointCount","auditIssueCount","auditStatusMessage","completed","nativeCompleted")
            })
        } } catch(error:Throwable) {
            if(error !is Exception && error !is LinkageError) throw error
            if(!p.nativeAttempted) {
                val cleanup=runCatching { p.cleanup?.invoke() }
                val rejection=scanStartNotSubmitted(p.rejectionCode ?: when(p.stage) {
                    "PERMISSION_CHECK" -> "SCAN_START_PERMISSION_CHECK_FAILED"
                    "REQUEST_PREPARATION" -> "SCAN_START_REQUEST_PREPARATION_FAILED"
                    "PAYLOAD_PREPARATION" -> "SCAN_START_PAYLOAD_PREPARATION_FAILED"
                    else -> "SCAN_START_PRECHECK_FAILED"
                },p.stage,error.javaClass.simpleName)
                // No native Audit was created; incomplete local cleanup is a separate observation.
                if(cleanup.isSuccess) rejection else JsonObject(rejection+mapOf(
                    "localPreparationCleanup" to JsonPrimitive("UNVERIFIED"),
                    "cleanupErrorClass" to JsonPrimitive(cleanup.exceptionOrNull()!!.javaClass.simpleName)))
            } else buildJsonObject {
                put("status",if(p.accepted) "submitted_status_unavailable" else "submission_outcome_unknown")
                put("stage",p.stage);put("nativeAuditCreated",if(p.nativeCreated) JsonPrimitive(true) else JsonNull)
                put("errorCode",if(p.accepted) "SCAN_START_POST_SUBMISSION_OBSERVATION_FAILED" else "SCAN_START_NATIVE_OUTCOME_UNKNOWN")
                put("causeClass",error.javaClass.simpleName)
                p.cleanupErrorClass?.let { put("cleanupErrorClass",it) }
                p.auditId?.let { id ->
                    put("auditId",id)
                    (p.observation ?: runCatching { activeAudits.snapshot(id) }.getOrNull())?.let { observed ->
                        for(field in listOf("auditRequestCount","auditErrorCount","auditInsertionPointCount","auditIssueCount","auditStatusMessage"))
                            observed[field]?.let { put(field,it) }
                    }
                }
                p.payloadRunId?.let { put("payloadRunId",it) }
                put(if(p.accepted) "observationError" else "submissionError","START_STAGE_FAILED")
            }
        }
    }
    private fun perform(input:StartActiveScan,config:McpConfig,p:Progress):Outcome = with(input) {
            p.rejectionCode="UNSUPPORTED_ACTIVE_SCAN_CONFIG"
            require(input.config==null) { "UNSUPPORTED_ACTIVE_SCAN_CONFIG: native Task insertion-point strategy and resource-pool assignment cannot be set by this API; verify them in Burp before submitting. No audit was created." }
            p.rejectionCode="INVALID_SCAN_WORKLOAD"
            workload?.validate()
            // << mniwa
            p.rejectionCode="INVALID_SCAN_ETA_PROFILE"
            require(etaProfile == null || etaProfile.matches(Regex("[A-Za-z0-9_.-]{1,128}"))) { "etaProfile must be a non-secret label of 1..128 letters, digits, underscore, period or hyphen" }
            p.rejectionCode=null
            // << mniwa
            val usesHttps = protocol.equals("https", ignoreCase = true)

            p.stage="PERMISSION_CHECK"
            val allowed = runBlocking {
                HttpRequestSecurity.checkHttpRequestPermission(host, port, config, request, api)
            }
            if (!allowed) {
                p.rejectionCode="SCAN_START_PERMISSION_DENIED"
                api.logging().logToOutput("MCP Active Scan denied: $host:$port")
                return@with Outcome.Denied
            }

            p.stage="REQUEST_PREPARATION"
            val fixedContent = normalizeHttpContent(request)
            validateRawHttpRequest(fixedContent)
            val service = HttpService.httpService(host, port, usesHttps)
            val httpRequest = HttpRequest.httpRequest(service, fixedContent)

            val selectedOffsets = insertionPointParameters?.let { selectAuditParameters(httpRequest.parameters(), it, httpRequest.toByteArray().length()) }

            val auditConfiguration = AuditConfiguration.auditConfiguration(
                BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS
            )

            p.stage="PAYLOAD_PREPARATION"
            val payloadRun = payloadProfile?.let { payloadRuns.prepare(httpRequest, insertionPointParameters, it) }
            p.payloadRunId=payloadRun?.id
            p.cleanup={ payloadRun?.close();Unit }
            val scanRequest = payloadRun?.scanRequest ?: httpRequest
            // The marker header shifts body offsets. Resolve explicit native ranges again.
            val scanOffsets = if (payloadRun == null) selectedOffsets else insertionPointParameters?.let {
                selectAuditParameters(scanRequest.parameters(), it, scanRequest.toByteArray().length())
            }
            p.stage="REQUEST_PREPARATION";p.rejectionCode="SCAN_START_SCANNER_SERVICE_UNAVAILABLE"
            val scanner=api.scanner()
            p.rejectionCode=null
            p.stage="NATIVE_AUDIT_CREATION";p.nativeAttempted=true
            val audit = try { scanner.startAudit(auditConfiguration) } catch (error: Throwable) {
                if(error !is Exception && error !is LinkageError) throw error
                runCatching { payloadRun?.close() }.exceptionOrNull()?.let { cleanup ->
                    p.cleanupErrorClass=cleanup.javaClass.simpleName;error.addSuppressed(cleanup)
                }
                throw error
            }
            p.nativeCreated=true
            payloadRun?.audit = audit
            val auditId = activeAudits.register(audit, host, port, protocol, fixedContent.lineSequence().first().split(' ').getOrElse(1) { "" }, etaProfile, httpRequest.method(), buildJsonArray { httpRequest.parameters().map { it.type().name + ":" + it.name() }.sorted().forEach { add(it) } }.toString())
            p.auditId=auditId
            payloadRun?.auditId = auditId
            p.stage="NATIVE_SUBMISSION"
            val submissionError = activeAudits.submit(auditId) { addSelectedAuditRequest(audit, scanRequest, scanOffsets) }
            p.accepted=submissionError==null
            if (submissionError != null) {
                payloadRun?.submissionError = submissionError
                // Stop additional payload work, retain its ledger and native handle for investigation.
                runCatching { payloadRun?.close() }
            }

            p.stage="POST_SUBMISSION_OBSERVATION"
            api.logging().logToOutput(
                "MCP Active Scan submission ${if (submissionError == null) "returned" else "uncertain"}: auditId=$auditId host=$host port=$port protocol=$protocol requestLength=${fixedContent.length}"
            )
            payloadRun?.auditId = auditId

            val initialSnapshot = activeAudits.snapshot(auditId, workload)
            p.observation=initialSnapshot

            // << mniwa
            Outcome.Started(buildJsonObject {
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
            },initialSnapshot)
    }
}
