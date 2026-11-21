package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Registration
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.scanner.audit.Audit
import burp.api.montoya.scanner.scancheck.ScanCheckType
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import java.nio.file.Files
import java.nio.file.Path
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

internal const val PAYLOAD_SCAN_DESCRIPTION = "Optional payloadProfile adds spreadsheet payloads to the existing native audit. Optional timingControls adds explicit confirmation requests after the full spreadsheet attempts, without dropping or counting them as spreadsheet rows. Supply exact preflight positionId, mode append/replace, repetitions 3..10 and 2..6 levels, each with requestedDelayMillis (1..60000), trueValue and falseValue. Only parsed query/form/JSON value positions are supported; method/raw/array positions are refused for these controls. Values must already be authorized and semantically reviewed; placeholders are not bound. Baseline request is the normal control. Repeated writes can have side effects: verify authentication, repeatability, target permission and cleanup before using this option. Preflight reports additionalTimingControlRequests. The controls use the same Scanner callback Http and a separate timing-controls evidence directory, interleaving levels and alternating order. Missing response, non-2xx, cancellation or evidence failure stops the controls without replay; all remaining identities are retained. Omit timingControls for unchanged scan behavior. The collectedTimingComparison is a delay pattern, never an automatic SQLi verdict. Omit it to retain the existing scan path. For a user request to run ActiveScan at Hard, set payloadProfile.tier=hard; this includes light+medium+hard rows in the same native audit. Preserve each row's insertion mode and every compatible selected position, and use the same authentication, preparation, result and cleanup workflow as for Medium. Do not silently substitute Medium or treat the tier as a native Burp scan-intensity setting. tier is light (light only), medium (light+medium), or hard (all tiers); omitted modes means append, replace and array, each row only in its declared mode. Provide absolute local workbookPath and an existing authorized evidenceRoot on the Burp host. The workbook is read directly; no exported JSON catalog or exporter script is required. Optional catalogPath supports existing callers only: when supplied, every payload/grep definition and source digest must match the current workbook or preparation fails. Do not filter by family or prior Scan unless the user explicitly defers specific payloads. Optional deferredPayloads maps exact selected payload IDs to nonblank user-authorized reasons (at most 500 characters each). Unknown IDs or IDs outside the selected tier/modes are refused. Deferred rows remain in every planned position as NOT_EXECUTABLE with USER_DEFERRED:reason and are never sent or silently counted as tested. Full wirePlanReady/completed/allCandidatesRecorded remain false. Separate nonDeferredWirePlanReady/nonDeferredExecutionCompleted report only the remaining scope; they are false for an empty scope and are not diagnosis completion. Omit deferredPayloads for unchanged full-tier execution. Both paths preserve every selected payload ID, raw value, mode, context and guidance from the same workbook byte snapshot. bindings maps exact __TOKEN__ strings to observed authorized values. Never invent unresolved resources. Parameter payloads use parsed parameter positions, respecting insertionPointParameters. Optional jsonContainerPointers lists exact JSON Pointers to whole objects or arrays in a UTF-8 JSON body (empty string selects the root; ~1 escapes / and ~0 escapes ~). These add independent json-value positions to native leaf positions; each attempt starts from the baseline, so nested pointers do not accumulate changes. Native insertionPointParameters still names native parameters only; do not put a container-only name there. Missing/scalar/duplicate pointers, duplicate object keys, invalid JSON, nesting above 128, or bodies above 1 MiB are refused before Scan. Omit this option to preserve existing selection. Container replacement can change protected fields; observe normal and rejected objects and verify resulting state/cleanup. Spreadsheet category METHOD rows additionally replace only the request-line method token, never cookies or other raw parameter values; this method position is separate from the native parameter-value allowlist. Explain and authorize the potential method changes and verify diagnostic data and restoration before starting a tier that includes them. Other nonparameter header/path positions are not added. The catalog preserves category, guidance and caution from the workbook; inspect and follow these application constraints before scanning. array appends to query/form names; append extends values; replace replaces values. Incompatible contexts, missing bindings and missing positions are retained as nonexecutable candidates. Completion requires a recorded response at every compatible payload/position pair and at least one executed compatible position for every selected payload ID. Only declared context incompatibility is an accepted nonsend; missing bindings or no applicable position remain incomplete. No silent fallback or success. Transfer-Encoding is currently refused. A random X-MCP-Payload-Run header is added to associate the scan callback; an existing header of this name is refused. Additional payload requests remove this marker. Review marker compatibility and complete the usual authentication, Macro/CPH, baseline and cleanup checks before starting. Read get_payload_scan_results using payloadRunId to inspect every candidate and evidence, in addition to native audit status. The current integration requires validation before production use. "

@Serializable
data class PayloadScanOptions(
    val tier: String, val catalogPath: String? = null, val workbookPath: String, val evidenceRoot: String,
    val modes: List<String> = listOf("append", "replace", "array"),
    val bindings: Map<String, String> = emptyMap(),
    val jsonContainerPointers: List<String> = emptyList(),
    val timingControls: PayloadTimingControls? = null,
    val deferredPayloads: Map<String, String> = emptyMap()
)

@Serializable
data class GetPayloadScanResults(val runId: String, val offset: Int = 0, val count: Int = 50, val includeWireEvidence: Boolean = false,
    val includeReviewReport: Boolean = false, val timingRounds: List<PayloadTimingRoundRef> = emptyList())

@Serializable
data class PlanPayloadScan(val request: String, val host: String, val port: Int, val protocol: String,
    val payloadProfile: PayloadScanOptions, val insertionPointParameters: List<AuditParameterSelector>? = null,
    val offset: Int = 0, val count: Int = 50)

internal data class PreparedPayloadPlan(val catalog: PayloadProfileCatalog, val plan: PayloadWirePlan, val root: Path,
    val timing: PayloadTimingCollection? = null)

/** Shared by the read-only preflight and real start: no audit, registration or evidence writes. */
internal fun preparePayloadPlan(request: HttpRequest, selectors: List<AuditParameterSelector>?, options: PayloadScanOptions): PreparedPayloadPlan {
    require(!request.hasHeader(PAYLOAD_RUN_HEADER)) { "Reserved payload-run header is already present" }
    require(!request.hasHeader("Transfer-Encoding")) { "Payload scan does not yet support Transfer-Encoding" }
    val catalog = loadPayloadProfile(options.catalogPath?.let(Path::of), Path.of(options.workbookPath))
    val root = Path.of(options.evidenceRoot).toAbsolutePath().normalize()
    require(Files.isDirectory(root)) { "Evidence root must be an existing authorized local directory" }
    val bytes = request.toByteArray().bytes
    val form = request.headerValue("Content-Type")?.substringBefore(';')?.trim()?.equals("application/x-www-form-urlencoded", true) == true
    if (options.jsonContainerPointers.isNotEmpty()) {
        val mediaType = request.headerValue("Content-Type")?.substringBefore(';')?.trim()?.lowercase()
        require(mediaType == "application/json" || mediaType?.endsWith("+json") == true) { "JSON container pointers require JSON Content-Type" }
    }
    val positions = resolvePayloadPositions(bytes, request.parameters(), selectors, form) +
        resolvePayloadJsonContainers(bytes, options.jsonContainerPointers) +
        if (catalog.select(options.tier, options.modes).any { it.category == "METHOD" })
            listOf(resolvePayloadMethodPosition(bytes)) else emptyList()
    return PreparedPayloadPlan(catalog, PayloadWirePlan.create(bytes, catalog, options.tier, positions, options.bindings, options.modes, options.deferredPayloads), root,
        options.timingControls?.let { prepareTimingCollection(bytes,positions,it) })
}

internal fun payloadPlanSummary(prepared: PreparedPayloadPlan, offset: Int, count: Int): String {
    require(offset >= 0 && count in 1..100) { "Expected nonnegative offset and count 1..100" }
    val plan = prepared.plan
    val rows = plan.candidates
    val groups = rows.groupBy { it.payloadId }
    val activeRows = rows.filterNot { it.reason?.startsWith("USER_DEFERRED:") == true }
    val activeGroups = activeRows.groupBy { it.payloadId }
    return buildJsonObject {
        put("status", "planned_without_sending")
        put("sourceSha256", plan.sourceSha256); put("requestSha256", plan.requestSha256)
        put("selectedPayloads", groups.size); put("totalCandidates", rows.size)
        put("additionalTimingControlRequests", prepared.timing?.snapshot()?.size ?: 0)
        put("readyCandidates", rows.count { it.state == "READY" })
        put("deferredPayloadIds", buildJsonArray { groups.filterValues { group -> group.all { it.reason?.startsWith("USER_DEFERRED:") == true } }.keys.forEach { add(it) } })
        put("nonDeferredWirePlanReady", activeGroups.isNotEmpty() && activeGroups.values.all { group -> group.any { it.state == "READY" } } &&
            activeRows.all { it.state == "READY" || it.reason == "CONTEXT_NOT_APPLICABLE" })
        put("wirePlanReady", groups.isNotEmpty() && groups.values.all { group -> group.any { it.state == "READY" } } &&
            rows.all { it.state == "READY" || it.reason == "CONTEXT_NOT_APPLICABLE" })
        put("payloadsWithoutReadyPosition", buildJsonArray { groups.filterValues { group -> group.none { it.state == "READY" } }.keys.forEach { add(it) } })
        put("missingBindings", buildJsonArray { rows.flatMap { it.missingBindings }.distinct().sorted().forEach { add(it) } })
        put("offset", offset); put("count", count)
        put("items", buildJsonArray { rows.drop(offset).take(count).forEach { row -> add(buildJsonObject {
            put("payloadId", row.payloadId); put("positionId", row.positionId?.let(::JsonPrimitive) ?: JsonNull)
            put("mode", row.mode); put("state", row.state); put("reason", row.reason?.let(::JsonPrimitive) ?: JsonNull)
            put("missingBindings", buildJsonArray { row.missingBindings.forEach { add(it) } })
        }) } })
    }.toString()
}

internal class PayloadRunRegistry(private val api: MontoyaApi) {
    internal class Run(val id: String, val plan: PayloadWirePlan, val execution: PayloadExecution,
        val store: PayloadEvidenceStore, val directory: Path, val scanRequest: HttpRequest,
        val timing: PayloadTimingCollection? = null, val timingStore: PayloadEvidenceStore? = null) {
        @Volatile var audit: Audit? = null
        @Volatile var auditId: String? = null
        @Volatile var submissionError: String? = null
        var registration: Registration? = null
        private val closed = AtomicBoolean()
        fun close() { execution.stop(); timing?.stop(); if (closed.compareAndSet(false, true)) registration?.deregister() }
        fun cancelled(): Boolean = closed.get() ||
            audit?.statusMessage()?.trim()?.lowercase()?.removeSuffix(".") in setOf("cancelled", "canceled")
        fun maySend(): Boolean {
            while (!closed.get()) {
                when (audit?.statusMessage()?.trim()?.lowercase()?.removeSuffix(".")) {
                    "scanning", "auditing", "running" -> return true
                    "paused", "queued", "waiting", "starting" -> Thread.sleep(100)
                    else -> return false
                }
            }
            return false
        }
    }
    private val runs = ConcurrentHashMap<String, Run>()

    fun prepare(request: HttpRequest, selectors: List<AuditParameterSelector>?, options: PayloadScanOptions): Run {
        val (catalog, plan, root, timing) = preparePayloadPlan(request, selectors, options)
        val id = UUID.randomUUID().toString()
        val dir = root.resolve("payload-$id")
        val store = PayloadEvidenceStore.create(dir, plan, catalog.grep)
        val timingStore = timing?.let { PayloadEvidenceStore.createControls(dir.resolve("timing-controls"),it.snapshot(),plan.requestSha256) }
        val run = Run(id, plan, PayloadExecution(plan), store, dir, request.withAddedHeader(PAYLOAD_RUN_HEADER, id),timing,timingStore)
        run.registration = api.scanner().registerActiveScanCheck(PayloadActiveScanCheck(id, request.httpService(),
            request.method(), request.path(), run.execution, store, run::maySend, run::cancelled,timing,timingStore), ScanCheckType.PER_REQUEST)
        api.extension().registerUnloadingHandler { run.close() }
        runs[id] = run
        return run
    }

    fun results(id: String, offset: Int, count: Int, includeWire: Boolean, includeReviewReport: Boolean = false,
        timingRounds: List<PayloadTimingRoundRef> = emptyList()): String {
        require(offset >= 0 && count in 1..100) { "Expected nonnegative offset and count 1..100" }
        val run = runs[id] ?: return buildJsonObject { put("success", false); put("errorCode", "PAYLOAD_RUN_NOT_TRACKED") }.toString()
        val result = results(run, offset, count, includeWire, includeReviewReport)
        if (timingRounds.isEmpty()) return result
        val comparison = resolvePayloadTiming(timingRounds) { key -> runs[key] ?: error("Timing evidence run is not tracked") }
        return buildJsonObject {
            Json.parseToJsonElement(result).jsonObject.forEach { (key, value) -> put(key, value) }
            put("timingComparison", Json.encodeToJsonElement(comparison))
        }.toString()
    }

    internal fun results(run: Run, offset: Int, count: Int, includeWire: Boolean, includeReviewReport: Boolean = false): String {
        val id = run.id
        val rows = run.execution.snapshot()
        val observation = run.audit?.let { audit -> runCatching { audit.statusMessage() } }
        val message = observation?.getOrNull()
        val nativeComplete = message?.trim()?.lowercase()?.removeSuffix(".") in setOf("done", "finished", "complete", "completed")
        if (nativeComplete || (run.execution.callbackFinished && (run.timing?.finished != false))) run.close()
        val grepComplete = if (run.execution.callbackFinished) rows.all { item ->
            if (item.state == "NOT_EXECUTABLE" && item.reason == "CONTEXT_NOT_APPLICABLE") true
            else item.requestSha256 != null && run.store.read(item.index, item).grep.all { it.state in setOf("MATCH", "NO_MATCH") }
        } else false
        val timingRecorded = run.timing?.let { it.finished && it.snapshot().all { row -> row.state=="RESPONSE_RECEIVED" } } ?: true
        val nonDeferredGrepComplete = run.execution.callbackFinished && rows.filterNot { it.reason?.startsWith("USER_DEFERRED:") == true }.all { item ->
            if (item.state == "NOT_EXECUTABLE" && item.reason == "CONTEXT_NOT_APPLICABLE") true
            else item.requestSha256 != null && run.store.read(item.index, item).grep.all { it.state in setOf("MATCH", "NO_MATCH") }
        }
        val executionCompleted = run.submissionError == null && nativeComplete && run.execution.allCandidatesRecorded() && grepComplete && timingRecorded
        val timingRows = run.timing?.snapshot().orEmpty()
        val timingEvidence = timingRows.associate { item -> item.index to
            if (item.requestSha256 != null) requireNotNull(run.timingStore).read(item.index, item) else null }
        val timingComparison = run.timing?.comparison(run.plan.requestSha256, "$id:timing", timingRows)
        val report = if (includeReviewReport) payloadReviewReport(id, run.plan.requestSha256, rows.map { item ->
            val evidence = if (item.requestSha256 != null) run.store.read(item.index, item) else null
            item to run.store.triage(item, evidence)
        }, executionCompleted, timingRows, timingComparison) else null
        return buildJsonObject {
            put("success", true); put("runId", id); put("auditId", run.auditId?.let(::JsonPrimitive) ?: JsonNull)
            put("nativeAuditStatus", message?.let(::JsonPrimitive) ?: JsonNull)
            observation?.exceptionOrNull()?.let { put("nativeObservationError", it.javaClass.simpleName + ": " + it.message) }
            put("nativeCompleted", nativeComplete); put("payloadCallbackFinished", run.execution.callbackFinished)
            put("allCandidatesRecorded", run.execution.allCandidatesRecorded())
            put("grepEvaluationComplete", grepComplete)
            run.submissionError?.let { put("submissionError", it) }
            put("completed", executionCompleted)
            put("deferredPayloadIds", buildJsonArray { rows.filter { it.reason?.startsWith("USER_DEFERRED:") == true }.map { it.payloadId }.distinct().forEach { add(it) } })
            put("nonDeferredExecutionCompleted", run.submissionError == null && nativeComplete &&
                run.execution.allNonDeferredCandidatesRecorded() && nonDeferredGrepComplete && timingRecorded)
            put("completionScope", "EXECUTION_AND_EVIDENCE_ONLY")
            put("diagnosisCompleted", false)
            run.timing?.let { timing ->
                put("timingControlsFinished",timing.finished)
                put("timingControls",buildJsonArray {
                    timingRows.forEach { item ->
                        val evidence=timingEvidence[item.index]
                        if(includeWire && evidence!=null) add(Json.encodeToJsonElement(evidence))
                        else add(buildJsonObject {put("item",Json.encodeToJsonElement(item))})
                    }
                })
                put("collectedTimingComparison",Json.encodeToJsonElement(requireNotNull(timingComparison)))
            }
            report?.let { put("reviewReportMarkdown", it) }
            put("sourceSha256", run.plan.sourceSha256); put("requestSha256", run.plan.requestSha256)
            put("evidenceDirectory", run.directory.toString()); put("totalCandidates", rows.size)
            put("offset", offset); put("count", count)
            if (includeWire) put("scannerBaseline", run.store.readBaseline()?.let { Json.encodeToJsonElement(it) } ?: JsonNull)
            put("items", buildJsonArray {
                rows.drop(offset).take(count).forEach { item ->
                    if (item.requestSha256 != null) {
                        val evidence = run.store.read(item.index, item)
                        add(buildJsonObject {
                            if (includeWire) Json.encodeToJsonElement(evidence).jsonObject.forEach { (key, value) -> put(key, value) }
                            else { put("item", Json.encodeToJsonElement(item)); put("grep", Json.encodeToJsonElement(evidence.grep)) }
                            put("triage", Json.encodeToJsonElement(run.store.triage(item, evidence)))
                        })
                    } else add(buildJsonObject {
                        put("item", Json.encodeToJsonElement(item)); put("grep", JsonArray(emptyList()))
                        put("triage", Json.encodeToJsonElement(run.store.triage(item, null)))
                    })
                }
            })
        }.toString()
    }
}
