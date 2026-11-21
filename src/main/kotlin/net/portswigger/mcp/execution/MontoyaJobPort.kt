package net.portswigger.mcp.execution

import burp.api.montoya.MontoyaApi
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.*
import net.portswigger.diagnosis.runner.BurpExecutionPort
import net.portswigger.diagnosis.runner.EvidenceStreamingPort
import net.portswigger.mcp.jobs.ToolDispatch
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.LinkOption
import java.nio.file.StandardOpenOption

/** Adapts approved workflow operations to the existing MCP handlers and native settings. */
class MontoyaJobPort(private val api:MontoyaApi,private val dispatch:ToolDispatch,private val cph:CphClient,
    private val instanceId:String,private val capabilities:Set<String>,private val directory:Path,
    private val allowedInputRoots:List<Path>,private val allowConfigurationEditing:()->Boolean={true},
    private val secretGenerations:()->Map<String,String> = {emptyMap()},
    private val loggerHistory:net.portswigger.mcp.tools.LoggerHttpHistory?=null) : BurpExecutionPort, EvidenceStreamingPort {
    private val auditCursors=java.util.concurrent.ConcurrentHashMap<String,net.portswigger.mcp.tools.LoggerHistoryStatus>()
    private val projectMarkerKey="diagnostic-job-project-marker-v1"
    private fun projectMarker():String? = runCatching {
        api.persistence().extensionData().getString(projectMarkerKey)
    }.getOrNull()
    override fun ensureProjectMarker():String {
        val data=api.persistence().extensionData()
        val existing=data.getString(projectMarkerKey)
        if(existing!=null) {
            requireJob(existing.matches(Regex("[0-9a-f-]{36}")),"PROJECT_MARKER_INVALID")
            return existing
        }
        val marker=java.util.UUID.randomUUID().toString()
        data.setString(projectMarkerKey,marker)
        requireJob(data.getString(projectMarkerKey)==marker,"PROJECT_MARKER_WRITE_FAILED")
        return marker
    }
    private val projectMutation=UiProjectMutation(
        { jobJson.parseToJsonElement(api.burpSuite().exportProjectOptionsAsJson()).jsonObject },
        { patch -> api.burpSuite().importProjectOptionsFromJson(patch.toString()) })
    @Volatile private var recoveryObservationCheckpoint = loggerHistory?.status()
    override fun beginRecoveryObservation() { recoveryObservationCheckpoint=loggerHistory?.status() }
    override fun recoveryInventoryStopped():Boolean = retainedNativeInventoryStopped(json("get_active_scan_status"))
    override fun reconcileSettings(expected:BurpSnapshot,target:BurpSnapshot,operationId:String) {
        requireJob(allowConfigurationEditing(),"CONFIG_EDITING_DISABLED")
        requireJob(fingerprint(snapshot())==fingerprint(expected),"CURRENT_CONTEXT_CHANGED")
        requireJob(expected.projectMarker!=null && target.projectMarker==expected.projectMarker && target.instanceId==expected.instanceId,"PROJECT_IDENTITY_UNVERIFIED")
        projectMutation.apply(expected.project,target.project)
        cph.apply(target.cph,target.cphOrder,expected.cph,operationId)
    }
    override fun recoveryTrafficObservation():JsonObject {
        val logger = loggerHistory?.recoveryObservation(recoveryObservationCheckpoint)
            ?: super.recoveryTrafficObservation()
        val activity = runCatching { cph.activity() }
        return JsonObject(logger + buildJsonObject {
            put("cphActivity", activity.getOrNull() ?: JsonNull)
            put("cphActivityError", activity.exceptionOrNull()?.let {
                JsonPrimitive((it as? JobRejected)?.code ?: it.javaClass.simpleName)
            } ?: JsonNull)
            put("macroLifecycle", "UNVERIFIED")
        })
    }

    private val recoveryCaptureCheckpoint=loggerHistory?.status()?.let { it.captureId to it.latestId }
    override fun retirementReadiness(auditId:String):Boolean = retirementInventoryReady(json("get_active_scan_status"),auditId)
    override fun recoveryReadiness(endpoints:List<Endpoint>):Boolean = loggerHistory?.quiescent(endpoints.map {
        net.portswigger.mcp.schema.HttpService(it.host,it.port,it.scheme=="https")
    }.toSet())==true
    override fun currentRecoveryReadiness(endpoints:List<Endpoint>):Boolean {
        val checkpoint=recoveryCaptureCheckpoint ?: return false
        return loggerHistory?.quiescentAfter(endpoints.map {
            net.portswigger.mcp.schema.HttpService(it.host,it.port,it.scheme=="https")
        }.toSet(),checkpoint.first,checkpoint.second)==true
    }
    override fun allTrafficQuiescent():Boolean = loggerHistory?.allQuiescent()==true
    override fun restoreCph(config:JsonObject,order:List<String>,expected:JsonObject,operationId:String) {
        requireJob(allowConfigurationEditing(),"CONFIG_EDITING_DISABLED")
        cph.apply(config,order,expected,operationId)
    }
    private fun text(name:String,args:JsonObject=JsonObject(emptyMap())):String =
        dispatch.workerCall(name,args).joinToString("\n") { (it as? TextContent)?.text ?: throw JobRejected("UNEXPECTED_TOOL_RESULT") }
    private fun json(name:String,args:JsonObject=JsonObject(emptyMap())):JsonObject {
        val result=jobJson.parseToJsonElement(text(name,args)).jsonObject
        requireJob(result["success"]?.jsonPrimitive?.booleanOrNull!=false,"TOOL_REJECTED")
        return result
    }
    override fun snapshot():BurpSnapshot {
        val config=cph.export()
        return BurpSnapshot(instanceId,jobJson.parseToJsonElement(api.burpSuite().exportProjectOptionsAsJson()).jsonObject,
            config,config.keys.toList(),capabilities,projectMarker=projectMarker())
    }
    override fun apply(variant:CompiledVariant) = apply(variant,"adapter:${java.util.UUID.randomUUID()}")
    override fun apply(variant:CompiledVariant,operationId:String) = apply(variant,snapshot(),operationId)
    override fun apply(variant:CompiledVariant,before:BurpSnapshot,operationId:String) {
        requireJob(allowConfigurationEditing(),"CONFIG_EDITING_DISABLED")
        requireJob(fingerprint(snapshot())==fingerprint(before),"CURRENT_CONTEXT_CHANGED")
        val expectedCph=before.cph
        // CPH I/O remains outside EDT to avoid deadlocking its UI-thread handlers.
        projectMutation.apply(before.project,variant.project)
        cph.apply(variant.cph,variant.cphOrder,expectedCph,operationId)
    }
    override fun restore(baseline:BurpSnapshot,ownedCphNames:Set<String>) =
        restore(baseline,ownedCphNames,"adapter:${java.util.UUID.randomUUID()}")
    override fun restore(baseline:BurpSnapshot,ownedCphNames:Set<String>,operationId:String) = restore(baseline,ownedCphNames,snapshot(),operationId)
    override fun restore(baseline:BurpSnapshot,ownedCphNames:Set<String>,before:BurpSnapshot,operationId:String) {
        requireJob(allowConfigurationEditing(),"CONFIG_EDITING_DISABLED")
        requireJob(fingerprint(snapshot())==fingerprint(before),"CURRENT_CONTEXT_CHANGED")
        val current=before.cph
        val residual=current.filterKeys { it !in baseline.cph && it in ownedCphNames }.mapValues { (_,v) ->
            JsonObject(v.jsonObject + ("enabled" to JsonPrimitive(false)))
        }
        requireJob(current.keys.all { it in baseline.cph || it in ownedCphNames },"UNOWNED_CPH_TAB_DURING_RESTORE")
        projectMutation.apply(before.project,baseline.project)
        val restored=JsonObject(baseline.cph+residual)
        val options=digest("options")
        val order=baseline.cphOrder.filter { it!=options }+residual.keys+listOfNotNull(options.takeIf { it in restored })
        cph.apply(restored,order,current,operationId)
    }
    override fun replaceCph(config:JsonObject,order:List<String>) {
        requireJob(allowConfigurationEditing(),"CONFIG_EDITING_DISABLED")
        requireJob(config.keys==order.toSet() && order.size==config.size,"CPH_ORDER_INCONSISTENT")
        val before=cph.export()
        val names=before.keys.filter { it !in config }
        requireJob(names.isNotEmpty() && names.all { it.startsWith("job:") && before[it]?.jsonObject?.get("enabled")?.jsonPrimitive?.booleanOrNull==false },
            "CPH_PRUNE_REQUIRES_DISABLED_EXISTING_HANDLERS")
        requireJob(before.filterKeys { it !in names }==config && before.keys.filter { it !in names }==order,
            "CPH_PRUNE_RETAINED_CONFIG_CHANGED")
        cph.prune(names,before)
    }
    private fun send(request:RequestPlan):String {
        val e=request.endpoint
        val response=dispatch.workerHttp1(buildJsonObject {
            put("targetHostname",e.host);put("targetPort",e.port);put("usesHttps",e.scheme=="https");put("content",request.request)
        })
        requireJob(response.startsWith("HTTP/"),"HTTP_PROBE_DENIED_OR_NO_RESPONSE")
        return response
    }
    private fun loggerPages(status:JsonObject,afterId:Long=0,onPage:((JsonElement)->Unit)?=null,pageSize:Int=100):JsonArray {
        if(loggerHistory!=null) {
            val through=status["latestId"]?.jsonPrimitive?.longOrNull ?: throw JobRejected("LOGGER_METADATA_MISSING")
            requireJob(status["captureId"]?.jsonPrimitive?.content==loggerHistory.status().captureId,"LOGGER_CAPTURE_CHANGED")
            val pages=mutableListOf<JsonElement>();var offset=0
            while(true) {
                val entries=loggerHistory.page(pageSize,offset,afterId,through)
                if(entries.isEmpty()) break
                val page=JsonPrimitive(entries.joinToString("\n") { Json.encodeToString(net.portswigger.mcp.tools.LoggerHistoryItem.serializer(),it) })
                if(onPage==null) pages.add(page) else onPage.invoke(page)
                offset+=entries.size;requireJob(offset<=1_000_000,"LOGGER_WINDOW_REVIEW_LIMIT")
            }
            return JsonArray(pages)
        }
        val count=status["retainedEntries"]?.jsonPrimitive?.intOrNull ?: throw JobRejected("LOGGER_METADATA_MISSING")
        requireJob(count<=100000,"LOGGER_REVIEW_LIMIT")
        val pages=mutableListOf<JsonElement>()
        for(offset in 0 until count step pageSize) {
            val result=text("get_logger_http_history",buildJsonObject { put("offset",offset);put("count",pageSize) })
            requireJob(!result.contains("access denied by Burp Suite"),"LOGGER_PERMISSION_DENIED")
            val page=JsonPrimitive(result)
            if(onPage==null) pages.add(page) else onPage.invoke(page)
        }
        return JsonArray(pages)
    }
    private fun captureHttpEvidence(action:()->String):Pair<String,JsonObject> {
        val before=json("get_logger_history_status")
        val lower=before["latestId"]?.jsonPrimitive?.longOrNull ?: throw JobRejected("LOGGER_METADATA_MISSING")
        requireJob(loggerCaptureWindowHealthy(before,before),"LOGGER_INCOMPLETE")
        if(loggerHistory==null) requireJob((before["retainedEntries"] as? JsonPrimitive)?.takeIf { !it.isString }?.intOrNull?.let { it>=0 }==true,"LOGGER_METADATA_MISSING")
        val response=action()
        val after=json("get_logger_history_status")
        requireJob(loggerCaptureWindowHealthy(before,after),"LOGGER_INCOMPLETE")
        return response to buildJsonObject { put("before",before);put("after",after);put("loggerWindow",loggerCaptureWindow(before,after));put("pages",loggerPages(after,lower));put("semanticReviewRequired",true) }
    }
    override fun oncePreparation(request:RequestPlan):Pair<String,JsonObject> {
        requireJob(request.startOptions.isEmpty(),"PREPARATION_ONCE_SCAN_OPTIONS_FORBIDDEN")
        return captureHttpEvidence { send(request) }
    }
    override fun probe(variant:ScanVariant,branch:String):Pair<String,JsonObject> {
        requireJob(branch=="normal" || branch in variant.branchSetup,"UNPREPARED_BRANCH")
        return captureHttpEvidence {
            variant.branchSetup[branch].orEmpty().forEach(::send)
            send(variant.request)
        }
    }
    override fun start(variant:ScanVariant):JsonObject {
        val before=loggerHistory?.status()
        if(before!=null) {
            val checkpoint=jobJson.encodeToJsonElement(before).jsonObject
            requireJob(loggerCaptureWindowHealthy(checkpoint,checkpoint),"LOGGER_INCOMPLETE")
        }
        val result=dispatch.workerScanStart(buildJsonObject {
            variant.request.startOptions.forEach { (k,v) -> put(k,v) }
            val e=variant.request.endpoint
            put("request",variant.request.request);put("host",e.host);put("port",e.port);put("protocol",e.scheme)
        })
        result["auditId"]?.jsonPrimitive?.contentOrNull?.let { audit -> before?.let { auditCursors[audit]=it } }
        return result
    }
    override fun poll(auditId:String):JsonObject {
        val result=json("get_active_scan_status",buildJsonObject { put("auditId",auditId) })
        // The public tool returns a single-audit envelope, while the execution port consumes its audit.
        val audit=result["audit"] as? JsonObject ?: throw JobRejected("AUDIT_STATUS_MISSING")
        requireJob(audit["auditId"]?.jsonPrimitive?.contentOrNull==auditId,"AUDIT_STATUS_ID_MISMATCH")
        return audit
    }
    override fun collect(auditId:String,payloadRunId:String?):JsonObject = collectEvidence(auditId,payloadRunId,null)
    override fun collectTo(auditId:String,payloadRunId:String?,save:(String,JsonElement)->JsonElement):JsonObject = collectEvidence(auditId,payloadRunId,save)
    private fun collectEvidence(auditId:String,payloadRunId:String?,save:((String,JsonElement)->JsonElement)?):JsonObject = collectPartialEvidence(
        auditId=auditId,payloadExpected=payloadRunId!=null,
        savePage=save,
        loggerCheckpoint=auditCursors[auditId]?.let { jobJson.encodeToJsonElement(it).jsonObject },
        native={ poll(auditId) },
        payloadPages={ emit ->
            if(payloadRunId!=null) {
                var offset=0
                while(true) {
                    val page=json("get_payload_scan_results",buildJsonObject {
                        put("runId",payloadRunId);put("offset",offset);put("count",1)
                        put("includeWireEvidence",true);put("includeReviewReport",offset==0)
                    })
                    emit(page)
                    val size=page["items"]?.jsonArray?.size ?: throw JobRejected("PAYLOAD_PAGE_MISSING")
                    val total=page["totalCandidates"]?.jsonPrimitive?.intOrNull ?: throw JobRejected("PAYLOAD_TOTAL_MISSING")
                    offset+=size
                    requireJob(offset>=total || size>0,"PAYLOAD_PAGINATION_STALLED")
                    requireJob(offset<=1000000,"PAYLOAD_RESULT_LIMIT")
                    if(offset>=total) break
                }
            }
        },
        loggerStatus={ json("get_logger_history_status") },
        loggerPages={ status,emit ->
            val cursor=auditCursors[auditId]
            if(cursor!=null) requireJob(cursor.captureId==status["captureId"]?.jsonPrimitive?.content,"LOGGER_CAPTURE_CHANGED")
            loggerPages(status,cursor?.latestId ?: 0,emit,pageSize=1)
            Unit
        },
        issues={ emit ->
            var offset=0
            while(true) {
                val page=text("get_scanner_issues",buildJsonObject { put("offset",offset);put("count",1) })
                if(page=="Reached end of items") break
                emit(JsonPrimitive(page));offset+=1
                requireJob(offset<=100000,"ISSUE_PAGINATION_LIMIT")
            }
        })
    private fun safeFile(path:Path):Path {
        val absolute=path.toAbsolutePath().normalize()
        var p:Path?=absolute
        while(p!=null) {
            requireJob(!Files.isSymbolicLink(p) && !Files.readAttributes(p,java.nio.file.attribute.BasicFileAttributes::class.java,LinkOption.NOFOLLOW_LINKS).isOther,"UNSAFE_INPUT_PATH")
            p=p.parent
        }
        val real=absolute.toRealPath()
        requireJob(allowedInputRoots.any { real.startsWith(it.toRealPath()) } || real.startsWith(directory.toRealPath()),"INPUT_OUTSIDE_APPROVED_ROOTS")
        return real
    }
    override fun freezeInputs(job:JobProposal):JobProposal {
        // Coverage omissions fail before input snapshots, operator approval or any workflow transport.
        job.variants.forEach { validateNativeInputCoverage(it.request,it.inputExclusions) }
        val inputs=directory.resolve("inputs");val evidence=directory.resolve("evidence")
        Files.createDirectories(inputs);Files.createDirectories(evidence)
        val hashes=mutableMapOf<String,String>()
        val variants=job.variants.map { v ->
            val profile=v.request.startOptions["payloadProfile"]?.jsonObject ?: return@map v
            val mapped=profile.toMutableMap()
            listOf("workbookPath","catalogPath").forEach { key -> profile[key]?.jsonPrimitive?.contentOrNull?.let { path ->
                val bytes=Files.readAllBytes(safeFile(Path.of(path)));val sha=digest(bytes)
                // A statically reviewed draft may already bind this source path. Check the actual copied bytes too.
                job.inputDigests[path]?.let { expected -> requireJob(sha==expected,"INPUT_CHANGED_DURING_FREEZE") }
                val dest=inputs.resolve("$sha-${Path.of(path).fileName}")
                if(!Files.exists(dest)) Files.write(dest,bytes,StandardOpenOption.CREATE_NEW)
                requireJob(digest(Files.readAllBytes(dest))==sha,"INPUT_SNAPSHOT_CHANGED")
                mapped[key]=JsonPrimitive(dest.toAbsolutePath().toString());hashes[dest.toAbsolutePath().toString()]=sha
            } }
            mapped["evidenceRoot"]=JsonPrimitive(evidence.toAbsolutePath().toString())
            val updated=v.copy(request=v.request.copy(startOptions=JsonObject(v.request.startOptions+("payloadProfile" to JsonObject(mapped)))))
            var offset=0
            do {
                val preflight=json("plan_payload_scan",buildJsonObject {
                    put("request",updated.request.request);put("host",updated.request.endpoint.host);put("port",updated.request.endpoint.port);put("protocol",updated.request.endpoint.scheme)
                    put("payloadProfile",JsonObject(mapped));updated.request.startOptions["insertionPointParameters"]?.let { put("insertionPointParameters",it) }
                    put("offset",offset);put("count",100)
                })
                requireJob(preflight["wirePlanReady"]?.jsonPrimitive?.booleanOrNull==true ||
                    preflight["nonDeferredWirePlanReady"]?.jsonPrimitive?.booleanOrNull==true,"PAYLOAD_PREFLIGHT_INCOMPLETE")
                val count=preflight["items"]?.jsonArray?.size ?: throw JobRejected("PAYLOAD_PLAN_PAGE_MISSING")
                val total=preflight["totalCandidates"]?.jsonPrimitive?.intOrNull ?: throw JobRejected("PAYLOAD_PLAN_TOTAL_MISSING")
                offset+=count;requireJob(offset>=total || count>0,"PAYLOAD_PLAN_PAGINATION_STALLED")
                Files.writeString(inputs.resolve("${fingerprint(preflight)}.plan.json"),preflight.toString(),StandardOpenOption.CREATE,StandardOpenOption.TRUNCATE_EXISTING)
                if(offset>=total) break
                requireJob(offset<=1000000,"PAYLOAD_PLAN_LIMIT")
            } while(true)
            updated
        }
        return job.copy(variants=variants,inputDigests=hashes)
    }
    override fun validateInputCoverage(plan:CompiledPlan) {
        plan.variants.forEach { compiled ->
            val variant=compiled.variant
            validateNativeInputCoverage(variant.request,variant.inputExclusions,
                InputCoverage.applicableActions(compiled.project,variant.request.endpoint))
        }
    }
    override fun verifyInputs(job:JobProposal) {
        job.inputDigests.forEach { (path,sha) -> requireJob(digest(Files.readAllBytes(safeFile(Path.of(path))))==sha,"APPROVED_INPUT_CHANGED") }
        if(job.session.secretGenerations.isNotEmpty()) {
            val actual=secretGenerations()
            requireJob(job.session.secretGenerations.all { (handle,generation) -> actual[handle]==generation },"SECRET_GENERATION_CHANGED_OR_UNAVAILABLE")
        }
    }
}

/** Current tracked inventory only; pre-reload/UI audits still need the mandatory human review. */
internal fun retirementInventoryReady(snapshot:JsonObject,oldAuditId:String):Boolean = runCatching {
    if(snapshot["success"]!=JsonPrimitive(true)) return@runCatching false
    val audits=snapshot["audits"] as? JsonArray ?: return@runCatching false
    audits.all { value ->
        val audit=value.jsonObject
        val id=audit["auditId"]?.jsonPrimitive?.contentOrNull
        val status=audit["auditStatusMessage"]?.jsonPrimitive?.contentOrNull?.trim()?.lowercase()?.removeSuffix(".")
        !id.isNullOrBlank() && id!=oldAuditId && audit["submissionError"]==null && audit["observationError"]==null &&
            ((audit["completed"]?.jsonPrimitive?.booleanOrNull==true && status in setOf("done","finished","complete","completed")) ||
                status in setOf("cancelled","canceled"))
    }
}.getOrDefault(false)
