package net.portswigger.mcp.jobs

import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.*
import net.portswigger.diagnosis.runner.*
import net.portswigger.mcp.tools.mcpTool
import net.portswigger.mcp.tools.LOGIN_PREPARATION_GUIDANCE
import net.portswigger.mcp.tools.RATE_LIMIT_OBSERVATION_GUIDANCE
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors

@OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
@Serializable data class DiagnosticJob(val action:String,val executionId:String,val proposalJson:String?=null,
    val operationId:String?=null,val validationDigest:String?=null,val evidenceRef:String?=null,
    val index:Int=0,val offset:Int=0,val count:Int=20,
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER) val draftId:String?=null,
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER) val draftDigest:String?=null,
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER) val nextTargetsJson:String?=null)

/** One independent executor owns the workflow after approval; MCP calls never wait for a dialog. */
class DiagnosticJobService(private val worker:GuardedWorker,private val store:JobStore,val quick:Boolean, private val profileFile:java.nio.file.Path?=null,
    private val installation:InstallationVerification?=null):AutoCloseable {
    val drafts = JobDrafts(worker, store)
    val lookAhead = LookAheadPlanner(worker, store, drafts)
    private val executor=Executors.newCachedThreadPool { r -> Thread(r,"burp-diagnostic-job").apply { isDaemon=true } }
    private val active=ConcurrentHashMap<String,String>()
    private val executingOperation=ThreadLocal<String>()
    fun approvalPhase(value:String) {
        executingOperation.get()?.let { id ->
            val op=operation(id);store.put("mcp-operation:$id",JsonObject(op+("phase" to JsonPrimitive(value))))
        }
    }
    init {
        // Interrupted operations are observed, never silently replayed on extension reload.
        store.keys("mcp-operation:").forEach { key ->
            val value=store.get(key)!!.jsonObject
            if(value["state"]==JsonPrimitive("RUNNING")) store.put(key,JsonObject(value+mapOf("state" to JsonPrimitive("OUTCOME_UNKNOWN"),"nextAction" to JsonPrimitive("INSPECT_EXECUTION"))))
        }
    }
    private fun encode(value:ExecutionRecord)=jobJson.encodeToJsonElement(value)
    private fun record(id:String)=runCatching { worker.record(id) }.getOrNull()
    private fun operation(id:String)=store.get("mcp-operation:$id")?.jsonObject ?: throw JobRejected("OPERATION_NOT_FOUND")
    private fun planning(body:JsonObject,id:String):JsonObject {
        val original=lookAhead.report(id)
        val report=if(installation?.owns(id)==true) JsonObject(original+mapOf(
            "epochMatches" to JsonPrimitive(record(id)?.epoch==installation.epoch),
            "installationVerification" to JsonPrimitive(true))) else original
        return JsonObject(body+buildJsonObject {
            put("lookAheadPlanning",report)
            report["agentNextAction"]?.let { put("agentNextAction",it) }
        })
    }
    private fun next(r:ExecutionRecord?,op:JsonObject?):String = when {
        op?.get("state")==JsonPrimitive("RUNNING") && op["phase"]?.jsonPrimitive?.contentOrNull?.startsWith("AWAITING_")==true -> "APPROVE_STAGE_IN_BURP_THEN_POLL_SAME_OPERATION"
        op?.get("state")==JsonPrimitive("RUNNING") -> "POLL_SAME_OPERATION"
        op?.get("state")==JsonPrimitive("OUTCOME_UNKNOWN") -> "INSPECT_EXECUTION_NEVER_REPLAY"
        op?.get("state")==JsonPrimitive("FAILED") && op["errorCode"]==JsonPrimitive("HUMAN_DENIED") -> "WAIT_FOR_EXPLICIT_USER_RETRY"
        r?.state=="STATIC_VALIDATED" -> "PREPARE"
        r?.state=="VALIDATED" -> "REVIEW_VALIDATION_THEN_EXECUTE"
        r?.state=="EXECUTION_APPROVED" -> "EXECUTE_NEXT_VARIANT"
        r?.state in setOf("RUNNING","OBSERVATION_UNKNOWN") -> "OBSERVE_EXISTING_AUDIT_NEVER_RESTART"
        r?.state=="CONTROL_REQUIRED" && r.auditId!=null && r.warnings.lastOrNull() in setOf("APPROVAL_EXPIRED_OR_REVOKED_NATIVE_MAY_CONTINUE","APPROVAL_NOT_VALID") -> "REVIEW_APPROVAL_THEN_RENEW_SAME_AUDIT_OR_RECOVER"
        r?.state in setOf("CONTROL_REQUIRED","RECOVERY_REQUIRED","SUBMISSION_UNKNOWN") -> "VERIFY_NATIVE_STOPPED_THEN_RECOVER"
        r?.state=="EXECUTION_FINISHED" -> "REVIEW_RESULTS_AND_BUSINESS_CLEANUP"
        r?.state=="FAILED_RECONCILED" -> "CORRECT_REVALIDATE_NEW_EXECUTION"
        r?.state=="RETIRED_UNVERIFIED" -> "OLD_CONTEXT_RETIRED_DIAGNOSIS_AND_CLEANUP_INCOMPLETE"
        else -> "INSPECT_EXECUTION"
    }
    fun status(id:String):JsonObject {
        val r=record(id);val op=(active[id] ?: store.get("mcp-last-operation:$id")?.jsonPrimitive?.contentOrNull)?.let(::operation)
        requireJob(r!=null || op!=null,"NOT_FOUND")
        return planning(buildJsonObject {
            put("mode",if(quick) "QUICK" else "REVIEW");put("execution",r?.let(::encode) ?: JsonNull)
            val context=worker.contextStatus()
            val owner=context["ownerExecutionId"]?.jsonPrimitive?.contentOrNull
            put("context",if(owner!=null && installation?.owns(owner)==true)
                JsonObject(context+("ownerEpochChanged" to JsonPrimitive(record(owner)?.epoch!=installation.epoch))) else context)
            store.get("draft-origin:$id")?.let { put("draftOrigin",it) }
            op?.let { put("operation",it) };put("nextAction",next(r,op))
            if(r?.auditId!=null) {
                val native=runCatching { worker.observeNative(id) }.getOrNull()
                put("native",native ?: JsonNull)
            }
            put("diagnosisCompleted",false)
        },id)
    }
    @Synchronized private fun submit(input:DiagnosticJob):JsonObject {
        requireJob(input.action in setOf("propose","prepare","execute","advance","capture","recover","renew_continuation","retire","verify_exclusive_context","verify_scanner_workflow","verify_dynamic_workflow"),"UNSUPPORTED_JOB_ACTION")
        requireJob(input.action!="retire" || !quick,"HUMAN_MAINTENANCE_REVIEW_REQUIRED")
        val identity=fingerprint(jobJson.encodeToJsonElement(input.copy(operationId=null,index=0,offset=0,count=20)))
        val id=input.operationId ?: UUID.randomUUID().toString()
        requireJob(id.matches(Regex("[A-Za-z0-9_-]{1,100}")),"INVALID_OPERATION_ID")
        store.get("mcp-operation:$id")?.jsonObject?.let { old ->
            requireJob(old["requestDigest"]==JsonPrimitive(identity),"OPERATION_ID_REUSED");return old
        }
        if(input.action!="capture") active[input.executionId]?.let { return operation(it) }
        val start=buildJsonObject {
            put("operationId",id);put("executionId",input.executionId);put("action",input.action)
            put("requestDigest",identity);put("state","RUNNING");put("nextAction","POLL_SAME_OPERATION")
            put("phase","RUNNING")
        }
        store.put("mcp-operation:$id",start)
        store.put("mcp-last-operation:${input.executionId}",JsonPrimitive(id))
        if(input.action!="capture") active[input.executionId]=id
        executor.submit {
            executingOperation.set(id)
            val result=try {
                when(input.action) {
                    "verify_scanner_workflow","verify_dynamic_workflow" ->
                        (installation ?: throw JobRejected("INSTALLATION_PROFILE_UNAVAILABLE")).run(input.executionId,input.action=="verify_dynamic_workflow")
                    "verify_exclusive_context" -> {
                        requireJob(record(input.executionId) == null, "EXECUTION_ID_REUSED")
                        val profile = InstallationProfile(profileFile ?: throw JobRejected("INSTALLATION_PROFILE_UNAVAILABLE"))
                        val approved = java.util.concurrent.atomic.AtomicBoolean(false)
                        javax.swing.SwingUtilities.invokeAndWait {
                            approved.set(javax.swing.JOptionPane.showConfirmDialog(null,
                                "Test the exclusive ownership guard on this installation and register EXCLUSIVE_CONTEXT if verified?",
                                "Installation verification", javax.swing.JOptionPane.YES_NO_OPTION)
                                == javax.swing.JOptionPane.YES_OPTION)
                        }
                        requireJob(approved.get(), "HUMAN_DENIED")
                        profile.register(worker.verifyExclusiveContext())
                    }
                    "propose" -> {
                        val candidate=if(input.draftId!=null) drafts.load(input.draftId,input.draftDigest!!).plan.proposal
                            else jobJson.decodeFromString<JobProposal>(input.proposalJson ?: throw JobRejected("PROPOSAL_REQUIRED"))
                        val known=record(input.executionId)!=null
                        if(!known) {
                            lookAhead.requirePromotion(candidate,input.draftId,input.draftDigest)
                            // Refuse a new registration before waiting on another workflow's execution monitor.
                            requireJob(worker.contextStatus()["ownerExecutionId"]==JsonNull,"BURP_CONTEXT_BUSY")
                        }
                        val register={
                            if(input.draftId!=null) {
                                requireJob(worker.contextStatus()["ownerExecutionId"]==JsonNull,"BURP_CONTEXT_BUSY")
                                worker.registerDraft(input.executionId,drafts.load(input.draftId,input.draftDigest!!))
                            } else worker.register(input.executionId,candidate)
                        }
                        val plan=if(known) {
                            register().also { lookAhead.recordPromotion(candidate,input.draftId,input.draftDigest,input.executionId) }
                        } else lookAhead.withPromotion(candidate,input.draftId,input.draftDigest,input.executionId,register)
                        buildJsonObject {
                            put("planDigest",plan.planDigest);put("state","STATIC_VALIDATED")
                            store.get("draft-origin:${input.executionId}")?.let { put("draftOrigin",it) }
                        }
                    }
                    "prepare" -> {
                        val r=worker.record(input.executionId)
                        if(r.state=="STATIC_VALIDATED") worker.approve(input.executionId,ApprovalStage.PREPARATION)
                        if(worker.record(input.executionId).state!="VALIDATED") worker.prepare(input.executionId)
                        val report=worker.validation(input.executionId)
                        buildJsonObject { put("state","VALIDATED");put("validationDigest",fingerprint(report));put("probeCount",report.probes.size);put("semanticReviewRequired",true) }
                    }
                    "execute" -> {
                        requireJob(input.validationDigest==fingerprint(worker.validation(input.executionId)),"VALIDATION_REVIEW_DIGEST_REQUIRED")
                        var r=worker.record(input.executionId)
                        if(r.state in setOf("VALIDATED","EXECUTION_APPROVED")) lookAhead.requireDeclared(input.executionId)
                        if(r.state=="VALIDATED") { worker.approve(input.executionId,ApprovalStage.EXECUTION);r=worker.record(input.executionId) }
                        while(true) {
                            if(r.state=="EXECUTION_APPROVED") r=worker.start(input.executionId,r.fence,r.epoch)
                            lookAhead.onRunning(input.executionId)
                            if(r.state !in setOf("RUNNING","OBSERVATION_UNKNOWN")) break
                            Thread.sleep(2000)
                            if(quick && worker.quickRenewalDue(input.executionId)) worker.renewContinuation(input.executionId)
                            r=worker.poll(input.executionId)
                            lookAhead.onRunning(input.executionId)
                            if(r.state=="EXECUTION_APPROVED") continue
                            if(r.state !in setOf("RUNNING","OBSERVATION_UNKNOWN")) break
                        }
                        encode(r)
                    }
                    "advance" -> encode(worker.poll(input.executionId))
                    "capture" -> { worker.capturePartialResults(input.executionId);buildJsonObject { put("saved",true);put("diagnosisCompleted",false) } }
                    "recover" -> {
                        val ref=input.evidenceRef ?: throw JobRejected("RECOVERY_EVIDENCE_REFERENCE_REQUIRED")
                        encode(if(installation?.owns(input.executionId)==true) installation.recover(input.executionId,ref) else worker.recover(input.executionId,ref))
                    }
                    "retire" -> encode(worker.retire(input.executionId,input.evidenceRef ?: throw JobRejected("RETIREMENT_EVIDENCE_REFERENCE_REQUIRED")))
                    else -> encode(worker.renewContinuation(input.executionId))
                }.let { body -> JsonObject(start+mapOf("state" to JsonPrimitive("SUCCEEDED"),"result" to body,"nextAction" to JsonPrimitive(next(record(input.executionId),null)))) }
            } catch(e:Exception) {
                val failed=JsonObject(start+mapOf("state" to JsonPrimitive("FAILED"),"errorCode" to JsonPrimitive((e as? JobRejected)?.code ?: e.javaClass.simpleName)))
                JsonObject(failed+("nextAction" to JsonPrimitive(next(record(input.executionId),failed))))
            }
            store.put("mcp-operation:$id",result)
            active.remove(input.executionId,id)
            executingOperation.remove()
        }
        return start
    }
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    private fun rows(pages:JsonArray)=pages.asSequence().flatMap { page ->
        jobJson.decodeToSequence<JsonObject>(page.jsonPrimitive.content.byteInputStream(),DecodeSequenceMode.WHITESPACE_SEPARATED)
    }
    private fun compact(probe:ProbeEvidence):JsonElement {
        val logger=probe.logger;val before=logger["before"]?.jsonObject?.get("latestId")?.jsonPrimitive?.longOrNull ?: 0L
        val after=logger["after"]?.jsonObject?.get("latestId")?.jsonPrimitive?.longOrNull ?: Long.MAX_VALUE
        val pages=logger["pages"] as? JsonArray ?: return jobJson.encodeToJsonElement(probe)
        val selected=rows(pages).filter { (it["id"]?.jsonPrimitive?.longOrNull ?: -1L) in (before+1)..after }.toList()
        return jobJson.encodeToJsonElement(probe.copy(logger=JsonObject(logger+("pages" to JsonArray(selected.chunked(100).map { chunk -> JsonPrimitive(chunk.joinToString("\n") { it.toString() }) })))))
    }
    internal fun savedReviewFlows(id:String):JsonArray {
        requireJob(id.matches(Regex("[A-Za-z0-9_-]{1,100}")),"INVALID_EXECUTION_ID")
        return WorkflowEvidenceReview.probeFlows(worker.validation(id).probes.map { jobJson.encodeToJsonElement(it).jsonObject })
    }
    internal fun savedRateLimitConfigurations(id:String):JsonArray {
        requireJob(id.matches(Regex("[A-Za-z0-9_-]{1,100}")),"INVALID_EXECUTION_ID")
        return RateLimitObservations.savedDefaultPools(worker.plan(id))
    }
    fun call(input:DiagnosticJob):JsonObject {
        requireJob(input.executionId.matches(Regex("[A-Za-z0-9_-]{1,100}")),"INVALID_EXECUTION_ID")
        requireJob(input.offset>=0 && input.index>=0 && input.count in 1..100,"INVALID_EVIDENCE_PAGE")
        requireJob((input.draftId==null && input.draftDigest==null) ||
            (input.action=="propose" && !input.draftId.isNullOrBlank() && !input.draftDigest.isNullOrBlank() && input.proposalJson==null),
            "DRAFT_PROMOTION_ARGUMENTS_REQUIRED")
        requireJob(input.nextTargetsJson==null || input.action=="plan_next","LOOKAHEAD_DECLARATION_ARGUMENTS_NOT_ALLOWED")
        return when(input.action) {
            "verify_exclusive_context","verify_scanner_workflow","verify_dynamic_workflow" -> {
                requireJob(!quick, "REVIEW_REQUIRED")
                requireJob(input.executionId.length<=80 && input.proposalJson == null && input.evidenceRef == null && input.validationDigest == null,
                    "UNEXPECTED_SETUP_ARGUMENT")
                submit(input)
            }
            "plan_next" -> {
                requireJob(input.proposalJson==null && input.validationDigest==null && input.evidenceRef==null,
                    "LOOKAHEAD_DECLARATION_ARGUMENTS_NOT_ALLOWED")
                lookAhead.declare(input.executionId,input.nextTargetsJson ?: throw JobRejected("LOOKAHEAD_TARGETS_REQUIRED"))
            }
            "status" -> status(input.executionId)
            "operation" -> planning(operation(input.operationId ?: throw JobRejected("OPERATION_ID_REQUIRED")).also {
                requireJob(it["executionId"]==JsonPrimitive(input.executionId),"OPERATION_EXECUTION_MISMATCH")
            },input.executionId)
            "validation" -> {
                val report=worker.validation(input.executionId)
                buildJsonObject {
                    put("planDigest",report.planDigest);put("validationDigest",fingerprint(report));put("completedAt",report.completedAt)
                    put("restored",report.restored);put("totalProbes",report.probes.size);put("offset",input.offset)
                    put("probes",JsonArray(report.probes.drop(input.offset).take(input.count).map(::compact)))
                    if(report.preparationOnce.isNotEmpty()) {
                        put("totalPreparationOnce",report.preparationOnce.size)
                        put("preparationOnce",JsonArray(report.preparationOnce.drop(input.offset).take(input.count)
                            .map { jobJson.encodeToJsonElement(it) }))
                    }
                    put("semanticReviewRequired",true)
                }
            }
            "results","evidence" -> {
                val saved=worker.committedResults(input.executionId);val records=saved["records"]!!.jsonArray
                if(input.action=="results") buildJsonObject {
                    put("execution",saved["execution"]!!);put("diagnosisCompleted",false);put("totalRecords",records.size)
                    put("records",JsonArray(records.map { value -> JsonObject(value.jsonObject-filterKeys) }))
                } else {
                    requireJob(input.index<records.size,"RESULT_RECORD_NOT_FOUND")
                    val record=records[input.index].jsonObject
                    val pages=(record["loggerPages"] ?: record["logger"]?.jsonObject?.get("pages")) as? JsonArray ?: JsonArray(emptyList())
                    buildJsonObject {
                        put("recordIndex",input.index);put("offset",input.offset)
                        record["response"]?.let { put("selectedResponse",it) }
                        put("entries",JsonArray(rows(pages).drop(input.offset).take(input.count).toList()))
                    }
                }
            }
            "revoke" -> { worker.revoke(input.executionId);status(input.executionId) }
            else -> submit(input)
        }
    }
    override fun close() { executor.shutdownNow();executor.awaitTermination(5,java.util.concurrent.TimeUnit.SECONDS);lookAhead.close() }
    companion object { private val filterKeys=setOf("loggerPages","logger","siteMapIssues") }
}

fun Server.registerDiagnosticJobTool(service:DiagnosticJobService) {
    registerWorkflowEvidenceReview(service)
    registerDiagnosticDraftTool(service.drafts,service.lookAhead)
    mcpTool<DiagnosticJob>(LOOK_AHEAD_GUIDANCE + DRAFT_PROMOTION_GUIDANCE + """Manage a validated diagnostic job through MCP. Fresh REVIEW installations start with no verified capabilities. Bootstrap with action=verify_scanner_workflow (ordinary Scanner) or verify_dynamic_workflow (single-extraction CPH and Scanner), a fresh executionId of 1..80 letters/digits/underscore/hyphen and a stable operationId. No proposalJson, evidenceRef, validationDigest, draft or nextTargetsJson is accepted for these actions. Both return an asynchronous operationId; poll operation with the same executionId/operationId. The server generates its own isolated 127.0.0.1 fixture on an ephemeral port and fixed single-target plan, observes the source, then requests human PREPARATION and EXECUTION approvals, runs five probes, starts one native Audit, collects saved evidence, sends the normal control and restores settings. The empty next-target declaration is internal to this fixed plan. The human must first check no unrelated tasks use this Project. Ordinary capability checks remain unchanged; bootstrap authority cannot be used with caller-supplied plans or targets. Dynamic verification checks fresh one-time tokens in actual SCANNER traffic and their source responses; it verifies this fixture, not arbitrary site authentication, Macro, cached extraction or business cleanup. Registration requires a final human decision and records local evidence; a dynamic pass also registers SCANNER_WORKFLOW and EXCLUSIVE_CONTEXT. result.auditId is retained even after the execution record clears its live handle. Results and evidence remain readable through results/evidence. Denial, missing SCANNER evidence, timeout, uncertain submission or failed restoration never registers the unverified capability. Use recover with evidenceRef after confirming native/helper termination for an incomplete fixed-plan execution. Never replay a timed-out setup with a new ID; inspect the saved operation and execution first. Do not reload MCP or CPH during verification. After all setup executions finish and restoration is verified, perform a separate operator maintenance reload of MCP only to load the registered capabilities, keeping CPH and Project unchanged. action=verify_exclusive_context is a no-traffic ownership-guard check and registers only EXCLUSIVE_CONTEXT after human approval; it does not prove Scanner capability. This is the managed configuration/import/send/scan/recovery path; do not use UI settings imports or direct legacy mutation tools. executionId is a unique 1..100 letter/digit/underscore/hyphen execution identifier, distinct from proposal jobId. In direct propose without draftId/draftDigest, proposalJson is the complete structured JobProposal JSON string, preserving full observed HTTP material, native Macro/Rule/CPH settings and integer references. Obtain observations with get_proxy_http_request_by_id; includeParameters=true returns exact native names/types/offsets and includeBinary=true preserves upload bytes. Preserve dynamic configuration, authentication, diagnostic payloads, stored-effect variants and owned cleanup. action=plan_next is immediate planning-only metadata registration using nextTargetsJson, not an asynchronous native operation and not a target send. Status/operation agentNextAction identifies configuration work to perform alongside current monitoring; lookAheadPlanning is not a replacement for native progress or approval status.
${JOB_PROPOSAL_CONTRACT}Mutating actions propose, prepare, execute, advance, capture, recover and renew_continuation return an operationId immediately. Supply a stable operationId for idempotent retries; never repeat a submission after timeout with a different ID. Poll action=operation with the same executionId/operationId until SUCCEEDED or FAILED, and use status to observe execution/native state. Pending operations survive MCP server stop/start in the same extension; after an extension reload OUTCOME_UNKNOWN requires inspection, never automatic replay. Do not reload MCP or CPH during diagnosis.
Sequence: propose -> prepare -> inspect ALL validation pages and actual workflow evidence -> execute. For a long workflow, explicitly choose executionApprovalMaxAgeSeconds in the proposal from its expected full duration and show it for human approval; omission retains one hour. This changes neither validationMaxAgeSeconds nor revocation, snapshot, input or digest checks. It cannot extend an existing expired approval without a new human review. Native Task insertion-point strategy and resource-pool assignment are not controlled by this API: verify actual Task settings in Burp before start, and inspect original positions and skip reasons after finish. Pool creation or serialScannerRequests alone does not prove Task assignment or complete coverage. Shared CPH response caches are not request-isolated: set variants[].settings.serialScannerRequests=true for every cached multi-step workflow. The compiled plan temporarily sets the actual default resource pool limit to one for preparation, audit and control, preserves its other fields, and restores the complete original pool after each phase. This is a project-wide pool change: first verify no unrelated active task is using it. Exclusive job ownership alone does not serialize native Scanner requests. Before proposing, read output_project_options; a missing/invalid native pool is rejected rather than invented. Omitting serialScannerRequests keeps the old behavior, so actual enabled concurrency one must already be verified and maintained for cached workflows. Never fabricate a baseline or bypass managed writes. prepare performs operator approval and at least five existing-MCP workflow probes per variant/branch, then restores settings. validation paginates probes using offset/count (1..100); when present, totalPreparationOnce and preparationOnce expose the separate one-time evidence with the same independent offset/count window. Read all entries in both collections; one-time evidence never replaces five repeated probes. validationDigest binds both collections. Verify actual auth, fresh dynamic values, input preservation, selected response, rejection branches and cleanup; response existence is not semantic success. execute requires that exact reviewed validationDigest. It continues after approval, starts each approved variant once, observes the same audit, saves evidence, sends the approved benign control and restores settings; status and Logger tools remain usable during execution. Use the normal REVIEW installation with the user's Burp approval; chat 'ok' alone is insufficient. Preserve scope checks, verification, journals, exclusive ownership and conflict detection.
status and operation never send target traffic or change settings. results reads committed summaries; evidence uses index=record index and offset/count to read saved Logger entries and selected response. Site-map issues remain project-wide; use get_scanner_issues and do not invent per-audit issue counts. capture snapshots partial results without diagnostic target sends and never means completion. advance may collect, benign-resend and restore, so do not use it as a read-only status poll. status.context reports ownerExecutionId, ownerState and ownerEpochChanged for the persisted exclusive owner; use it to identify BURP_CONTEXT_BUSY rather than guessing from an empty native list.
Maintenance-only action=retire with nonblank evidenceRef is available in REVIEW after explicit user authorization for maintenance, never as an automatic workaround for recover rejection. It returns an operationId; use a stable operationId and poll it. It requires an old worker epoch, the exact exclusive owner, an unavailable old Audit handle, no active/unknown currently tracked audit, quiescent helper traffic and absence of ALL old job Macro/Rule/CPH definitions (including disabled definitions and references). The human must inspect the CURRENT Project Dashboard for pre-reload/UI-started audits and explicitly acknowledge the maintenance dialog: the old context is detached, no current native/helper traffic is running and current settings must be preserved. An empty API audit list alone is NOT proof of termination. The current snapshot is bound across review; any change refuses the operation. Do not automatically redisplay after HUMAN_DENIED. retire makes NO HTTP sends, imports, restores or native controls. It preserves the prior record, evidence and current snapshot, releases only that old ownership, and records RETIRED_UNVERIFIED with diagnosis and old termination/settings/business cleanup incomplete. It does not make old results successful or resume/recreate an audit. It cannot retire an execution belonging to the current worker epoch, another owner, or a live/uncertain retained handle. Ordinary proven termination still uses recover; unresolved current traffic/settings remain blockers. After maintenance/reload, re-read the current Project and revalidate new diagnostic workflows before scanning.
For confirmed bad settings, Cancel the exact native audit in Burp UI first, preserve partial evidence, correct/retest and create a new full audit; never Pause/edit/Resume. recover takes a nonblank evidenceRef identifying the observed termination; it independently checks terminal native/saved evidence, helper quiescence and ownership, restores the approved baseline through MCP/CPH API, and marks the old execution failed/reconciled. It NEVER starts/resumes/cancels scans or sends target requests and does not clean application data/sessions. Unknown termination, in-flight helper traffic or unrelated setting changes refuse recovery. A normal control or successful restore does not validate an incorrect previous audit. Revoke prevents future approved worker actions but cannot cancel native traffic; use the established UI control path. No workflow/result state alone is a vulnerability verdict or proof of complete business cleanup.""" + LOGIN_PREPARATION_GUIDANCE + RATE_LIMIT_OBSERVATION_GUIDANCE) {
        asciiJson(service.call(this).toString())
    }
}
