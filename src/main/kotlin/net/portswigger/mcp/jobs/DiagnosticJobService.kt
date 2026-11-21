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
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER) val nextTargetsJson:String?=null,
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER) val cphNamesJson:String?=null,
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER) val recoverySelectionJson:String?=null,
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER) val evidenceSource:String="logger",
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER) val includeWireEvidence:Boolean=true)

/** One independent executor owns the workflow after approval; MCP calls never wait for a dialog. */
class DiagnosticJobService(private val worker:GuardedWorker,private val store:JobStore,val quick:Boolean, private val profileFile:java.nio.file.Path?=null,
    private val installation:InstallationVerification?=null):AutoCloseable {
    val drafts = JobDrafts(worker, store)
    val lookAhead = LookAheadPlanner(worker, store, drafts)
    private val executor=Executors.newCachedThreadPool { r -> Thread(r,"burp-diagnostic-job").apply { isDaemon=true } }
    val stints=PreparationStints(worker,store,executor)
    private val active=ConcurrentHashMap<String,String>()
    private val unpersistedCompletions=ConcurrentHashMap<String,JsonObject>()
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
    private fun operation(id:String):JsonObject {
        val saved=store.get("mcp-operation:$id")?.jsonObject ?: throw JobRejected("OPERATION_NOT_FOUND")
        return if(saved["state"]==JsonPrimitive("RUNNING")) JsonObject(saved+unpersistedCompletions[id].orEmpty()) else saved
    }
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
        r?.state in setOf("CONTROL_REQUIRED","RECOVERY_REQUIRED","SUBMISSION_UNKNOWN","SUBMITTING") -> "RECOVERY_EVALUATE_THEN_REVIEW_SAFE_RECONCILIATION"
        r?.state=="EXECUTION_FINISHED" -> "REVIEW_RESULTS_AND_BUSINESS_CLEANUP"
        r?.state=="FAILED_RECONCILED" -> "CORRECT_REVALIDATE_NEW_EXECUTION"
        r?.state=="MAINTENANCE_RESTORED_UNVERIFIED" -> "OLD_DIAGNOSIS_INCOMPLETE_REPLAN_FRESH_BASELINE"
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
            store.get("storage-failure:$id")?.let { put("lastStorageFailure",it) }
            op?.let { put("operation",it) };put("nextAction",next(r,op))
            if(r!=null) {
                val outcome=runCatching { worker.startOutcome(id) }
                put("startOutcome",outcome.getOrNull() ?: JsonNull)
                outcome.exceptionOrNull()?.let { put("startOutcomeObservationError",(it as? JobRejected)?.code ?: it.javaClass.simpleName) }
            }
            if(r?.auditId!=null) {
                val native=runCatching { worker.observeNative(id) }.getOrNull()
                put("native",native ?: JsonNull)
                put("lastKnownNativeMetrics",worker.lastKnownNativeMetrics(id))
            }
            put("diagnosisCompleted",false)
        },id)
    }
    @Synchronized private fun submit(input:DiagnosticJob):JsonObject {
        requireJob(input.action in setOf("propose","prepare","execute","advance","capture","recover","recovery_reconcile","recover_unverified","renew_continuation","retire","prune_cph","restore_restart_cph","verify_exclusive_context","verify_scanner_workflow","verify_dynamic_workflow"),"UNSUPPORTED_JOB_ACTION")
        requireJob(input.action !in setOf("retire","prune_cph","recovery_reconcile","recover_unverified","restore_restart_cph") || !quick,"HUMAN_MAINTENANCE_REVIEW_REQUIRED")
        val identity=fingerprint(jobJson.encodeToJsonElement(input.copy(operationId=null,index=0,offset=0,count=20)))
        val id=input.operationId ?: UUID.randomUUID().toString()
        requireJob(id.matches(Regex("[A-Za-z0-9_-]{1,100}")),"INVALID_OPERATION_ID")
        store.get("mcp-operation:$id")?.jsonObject?.let { old ->
            requireJob(old["requestDigest"]==JsonPrimitive(identity),"OPERATION_ID_REUSED");return operation(id)
        }
        if(input.action!="capture") active[input.executionId]?.let { previous ->
            val pending=operation(previous)
            if(pending["state"]==JsonPrimitive("RUNNING")) return pending
            active.remove(input.executionId,previous)
        }
        val start=buildJsonObject {
            put("operationId",id);put("executionId",input.executionId);put("action",input.action)
            put("requestDigest",identity);put("state","RUNNING");put("nextAction","POLL_SAME_OPERATION")
            put("phase","RUNNING");put("observedAt",java.time.Instant.now().epochSecond)
        }
        store.transaction {
            store.put("mcp-operation:$id",start)
            store.put("mcp-last-operation:${input.executionId}",JsonPrimitive(id))
        }
        if(input.action!="capture") active[input.executionId]=id
        executor.submit {
            executingOperation.set(id)
            val result=try {
                stints.checkJobAction(input.executionId,input.action)
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
                    "recovery_reconcile" -> encode(worker.reconcileRecovery(input.executionId,
                        jobJson.decodeFromString<RecoverySelection>(input.recoverySelectionJson ?: throw JobRejected("RECOVERY_SELECTION_REQUIRED")),
                        input.evidenceRef ?: throw JobRejected("RECOVERY_EVIDENCE_REFERENCE_REQUIRED"),id))
                    "recover" -> {
                        val ref=input.evidenceRef ?: throw JobRejected("RECOVERY_EVIDENCE_REFERENCE_REQUIRED")
                        encode(if(installation?.owns(input.executionId)==true) installation.recover(input.executionId,ref) else worker.recover(input.executionId,ref))
                    }
                    "recover_unverified" -> encode(worker.recoverUnverified(input.executionId,
                        input.evidenceRef ?: throw JobRejected("UI_EVIDENCE_REQUIRED")))
                    "retire" -> encode(worker.retire(input.executionId,input.evidenceRef ?: throw JobRejected("RETIREMENT_EVIDENCE_REFERENCE_REQUIRED")))
                    "prune_cph" -> {
                        val names=jobJson.parseToJsonElement(input.cphNamesJson ?: throw JobRejected("CPH_PRUNE_NAMES_REQUIRED"))
                            .jsonArray.map { it.jsonPrimitive.content }
                        worker.pruneCph(input.executionId,names,input.evidenceRef ?: throw JobRejected("CPH_PRUNE_EVIDENCE_REQUIRED"))
                    }
                    "restore_restart_cph" -> {
                        val names=jobJson.parseToJsonElement(input.cphNamesJson ?: throw JobRejected("CPH_RESTORE_NAMES_REQUIRED"))
                            .jsonArray.map { it.jsonPrimitive.content }
                        worker.restoreRestartCph(input.executionId,names,
                            input.evidenceRef ?: throw JobRejected("CPH_RESTORE_EVIDENCE_REQUIRED"),id)
                    }
                    else -> encode(worker.renewContinuation(input.executionId))
                }.let { body -> JsonObject(start+mapOf("state" to JsonPrimitive("SUCCEEDED"),"result" to body,"nextAction" to JsonPrimitive(next(record(input.executionId),null)))) }
            } catch(e:Throwable) {
                if(e !is Exception && e !is LinkageError) throw e
                val details=(e as? JobRejected)?.safeDetails ?: (e as? java.sql.SQLException)?.let { sqliteFailureDetails(it,"PUBLIC_OPERATION") }.orEmpty()
                val failed=JsonObject(start+mapOf("state" to JsonPrimitive("FAILED"),"errorCode" to JsonPrimitive((e as? JobRejected)?.code ?: if(e is java.sql.SQLException) "STORE_SQLITE_FAILURE" else e.javaClass.simpleName))+
                    if(details.isEmpty()) emptyMap() else mapOf("errorDetails" to buildJsonObject { details.forEach { (key,value) -> put(key,value) } }))
                JsonObject(failed+("nextAction" to JsonPrimitive(next(record(input.executionId),failed))))
            }
            try {
                store.put("mcp-operation:$id",result)
            } catch(error:Throwable) {
                if(error !is Exception && error !is LinkageError) throw error
                // The task ended. Preserve the durable uncertain intent and expose the failed final save.
                unpersistedCompletions[id]=buildJsonObject {
                    put("state","OUTCOME_UNKNOWN");put("nextAction","INSPECT_EXECUTION_NEVER_REPLAY")
                    put("completionRecordPersisted",false);put("completionStateObserved",result.getValue("state"))
                    put("completionResultDigest",fingerprint(result))
                    put("persistenceError",(error as? JobRejected)?.code ?: error.javaClass.simpleName)
                }
            } finally {
                active.remove(input.executionId,id)
                executingOperation.remove()
            }
        }
        return start
    }
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    private fun rows(pages:JsonArray)=pages.asSequence().flatMap { page ->
        jobJson.decodeToSequence<JsonObject>(page.jsonPrimitive.content.byteInputStream(),DecodeSequenceMode.WHITESPACE_SEPARATED)
    }
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    private fun rows(pages:Sequence<JsonElement>)=pages.flatMap { page ->
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
        requireJob(input.recoverySelectionJson==null || input.action=="recovery_reconcile","RECOVERY_SELECTION_NOT_ALLOWED")
        requireJob(input.cphNamesJson==null || input.action in setOf("prune_cph","restore_restart_cph"),"CPH_MAINTENANCE_ARGUMENTS_NOT_ALLOWED")
        if(input.action=="recovery_reconcile") requireJob(input.proposalJson==null && input.validationDigest==null,"UNEXPECTED_RECOVERY_ARGUMENT")
        if(input.action=="recovery_replan") requireJob(input.validationDigest==null && input.evidenceRef==null,"UNEXPECTED_REPLAN_ARGUMENT")
        requireJob(input.evidenceSource in setOf("logger","payload","issues"),"UNKNOWN_EVIDENCE_SOURCE")
        requireJob(input.action=="evidence" || (input.evidenceSource=="logger" && input.includeWireEvidence),"EVIDENCE_ARGUMENTS_NOT_ALLOWED")
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
            "recovery_replan" -> {
                requireJob(!quick,"HUMAN_MAINTENANCE_REVIEW_REQUIRED")
                val selection=jobJson.decodeFromString<RecoveryReplanSelection>(input.proposalJson ?: throw JobRejected("RECOVERY_REPLAN_SELECTION_REQUIRED"))
                val draftId=input.operationId ?: throw JobRejected("RECOVERY_REPLAN_DRAFT_ID_REQUIRED")
                val draft=drafts.validateRecovery(draftId,input.executionId,selection,
                    legacyProposal={ worker.recoverySourceProposal(input.executionId,selection) }) { baseline ->
                    worker.recoveryProposal(input.executionId,selection,baseline)
                }
                JsonObject(drafts.report(draft)+buildJsonObject {
                    put("recoverySourceExecutionId",input.executionId);put("oldDiagnosisState","INCOMPLETE")
                    put("newRevision",draft.plan.proposal.revision);put("nextAction","PROPOSE_NEW_EXECUTION_WITH_THIS_DRAFT_THEN_PREPARE_REVIEW_AND_ALL_BRANCHES")
                })
            }
            "recovery_evaluate" -> worker.evaluateRecovery(input.executionId)
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
                    put("collections",saved["collections"] ?: JsonArray(emptyList()))
                    put("records",JsonArray(records.map { value -> JsonObject(value.jsonObject-filterKeys) }))
                } else {
                    requireJob(input.index<records.size,"RESULT_RECORD_NOT_FOUND")
                    val record=records[input.index].jsonObject
                    val source=when(input.evidenceSource) { "payload" -> "payloadPages";"issues" -> "siteMapIssues";else -> "loggerPages" }
                    val pages=worker.evidencePages(record,source,if(source=="loggerPages") 0 else input.offset)
                    buildJsonObject {
                        put("recordIndex",input.index);put("offset",input.offset);put("evidenceSource",input.evidenceSource)
                        if(input.includeWireEvidence) record["response"]?.let { put("selectedResponse",it) }
                        val metadataOnly=source=="siteMapIssues" && !input.includeWireEvidence
                        val selected=if(metadataOnly) worker.issuePageMetadata(record,input.offset).take(input.count)
                            else if(source=="loggerPages") rows(pages).drop(input.offset).take(input.count) else pages.take(input.count)
                        put("entries",JsonArray(selected.map { value -> if(input.includeWireEvidence || metadataOnly) value else buildJsonObject {
                            put("digest",fingerprint(value));put("verified",true)
                            put("wireEvidenceIncluded",false)
                        } }.toList()))
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

private const val COMMON_RECOVERY_GUIDANCE = """Common settings recovery (REVIEW only): Non-owned logging-only verbosity changes (native integer 1..4 in CPH Options or handlers) are preserved across prepare/start/normal completion and are not execution dependencies. Owned changes, tool flags, unknown fields and invalid/missing values remain guarded; exact import/readback equality is unchanged. Committed start outcomes survive supplementary metadata failures: status exposes the recorded Audit ID, startOutcome and lastKnownNativeMetrics through input/digest-verified read-only fallback without inventing timestamps, recreating native handles or changing stored state/epoch. START_RESULT_METADATA_SAVE_FAILED reports the persistence failure separately; inspect the same Audit; when execution is RUNNING/OBSERVATION_UNKNOWN use advance for observation/collection after storage is healthy, never execute a second Scan. Public operation acceptance metadata commits atomically before scheduling. If final operation persistence fails after the task ends, operation reports OUTCOME_UNKNOWN with completionRecordPersisted=false, completionStateObserved and a safe persistenceError; this is not a running task or proof of native termination. Reusing that operationId never replays the action. Inspect its existing execution/evidence and use a separately identified permitted observation/recovery operation once storage is healthy. An interrupted SUBMITTING with a bound recorded identifier can use the same dedicated recovery REVIEW only after fresh native/shared stop checks; an uncommitted identifier still does not prove acceptance or resolve its INTENT. A response observed before commit failure is labelled UNCOMMITTED_START_RESPONSE/UNVERIFIED, retains obtainable IDs and historical metrics, and leaves INTENT/SUBMISSION_UNKNOWN and no-replay protections intact. Such observations never establish no-Audit proof. Old-epoch IDs are history, not restored handles or stop evidence; corrupted/unverifiable committed results cannot fill missing IDs or authorize recovery. An unavailable historical start summary is shown as verificationState=UNAVAILABLE in the recovery REVIEW and is not an independent cleanup veto when the recorded native handle and fresh stop/ownership proofs already establish settings safety. It still cannot supply missing IDs or no-Audit proof. A producer-confirmed pre-Audit rejection records stage/errorCode and complete no-Audit/no-submission proof, keeps applied settings under RECOVERY_REQUIRED, and allows the same reviewed recovery contract after independent stop checks. A digest-verified COMMITTED no-Audit result bound to this plan/variant remains usable after worker restart or interrupted follow-up metadata writes without replaying the start; missing/INTENT/legacy-unverifiable results never establish this proof. Native non-creation does not certify Project/CPH, local payload registration or business cleanup; local cleanup uncertainty is reported separately and independent current shared-activity REVIEW remains mandatory. It never automatically retries or releases ownership. startOutcome reports a safe digest-bound cause summary in status/recovery_evaluate; missing legacy proof is not reconstructed. Once native creation was attempted, missing handles remain unknown; after known acceptance, later observation/logging failure retains the same handle and partial metrics. Known disabled actions, explicitly disabled invalid-session recovery branches and the unused validation Macro in current-request validation do not create execution Macro dependencies; explicit preparations and unknown action shapes remain guarded. New probe/Scan capture windows preserve historical counters and reject new loss, counter rollback, changed capture or missing metadata. Saved legacy evidence without a checkpoint retains its stricter completeness checks. A successful submission whose initial status is unavailable is OBSERVATION_UNKNOWN; observe that same Audit without resending. Actual uncertain submission remains SUBMISSION_UNKNOWN even if native execution later ends. status and recovery_evaluate expose lastKnownNativeMetrics from start/poll observations as historical values with timestamps and currentStopProof=false. Execution dependencies are evaluated separately from setting ownership: non-owned Rule edits/deletions and Macros used only by those Rules are preserved when both before/after scopes prove they cannot apply to any planned diagnostic/helper destination. Rules that may apply before or after the change, explicit plan dependencies, owned conflicts and unknown/advanced scopes remain guarded. If a previous reconciliation import may have completed but metadata was not finalized, explicitly submit a NEW public operationId and include resumeOperationId in recoverySelectionJson naming the ORIGINAL public operationId, retaining its snapshotDigest, decisions and evidenceRef. This performs no import and requires the saved reviewed candidate to match current settings, fresh stop checks and a dedicated REVIEW before metadata-only cleanup/lock release. It never replays the original INTENT; changed settings require separate assessment. Retained authentication restoration follows the validated restoration baseline. Failed apply attempts save obtainable readback and preserve unknown intent; a missing readback remains explicit. Journaled beforeSnapshot and apply readback distinguish preserved non-owned edits from unattributed apply effects without expanding ownership. Native, payload, Logger and issue evidence are collected independently; collectionErrors identifies unavailable sources, already collected pages remain saved and any collection failure keeps complete/quiescent false. Effective order of applicable enabled session Rules is a separate execution dependency; moving unrelated disabled Rules is preserved. Known simple-scope query lowercasing uses the same narrow comparison for import and reverse restoration; unknown Rule/target changes still refuse. first call action=recovery_evaluate for the existing executionId. It reports four-way paths, restoration presence/digests, recorded apply operation, independent current activity facts, public operation failures separately from worker transitions, and missing evidence. Logger gap metadata includes a bounded sample with explicit unknown Audit attribution; it never labels gaps as current activity without sending traffic. Historical response gaps and cumulative capture errors are not current activity. For a settings-only candidate call action=recovery_reconcile with the SAME executionId, stable operationId, nonblank evidenceRef and recoverySelectionJson as a JSON STRING: {"snapshotDigest":"exact currentSnapshotDigest from evaluation","decisions":{"/exact/returned/path":"KEEP_CURRENT"}}. Decisions are KEEP_CURRENT or RESTORE_BASELINE; unspecified unambiguous owned changes restore to the pre-apply baseline and non-owned changes are preserved. Conflicting fields need explicit decisions. Non-owned changes/deletions cannot be restored; explicitly selected missing saved CPH definitions and required missing cached sources are recreated disabled. Dependency checks cover active handlers, their transitive cached sources and explicitly restored definitions. Only dynamic cached-extraction mode consumes cached_selection; stored unused STATIC/SINGLE selections are preserved when readback matches, even if the former source is absent. This never waives actual cache dependencies, complete atomic readback or verified rollback. JSON object field order is insignificant; tab/array order, values, scalar types and missing versus null remain strict. Cache errors expose safe tabName, fieldName and CPH-specific preflight/readback stage. A CPH preflight error does not prove earlier Project changes or workflow steps were rolled back; inspect the same operation and saved evidence before recovery. Unchanged unrelated inactive incomplete references are preserved; activating or restoring a definition still requires valid dependencies. Dependency-definition collisions and incompatible ordering are refused; the REVIEW lists all added and preserved names. Unknown ownership cannot be resolved by selecting KEEP. Recorded apply readback when available (missing legacy readback is explicit evidence shortage, current-only unattributed definitions remain blocked), same Project marker, exact current snapshot, compatible adapter/capabilities, independent native/current MCP/CPH stop and trusted human verification of Macro and all shared/UI/pre-reload Task activity are mandatory. Current-window loss or unknown current activity refuses cleanup. Same-process native termination must be observed; nativeCompleted=true together with a known terminal native status can prove execution termination while completed remains null and submission acceptance remains UNKNOWN. This never proves request acceptance or diagnosis success. after separately authorized process shutdown maintenance the same saved Project, old-process exit evidence and no retained handle/current unknown audit must be confirmed in the dedicated REVIEW. An empty audit list, elapsed time, old response gaps or Logger inactivity never prove stop. The human reviews all selected paths, before/target digests and incomplete old diagnosis; Quick approval and AI JSON stop flags cannot authorize this operation. Approval-time changes refuse mutation. Ambiguous native definition identities, unsupported array/section shapes, missing CPH cache dependencies or uncertain ownership retain the lock. Known Macro/Rule arrays use unique identities and a UI-thread compare/partial-import/readback sequence that preserves non-owned definitions; arbitrary section deletions and other opaque arrays are refused. A missing historical readback is never synthesized. The service journals the candidate and intent, uses atomic CPH keep import, verifies exact readback then commits settings cleanup and lock release together. Newly created owned CPH tabs are retained disabled and reported. Timeout/unknown intent never automatically replays; inspect the same operation and re-evaluate. This operation preserves old plans/digests/HTTP evidence and marks MAINTENANCE_RESTORED_UNVERIFIED/INCOMPLETE, never successful diagnosis. It does not send HTTP, start/resume/cancel an Audit, invalidate sessions or clean business data. After cleanup action=recovery_replan requires the OLD executionId, operationId as a new immutable draft ID, and proposalJson as a JSON STRING {"revision":2,"ruleDescriptions":[]}; choose a revision greater than the saved proposal, never copy this example number blindly. With no Rule selections it uses the old proposal at the explicit new revision, reusing formally retained identical authentication definitions in the same saved Project as explicit existing-state selections instead of adding duplicate Macro/Rule/CPH definitions. Missing retained definitions remain proposed additions; same-name definition conflicts refuse replan. This never changes the saved old proposal or reuses its approvals or validation; selected owned Rule descriptions use recorded native URL scope observations only when their authority/path and all other fields retain the permitted identity and scope shape. Unsupported changes, activation/host/path changes or broadening refuse candidate creation. It compiles against a fresh idle baseline and returns draftId/draftDigest, not approval or test success. Propose that draft with a NEW executionId, obtain preparation REVIEW and inspect all required branch evidence before separate Execution REVIEW; old Scan is never replayed. After cleanup explicitly submit a new revision and new execution against the latest idle baseline, obtain preparation REVIEW, verify every required branch and review the new validationDigest before requesting separate Execution REVIEW. Native readback differences are not automatically equivalent or automatically copied into a new plan. Legacy recover/recover_unverified retain their existing stricter contracts below.

"""

private const val STORAGE_FAILURE_GUIDANCE = """Evidence storage preserves complete JSON and its digest using atomic chunked SQLite rows for large documents; legacy inline records remain readable. STORE_SQLITE_FAILURE returns errorDetails.stage, sqliteCode and sqlitePrimaryCode as safe fixed-stage/numeric diagnostics, without SQL messages or HTTP secrets. status.lastStorageFailure, when present, is a historical automatic evidence/restore failure, not a current storage health test or proof of recovery. Do not infer the cause of a legacy SQLiteException lacking numeric codes. A storage failure preserves uncertain intents, old diagnosis incompleteness and exclusive ownership; do not resend scans or repeat an uncertain operation under a new ID. Inspect the same operation and execution, correct the identified storage condition through authorized maintenance, then use recovery_evaluate and the existing dedicated recovery REVIEW with independent stop and ownership checks. Chunking does not cure disk exhaustion, corruption, locks or JVM memory exhaustion. Old unobserved responses remain missing. Source/build success is not settings restoration, lock release or completed diagnosis.
"""

private const val PAGED_EVIDENCE_GUIDANCE = """Normal capture saves full Logger, payload and site-map issue evidence one page at a time, with digest-bound STORE_REFERENCES_V1 page references instead of a single aggregate JSON. results returns source manifests and collections (COLLECTING after interruption, PARTIAL on source failure, COLLECTED after observation); these states do not certify diagnosis, native termination or cleanup. action=evidence uses index for result record, evidenceSource=logger (default), payload or issues. offset/count select Logger entries, or payload/issue pages. includeWireEvidence=true by default; false verifies the selected saved pages/entries and returns only their digests, never HTTP bodies. Issue evidence covers the Project site-map and is not Audit-specific. capture is read-only and permitted for a retained Audit ID after restart; it does not restore handles, replay a Scan, send controls, change settings, release locks or prove old activity stopped. Missing native/capture evidence remains explicit and complete/quiescent stay false. A new capture operation can collect existing evidence after storage repair; reusing the same operationId never repeats it. Interrupted page collections remain recorded separately from committed result records.
"""

fun Server.registerDiagnosticJobTool(service:DiagnosticJobService) {
    if(!service.quick) registerPreparationStintTool(service.stints)
    registerWorkflowEvidenceReview(service)
    registerDiagnosticDraftTool(service.drafts,service.lookAhead)
    // Recovery evaluation is synchronous, observation-only, and never acquires or releases context.
    mcpTool<DiagnosticJob>(PAGED_EVIDENCE_GUIDANCE + STORAGE_FAILURE_GUIDANCE + COMMON_RECOVERY_GUIDANCE + LOOK_AHEAD_GUIDANCE + DRAFT_PROMOTION_GUIDANCE + """Manage a validated diagnostic job through MCP. action=recovery_evaluate requires the existing executionId and returns read-only observations of the current native audit, setting differences by JSON Pointer, owner, missing evidence and all detected blockers. Values are represented by presence and digests to avoid exposing credentials. Legacy apply readbacks are explicitly unavailable. Response gaps and current traffic safety are separate fields. Native or snapshot observation failures remain explicit while other observations are returned. This evaluation never grants permission to restore, release context, send traffic or start scans. executable=false always. Unknown stop evidence requires operator review of preserved Project/runtime and independently verified process, Task, Macro and CPH activity. Do not infer stop from time, an empty audit list or Logger inactivity. Fresh REVIEW installations start with no verified capabilities. Bootstrap with action=verify_scanner_workflow (ordinary Scanner) or verify_dynamic_workflow (single-extraction CPH and Scanner), a fresh executionId of 1..80 letters/digits/underscore/hyphen and a stable operationId. No proposalJson, evidenceRef, validationDigest, draft or nextTargetsJson is accepted for these actions. Both return an asynchronous operationId; poll operation with the same executionId/operationId. The server generates its own isolated 127.0.0.1 fixture on an ephemeral port and fixed single-target plan, observes the source, then requests human PREPARATION and EXECUTION approvals, runs five probes, starts one native Audit, collects saved evidence, sends the normal control and restores settings. The empty next-target declaration is internal to this fixed plan. The human must first check no unrelated tasks use this Project. Ordinary capability checks remain unchanged; bootstrap authority cannot be used with caller-supplied plans or targets. Dynamic verification checks fresh one-time tokens in actual SCANNER traffic and their source responses; it verifies this fixture, not arbitrary site authentication, Macro, cached extraction or business cleanup. Registration requires a final human decision and records local evidence; a dynamic pass also registers SCANNER_WORKFLOW and EXCLUSIVE_CONTEXT. result.auditId is retained even after the execution record clears its live handle. Results and evidence remain readable through results/evidence. Denial, missing SCANNER evidence, timeout, uncertain submission or failed restoration never registers the unverified capability. Use recover with evidenceRef after confirming native/helper termination for an incomplete fixed-plan execution. Never replay a timed-out setup with a new ID; inspect the saved operation and execution first. Do not reload MCP or CPH during verification. After all setup executions finish and restoration is verified, perform a separate operator maintenance reload of MCP only to load the registered capabilities, keeping CPH and Project unchanged. action=verify_exclusive_context is a no-traffic ownership-guard check and registers only EXCLUSIVE_CONTEXT after human approval; it does not prove Scanner capability. This is the managed configuration/import/send/scan/recovery path; do not use UI settings imports or direct legacy mutation tools. executionId is a unique 1..100 letter/digit/underscore/hyphen execution identifier, distinct from proposal jobId. In direct propose without draftId/draftDigest, proposalJson is the complete structured JobProposal JSON string, preserving full observed HTTP material, native Macro/Rule/CPH settings and integer references. Obtain observations with get_proxy_http_request_by_id; includeParameters=true returns exact native names/types/offsets and includeBinary=true preserves upload bytes. Preserve dynamic configuration, authentication, diagnostic payloads, stored-effect variants and owned cleanup. action=plan_next is immediate planning-only metadata registration using nextTargetsJson, not an asynchronous native operation and not a target send. Status/operation agentNextAction identifies configuration work to perform alongside current monitoring; lookAheadPlanning is not a replacement for native progress or approval status.
${JOB_PROPOSAL_CONTRACT}Mutating actions propose, prepare, execute, advance, capture, recover and renew_continuation return an operationId immediately. Supply a stable operationId for idempotent retries; never repeat a submission after timeout with a different ID. Poll action=operation with the same executionId/operationId until SUCCEEDED or FAILED, and use status to observe execution/native state. Pending operations survive MCP server stop/start in the same extension; after an extension reload OUTCOME_UNKNOWN requires inspection, never automatic replay. Do not reload MCP or CPH during diagnosis.
Sequence: propose -> prepare -> inspect ALL validation pages and actual workflow evidence -> execute. For a long workflow, explicitly choose executionApprovalMaxAgeSeconds in the proposal from its expected full duration and show it for human approval; omission retains one hour. This changes neither validationMaxAgeSeconds nor revocation, snapshot, input or digest checks. It cannot extend an existing expired approval without a new human review. Native Task insertion-point strategy and resource-pool assignment are not controlled by this API: verify actual Task settings in Burp before start, and inspect original positions and skip reasons after finish. Pool creation or serialScannerRequests alone does not prove Task assignment or complete coverage. Shared CPH response caches are not request-isolated: set variants[].settings.serialScannerRequests=true for every cached multi-step workflow. The compiled plan temporarily sets the actual default resource pool limit to one for preparation, audit and control, preserves its other fields, and restores the complete original pool after each phase. This is a project-wide pool change: first verify no unrelated active task is using it. Exclusive job ownership alone does not serialize native Scanner requests. Before proposing, read output_project_options; a missing/invalid native pool is rejected rather than invented. Omitting serialScannerRequests keeps the old behavior, so actual enabled concurrency one must already be verified and maintained for cached workflows. Never fabricate a baseline or bypass managed writes. prepare performs operator approval and at least five existing-MCP workflow probes per variant/branch, then restores settings. validation paginates probes using offset/count (1..100); when present, totalPreparationOnce and preparationOnce expose the separate one-time evidence with the same independent offset/count window. Read all entries in both collections; one-time evidence never replaces five repeated probes. validationDigest binds both collections. Verify actual auth, fresh dynamic values, input preservation, selected response, rejection branches and cleanup; response existence is not semantic success. execute requires that exact reviewed validationDigest. It continues after approval, starts each approved variant once, observes the same audit, saves evidence, sends the approved benign control and restores settings; status and Logger tools remain usable during execution. Use the normal REVIEW installation with the user's Burp approval; chat 'ok' alone is insufficient. Preserve scope checks, verification, journals, exclusive ownership and conflict detection.
status and operation never send target traffic or change settings. results reads committed summaries; evidence uses index=record index and offset/count to read saved Logger entries and selected response. Site-map issues remain project-wide; use get_scanner_issues and do not invent per-audit issue counts. capture snapshots partial results without diagnostic target sends and never means completion. advance may collect, benign-resend and restore, so do not use it as a read-only status poll. status.context reports ownerExecutionId, ownerState and ownerEpochChanged for the persisted exclusive owner; use it to identify BURP_CONTEXT_BUSY rather than guessing from an empty native list.
Maintenance-only action=retire with nonblank evidenceRef is available in REVIEW after explicit user authorization for maintenance, never as an automatic workaround for recover rejection. It returns an operationId; use a stable operationId and poll it. It requires an old worker epoch, the exact exclusive owner, an unavailable old Audit handle, no active/unknown currently tracked audit, quiescent helper traffic and absence of ALL old job Macro/Rule/CPH definitions (including disabled definitions and references). The human must inspect the CURRENT Project Dashboard for pre-reload/UI-started audits and explicitly acknowledge the maintenance dialog: the old context is detached, no current native/helper traffic is running and current settings must be preserved. An empty API audit list alone is NOT proof of termination. The current snapshot is bound across review; any change refuses the operation. Do not automatically redisplay after HUMAN_DENIED. retire makes NO HTTP sends, imports, restores or native controls. It preserves the prior record, evidence and current snapshot, releases only that old ownership, and records RETIRED_UNVERIFIED with diagnosis and old termination/settings/business cleanup incomplete. It does not make old results successful or resume/recreate an audit. It cannot retire an execution belonging to the current worker epoch, another owner, or a live/uncertain retained handle. Ordinary proven termination still uses recover; unresolved current traffic/settings remain blockers. After maintenance/reload, re-read the current Project and revalidate new diagnostic workflows before scanning.
Maintenance-only action=recover_unverified is REVIEW-only for an old worker epoch with unresolved old send termination. It requires nonblank evidenceRef, the exact exclusive owner, no current tracked active/unknown Audit, current-capture helper quiescence, strict current Project/CPH ownership or the existing cold-CPH guard, a separate Burp human dialog, and unchanged snapshots across review. It restores settings without sending target traffic or controlling a Scan, records MAINTENANCE_RESTORED_UNVERIFIED and oldTerminationVerified=false, and keeps diagnosis INCOMPLETE. Never treat it as ordinary recover or proof that old traffic ended. Maintenance-only action=restore_restart_cph uses the terminal source executionId, stable operationId, nonblank evidenceRef and cphNamesJson as an exact JSON array of missing disabled handler names. It requires a saved Project marker matching the formal runtime baseline, a different Burp instance, unchanged Project/Options/existing CPH, idle Audit and helper traffic, and a separate REVIEW dialog. The service includes missing cached dependencies, restores only selected disabled definitions in saved order through the atomic CPH endpoint, and requires full readback. Missing identity, unknown/active definitions, concurrent changes or unknown import outcome refuse restoration. It does not restore every historical handler or send HTTP. Maintenance-only action=prune_cph is available in REVIEW after explicit user authorization. Use a fresh maintenance executionId, stable operationId, nonblank evidenceRef, and cphNamesJson containing the exact JSON array of handler names. It requires an idle managed context and removes only existing disabled names beginning with job:. Options, Project settings, retained handlers, native Tasks, HTTP traffic, business data and diagnostic ledgers are not changed. The human reviews every name and before/after snapshot digests in Burp. The service rechecks the unchanged complete snapshot across review, imports the reduced CPH configuration, and requires exact full readback. Enabled, missing, duplicate, non-job, ambiguous or concurrently changed definitions are refused. Selecting a name is an operator decision: the service does not infer completed scans or future non-use. Preserve any definition referenced by a remaining target or intended authentication retention. After success, re-read CPH and revalidate every new diagnostic plan against the new idle baseline.
For confirmed bad settings, Cancel the exact native audit in Burp UI first, preserve partial evidence, correct/retest and create a new full audit; never Pause/edit/Resume. recover takes a nonblank evidenceRef identifying the observed termination; it independently checks terminal native/saved evidence, helper quiescence and ownership, restores the approved baseline through MCP/CPH API, and marks the old execution failed/reconciled. It NEVER starts/resumes/cancels scans or sends target requests and does not clean application data/sessions. Unknown termination, in-flight helper traffic or unrelated setting changes refuse recovery. A normal control or successful restore does not validate an incorrect previous audit. Revoke prevents future approved worker actions but cannot cancel native traffic; use the established UI control path. No workflow/result state alone is a vulnerability verdict or proof of complete business cleanup.
Cold CPH recovery after separately authorized shutdown maintenance: if the same saved Project has been reopened in a new Burp instance and CPH has lost ALL handlers, recover may offer a distinct REVIEW-only full-baseline restoration. It requires the old worker epoch's exact exclusive owner, terminal native/saved evidence as usual, quiescent helper traffic, no retained old handle and no active/unknown currently tracked audit. The CPH configuration must be exactly its factory Options alone (Repeater/Proxy true; Scanner/Extender/Spider/Intruder/Sequencer/Target false; verbosity 3), with no extra fields, handlers or order entries; partial loss and modified Options are refused. Project/scope/pool/capability conflicts still refuse. The HUMAN must inspect the current Project Dashboard, confirm no current/UI/pre-reload audit or Macro/CPH traffic, and explicitly approve restoration of the saved formal baseline's complete CPH definitions/order/Options and original Project settings. Generic approval, Quick authorization and chat consent cannot substitute for this dialog. Current snapshot, owner and traffic are rechecked across review; changes refuse restoration. The pre-restore snapshot and recovery fact are journaled without editing old NO_RESPONSE evidence. This is settings recovery only, never input replay, application cleanup, a Scan restart or proof of prior diagnostic success. Do not reload a running diagnosis to manufacture a cold state.""" + LOGIN_PREPARATION_GUIDANCE + RATE_LIMIT_OBSERVATION_GUIDANCE) {
        asciiJson(service.call(this).toString())
    }
}
