package net.portswigger.diagnosis.runner

import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.*
import java.time.Clock
import java.util.UUID

interface BurpExecutionPort {
    fun freezeInputs(job:JobProposal):JobProposal = job
    fun verifyInputs(job:JobProposal) {}
    fun validateInputCoverage(plan:CompiledPlan) {}
    fun snapshot(): BurpSnapshot
    fun ensureProjectMarker():String? = null
    fun apply(variant: CompiledVariant)
    fun apply(variant: CompiledVariant, operationId:String) = apply(variant)
    fun apply(variant:CompiledVariant,expected:BurpSnapshot,operationId:String) {
        requireJob(fingerprint(snapshot())==fingerprint(expected),"CURRENT_CONTEXT_CHANGED")
        apply(variant,operationId)
    }
    fun restore(baseline: BurpSnapshot, ownedCphNames: Set<String>)
    fun restore(baseline: BurpSnapshot, ownedCphNames: Set<String>, operationId:String) = restore(baseline,ownedCphNames)
    fun restore(baseline:BurpSnapshot,ownedCphNames:Set<String>,expected:BurpSnapshot,operationId:String) {
        requireJob(fingerprint(snapshot())==fingerprint(expected),"CURRENT_CONTEXT_CHANGED")
        restore(baseline,ownedCphNames,operationId)
    }
    /** Exact reviewed candidate; expected snapshot is checked immediately before mutation. */
    fun reconcileSettings(expected:BurpSnapshot,target:BurpSnapshot,operationId:String):Unit =
        throw JobRejected("COMMON_RECOVERY_UNSUPPORTED")
    fun recoveryInventoryStopped():Boolean = false
    fun currentRecoveryReadiness(endpoints:List<Endpoint>):Boolean = false
    fun allTrafficQuiescent():Boolean = false
    fun restoreCph(config:JsonObject,order:List<String>,expected:JsonObject,operationId:String):Unit =
        throw JobRejected("CPH_RESTART_RESTORE_UNSUPPORTED")
    /** Maintenance-only exact CPH replacement. It must not change Project settings or send HTTP traffic. */
    fun replaceCph(config:JsonObject,order:List<String>):Unit = throw JobRejected("CPH_MAINTENANCE_UNSUPPORTED")
    /** One approved request in the once-only preparation list, outside all workflow probes. */
    fun oncePreparation(request:RequestPlan):Pair<String,JsonObject> = throw JobRejected("PREPARATION_ONCE_UNSUPPORTED")
    fun probe(variant: ScanVariant, branch: String): Pair<String, JsonObject>
    fun start(variant: ScanVariant): JsonObject
    fun poll(auditId: String): JsonObject
    fun collect(auditId: String, payloadRunId: String?): JsonObject
    /** Read-only observation of outstanding helper traffic; false unless supported by the adapter. */
    /** Independent facts only. No absence of response is interpreted as a currently live send. */
    fun beginRecoveryObservation() {}
    fun recoveryTrafficObservation():JsonObject = buildJsonObject {
        put("captureHealth", "UNVERIFIED"); put("sendLifecycle", "UNVERIFIED")
        put("nativeAndHelperStop", "UNVERIFIED")
    }
    fun recoveryReadiness(endpoints:List<Endpoint>):Boolean = false
    /** A missing old handle AND no active/unknown tracked audit. Not proof of old termination. */
    fun retirementReadiness(auditId:String):Boolean = false
}
fun interface HumanApprover {
    /** Local installation checks are separate from job authorization; fail closed by default. */
    fun reviewInstallation(message:String):String? = null
    /** Only a trusted UI implementation may approve; never take an approved flag from job JSON. */
    fun review(plan: CompiledPlan, stage: ApprovalStage, report: ValidationReport?): String?
    /** Trusted human decision over an ordered, immutable list. The final review only records evidence. */
    fun reviewStint(stintId:String, plans:List<CompiledPlan>, reports:List<ValidationReport>):String? = null
    fun reviewRecovery(plan:CompiledPlan,record:ExecutionRecord,evidenceRef:String):String? = review(plan,ApprovalStage.RECOVERY,null)
    fun reviewRestore(plan:CompiledPlan,record:ExecutionRecord,evidenceRef:String):String? = reviewRecovery(plan,record,evidenceRef)
    /** Complete CPH loss after restart requires a distinct REVIEW-only decision; fail closed by default. */
    fun reviewColdCphRestore(plan:CompiledPlan,record:ExecutionRecord,evidenceRef:String,currentDigest:String):String? = null
    fun reviewUnverifiedRestore(plan:CompiledPlan,record:ExecutionRecord,evidenceRef:String,currentDigest:String,coldCph:Boolean):String? = null
    fun reviewRestartCphRestore(sourceExecutionId:String,names:List<String>,evidenceRef:String,currentDigest:String,targetDigest:String):String? = null
    fun reviewContinuation(plan:CompiledPlan,record:ExecutionRecord,report:ValidationReport):String? = review(plan,ApprovalStage.EXECUTION,report)
    /** Explicit maintenance attestation only; old implementations must fail closed. */
    fun reviewRetirement(plan:CompiledPlan,record:ExecutionRecord,evidenceRef:String,currentDigest:String):String? = null
    /** Explicit REVIEW-only removal of disabled, job-owned CPH definitions. */
    fun reviewCphPrune(names:List<String>,evidenceRef:String,currentDigest:String,targetDigest:String):String? = null
    fun reviewReconciliation(plan:CompiledPlan,record:ExecutionRecord,evidenceRef:String,summary:JsonObject):String? = null
}

class GuardedWorker(private val port: BurpExecutionPort, private val store: JobStore,
    private val approver: HumanApprover, private val clock: Clock = Clock.systemUTC()) {
    val epoch: String = UUID.randomUUID().toString()
    private fun now() = clock.instant().epochSecond
    private inline fun <reified T> read(key: String): T = jobJson.decodeFromJsonElement(store.get(key) ?: throw JobRejected("NOT_FOUND"))
    private inline fun <reified T> save(key: String, value: T) = store.put(key,jobJson.encodeToJsonElement(value))
    fun record(id: String): ExecutionRecord {
        val saved=read<ExecutionRecord>("execution:$id")
        if(saved.auditId!=null || saved.state !in setOf("SUBMITTING","SUBMISSION_UNKNOWN","OBSERVATION_UNKNOWN","RECOVERY_REQUIRED")) return saved
        // Observation only: recover recorded identifiers, never recreate a native handle or change state/epoch.
        val result=runCatching { committedStartResult(id,saved) ?: uncommittedStartObservation(id,saved) }.getOrNull() ?: return saved
        return saved.copy(auditId=startHandle(result,"auditId"),payloadRunId=startHandle(result,"payloadRunId"))
    }
    private fun startHandle(result:JsonObject,key:String):String? =
        (result[key] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull?.takeIf { it.isNotBlank() }
    private fun committedStartResult(id:String,r:ExecutionRecord):JsonObject? {
        val p=plan(id)
        requireJob(r.planDigest==p.planDigest,"START_RESULT_PLAN_MISMATCH")
        val variant=p.variants.getOrNull(r.variantIndex) ?: return null
        return store.committedOnceResult("$id:start:${r.variantIndex}",fingerprint(variant.variant)) as? JsonObject
    }
    private fun uncommittedStartObservation(id:String,r:ExecutionRecord):JsonObject? =
        (store.get("start-observation:$id:${r.variantIndex}") as? JsonObject)?.also {
            requireJob(it["planDigest"]==JsonPrimitive(r.planDigest) && it["operationId"]==JsonPrimitive("$id:start:${r.variantIndex}"),"START_OUTCOME_BINDING_MISMATCH")
        }
    fun plan(id: String): CompiledPlan = read("plan:$id")
    fun validation(id:String):ValidationReport = read("validation:$id")
    private val nativeMetricFields=listOf("auditRequestCount","auditErrorCount","auditInsertionPointCount","auditIssueCount","auditStatusMessage","completed","nativeCompleted")
    fun lastKnownNativeMetrics(id:String):JsonObject {
        val r=record(id)
        val saved=(store.get("native-known:$id:"+r.variantIndex) as? JsonObject) ?: JsonObject(emptyMap())
        val committed=runCatching { committedStartResult(id,r) }.getOrNull() ?: return saved
        // A missing metadata timestamp stays unknown; these values cannot prove current stop.
        return JsonObject(historicalMetrics(startHandle(committed,"auditId"),committed,null,"COMMITTED_START_RESULT")+saved)
    }
    private fun noAuditStartProof(id:String,r:ExecutionRecord,p:CompiledPlan):JsonObject? {
        if(r.auditId!=null || r.planDigest!=p.planDigest) return null
        return committedStartResult(id,r)?.takeIf(::provenNoAuditStart)
    }
    fun startOutcome(id:String):JsonElement {
        val r=record(id)
        val result=committedStartResult(id,r)
        val saved=store.get("start-outcome:$id:"+r.variantIndex) as? JsonObject
        if(saved!=null) {
            requireJob(saved["planDigest"]==JsonPrimitive(r.planDigest) && saved["operationId"]==JsonPrimitive("$id:start:${r.variantIndex}"),"START_OUTCOME_BINDING_MISMATCH")
            if(result!=null) requireJob(saved["result"]?.jsonObject?.get("responseDigest")==JsonPrimitive(fingerprint(result)),"START_OUTCOME_RESULT_MISMATCH")
            return saved
        }
        if(result==null) return uncommittedStartObservation(id,r) ?: JsonNull
        return buildJsonObject {
            put("operationId","$id:start:${r.variantIndex}");put("planDigest",r.planDigest)
            put("observedAt",JsonNull);put("observationTimeState","NOT_RECORDED")
            put("source","COMMITTED_START_RESULT");put("result",scanStartSummary(result))
        }
    }
    /** Display evidence is optional. It never replaces the independent stop/ownership proof gates. */
    private fun recoveryStartOutcome(id:String):JsonElement = runCatching { startOutcome(id) }.getOrElse { error ->
        buildJsonObject {
            put("verificationState","UNAVAILABLE")
            put("verificationError",(error as? JobRejected)?.code ?: error.javaClass.simpleName)
            put("currentStopProof",false)
        }
    }
    fun committedResults(id:String):JsonObject = SavedResults(store).read(id)
    fun evidencePages(record:JsonObject,source:String,skipPages:Int=0):Sequence<JsonElement> = SavedResults(store).pages(record,source,skipPages)
    fun issuePageMetadata(record:JsonObject,offset:Int):Sequence<JsonElement> = SavedResults(store).issuePageMetadata(record,offset)
    private fun collectEvidence(id:String,auditId:String,payloadRunId:String?):JsonObject {
        if(port !is EvidenceStreamingPort) return port.collect(auditId,payloadRunId)
        val writer=EvidencePageWriter(store,id,auditId)
        val evidence=port.collectTo(auditId,payloadRunId,writer::save)
        val errors=evidence["collectionErrors"] as? JsonObject
        val storageSource=errors?.entries?.firstOrNull { it.value==JsonPrimitive("STORE_SQLITE_FAILURE") }?.key
        if(storageSource!=null) store.put("storage-failure:$id",buildJsonObject {
            put("errorCode","STORE_SQLITE_FAILURE");put("source",storageSource)
            put("errorDetails",(evidence["collectionErrorDetails"] as? JsonObject)?.get(storageSource) ?: JsonNull)
            put("diagnosisCompleted",false)
        })
        val collectionKey=writer.finish(evidence["collectionErrors"] as? JsonObject ?: JsonObject(emptyMap()))
        return JsonObject(evidence+("collectionKey" to JsonPrimitive(collectionKey)))
    }
    /** Last known values are historical evidence, never substituted into current terminal/traffic decisions. */
    private fun historicalMetrics(auditId:String?,observation:JsonObject,observedAt:Long?,source:String):JsonObject = buildJsonObject {
        for(field in nativeMetricFields) {
            val value=observation[field]
            if(value!=null && value!=JsonNull) put(field,buildJsonObject {
                put("value",value);put("observedAt",observedAt?.let(::JsonPrimitive) ?: JsonNull)
                put("auditId",auditId?.let(::JsonPrimitive) ?: JsonNull);put("source",source);put("currentStopProof",false)
            })
        }
    }
    private fun retainNativeMetrics(id:String,variantIndex:Int,auditId:String?,observation:JsonObject) = store.transaction {
        val key="native-known:$id:$variantIndex"
        val previous=(store.get(key) as? JsonObject) ?: JsonObject(emptyMap())
        store.put(key,JsonObject(previous+historicalMetrics(auditId,observation,now(),"NATIVE_API")))
    }

    /** Observation only. Unknown stop evidence remains unknown, independently of historical HTTP gaps. */
    @Synchronized fun evaluateRecovery(id: String): JsonObject {
        val record = record(id)
        val plan = plan(id)
        val observedAt = now()
        port.beginRecoveryObservation()
        val snapshot = runCatching { port.snapshot() }
        val native = record.auditId?.let { audit -> runCatching { port.poll(audit) } }
        native?.getOrNull()?.let { retainNativeMetrics(id,record.variantIndex,record.auditId,it) }
        val traffic = runCatching { port.recoveryReadiness(plan.expandedEndpoints) }
        val trafficObservation = runCatching { port.recoveryTrafficObservation() }
        val blockers = mutableListOf<String>()
        if (snapshot.isFailure) blockers.add("CURRENT_SETTINGS_UNAVAILABLE")
        val current = snapshot.getOrNull()
        if (current != null) {
            if (plan.baseline.projectMarker == null || current.projectMarker != plan.baseline.projectMarker)
                blockers.add("PROJECT_IDENTITY_UNVERIFIED")
            if (current.adapterVersion != plan.baseline.adapterVersion ||
                !current.capabilities.containsAll(plan.proposal.requiredCapabilities)) blockers.add("RECOVERY_CONTEXT_CHANGED")
        }
        val nativeStopped = native?.getOrNull()?.let(::terminal) == true
        val noAuditObservation=runCatching { noAuditStartProof(id,record,plan) }
        val noAudit=noAuditObservation.getOrNull()!=null
        if(noAuditObservation.isFailure) blockers.add("START_OUTCOME_UNVERIFIABLE")
        if (!noAudit && !nativeStopped && (record.auditId!=null || record.state=="SUBMISSION_UNKNOWN")) blockers.add("NATIVE_TERMINATION_UNPROVEN")
        val activityBlockers=recoveryActivityBlockers(trafficObservation.getOrNull() ?: JsonObject(emptyMap()))
        if (activityBlockers.isNotEmpty()) blockers.add("CURRENT_ACTIVITY_UNVERIFIED")
        blockers.addAll(activityBlockers)
        val owner = store.get("active")?.jsonPrimitive?.contentOrNull
        if (owner != null && owner != id) blockers.add("ANOTHER_EXECUTION_OWNS_CONTEXT")
        val variant = plan.variants.getOrNull(record.variantIndex)
        if (variant == null) blockers.add("APPLIED_VARIANT_UNVERIFIED")
        val readbackKey = store.get("latest-apply-readback:$id")?.jsonPrimitive?.contentOrNull
        val readback = readbackKey?.let { store.get(it)?.jsonObject }
            ?.takeIf { it["planDigest"] == JsonPrimitive(plan.planDigest) &&
                it["settingsDigest"] == variant?.settingsDigest?.let(::JsonPrimitive) }
        val applied = readback?.get("snapshot") as? JsonObject
        // A missing readback is reported, never fabricated or itself treated as current activity.
        // Legacy executions retain explicitly missing readback evidence.
        val differenceObservation=runCatching { if (current != null && variant != null) recoveryEvidenceDifferences(
            plan.baseline, expected(plan,variant),applied?.let { jobJson.decodeFromJsonElement<BurpSnapshot>(it) },current,
            readback?.get("beforeSnapshot")?.takeUnless { it==JsonNull }?.let { jobJson.decodeFromJsonElement<BurpSnapshot>(it) }
        ) else emptyList() }
        val differences=differenceObservation.getOrDefault(emptyList())
        val destination=recoveryBaseline(id,plan)
        val directedDifferences=recoveryDestinations(differences,recoverySettings(destination))
        if(differenceObservation.isFailure) blockers.add((differenceObservation.exceptionOrNull() as? JobRejected)?.code ?: "SETTING_DIFFERENCES_UNAVAILABLE")
        val dependencyObservation=runCatching { if(current!=null && variant!=null) settingDependencyDifferences(plan,expected(plan,variant),current) else emptyList() }
        if(dependencyObservation.isFailure) blockers.add("DEPENDENCY_OBSERVATION_UNAVAILABLE")
        if (differences.any { it.disposition in setOf(RecoveryDisposition.CONFLICT_REVIEW, RecoveryDisposition.UNKNOWN_OWNER) }) blockers.add("SETTING_CONFLICTS_REQUIRE_REVIEW")
        if(differences.any { it.disposition==RecoveryDisposition.UNKNOWN_OWNER }) blockers.add("AMBIGUOUS_OWNERSHIP")
        val inventory=runCatching { port.recoveryInventoryStopped() }
        if(inventory.getOrNull()!=true) blockers.add("CURRENT_AUDIT_ACTIVITY_UNVERIFIED")
        if(current!=null && differenceObservation.isSuccess && differences.none { it.disposition in setOf(RecoveryDisposition.CONFLICT_REVIEW,RecoveryDisposition.UNKNOWN_OWNER) }) {
            runCatching {
                val candidate=recoveryCandidateSnapshot(current,selectedRecoveryCandidate(recoverySettings(current),directedDifferences,emptyMap()),destination)
                recoveryProjectPatch(current.project,candidate.project)
            }.exceptionOrNull()?.let { blockers.add((it as? JobRejected)?.code ?: "RECOVERY_CANDIDATE_UNAVAILABLE") }
        }
        return buildJsonObject {
            put("executionId", id); put("planDigest", plan.planDigest); put("observedAt", observedAt)
            put("execution", jobJson.encodeToJsonElement(record)); put("ownerExecutionId", owner?.let(::JsonPrimitive) ?: JsonNull)
            put("causeHistory",JsonArray(store.keys("transition:$id:").mapNotNull { store.get(it) }))
            put("operationCauses",JsonArray(store.keys("mcp-operation:").mapNotNull { key ->
                (store.get(key) as? JsonObject)?.takeIf { it["executionId"]==JsonPrimitive(id) && it["errorCode"]!=null }?.let { operation ->
                    JsonObject(operation.filterKeys { it in setOf("operationId","action","phase","state","errorCode","errorDetails","observedAt") })
                }
            }))
            put("causeOrdering", "Use recorded observation times only; missing legacy timestamps do not establish event order. Worker stop warnings and recovery refusal are separate observations.")
            put("exclusiveContextRetainedReason",if(owner==id) "SETTINGS_RECONCILIATION_NOT_COMMITTED" else "NOT_OWNED_BY_THIS_EXECUTION")
            put("native", native?.getOrNull() ?: JsonNull)
            put("lastKnownNativeMetrics",lastKnownNativeMetrics(id))
            val start=runCatching { startOutcome(id) }
            put("startOutcome",start.getOrNull() ?: JsonNull)
            put("startOutcomeObservationError",start.exceptionOrNull()?.let { JsonPrimitive((it as? JobRejected)?.code ?: it.javaClass.simpleName) } ?: JsonNull)
            put("noAuditStartProven",noAudit)
            put("nativeObservationError", native?.exceptionOrNull()?.javaClass?.simpleName?.let(::JsonPrimitive) ?: JsonNull)
            put("snapshotError", snapshot.exceptionOrNull()?.javaClass?.simpleName?.let(::JsonPrimitive) ?: JsonNull)
            put("currentSnapshotDigest", current?.let { JsonPrimitive(fingerprint(it)) } ?: JsonNull)
            put("applyReadback", if (applied == null) "NOT_RECORDED" else "RECORDED")
            put("applyOperationId", readback?.get("operationId") ?: JsonNull)
            put("applyObservedAt", readback?.get("observedAt") ?: JsonNull)
            put("responseEvidence", "REVIEW_SAVED_LOGGER_EVIDENCE")
            put("sendLifecycle", "INDIVIDUAL_SCANNER_COMPLETION_UNVERIFIED")
            put("trafficObservation", trafficObservation.getOrNull() ?: JsonNull)
            put("trafficObservationError", trafficObservation.exceptionOrNull()?.javaClass?.simpleName?.let(::JsonPrimitive) ?: JsonNull)
            put("captureHealth", trafficObservation.getOrNull()?.get("captureHealth") ?: JsonPrimitive("UNVERIFIED"))
            put("currentTrafficSafety", if (activityBlockers.isEmpty()) "REQUIRES_NATIVE_AND_HUMAN_SHARED_DEPENDENCY_STOP_REVIEW" else "UNVERIFIED")
            put("legacyReadiness",traffic.getOrNull()?.let(::JsonPrimitive) ?: JsonNull)
            put("stopMaintenance", "If independent stop evidence is unavailable, preserve the saved Project and formal runtime, obtain explicit shutdown maintenance authorization, verify the old Burp process exited, reopen the same Project, then evaluate this same execution again. Never infer stop from elapsed time or an empty inventory.")
            put("dependencyDifferences",jobJson.encodeToJsonElement(dependencyObservation.getOrDefault(emptyList())))
            put("differenceObservationError",differenceObservation.exceptionOrNull()?.let { JsonPrimitive((it as? JobRejected)?.code ?: it.javaClass.simpleName) } ?: JsonNull)
            put("dependencyObservationError",dependencyObservation.exceptionOrNull()?.let { JsonPrimitive((it as? JobRejected)?.code ?: it.javaClass.simpleName) } ?: JsonNull)
            put("auditOutcome", "INCOMPLETE")
            put("differences", JsonArray(directedDifferences.map { difference -> buildJsonObject {
                put("path", difference.path); put("disposition", difference.disposition.name)
                fun value(label: String, element: JsonElement?) {
                    put("${label}Present", element != null)
                    put("${label}Digest", element?.let { JsonPrimitive(fingerprint(it)) } ?: JsonNull)
                }
                value("baseline", difference.baseline); value("approved", difference.approved); value("applied", difference.applied)
                value("current", difference.current)
                value("restoration",if(difference.restorationSpecified) difference.restoration else difference.baseline)
            } }))
            put("blockers", JsonArray(blockers.map(::JsonPrimitive)))
            put("nextAction", "REVIEW_OBSERVATIONS_AND_MISSING_STOP_EVIDENCE")
            put("executable", false); put("diagnosisCompleted", false)
        }
    }

    /** Settings-only common recovery. Old plan, HTTP rows and uncertain side effects remain immutable. */
    @Synchronized fun reconcileRecovery(id:String,selection:RecoverySelection,evidenceRef:String,operationId:String):ExecutionRecord {
        val r=record(id);val p=plan(id)
        if(r.state=="MAINTENANCE_RESTORED_UNVERIFIED") return r
        val noAudit=noAuditStartProof(id,r,p)!=null
        val interruptedOldEpoch=r.epoch!=epoch && r.state !in setOf("EXECUTION_FINISHED","FAILED_RECONCILED","RETIRED_UNVERIFIED")
        val identifiedInterruptedStart=r.state=="SUBMITTING" && (noAudit || r.auditId!=null)
        requireJob(r.state in setOf("RECOVERY_REQUIRED","SUBMISSION_UNKNOWN","CONTROL_REQUIRED","OBSERVATION_UNKNOWN") || interruptedOldEpoch || identifiedInterruptedStart,"RECOVERY_NOT_AVAILABLE")
        requireJob(evidenceRef.isNotBlank(),"RECOVERY_EVIDENCE_REFERENCE_REQUIRED")
        requireJob(store.get("active")?.jsonPrimitive?.contentOrNull==id,"RECOVERY_OWNER_REQUIRED")
        val before=port.snapshot()
        val effectOperationId=selection.resumeOperationId ?: operationId
        requireJob(effectOperationId.matches(Regex("[A-Za-z0-9_-]{1,100}")),"INVALID_OPERATION_ID")
        val recoveryKey="common-recovery:$id:$effectOperationId"
        val selectionDigest=fingerprint(jobJson.encodeToJsonElement(selection.copy(resumeOperationId=null)))
        val reviewed=store.get("$recoveryKey:reviewed") as? JsonObject
        requireJob(selection.resumeOperationId==null || reviewed!=null,"RECOVERY_REVIEW_RECORD_MISSING")
        if(reviewed!=null) {
            requireJob(reviewed["selectionDigest"]==JsonPrimitive(selectionDigest) && reviewed["evidenceRef"]==JsonPrimitive(evidenceRef),"OPERATION_ID_REUSED")
            val savedTarget=read<BurpSnapshot>("$recoveryKey:target")
            val target=savedTarget.copy(instanceId=before.instanceId)
            requireJob(fingerprint(before)==fingerprint(target),"RECOVERY_EFFECT_RECONCILIATION_REQUIRED")
            requireJob(p.baseline.projectMarker!=null && before.projectMarker==p.baseline.projectMarker,"PROJECT_IDENTITY_UNVERIFIED")
            fun stopForMetadataCommit() {
                requireJob(recoveryActivityBlockers(port.recoveryTrafficObservation()).isEmpty() && port.recoveryInventoryStopped(),"CURRENT_ACTIVITY_UNVERIFIED")
                if(noAudit) return
                if(r.epoch==epoch) r.auditId?.let { requireJob(terminal(port.poll(it)),"NATIVE_TERMINATION_UNPROVEN") }
                else requireJob(before.instanceId!=p.baseline.instanceId && port.retirementReadiness(r.auditId ?: id),"OLD_PROCESS_TERMINATION_UNVERIFIED")
            }
            stopForMetadataCommit()
            val summary=buildJsonObject {
                put("interruptedOperation",operationId);put("currentDigest",fingerprint(before));put("targetDigest",fingerprint(target))
                put("resumeMetadataOnly",true);put("diagnosisState","INCOMPLETE");put("oldProcessStopAttestationRequired",r.epoch!=epoch && !noAudit)
                put("startOutcome",recoveryStartOutcome(id));put("noAuditStartProven",noAudit)
            }
            val traffic=recoveryTrafficFence(port.recoveryTrafficObservation())
            val who=approver.reviewReconciliation(p,r,evidenceRef,summary) ?: throw JobRejected("HUMAN_DENIED")
            requireJob(who.isNotBlank() && !who.startsWith("Quick:"),"HUMAN_MAINTENANCE_REVIEW_REQUIRED")
            requireJob(record(id)==r && store.get("active")==JsonPrimitive(id) && fingerprint(port.snapshot())==fingerprint(target),"CURRENT_CONTEXT_CHANGED")
            stopForMetadataCommit()
            requireJob(fingerprint(recoveryTrafficFence(port.recoveryTrafficObservation()))==fingerprint(traffic),"TRAFFIC_CHANGED_DURING_REVIEW")
            // INTENT/HTTP evidence are unchanged. The dedicated review accepts observed settings only.
            return finishCommonRecovery(id,r,recoveryKey,who,evidenceRef,summary)
        }
        requireJob(fingerprint(before)==selection.snapshotDigest,"CURRENT_CONTEXT_CHANGED")
        requireJob(p.baseline.projectMarker!=null && before.projectMarker==p.baseline.projectMarker,"PROJECT_IDENTITY_UNVERIFIED")
        requireJob(before.adapterVersion==p.baseline.adapterVersion && before.capabilities.containsAll(p.proposal.requiredCapabilities),"RECOVERY_CONTEXT_CHANGED")
        fun stopped() {
            requireJob(recoveryActivityBlockers(port.recoveryTrafficObservation()).isEmpty(),"CURRENT_ACTIVITY_UNVERIFIED")
            requireJob(port.recoveryInventoryStopped(),"CURRENT_AUDIT_ACTIVITY_UNVERIFIED")
            if(noAudit) return
            if(r.epoch==epoch) {
                requireJob(r.state!="SUBMISSION_UNKNOWN" || r.auditId!=null,"NATIVE_TERMINATION_UNPROVEN")
                r.auditId?.let { requireJob(terminal(port.poll(it)),"NATIVE_TERMINATION_UNPROVEN") }
            } else {
                requireJob(before.instanceId!=p.baseline.instanceId,"OLD_PROCESS_TERMINATION_UNVERIFIED")
                requireJob(port.retirementReadiness(r.auditId ?: id),"CURRENT_AUDIT_ACTIVITY_OR_HANDLE_PRESENT")
            }
        }
        // Save everything available even when a later safety check refuses cleanup.
        r.auditId?.let { audit -> runCatching { collectEvidence(id,audit,r.payloadRunId) }.fold(
            { appendEvidence(id,"recovery-observation:$id:${UUID.randomUUID()}",it) },
            { appendEvidence(id,"recovery-observation:$id:${UUID.randomUUID()}",buildJsonObject { put("auditId",audit);put("observationError",it.javaClass.simpleName);put("complete",false) }) }) }
        val v=p.variants.getOrNull(r.variantIndex) ?: throw JobRejected("APPLIED_VARIANT_UNVERIFIED")
        val key=store.get("latest-apply-readback:$id")?.jsonPrimitive?.contentOrNull
        val readback=key?.let { store.get(it)?.jsonObject }?.takeIf { it["planDigest"]==JsonPrimitive(p.planDigest) && it["settingsDigest"]==JsonPrimitive(v.settingsDigest) }
        val applied=(readback?.get("snapshot") as? JsonObject)?.let { jobJson.decodeFromJsonElement<BurpSnapshot>(it) }
        val beforeApply=readback?.get("beforeSnapshot")?.takeUnless { it==JsonNull }?.let { jobJson.decodeFromJsonElement<BurpSnapshot>(it) }
        val differences=recoveryEvidenceDifferences(p.baseline,expected(p,v),applied,before,beforeApply)
        val destination=recoveryBaseline(id,p)
        val directed=recoveryDestinations(differences,recoverySettings(destination))
        val settings=selectedRecoveryCandidate(recoverySettings(before),directed,selection.decisions)
        var target=recoveryCandidateSnapshot(before,settings,destination)
        // The atomic keep-import contract retains newly created owned tabs, disabled and reported.
        val residual=before.cph.filterKeys { it !in target.cph }
        requireJob(residual.keys.all { it.startsWith("job:${p.proposal.jobId}:") },"UNOWNED_CPH_REMOVAL_FORBIDDEN")
        if(residual.isNotEmpty()) target=target.copy(cph=JsonObject(target.cph+residual.mapValues { (_,value) -> JsonObject(value.jsonObject+("enabled" to JsonPrimitive(false))) }),
            cphOrder=target.cphOrder+before.cphOrder.filter { it in residual })
        recoveryProjectPatch(before.project,target.project)
        stopped()
        val reviewedTraffic=recoveryTrafficFence(port.recoveryTrafficObservation())
        val summary=buildJsonObject {
            put("currentDigest",fingerprint(before));put("targetDigest",fingerprint(target))
            put("decisions",jobJson.encodeToJsonElement(selection.decisions));put("diagnosisState","INCOMPLETE")
            put("applyReadbackEvidence",if(applied==null) "NOT_RECORDED" else "RECORDED")
            put("paths",JsonArray(differences.map { JsonPrimitive(it.path+":"+it.disposition.name) }))
            put("addedDisabledDefinitions",JsonArray(target.cph.keys.filter { it !in before.cph }.map(::JsonPrimitive)))
            put("keptNonOwnedDefinitions",JsonArray(before.cph.keys.filter { name ->
                name in target.cph && cphDefinitions(JsonObject(mapOf(name to before.cph.getValue(name))))==cphDefinitions(JsonObject(mapOf(name to target.cph.getValue(name))))
            }.map(::JsonPrimitive)))
            put("changedSettingPaths",JsonArray(recoveryDifferences(recoverySettings(before),recoverySettings(target),null,recoverySettings(before))
                .filter { it.baseline!=it.approved }.map { JsonPrimitive(it.path) }))
            put("oldProcessStopAttestationRequired",r.epoch!=epoch && !noAudit)
            put("startOutcome",recoveryStartOutcome(id));put("noAuditStartProven",noAudit)
            put("trafficDigest",fingerprint(reviewedTraffic))
        }
        val who=approver.reviewReconciliation(p,r,evidenceRef,summary) ?: throw JobRejected("HUMAN_DENIED")
        requireJob(who.isNotBlank() && !who.startsWith("Quick:"),"HUMAN_MAINTENANCE_REVIEW_REQUIRED")
        requireJob(record(id)==r && store.get("active")==JsonPrimitive(id),"EXECUTION_CHANGED_DURING_REVIEW")
        requireJob(fingerprint(port.snapshot())==fingerprint(before),"CURRENT_CONTEXT_CHANGED")
        stopped()
        requireJob(fingerprint(recoveryTrafficFence(port.recoveryTrafficObservation()))==fingerprint(reviewedTraffic),"TRAFFIC_CHANGED_DURING_REVIEW")
        store.transaction {
            save("$recoveryKey:before",before);save("$recoveryKey:target",target)
            store.put("$recoveryKey:reviewed",buildJsonObject {
                put("selectionDigest",selectionDigest);put("evidenceRef",evidenceRef);put("operator",who)
                put("summary",summary);put("reviewedAt",now())
            })
        }
        store.onceJson(recoveryKey,fingerprint(summary)) {
            port.reconcileSettings(before,target,recoveryKey)
            val actual=port.snapshot()
            requireJob(fingerprint(actual)==fingerprint(target),"RECOVERY_READBACK_CHANGED")
            jobJson.encodeToJsonElement(actual)
        }
        requireJob(fingerprint(port.snapshot())==fingerprint(target),"RECOVERY_READBACK_CHANGED")
        stopped()
        return finishCommonRecovery(id,r,recoveryKey,who,evidenceRef,summary)
    }

    private fun finishCommonRecovery(id:String,r:ExecutionRecord,recoveryKey:String,who:String,evidenceRef:String,summary:JsonObject):ExecutionRecord {
        val next=r.copy(state="MAINTENANCE_RESTORED_UNVERIFIED",diagnosisState="INCOMPLETE",evidenceState="INCOMPLETE",cleanupState="SETTINGS_RECONCILED_REVALIDATION_AND_BUSINESS_REVIEW_REQUIRED",
            warnings=r.warnings+"COMMON_RECOVERY_NO_TARGET_REPLAY_NEW_REVISION_REQUIRED")
        store.transaction {
            store.put("$recoveryKey:review",buildJsonObject { put("operator",who);put("evidenceRef",evidenceRef);put("summary",summary);put("previous",jobJson.encodeToJsonElement(r));put("confirmedAt",now()) })
            write(next);store.put("active",JsonNull)
        }
        return next
    }

    /** No target traffic. The caller must compile this new proposal against a fresh idle baseline. */
    @Synchronized fun recoveryProposal(id:String,selection:RecoveryReplanSelection):JobProposal {
        return recoveryProposal(id,selection,port.snapshot())
    }

    /** The caller compiles against this same immutable snapshot; never mix definition reuse with a later baseline. */
    @Synchronized fun recoveryProposal(id:String,selection:RecoveryReplanSelection,current:BurpSnapshot):JobProposal {
        val proposal=recoverySourceProposal(id,selection)
        return reuseRecoveredAuthentication(plan(id),proposal,current)
    }

    /** Immutable pre-reuse candidate also verifies legacy recovery drafts without observing or rewriting live settings. */
    @Synchronized fun recoverySourceProposal(id:String,selection:RecoveryReplanSelection):JobProposal {
        val r=record(id);val p=plan(id)
        requireJob(r.state in setOf("FAILED_RECONCILED","MAINTENANCE_RESTORED_UNVERIFIED"),"OLD_EXECUTION_NOT_RECONCILED")
        requireJob(store.get("active")?.jsonPrimitive?.contentOrNull==null,"BURP_CONTEXT_BUSY")
        requireJob(selection.revision>p.proposal.revision,"RECOVERY_NEW_REVISION_REQUIRED")
        if(selection.ruleDescriptions.isEmpty()) return p.proposal.copy(revision=selection.revision)
        val key=store.get("latest-apply-readback:$id")?.jsonPrimitive?.contentOrNull ?: throw JobRejected("NATIVE_READBACK_NOT_RECORDED")
        val observation=store.get(key)?.jsonObject ?: throw JobRejected("NATIVE_READBACK_NOT_RECORDED")
        requireJob(observation["planDigest"]==JsonPrimitive(p.planDigest),"APPLY_READBACK_PLAN_MISMATCH")
        val observed=jobJson.decodeFromJsonElement<BurpSnapshot>(observation.getValue("snapshot"))
        return observedRecoveryProposal(p,observed,selection)
    }

    fun contextStatus():JsonObject = buildJsonObject {
        val owner=store.get("active")?.jsonPrimitive?.contentOrNull
        put("ownerExecutionId",owner?.let(::JsonPrimitive) ?: JsonNull)
        owner?.let { id -> val r=record(id);put("ownerState",r.state);put("ownerEpochChanged",r.epoch!=epoch) }
    }

    /**
     * Remove explicitly selected disabled job-owned CPH definitions while the managed context is idle.
     * This never changes Project settings, sends HTTP traffic, or infers that a job is complete.
     */
    @Synchronized fun pruneCph(id:String,names:List<String>,evidenceRef:String):JsonObject {
        requireJob(id.matches(Regex("[A-Za-z0-9_-]{1,100}")),"INVALID_MAINTENANCE_ID")
        requireJob(evidenceRef.isNotBlank(),"CPH_PRUNE_EVIDENCE_REQUIRED")
        requireJob(names.isNotEmpty() && names.size<=1000 && names.size==names.toSet().size,"INVALID_CPH_PRUNE_NAMES")
        requireJob(names.all { it.startsWith("job:") && it.count { ch -> ch==':' }>=2 },"CPH_PRUNE_JOB_OWNERSHIP_REQUIRED")
        requireJob(store.get("active")?.jsonPrimitive?.contentOrNull==null,"BURP_CONTEXT_BUSY")
        requireJob(port.retirementReadiness(id),"CURRENT_AUDIT_ACTIVITY_OR_HANDLE_PRESENT")
        requireJob(port.allTrafficQuiescent(),"HELPER_TRAFFIC_NOT_QUIESCENT")
        val before=port.snapshot()
        requireJob(names.all { name -> before.cph[name]?.jsonObject?.get("enabled")?.jsonPrimitive?.booleanOrNull==false },
            "CPH_PRUNE_REQUIRES_DISABLED_EXISTING_HANDLERS")
        val target=before.copy(
            cph=JsonObject(before.cph.filterKeys { it !in names }),
            cphOrder=before.cphOrder.filter { it !in names })
        requireJob(target.cph.keys==target.cphOrder.toSet() && target.cphOrder.size==target.cph.size,"CPH_ORDER_INCONSISTENT")
        val beforeDigest=fingerprint(before);val targetDigest=fingerprint(target)
        val human=approver.reviewCphPrune(names.sorted(),evidenceRef,beforeDigest,targetDigest)
            ?: throw JobRejected("HUMAN_DENIED")
        requireJob(human.isNotBlank() && !human.startsWith("Quick:"),"HUMAN_MAINTENANCE_REVIEW_REQUIRED")
        requireJob(store.get("active")?.jsonPrimitive?.contentOrNull==null,"BURP_CONTEXT_BUSY")
        requireJob(port.retirementReadiness(id),"CURRENT_AUDIT_ACTIVITY_OR_HANDLE_PRESENT")
        requireJob(port.allTrafficQuiescent(),"HELPER_TRAFFIC_NOT_QUIESCENT")
        requireJob(fingerprint(port.snapshot())==beforeDigest,"CURRENT_CONTEXT_CHANGED")
        var responseUnknown=false
        try { port.replaceCph(target.cph,target.cphOrder) } catch(e:Exception) {
            responseUnknown=true
            val observed=runCatching { port.snapshot() }.getOrNull()
            if(observed==null || fingerprint(observed)!=targetDigest) throw JobRejected("CPH_PRUNE_OUTCOME_UNKNOWN")
        }
        val after=port.snapshot()
        requireJob(fingerprint(after)==targetDigest,"CPH_PRUNE_READBACK_MISMATCH")
        val result=buildJsonObject {
            put("maintenanceId",id);put("removedCount",names.size)
            put("beforeCphCount",before.cph.size);put("afterCphCount",after.cph.size)
            put("beforeDigest",beforeDigest);put("afterDigest",fingerprint(after))
            put("projectUnchanged",before.project==after.project)
            put("importResponseUnknownReadbackMatched",responseUnknown)
            put("httpTrafficSent",false);put("scanControlled",false)
        }
        store.put("cph-prune:$id",buildJsonObject {
            put("operator",human);put("evidenceRef",evidenceRef);put("confirmedAt",now())
            put("removedNames",JsonArray(names.sorted().map(::JsonPrimitive)))
            put("before",jobJson.encodeToJsonElement(before));put("after",jobJson.encodeToJsonElement(after))
            put("result",result)
        })
        return result
    }
    /** Selected disabled definitions only, from a marked formal baseline after a cold restart. */
    @Synchronized fun restoreRestartCph(id:String,names:List<String>,evidenceRef:String,operationId:String):JsonObject {
        requireJob(evidenceRef.isNotBlank(),"CPH_RESTORE_EVIDENCE_REQUIRED")
        requireJob(names.isNotEmpty() && names.size<=1000 && names.size==names.toSet().size,"INVALID_CPH_RESTORE_NAMES")
        val r=record(id);val p=plan(id)
        requireJob(r.state in setOf("EXECUTION_FINISHED","FAILED_RECONCILED","MAINTENANCE_RESTORED_UNVERIFIED"),
            "CPH_RESTORE_SOURCE_NOT_TERMINAL")
        val formal=store.get("cph-project-baseline:$id")?.jsonObject ?: throw JobRejected("CPH_FORMAL_BASELINE_MISSING")
        requireJob(formal["planDigest"]==JsonPrimitive(p.planDigest) &&
            formal["projectMarker"]==JsonPrimitive(p.baseline.projectMarker),"CPH_FORMAL_BASELINE_MISMATCH")
        fun stopped() {
            requireJob(store.get("active")?.jsonPrimitive?.contentOrNull==null,"BURP_CONTEXT_BUSY")
            requireJob(port.retirementReadiness(r.auditId ?: id),"CURRENT_AUDIT_ACTIVITY_OR_HANDLE_PRESENT")
            requireJob(port.allTrafficQuiescent(),"HELPER_TRAFFIC_NOT_QUIESCENT")
        }
        stopped()
        val saved=recoveryBaseline(id,p)
        requireJob(formal["baselineDigest"]==JsonPrimitive(fingerprint(p.baseline)) &&
            formal["restorationBaselineDigest"]==(p.restorationBaseline?.let { JsonPrimitive(fingerprint(it)) } ?: JsonNull) &&
            saved in listOfNotNull(p.baseline,p.restorationBaseline),"CPH_FORMAL_BASELINE_MISMATCH")
        val before=port.snapshot()
        val (target,selected)=selectRestartCphRestore(saved,before,names.toSet())
        val beforeDigest=fingerprint(before);val targetDigest=fingerprint(target)
        val who=approver.reviewRestartCphRestore(id,selected.toList().sorted(),evidenceRef,beforeDigest,targetDigest)
            ?: throw JobRejected("HUMAN_DENIED")
        requireJob(who.isNotBlank() && !who.startsWith("Quick:"),"HUMAN_MAINTENANCE_REVIEW_REQUIRED")
        stopped()
        requireJob(record(id)==r && fingerprint(port.snapshot())==beforeDigest,"CURRENT_CONTEXT_CHANGED")
        val innerOperation="restore:${digest("$id:$operationId")}".take(200)
        store.onceJson("$id:restart-cph-restore:$operationId",targetDigest) {
            port.restoreCph(target.cph,target.cphOrder,before.cph,innerOperation)
            val after=port.snapshot();requireJob(fingerprint(after)==targetDigest,"CPH_RESTORE_READBACK_MISMATCH")
            jobJson.encodeToJsonElement(after)
        }
        val after=port.snapshot();requireJob(fingerprint(after)==targetDigest,"CPH_RESTORE_READBACK_MISMATCH")
        val result=buildJsonObject {
            put("sourceExecutionId",id);put("restoredNames",JsonArray(selected.map(::JsonPrimitive)))
            put("beforeDigest",beforeDigest);put("afterDigest",targetDigest)
            put("projectUnchanged",before.project==after.project);put("httpTrafficSent",false);put("scanControlled",false)
        }
        store.put("cph-restart-restore:$id:$operationId",buildJsonObject {
            put("operator",who);put("evidenceRef",evidenceRef);put("confirmedAt",now())
            put("before",jobJson.encodeToJsonElement(before));put("after",jobJson.encodeToJsonElement(after));put("result",result)
        })
        return result
    }
    fun quickRenewalDue(id:String):Boolean {
        val a=store.get("approval:$id:EXECUTION")?.let { jobJson.decodeFromJsonElement<ApprovalRecord>(it) } ?: return false
        return a.approver.startsWith("Quick:") && a.revokedAt==null && now()>=a.expiresAt
    }
    /** Status observation never sends a normal control or changes settings. */
    fun observeNative(id:String):JsonObject? {
        val r=record(id)
        return r.auditId?.let { audit -> port.poll(audit).also { retainNativeMetrics(id,r.variantIndex,audit,it) } }
    }
    private fun write(r: ExecutionRecord) {
        val previous=store.get("execution:${r.executionId}")
        if(previous!=jobJson.encodeToJsonElement(r)) store.put("transition:${r.executionId}:${now()}:${UUID.randomUUID()}",buildJsonObject {
            put("observedAt",now());put("source","WORKER_STATE_TRANSITION")
            put("previous",previous ?: JsonNull);put("current",jobJson.encodeToJsonElement(r))
        })
        save("execution:${r.executionId}",r)
    }

    @Synchronized fun register(id: String, proposal: JobProposal): CompiledPlan {
        return registerPlan(id, proposal, null)
    }

    /** Referenced baselines never inspect or modify the running Burp. Idle capture is read-only. */
    fun draftBaseline(sourceExecutionId: String?): BurpSnapshot {
        if(sourceExecutionId != null) return plan(sourceExecutionId).let { it.restorationBaseline ?: it.baseline }
        requireJob(store.get("active")?.jsonPrimitive?.contentOrNull == null, "DRAFT_BASELINE_EXECUTION_REQUIRED")
        return idleDraftBaseline()
    }
    @Synchronized private fun idleDraftBaseline(): BurpSnapshot {
        requireJob(store.get("active")?.jsonPrimitive?.contentOrNull == null, "DRAFT_BASELINE_EXECUTION_REQUIRED")
        return port.snapshot()
    }

    @Synchronized fun registerDraft(id: String, draft: JobDraft): CompiledPlan {
        requireJob(draft.draftDigest == draftDigest(draft.draftId, draft.baselineExecutionId, draft.plan), "DRAFT_CHANGED")
        return registerPlan(id, draft.plan.proposal, draft)
    }

    private fun registerPlan(id: String, proposal: JobProposal, draft: JobDraft?): CompiledPlan {
        requireJob(id.matches(Regex("[A-Za-z0-9_-]{1,100}")),"INVALID_EXECUTION_ID")
        store.get("plan:$id")?.let {
            val old = jobJson.decodeFromJsonElement<CompiledPlan>(it)
            requireJob(store.get("submitted-proposal:$id")?.jsonPrimitive?.content==fingerprint(proposal),"EXECUTION_ID_REUSED")
            requireJob(record(id).planDigest==old.planDigest,"INCOMPLETE_REGISTRATION")
            if(draft!=null) requireJob(store.get("draft-origin:$id")?.jsonObject?.get("draftDigest")==JsonPrimitive(draft.draftDigest),
                "DRAFT_ORIGIN_MISMATCH")
            return old
        }
        requireJob(store.get("active")?.jsonPrimitive?.contentOrNull == null, "BURP_CONTEXT_BUSY")
        if(draft!=null) port.verifyInputs(proposal)
        val marker=port.ensureProjectMarker()
        val snapshot=port.snapshot()
        if(marker!=null) requireJob(snapshot.projectMarker==marker,"PROJECT_IDENTITY_CHANGED")
        val compiled = JobCompiler().compile(port.freezeInputs(proposal),snapshot)
        port.validateInputCoverage(compiled)
        store.transaction {
            store.put("submitted-proposal:$id",JsonPrimitive(fingerprint(proposal)))
            save("plan:$id",compiled)
            if(marker!=null) store.put("cph-project-baseline:$id",buildJsonObject {
                put("projectMarker",marker);put("planDigest",compiled.planDigest)
                put("projectDigest",fingerprint(compiled.baseline.project))
                put("cphDigest",settingsDigest(compiled.baseline.project,compiled.baseline.cph,compiled.baseline.cphOrder))
                put("baselineDigest",fingerprint(compiled.baseline))
                put("restorationBaselineDigest",compiled.restorationBaseline?.let { JsonPrimitive(fingerprint(it)) } ?: JsonNull)
                put("cph",compiled.baseline.cph)
                put("cphOrder",JsonArray(compiled.baseline.cphOrder.map(::JsonPrimitive)))
            })
            val fence = (store.get("fence")?.jsonPrimitive?.longOrNull ?: 0) + 1
            store.put("fence",JsonPrimitive(fence))
            write(ExecutionRecord(id,compiled.planDigest,epoch,fence,state="STATIC_VALIDATED"))
            if(draft!=null) store.put("draft-origin:$id", buildJsonObject {
                put("draftId",draft.draftId);put("draftDigest",draft.draftDigest)
                put("staticPlanDigest",draft.plan.planDigest);put("draftBaselineDigest",fingerprint(draft.plan.baseline))
                put("baselineChangedSinceDraft",fingerprint(compiled.baseline)!=fingerprint(draft.plan.baseline))
            })
        }
        return compiled
    }

    @Synchronized fun approve(id: String, stage: ApprovalStage): ApprovalRecord {
        requireJob(store.get("hw-member:$id")==null,"STINT_REVIEW_REQUIRED")
        requireJob(stage!=ApprovalStage.RECOVERY,"USE_RECONCILIATION")
        val r = live(id); val p = plan(id)
        InputCoverage.validateRequestedScope(p.proposal)
        validateAuthenticationToolScopes(p)
        val report = if(stage==ApprovalStage.EXECUTION) read<ValidationReport>("validation:$id") else null
        requireJob(if(stage==ApprovalStage.PREPARATION) r.state=="STATIC_VALIDATED" else r.state=="VALIDATED","INVALID_APPROVAL_STAGE")
        if(report!=null) {
            requireJob(report.planDigest==p.planDigest && report.restored && now()-report.completedAt in 0..p.proposal.validationMaxAgeSeconds,"VALIDATION_EXPIRED")
            checkOncePreparation(p,report)
            p.variants.forEach { v -> v.variant.requiredBranches.forEach { branch ->
                requireJob(report.probes.count { it.variantId==v.variant.id && it.branch==branch && it.settingsDigest==v.settingsDigest }>=5,"FIVE_PROBES_REQUIRED")
            } }
        }
        val who = approver.review(p,stage,report) ?: throw JobRejected("HUMAN_DENIED")
        requireJob(who.isNotBlank(),"APPROVER_REQUIRED")
        port.verifyInputs(p.proposal)
        checkSnapshot(if(stage==ApprovalStage.PREPARATION) p.baseline else read("prepared-baseline:$id"),port.snapshot(),p)
        if(report!=null) requireJob(report==read<ValidationReport>("validation:$id") && now()-report.completedAt in 0..p.proposal.validationMaxAgeSeconds,"VALIDATION_EXPIRED_OR_CHANGED")
        val duration=if(stage==ApprovalStage.EXECUTION) p.proposal.executionApprovalMaxAgeSeconds else 3600L
        val a = ApprovalRecord(UUID.randomUUID().toString(),id,p.planDigest,stage,now(),now()+duration,who,report?.let(::fingerprint))
        store.transaction {
            save("approval:$id:${stage.name}",a)
            write(r.copy(state=if(stage==ApprovalStage.PREPARATION) "PREPARATION_APPROVED" else "EXECUTION_APPROVED"))
        }
        return a
    }
    @Synchronized fun reviewStint(stintId:String, ids:List<String>, finalReview:Boolean, manifestDigest:String,reviewDigest:String):JsonObject {
        requireJob(ids.isNotEmpty() && ids.distinct().size==ids.size,"INVALID_STINT_SELECTION")
        val plans=ids.map(::plan)
        val reports=if(finalReview) ids.map(::validation) else emptyList()
        fun verify() {
            requireJob(contextStatus()["ownerExecutionId"]==JsonNull,"BURP_CONTEXT_BUSY")
            val baseline=port.snapshot()
            ids.forEachIndexed { index,id ->
                val p=plans[index]
                val r=live(id)
                requireJob(r.planDigest==p.planDigest && r.state==(if(finalReview) "VALIDATED" else "STATIC_VALIDATED"),"INVALID_APPROVAL_STAGE")
                InputCoverage.validateRequestedScope(p.proposal)
                validateAuthenticationToolScopes(p)
                port.verifyInputs(p.proposal)
                checkSnapshot(if(finalReview) read("prepared-baseline:$id") else p.baseline,baseline,p)
                if(finalReview) {
                    val report=reports[index]
                    requireJob(report==validation(id) && report.restored && report.planDigest==p.planDigest &&
                        now()-report.completedAt in 0..p.proposal.validationMaxAgeSeconds,"VALIDATION_EXPIRED_OR_CHANGED")
                    checkOncePreparation(p,report)
                    p.variants.forEach { v -> v.variant.requiredBranches.forEach { branch ->
                        requireJob(report.probes.count { it.variantId==v.variant.id && it.branch==branch && it.settingsDigest==v.settingsDigest }>=5,"FIVE_PROBES_REQUIRED")
                    } }
                }
            }
        }
        verify()
        val who=approver.reviewStint(stintId,plans,reports)
        requireJob(!who.isNullOrBlank(),"HUMAN_DENIED")
        verify()
        val at=now()
        val receipt=buildJsonObject {
            put("manifestDigest",manifestDigest);put("reviewDigest",reviewDigest);put("approver",who);put("approvedAt",at)
            put("stage",if(finalReview) "FINAL_REVIEW" else "PREPARATION")
            put("items",buildJsonArray { ids.forEachIndexed { i,id -> add(buildJsonObject {
                put("executionId",id);put("planDigest",plans[i].planDigest)
                if(finalReview) put("validationDigest",fingerprint(reports[i]))
            }) } })
        }
        store.transaction {
            if(!finalReview) ids.forEachIndexed { i,id ->
                save("approval:$id:PREPARATION",ApprovalRecord(UUID.randomUUID().toString(),id,plans[i].planDigest,
                    ApprovalStage.PREPARATION,at,at+3600,who!!))
                write(record(id).copy(state="PREPARATION_APPROVED"))
            }
            store.put("hw-review:$reviewDigest",receipt)
        }
        return receipt
    }
    private fun live(id: String): ExecutionRecord = record(id).also {
        requireJob(it.epoch==epoch,"WORKER_EPOCH_CHANGED_RECONCILIATION_REQUIRED")
    }
    private fun permitted(id: String, stage: ApprovalStage) {
        val a = read<ApprovalRecord>("approval:$id:${stage.name}")
        requireJob(a.revokedAt==null && now()>=a.approvedAt && now()<a.expiresAt && a.planDigest==plan(id).planDigest,"APPROVAL_NOT_VALID")
        if(stage==ApprovalStage.EXECUTION) requireJob(a.reportDigest==fingerprint(read<ValidationReport>("validation:$id")),"APPROVED_VALIDATION_CHANGED")
        port.verifyInputs(plan(id).proposal)
    }
    @Synchronized fun revoke(id: String) = store.transaction {
        ApprovalStage.entries.forEach { stage -> store.get("approval:$id:${stage.name}")?.let {
            save("approval:$id:${stage.name}",jobJson.decodeFromJsonElement<ApprovalRecord>(it).copy(revokedAt=now()))
        } }
        val r=record(id)
        if(r.state !in setOf("STATIC_VALIDATED","VALIDATED","EXECUTION_FINISHED","RETIRED_UNVERIFIED","FAILED_RECONCILED")) write(r.copy(state="CONTROL_REQUIRED"))
    }
    /** Renew only an identified, unchanged existing audit. Never restart an uncertain submission. */
    @Synchronized fun renewContinuation(id:String):ExecutionRecord {
        val r=live(id);val p=plan(id)
        requireJob(r.state in setOf("RUNNING","OBSERVATION_UNKNOWN","CONTROL_REQUIRED"),"CONTINUATION_NOT_AVAILABLE")
        val auditId=r.auditId ?: throw JobRejected("LIVE_AUDIT_REQUIRED")
        requireJob(store.get("active")?.jsonPrimitive?.contentOrNull==id,"EXECUTION_DOES_NOT_OWN_CONTEXT")
        checkSnapshot(expected(p,p.variants[r.variantIndex]),port.snapshot(),p)
        port.verifyInputs(p.proposal)
        val native=port.poll(auditId)
        requireJob(native["completed"]?.jsonPrimitive?.booleanOrNull!=null && native["submissionError"]==null &&
            native["auditStatusMessage"]?.jsonPrimitive?.contentOrNull?.lowercase() !in setOf("cancelled","canceled"),"AUDIT_NOT_CONFIRMED")
        val report=read<ValidationReport>("validation:$id")
        val human=approver.reviewContinuation(p,r,report) ?: throw JobRejected("HUMAN_DENIED")
        requireJob(human.isNotBlank(),"APPROVER_REQUIRED")
        checkSnapshot(expected(p,p.variants[r.variantIndex]),port.snapshot(),p)
        port.verifyInputs(p.proposal)
        requireJob(report==read<ValidationReport>("validation:$id"),"APPROVED_VALIDATION_CHANGED")
        val after=port.poll(auditId)
        requireJob(after["completed"]?.jsonPrimitive?.booleanOrNull!=null && after["submissionError"]==null &&
            after["auditStatusMessage"]?.jsonPrimitive?.contentOrNull?.lowercase() !in setOf("cancelled","canceled"),"AUDIT_NOT_CONFIRMED")
        val old=read<ApprovalRecord>("approval:$id:EXECUTION")
        val next=r.copy(state="RUNNING",warnings=r.warnings+"SAME_AUDIT_CONTINUATION_APPROVED")
        store.transaction {
            save("approval-history:$id:${old.id}",old)
            save("approval:$id:EXECUTION",ApprovalRecord(UUID.randomUUID().toString(),id,p.planDigest,ApprovalStage.EXECUTION,
                now(),now()+p.proposal.executionApprovalMaxAgeSeconds,human,fingerprint(report)))
            write(next)
        }
        return next
    }
    /** Exercise the production ownership guard on this installation without publishing a temporary owner. */
    @Synchronized fun verifyExclusiveContext(): JsonObject = store.transaction {
        requireJob(store.get("active")?.jsonPrimitive?.contentOrNull == null, "BURP_CONTEXT_BUSY")
        val probe = "setup-" + UUID.randomUUID()
        acquire(probe)
        val refusal = try {
            acquire(probe + "-contender")
            null
        } catch (error: JobRejected) {
            error.code
        }
        requireJob(refusal == "BURP_CONTEXT_BUSY" && store.get("active") == JsonPrimitive(probe),
            "EXCLUSIVE_CONTEXT_VERIFICATION_FAILED")
        store.put("active", JsonNull)
        val evidence = buildJsonObject {
            put("capability", "EXCLUSIVE_CONTEXT")
            put("workerEpoch", epoch)
            put("verifiedAt", now())
            put("competingAcquire", refusal)
            put("ownerReleased", true)
        }
        store.put("setup-evidence:EXCLUSIVE_CONTEXT", evidence)
        evidence
    }
    private fun acquire(id: String) {
        val active=store.get("active")?.jsonPrimitive?.contentOrNull
        requireJob(active==null || active==id,"BURP_CONTEXT_BUSY")
        store.put("active",JsonPrimitive(id))
    }
    private fun checkSnapshot(expected: BurpSnapshot, actual: BurpSnapshot, p: CompiledPlan) {
        requireJob(expected.instanceId==actual.instanceId && expected.adapterVersion==actual.adapterVersion,"INSTANCE_CHANGED")
        if(expected.projectMarker!=null) requireJob(expected.projectMarker==actual.projectMarker,"PROJECT_IDENTITY_CHANGED")
        requireJob(actual.capabilities.containsAll(p.proposal.requiredCapabilities),"CAPABILITY_CHANGED")
        val dependencies=settingDependencyDifferences(p,expected,actual)
        requireJob(projectNativeScopeEquivalent(expected.project,actual.project) ||
            dependencies.none { it.path.startsWith("/project/") && it.impact!="UNAFFECTED" },"PROJECT_SETTINGS_CHANGED")
        requireJob(dependencies.none { it.path.startsWith("/cph/") && it.impact!="UNAFFECTED" },"CPH_SETTINGS_CHANGED")
        val needed=expected.cph.keys.filter { name -> expected.cph[name]?.jsonObject?.get("enabled")==JsonPrimitive(true) || name==digest("options") }.toMutableSet()
        fun addDependency(name:String) {
            val tab=expected.cph[name]?.jsonObject ?: return
            if(tab["dynamic_checkbox"]!=JsonPrimitive(true) || tab["extract_choice_index"]!=JsonPrimitive(2)) return
            val source=tab["cached_selection"]?.jsonPrimitive?.contentOrNull
            if(!source.isNullOrBlank() && needed.add(source)) addDependency(source)
        }
        needed.toList().forEach(::addDependency)
        requireJob(actual.cphOrder.filter { it in needed }==expected.cphOrder.filter { it in needed },"CPH_ORDER_CHANGED")
    }
    private fun expected(p: CompiledPlan,v: CompiledVariant) = p.baseline.copy(project=v.project,cph=v.cph,cphOrder=v.cphOrder)
    /** The merged/reviewed restoration target is stronger than permission to send under current dependencies. */
    private fun checkRestoredSnapshot(target:BurpSnapshot,actual:BurpSnapshot,p:CompiledPlan) {
        requireJob(target.instanceId==actual.instanceId && target.adapterVersion==actual.adapterVersion,"INSTANCE_CHANGED")
        if(target.projectMarker!=null) requireJob(target.projectMarker==actual.projectMarker,"PROJECT_IDENTITY_CHANGED")
        requireJob(actual.capabilities.containsAll(p.proposal.requiredCapabilities),"CAPABILITY_CHANGED")
        requireJob(projectNativeScopeEquivalent(target.project,actual.project),"PROJECT_SETTINGS_NOT_RESTORED")
        val targetCph=cphDefinitions(target.cph)
        val currentCph=cphDefinitions(actual.cph)
        requireJob(JsonObject(currentCph.filterKeys { it in targetCph })==targetCph,"CPH_SETTINGS_NOT_RESTORED")
        // Atomic keep-import may retain newly created owned definitions, disabled and unchanged.
        val residues=currentCph.filterKeys { it !in targetCph }
        for((name,value) in residues) {
            val approved=p.variants.mapNotNull { it.cph[name] as? JsonObject }
            requireJob(name in p.variants.flatMap { it.variant.settings.cph.keys } &&
                value.jsonObject["enabled"]==JsonPrimitive(false) && approved.any { definition ->
                    cphDefinitions(JsonObject(mapOf(name to JsonObject(definition+("enabled" to JsonPrimitive(false))))))[name]==value
                },"UNVERIFIED_CPH_RESTORE_RESIDUE")
        }
        requireJob(actual.cphOrder.toSet()==actual.cph.keys && actual.cphOrder.size==actual.cph.size,"CPH_ORDER_INCONSISTENT")
        requireJob(actual.cphOrder.filter { it in targetCph }==target.cphOrder,"CPH_ORDER_NOT_RESTORED")
    }
    private fun checkedApply(id:String,p:CompiledPlan,v:CompiledVariant,operation:String,stage:ApprovalStage) {
        permitted(id,stage)
        store.onceJson("$id:$operation",v.settingsDigest) {
            permitted(id,stage)
            val phaseBefore=port.snapshot()
            save("apply-before:$id:$operation",phaseBefore)
            var applyFailure:Exception?=null
            val phaseBaseline=store.get("phase-baseline:$id")?.let { jobJson.decodeFromJsonElement<BurpSnapshot>(it) } ?: p.baseline
            val phaseTarget=approvedPhaseCandidate(phaseBaseline,expected(p,v),phaseBefore)
            save("apply-target:$id:$operation",phaseTarget)
            try { port.apply(v.copy(project=phaseTarget.project,cph=phaseTarget.cph,cphOrder=phaseTarget.cphOrder),phaseBefore,"$id:$operation") } catch(error:Exception) { applyFailure=error }
            val readback = try { port.snapshot() } catch(error:Exception) {
                store.put("apply-observation-failure:$id:$operation",buildJsonObject {
                    put("operationId","$id:$operation");put("observedAt",now())
                    put("applyError",applyFailure?.javaClass?.simpleName?.let(::JsonPrimitive) ?: JsonNull)
                    put("readbackError",error.javaClass.simpleName)
                })
                throw applyFailure ?: error
            }
            val readbackKey = "apply-readback:$id:${UUID.randomUUID()}"
            store.transaction {
                store.put(readbackKey, buildJsonObject {
                    put("operationId", "$id:$operation"); put("observedAt", now())
                    put("planDigest", p.planDigest); put("settingsDigest", v.settingsDigest)
                    put("snapshot", jobJson.encodeToJsonElement(readback))
                    put("beforeSnapshot",jobJson.encodeToJsonElement(phaseBefore))
                    put("applyOutcome",if(applyFailure==null) "RETURNED" else "UNKNOWN")
                    put("applyError",applyFailure?.let { JsonPrimitive((it as? JobRejected)?.code ?: it.javaClass.simpleName) } ?: JsonNull)
                })
                store.put("latest-apply-readback:$id", JsonPrimitive(readbackKey))
            }
            applyFailure?.let { throw it }
            checkSnapshot(expected(p,v),readback,p)
            JsonPrimitive(true)
        }
    }
    private fun restore(id:String,p:CompiledPlan,from:CompiledVariant,operation:String,stage:ApprovalStage): BurpSnapshot {
        checkSnapshot(expected(p,from),port.snapshot(),p)
        permitted(id,stage)
        store.onceJson("$id:$operation",p.planDigest) {
            permitted(id,stage)
            val destination=p.restorationBaseline ?: p.baseline
            val current=port.snapshot()
            val target=approvedPhaseCandidate(expected(p,from),destination,current)
            save("restore-before:$id:$operation",current)
            save("restore-target:$id:$operation",target)
            port.restore(target,p.variants.flatMap { it.variant.settings.cph.keys }.toSet(),current,"$id:$operation")
            val actual=port.snapshot(); checkRestoredSnapshot(target,actual,p)
            // Keep only proven owned disabled residue in the logical baseline, never human changes.
            val residue=actual.cph.filter { (name,value) ->
                name !in destination.cph && name.startsWith("job:"+p.proposal.jobId+":") &&
                    value.jsonObject["enabled"]==JsonPrimitive(false)
            }
            val phaseBaseline=destination.copy(cph=JsonObject(destination.cph+residue),
                cphOrder=actual.cphOrder.filter { it in destination.cph || it in residue })
            save("phase-baseline:$id",phaseBaseline)
            jobJson.encodeToJsonElement(actual)
        }
        return port.snapshot()
    }
    private fun checkOncePreparation(p:CompiledPlan,report:ValidationReport) {
        val expected=p.variants.flatMap { v -> v.variant.preparationOnce.indices.map { v.variant.id to it } }.toSet()
        val actual=report.preparationOnce.map { it.variantId to it.index }
        requireJob(actual.size==expected.size && actual.toSet()==expected && report.preparationOnce.all { evidence ->
            evidence.settingsDigest==p.variants.single { it.variant.id==evidence.variantId }.settingsDigest && evidence.response.isNotBlank()
        },"PREPARATION_ONCE_EVIDENCE_REQUIRED")
    }
    @Synchronized fun prepare(id:String): ValidationReport {
        val r=live(id); val p=plan(id)
        InputCoverage.validateRequestedScope(p.proposal)
        validateAuthenticationToolScopes(p)
        if(r.state=="VALIDATED") return read("validation:$id")
        requireJob(r.state=="PREPARATION_APPROVED","INVALID_STATE")
        permitted(id,ApprovalStage.PREPARATION)
        checkSnapshot(p.baseline,port.snapshot(),p)
        store.transaction { acquire(id);write(r.copy(state="PREPARING")) }
        val probes=mutableListOf<ProbeEvidence>()
        val preparationOnce=mutableListOf<PreparationEvidence>()
        try {
            p.variants.forEachIndexed { phaseIndex,v ->
                write(record(id).copy(variantIndex=phaseIndex))
                permitted(id,ApprovalStage.PREPARATION)
                checkedApply(id,p,v,"prepare-apply:${v.variant.id}",ApprovalStage.PREPARATION)
                v.variant.preparationOnce.forEachIndexed { index,request ->
                    permitted(id,ApprovalStage.PREPARATION)
                    checkSnapshot(expected(p,v),port.snapshot(),p)
                    val input=fingerprint(buildJsonObject {
                        put("planDigest",p.planDigest);put("settingsDigest",v.settingsDigest)
                        put("request",jobJson.encodeToJsonElement(request))
                    })
                    val result=store.onceJson("$id:preparation-once:${v.variant.id}:$index",input) {
                        permitted(id,ApprovalStage.PREPARATION)
                        checkSnapshot(expected(p,v),port.snapshot(),p)
                        val (response,logger)=port.oncePreparation(request)
                        requireJob(response.isNotBlank(),"NO_PREPARATION_ONCE_RESPONSE")
                        jobJson.encodeToJsonElement(PreparationEvidence(v.variant.id,index,v.settingsDigest,response,logger,now()))
                    }
                    preparationOnce.add(jobJson.decodeFromJsonElement(result))
                    save("partial-preparation-once:$id",preparationOnce)
                }
                v.variant.requiredBranches.forEach { branch -> repeat(5) { index ->
                    permitted(id,ApprovalStage.PREPARATION)
                    checkSnapshot(expected(p,v),port.snapshot(),p)
                    val result=store.onceJson("$id:probe:${v.variant.id}:$branch:$index",v.settingsDigest) {
                        val (response,logger)=port.probe(v.variant,branch)
                        requireJob(response.isNotBlank(),"NO_PROBE_RESPONSE")
                        jobJson.encodeToJsonElement(ProbeEvidence(v.variant.id,branch,index,v.settingsDigest,response,logger,now()))
                    }
                    probes.add(jobJson.decodeFromJsonElement(result))
                } }
                restore(id,p,v,"prepare-restore:${v.variant.id}",ApprovalStage.PREPARATION)
            }
            val actual=port.snapshot()
            val report=ValidationReport(p.planDigest,probes,now(),true,actual.cph.keys.filter { it !in p.baseline.cph },preparationOnce)
            store.transaction {
                save("validation:$id",report);save("prepared-baseline:$id",actual)
                write(r.copy(state="VALIDATED",cleanupState="SETTINGS_RESTORED_WITH_REPORTED_RESIDUE"))
                store.put("active",JsonNull)
            }
            return report
        } catch(e:Exception) {
            save("partial-validation:$id",probes)
            save("partial-preparation-once:$id",preparationOnce)
            write(record(id).copy(state="RECOVERY_REQUIRED",warnings=listOf((e as? JobRejected)?.code ?: "PREPARATION_OUTCOME_UNKNOWN")))
            throw e
        }
    }
    @Synchronized fun start(id:String, fence:Long, expectedEpoch:String): ExecutionRecord {
        var r=live(id);val p=plan(id)
        requireJob(r.fence==fence && epoch==expectedEpoch,"STALE_WORKER_OR_FENCE")
        if(r.state=="RUNNING") return r
        requireJob(r.state=="EXECUTION_APPROVED","INVALID_STATE")
        InputCoverage.validateRequestedScope(p.proposal)
        validateAuthenticationToolScopes(p)
        permitted(id,ApprovalStage.EXECUTION)
        val report=read<ValidationReport>("validation:$id")
        requireJob(now()-report.completedAt in 0..p.proposal.validationMaxAgeSeconds,"VALIDATION_EXPIRED")
        checkSnapshot(read("prepared-baseline:$id"),port.snapshot(),p)
        val v=p.variants[r.variantIndex]
        r=r.copy(state="APPLYING",cleanupState="SETTINGS_APPLY_OUTCOME_PENDING")
        store.transaction { acquire(id);write(r) }
        var submitting=false
        var committed=false
        var metadataComplete=false
        var observedStart:JsonObject?=null
        try {
            checkedApply(id,p,v,"run-apply:${r.variantIndex}",ApprovalStage.EXECUTION)
            r=r.copy(cleanupState="SETTINGS_APPLIED")
            permitted(id,ApprovalStage.EXECUTION)
            write(r.copy(state="SUBMITTING"));submitting=true
            val response=store.onceJson("$id:start:${r.variantIndex}",fingerprint(v.variant)) {
                port.start(v.variant).also { observedStart=it }
            }.jsonObject
            committed=true
            val noAudit=provenNoAuditStart(response)
            val status=(response["status"] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull
            val handle=startHandle(response,"auditId")
            val state=when {
                noAudit -> "RECOVERY_REQUIRED"
                handle==null || response["submissionError"]?.let { it!=JsonNull }==true -> "SUBMISSION_UNKNOWN"
                status=="submitted_status_unavailable" -> "OBSERVATION_UNKNOWN"
                status=="started" -> "RUNNING"
                else -> "SUBMISSION_UNKNOWN"
            }
            // Keep the known outcome in memory BEFORE any supplementary persistence can fail.
            r=r.copy(state=state,auditId=handle,payloadRunId=startHandle(response,"payloadRunId"),
                warnings=r.warnings+listOfNotNull(scanStartErrorCode(response)))
            if(noAudit) submitting=false
            store.transaction {
                write(r)
                retainNativeMetrics(id,r.variantIndex,r.auditId,response)
                store.put("start-outcome:$id:${r.variantIndex}",buildJsonObject {
                    put("operationId","$id:start:${r.variantIndex}");put("planDigest",p.planDigest);put("observedAt",now())
                    put("result",scanStartSummary(response))
                })
                if(noAudit) save("start-rejection:$id:${r.variantIndex}",response)
            }
            metadataComplete=true
            if(noAudit) throw JobRejected(scanStartErrorCode(response)!!,mapOf("stage" to response.getValue("stage").jsonPrimitive.content))
            requireJob(!r.auditId.isNullOrBlank(),scanStartErrorCode(response) ?: "START_HANDLE_MISSING")
            return r
        } catch(e:Throwable) {
            if(e !is Exception && e !is LinkageError) throw e
            val warning=if(!committed && observedStart!=null) "START_RESULT_COMMIT_FAILED:"+((e as? JobRejected)?.code ?: e.javaClass.simpleName)
                else if(committed && !metadataComplete) "START_RESULT_METADATA_SAVE_FAILED:"+((e as? JobRejected)?.code ?: e.javaClass.simpleName)
                else (e as? JobRejected)?.code ?: "START_OUTCOME_UNKNOWN"
            if(!committed) observedStart?.let { observed ->
                r=r.copy(auditId=startHandle(observed,"auditId"),payloadRunId=startHandle(observed,"payloadRunId"))
                // Retain observations, never convert an INTENT into COMMITTED proof or retry its action.
                val observationSaved=runCatching { store.transaction {
                    retainNativeMetrics(id,r.variantIndex,r.auditId,observed)
                    store.put("start-observation:$id:${r.variantIndex}",buildJsonObject {
                        put("operationId","$id:start:${r.variantIndex}");put("planDigest",p.planDigest);put("observedAt",now())
                        put("source","UNCOMMITTED_START_RESPONSE");put("commitState","UNVERIFIED")
                        r.auditId?.let { put("auditId",it) };r.payloadRunId?.let { put("payloadRunId",it) }
                        put("result",scanStartSummary(observed))
                    })
                } }
                observationSaved.exceptionOrNull()?.let { failure ->
                    r=r.copy(warnings=r.warnings+("START_OBSERVATION_SAVE_FAILED:"+failure.javaClass.simpleName))
                }
            }
            // A committed outcome is not made uncertain by a later metadata failure.
            write(r.copy(state=if(committed) r.state else if(submitting) "SUBMISSION_UNKNOWN" else "RECOVERY_REQUIRED",warnings=(r.warnings+warning).distinct()))
            throw e
        }
    }
    @Synchronized fun poll(id:String): ExecutionRecord {
        val r=record(id);val p=plan(id)
        requireJob(r.epoch==epoch,"WORKER_EPOCH_CHANGED_RECONCILIATION_REQUIRED")
        if(r.state=="EXECUTION_FINISHED") return r
        val retainedAuditId=r.auditId
        if(r.state=="SUBMISSION_UNKNOWN" && retainedAuditId!=null) {
            val observation=port.poll(retainedAuditId)
            retainNativeMetrics(id,r.variantIndex,retainedAuditId,observation)
            save("uncertain-observation:$id",observation)
            // An apparently finished native task does not prove acceptance of the original request.
            return r
        }
        requireJob(r.state=="RUNNING" || r.state=="OBSERVATION_UNKNOWN","CONTROL_OR_RECOVERY_REQUIRED")
        try { permitted(id,ApprovalStage.EXECUTION) } catch(e:Exception) {
            return r.copy(state="CONTROL_REQUIRED",warnings=listOf("APPROVAL_EXPIRED_OR_REVOKED_NATIVE_MAY_CONTINUE")).also(::write)
        }
        val snapshot=try { port.poll(r.auditId!!) } catch(e:Exception) {
            return r.copy(state="OBSERVATION_UNKNOWN").also(::write)
        }
        retainNativeMetrics(id,r.variantIndex,r.auditId,snapshot)
        save("observation:$id:${r.variantIndex}",snapshot)
        val status=snapshot["auditStatusMessage"]?.jsonPrimitive?.contentOrNull?.lowercase()
        if(status in setOf("cancelled","canceled")) return r.copy(state="CONTROL_REQUIRED",warnings=listOf("CANCELLED_PARTIAL_RESULTS_RETAINED")).also(::write)
        if(snapshot["completed"]?.jsonPrimitive?.booleanOrNull!=true || snapshot["submissionError"]?.let { it!=JsonNull }==true) {
            return r.copy(state=if(snapshot["observationError"]?.let { it!=JsonNull }==true || snapshot["completed"]==JsonNull) "OBSERVATION_UNKNOWN" else "RUNNING").also(::write)
        }
        val v=p.variants[r.variantIndex]
        return try {
            val evidence=collectEvidence(id,r.auditId!!,r.payloadRunId)
            appendEvidence(id,"result:$id:${r.variantIndex}",evidence)
            if((evidence["collectionErrors"] as? JsonObject)?.isNotEmpty()==true) {
                return r.copy(state="RECOVERY_REQUIRED",evidenceState="PARTIAL",warnings=r.warnings+"PARTIAL_EVIDENCE_COLLECTION_FAILED").also(::write)
            }
            if(evidence["quiescent"]?.jsonPrimitive?.booleanOrNull!=true) {
                return r.copy(state="RUNNING",evidenceState="PARTIAL").also(::write)
            }
            checkSnapshot(expected(p,v),port.snapshot(),p)
            permitted(id,ApprovalStage.EXECUTION)
            // A post-scan normal request is a separately journaled side effect under the execution approval.
            val afterKey="normal-after:$id:${r.variantIndex}"
            val after=store.onceJson("$id:normal-after:${r.variantIndex}",v.settingsDigest) {
                permitted(id,ApprovalStage.EXECUTION)
                val (response,logger)=port.probe(v.variant,"normal")
                requireJob(response.isNotBlank(),"NO_PROBE_RESPONSE")
                buildJsonObject { put("response",response);put("logger",logger) }
            }
            appendEvidence(id,afterKey,after)
            restore(id,p,v,"run-restore:${r.variantIndex}",ApprovalStage.EXECUTION)
            val all=r.variantIndex+1==p.variants.size
            val next=r.copy(state=if(all) "EXECUTION_FINISHED" else "EXECUTION_APPROVED",variantIndex=r.variantIndex+1,
                auditId=null,payloadRunId=null,evidenceState=if(r.evidenceState!="INCOMPLETE" && evidence["complete"]?.jsonPrimitive?.booleanOrNull==true) "COLLECTED" else "INCOMPLETE",
                cleanupState="SETTINGS_RESTORED_BUSINESS_REVIEW_REQUIRED")
            val baseline=if(!all) port.snapshot() else null
            store.transaction {
                if(!all) save("prepared-baseline:$id",baseline!!) else store.put("active",JsonNull)
                write(next)
            }
            next
        } catch(e:Exception) {
            val storageDetails=(e as? JobRejected)?.takeIf { it.code=="STORE_SQLITE_FAILURE" }?.safeDetails ?:
                (e as? java.sql.SQLException)?.let { sqliteFailureDetails(it,"EVIDENCE_OR_RESTORE") }
            if(storageDetails!=null) store.put("storage-failure:$id",buildJsonObject {
                put("errorCode","STORE_SQLITE_FAILURE")
                put("errorDetails",buildJsonObject { storageDetails.forEach { (key,value) -> put(key,value) } })
                put("diagnosisCompleted",false)
            })
            r.copy(state=if((e as? JobRejected)?.code=="APPROVAL_NOT_VALID") "CONTROL_REQUIRED" else "RECOVERY_REQUIRED",
                warnings=listOf((e as? JobRejected)?.code ?: "EVIDENCE_OR_RESTORE_FAILED")).also(::write)
        }
    }
    private fun appendEvidence(id:String,base:String,value:JsonElement) = store.transaction {
        val refs=(store.get("result-index:$id") as? JsonArray)?.toMutableList() ?: mutableListOf()
        val previous=store.get(base)
        val key=if(previous==null || fingerprint(previous)==fingerprint(value)) base else "$base:${UUID.randomUUID()}"
        val reference=buildJsonObject { put("key",key);put("digest",fingerprint(value)) }
        if(reference !in refs) {
            requireJob(refs.size<1000,"PARTIAL_EVIDENCE_LIMIT")
            store.put(key,value);refs.add(reference);store.put("result-index:$id",JsonArray(refs))
        }
    }
    /** UI observation is recorded, never implemented by a new Montoya pause/cancel tool. */
    @Synchronized fun recordControl(id:String, observation:JsonObject): ExecutionRecord {
        requireJob(observation["evidenceRef"]?.jsonPrimitive?.content?.isNotBlank()==true,"UI_EVIDENCE_REQUIRED")
        store.put("control:$id",observation)
        return record(id).copy(state="CONTROL_REQUIRED",warnings=listOf("UI_OBSERVATION_REQUIRES_TARGET_AND_NATIVE_RECONCILIATION")).also(::write)
    }
    @Synchronized fun savedResults(id:String):JsonObject {
        if(store.get("result-index:$id")==null) capturePartialResults(id)
        return SavedResults(store).read(id)
    }
    @Synchronized fun capturePartialResults(id:String):JsonObject {
        // Read-only collection is also useful after restart; this never restores a native handle.
        val r=record(id)
        val retainedAuditId=r.auditId ?: throw JobRejected("NO_LIVE_AUDIT_FOR_PARTIAL_RESULTS")
        val evidence=collectEvidence(id,retainedAuditId,r.payloadRunId)
        val partial=JsonObject(evidence+mapOf("observationKind" to JsonPrimitive("PARTIAL_OBSERVATION"),"complete" to JsonPrimitive(false)))
        val key="partial:$id:${UUID.randomUUID()}"
        appendEvidence(id,key,partial)
        return SavedResults(store).read(id)
    }
    private fun terminal(native:JsonObject):Boolean = nativeExecutionTerminal(native)

    /** Durable, digest-checked terminal evidence is usable after an installation update.
     * It never resurrects an Audit handle or proves the diagnosis complete. */
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    private fun savedTermination(id:String,audit:String,p:CompiledPlan):Boolean = try {
        SavedResults(store).read(id)["records"]!!.jsonArray.any { value ->
            val record=value.jsonObject
            if(record["auditId"]?.jsonPrimitive?.contentOrNull!=audit || !terminal(record["native"]?.jsonObject ?: return@any false)) return@any false
            val status=record["loggerStatus"]?.jsonObject ?: return@any false
            val window=record["loggerWindow"] as? JsonObject
            if(window!=null) {
                if(window["after"]!=status || !loggerCaptureWindowHealthy(window)) return@any false
            } else if(status["droppedEntries"]?.jsonPrimitive?.longOrNull!=0L || status["captureErrors"]?.jsonPrimitive?.longOrNull!=0L) return@any false
            if(record["loggerPages"] !is JsonArray) return@any false
            val pages=SavedResults(store).pages(record,"loggerPages")
            pages.all { page ->
                jobJson.decodeToSequence<JsonObject>(page.jsonPrimitive.content.byteInputStream(),DecodeSequenceMode.WHITESPACE_SEPARATED).all { item ->
                    val service=item["httpService"]?.jsonObject
                    val relevant=item["tool"]?.jsonPrimitive?.contentOrNull in setOf("SCANNER","EXTENSIONS") && p.expandedEndpoints.any { endpoint ->
                        service?.get("host")?.jsonPrimitive?.contentOrNull.equals(endpoint.host,true) &&
                            service?.get("port")?.jsonPrimitive?.intOrNull==endpoint.port && service["secure"]?.jsonPrimitive?.booleanOrNull==(endpoint.scheme=="https")
                    }
                    !relevant || item["responseState"]?.jsonPrimitive?.contentOrNull=="RESPONSE_RECEIVED"
                }
            }
        }
    } catch(_:Exception) { false }

    /** Restore the approved baseline through the same adapter. No target sends or native control. */
    @Synchronized fun recover(id:String,evidenceRef:String):ExecutionRecord {
        val r=record(id);val p=plan(id)
        if(r.state=="FAILED_RECONCILED") return r
        requireJob(r.state!="RETIRED_UNVERIFIED","RETIRED_EXECUTION_INCOMPLETE")
        requireJob(r.state!="EXECUTION_FINISHED" && evidenceRef.isNotBlank(),"RECOVERY_NOT_AVAILABLE")
        val active=store.get("active")?.jsonPrimitive?.contentOrNull
        requireJob(active==null || active==id,"ANOTHER_EXECUTION_OWNS_CONTEXT")
        requireJob(r.auditId!=null || r.state!="SUBMISSION_UNKNOWN","NATIVE_TERMINATION_UNPROVEN")
        fun stopped() {
            r.auditId?.let { audit ->
                val live=runCatching { port.poll(audit) }.getOrNull()
                requireJob(if(live!=null) terminal(live) else savedTermination(id,audit,p),"NATIVE_TERMINATION_UNPROVEN")
            }
            requireJob(port.recoveryReadiness(p.expandedEndpoints),"HELPER_TRAFFIC_NOT_QUIESCENT")
        }
        stopped()
        val initial=port.snapshot()
        val coldCph=try { checkRecoveryOwnership(p,initial);false } catch(e:JobRejected) {
            if(e.code !in setOf("UNRELATED_CPH_CHANGED","UNRELATED_CPH_OPTIONS_CHANGED","UNRELATED_CPH_ORDER_CHANGED")) throw e
            requireJob(r.epoch!=epoch && active==id,"COLD_CPH_RECOVERY_NOT_AVAILABLE")
            requireJob(port.retirementReadiness(r.auditId ?: id),"CURRENT_AUDIT_ACTIVITY_OR_HANDLE_PRESENT")
            checkColdCphRecoveryOwnership(p,initial)
            true
        }
        if(r.auditId!=null && store.get("result-index:$id")==null && r.epoch==epoch) capturePartialResults(id)
        val who=(if(coldCph) approver.reviewColdCphRestore(p,r,evidenceRef,fingerprint(initial))
            else approver.reviewRestore(p,r,evidenceRef)) ?: throw JobRejected("HUMAN_DENIED")
        requireJob(who.isNotBlank() && (!coldCph || !who.startsWith("Quick:")),"APPROVER_REQUIRED")
        stopped();val before=port.snapshot()
        if(coldCph) {
            requireJob(store.get("active")?.jsonPrimitive?.contentOrNull==id && record(id)==r,"EXECUTION_CHANGED_DURING_REVIEW")
            requireJob(port.retirementReadiness(r.auditId ?: id),"CURRENT_AUDIT_ACTIVITY_OR_HANDLE_PRESENT")
            requireJob(fingerprint(before)==fingerprint(initial),"CURRENT_CONTEXT_CHANGED")
            checkColdCphRecoveryOwnership(p,before)
        } else checkRecoveryOwnership(p,before)
        val baseline=recoveryBaseline(id,p).copy(instanceId=before.instanceId)
        val alreadyRestored=runCatching { checkRestoredSnapshot(baseline,before,p);true }.getOrDefault(false)
        try {
            if(!alreadyRestored) store.onceJson("$id:recover-settings",p.planDigest) {
                port.restore(baseline,p.variants.flatMap { it.variant.settings.cph.keys }.toSet(),before,"$id:recover-settings")
                val actual=port.snapshot();checkRestoredSnapshot(baseline,actual,p)
                jobJson.encodeToJsonElement(actual)
            }
            checkRestoredSnapshot(baseline,port.snapshot(),p)
            val next=r.copy(epoch=epoch,state="FAILED_RECONCILED",cleanupState="SETTINGS_RESTORED_BUSINESS_REVIEW_REQUIRED",
                warnings=r.warnings+"BASELINE_RESTORED_NO_TARGET_REPLAY"+
                    if(coldCph) listOf("COLD_CPH_BASELINE_RESTORED_AFTER_HUMAN_REVIEW") else emptyList())
            store.transaction {
                save("approval:$id:RECOVERY",ApprovalRecord(UUID.randomUUID().toString(),id,p.planDigest,ApprovalStage.RECOVERY,now(),now()+3600,who))
                store.put("reconciliation:$id",buildJsonObject { put("operator",who);put("evidenceRef",evidenceRef);put("confirmedAt",now());put("previous",jobJson.encodeToJsonElement(r));put("automaticSettingsRestore",true)
                    if(coldCph) { put("coldCphRestore",true);put("preRestoreSnapshot",jobJson.encodeToJsonElement(initial)) } })
                write(next);store.put("active",JsonNull)
            }
            return next
        } catch(e:Exception) {
            write(r.copy(state="RECOVERY_REQUIRED",warnings=r.warnings+((e as? JobRejected)?.code ?: "SETTINGS_RESTORE_OUTCOME_UNKNOWN")))
            throw e
        }
    }
    /** Old-context maintenance: restore settings while preserving unknown transport termination. */
    @Synchronized fun recoverUnverified(id:String,evidenceRef:String):ExecutionRecord {
        val r=record(id);val p=plan(id)
        requireJob(evidenceRef.isNotBlank(),"UI_EVIDENCE_REQUIRED")
        requireJob(r.epoch!=epoch && r.state !in setOf("EXECUTION_FINISHED","FAILED_RECONCILED",
            "RETIRED_UNVERIFIED","MAINTENANCE_RESTORED_UNVERIFIED","SUBMISSION_UNKNOWN"),"UNVERIFIED_RESTORE_NOT_AVAILABLE")
        fun stopped() {
            requireJob(store.get("active")?.jsonPrimitive?.contentOrNull==id,"EXECUTION_DOES_NOT_OWN_CONTEXT")
            requireJob(port.retirementReadiness(r.auditId ?: id),"CURRENT_AUDIT_ACTIVITY_OR_HANDLE_PRESENT")
            requireJob(port.currentRecoveryReadiness(p.expandedEndpoints),"CURRENT_HELPER_TRAFFIC_NOT_QUIESCENT")
        }
        stopped()
        val before=port.snapshot()
        val coldCph=try { checkRecoveryOwnership(p,before);false } catch(e:JobRejected) {
            if(e.code !in setOf("UNRELATED_CPH_CHANGED","UNRELATED_CPH_OPTIONS_CHANGED","UNRELATED_CPH_ORDER_CHANGED")) throw e
            checkColdCphRecoveryOwnership(p,before)
            true
        }
        val beforeDigest=fingerprint(before)
        val human=approver.reviewUnverifiedRestore(p,r,evidenceRef,beforeDigest,coldCph)
            ?: throw JobRejected("HUMAN_DENIED")
        requireJob(human.isNotBlank() && !human.startsWith("Quick:"),"HUMAN_MAINTENANCE_REVIEW_REQUIRED")
        stopped()
        requireJob(record(id)==r && fingerprint(port.snapshot())==beforeDigest,"CURRENT_CONTEXT_CHANGED")
        if(coldCph) checkColdCphRecoveryOwnership(p,before) else checkRecoveryOwnership(p,before)
        val baseline=recoveryBaseline(id,p).copy(instanceId=before.instanceId)
        val alreadyRestored=runCatching { checkRestoredSnapshot(baseline,before,p);true }.getOrDefault(false)
        try {
            if(!alreadyRestored) store.onceJson("$id:recover-unverified-settings",p.planDigest) {
                port.restore(baseline,p.variants.flatMap { it.variant.settings.cph.keys }.toSet(),
                    before,"$id:recover-unverified-settings")
                val actual=port.snapshot();checkRestoredSnapshot(baseline,actual,p)
                jobJson.encodeToJsonElement(actual)
            }
            val after=port.snapshot();checkRestoredSnapshot(baseline,after,p)
            val next=r.copy(epoch=epoch,state="MAINTENANCE_RESTORED_UNVERIFIED",
                cleanupState="SETTINGS_RESTORED_BUSINESS_REVIEW_REQUIRED",diagnosisState="INCOMPLETE",
                warnings=r.warnings+"OLD_TERMINATION_UNVERIFIED"+"BASELINE_RESTORED_NO_TARGET_REPLAY")
            store.transaction {
                store.put("unverified-recovery:$id",buildJsonObject {
                    put("operator",human);put("evidenceRef",evidenceRef);put("confirmedAt",now())
                    put("previous",jobJson.encodeToJsonElement(r));put("before",jobJson.encodeToJsonElement(before))
                    put("after",jobJson.encodeToJsonElement(after));put("coldCph",coldCph)
                    put("oldTerminationVerified",false);put("httpTrafficSent",false);put("scanControlled",false)
                })
                write(next);store.put("active",JsonNull)
            }
            return next
        } catch(e:Exception) {
            write(r.copy(state="RECOVERY_REQUIRED",warnings=r.warnings+((e as? JobRejected)?.code ?: "SETTINGS_RESTORE_OUTCOME_UNKNOWN")))
            throw e
        }
    }
    /** A human first confirms UI termination/quiescence and restores settings; this never controls a native task. */
    @Synchronized fun reconcileRestored(id:String,evidenceRef:String):ExecutionRecord {
        val r=record(id);val p=plan(id)
        requireJob(evidenceRef.isNotBlank(),"UI_EVIDENCE_REQUIRED")
        requireJob(r.state !in setOf("EXECUTION_FINISHED","FAILED_RECONCILED","RETIRED_UNVERIFIED"),"ALREADY_TERMINAL")
        val human=approver.reviewRecovery(p,r,evidenceRef) ?: throw JobRejected("HUMAN_DENIED")
        val actual=port.snapshot()
        checkRestoredSnapshot(recoveryBaseline(id,p).copy(instanceId=actual.instanceId),actual,p)
        store.put("reconciliation:$id",buildJsonObject { put("operator",human);put("evidenceRef",evidenceRef);put("confirmedAt",now());put("previous",jobJson.encodeToJsonElement(r)) })
        val active=store.get("active")?.jsonPrimitive?.contentOrNull
        requireJob(active==null || active==id,"ANOTHER_EXECUTION_OWNS_CONTEXT")
        val next=r.copy(state="FAILED_RECONCILED",cleanupState="SETTINGS_RESTORED_BUSINESS_REVIEW_REQUIRED",
            warnings=r.warnings+"HUMAN_RECONCILED_NO_AUTOMATIC_REPLAY")
        store.transaction { write(next);store.put("active",JsonNull) }
        return next
    }

    // A failed/incomplete preparation never promotes authentication definitions into reusable settings.
    private fun recoveryBaseline(id:String,p:CompiledPlan):BurpSnapshot =
        if(store.get("validation:$id")!=null) p.restorationBaseline ?: p.baseline else p.baseline
    /** Maintenance only. Preserves unknown old outcomes; NEVER restores settings or declares termination. */
    @Synchronized fun retire(id:String,evidenceRef:String):ExecutionRecord {
        val r=record(id);val p=plan(id)
        if(r.state=="RETIRED_UNVERIFIED") return r
        requireJob(evidenceRef.isNotBlank(),"RETIREMENT_EVIDENCE_REFERENCE_REQUIRED")
        requireJob(r.epoch!=epoch,"LIVE_CONTEXT_CANNOT_RETIRE")
        val auditId=r.auditId ?: throw JobRejected("RETIREMENT_NOT_AVAILABLE")
        requireJob(r.state !in setOf("EXECUTION_FINISHED","FAILED_RECONCILED","SUBMISSION_UNKNOWN"),"RETIREMENT_NOT_AVAILABLE")
        fun checkedSnapshot():BurpSnapshot {
            requireJob(store.get("active")?.jsonPrimitive?.contentOrNull==id,"EXECUTION_DOES_NOT_OWN_CONTEXT")
            requireJob(port.retirementReadiness(auditId),"CURRENT_AUDIT_ACTIVITY_OR_HANDLE_PRESENT")
            requireJob(port.recoveryReadiness(p.expandedEndpoints),"HELPER_TRAFFIC_NOT_QUIESCENT")
            return port.snapshot().also { checkRetirementSettingsAbsent(p,it) }
        }
        val before=checkedSnapshot();val currentDigest=fingerprint(before)
        val human=approver.reviewRetirement(p,r,evidenceRef,currentDigest) ?: throw JobRejected("HUMAN_DENIED")
        requireJob(human.isNotBlank() && !human.startsWith("Quick:"),"HUMAN_MAINTENANCE_REVIEW_REQUIRED")
        requireJob(fingerprint(checkedSnapshot())==currentDigest,"CURRENT_CONTEXT_CHANGED")
        requireJob(record(id)==r,"EXECUTION_CHANGED_DURING_REVIEW")
        val next=r.copy(epoch=epoch,state="RETIRED_UNVERIFIED",cleanupState="NOT_RESTORED_OLD_CONTEXT_RETIRED",diagnosisState="INCOMPLETE",
            warnings=r.warnings+"HUMAN_RETIRED_OLD_CONTEXT_TERMINATION_AND_CLEANUP_UNVERIFIED")
        store.transaction {
            requireJob(store.get("active")?.jsonPrimitive?.contentOrNull==id,"EXECUTION_DOES_NOT_OWN_CONTEXT")
            save("retirement:$id",buildJsonObject {
                put("operator",human);put("evidenceRef",evidenceRef);put("confirmedAt",now())
                put("previous",jobJson.encodeToJsonElement(r));put("preservedCurrentSnapshot",jobJson.encodeToJsonElement(before));put("currentSnapshotDigest",currentDigest)
                put("oldTerminationVerified",false);put("oldSettingsRestored",false);put("diagnosisCompleted",false)
            })
            write(next);store.put("active",JsonNull)
        }
        return next
    }
}
