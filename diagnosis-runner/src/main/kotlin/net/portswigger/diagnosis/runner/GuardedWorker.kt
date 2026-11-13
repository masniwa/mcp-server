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
    fun apply(variant: CompiledVariant)
    fun restore(baseline: BurpSnapshot, ownedCphNames: Set<String>)
    /** One approved request in the once-only preparation list, outside all workflow probes. */
    fun oncePreparation(request:RequestPlan):Pair<String,JsonObject> = throw JobRejected("PREPARATION_ONCE_UNSUPPORTED")
    fun probe(variant: ScanVariant, branch: String): Pair<String, JsonObject>
    fun start(variant: ScanVariant): JsonObject
    fun poll(auditId: String): JsonObject
    fun collect(auditId: String, payloadRunId: String?): JsonObject
    /** Read-only observation of outstanding helper traffic; false unless supported by the adapter. */
    fun recoveryReadiness(endpoints:List<Endpoint>):Boolean = false
    /** A missing old handle AND no active/unknown tracked audit. Not proof of old termination. */
    fun retirementReadiness(auditId:String):Boolean = false
}
fun interface HumanApprover {
    /** Only a trusted UI implementation may approve; never take an approved flag from job JSON. */
    fun review(plan: CompiledPlan, stage: ApprovalStage, report: ValidationReport?): String?
    fun reviewRecovery(plan:CompiledPlan,record:ExecutionRecord,evidenceRef:String):String? = review(plan,ApprovalStage.RECOVERY,null)
    fun reviewRestore(plan:CompiledPlan,record:ExecutionRecord,evidenceRef:String):String? = reviewRecovery(plan,record,evidenceRef)
    fun reviewContinuation(plan:CompiledPlan,record:ExecutionRecord,report:ValidationReport):String? = review(plan,ApprovalStage.EXECUTION,report)
    /** Explicit maintenance attestation only; old implementations must fail closed. */
    fun reviewRetirement(plan:CompiledPlan,record:ExecutionRecord,evidenceRef:String,currentDigest:String):String? = null
}

class GuardedWorker(private val port: BurpExecutionPort, private val store: JobStore,
    private val approver: HumanApprover, private val clock: Clock = Clock.systemUTC()) {
    val epoch: String = UUID.randomUUID().toString()
    private fun now() = clock.instant().epochSecond
    private inline fun <reified T> read(key: String): T = jobJson.decodeFromJsonElement(store.get(key) ?: throw JobRejected("NOT_FOUND"))
    private inline fun <reified T> save(key: String, value: T) = store.put(key,jobJson.encodeToJsonElement(value))
    fun record(id: String): ExecutionRecord = read("execution:$id")
    fun plan(id: String): CompiledPlan = read("plan:$id")
    fun validation(id:String):ValidationReport = read("validation:$id")
    fun committedResults(id:String):JsonObject = SavedResults(store).read(id)
    fun contextStatus():JsonObject = buildJsonObject {
        val owner=store.get("active")?.jsonPrimitive?.contentOrNull
        put("ownerExecutionId",owner?.let(::JsonPrimitive) ?: JsonNull)
        owner?.let { id -> val r=record(id);put("ownerState",r.state);put("ownerEpochChanged",r.epoch!=epoch) }
    }
    fun quickRenewalDue(id:String):Boolean {
        val a=store.get("approval:$id:EXECUTION")?.let { jobJson.decodeFromJsonElement<ApprovalRecord>(it) } ?: return false
        return a.approver.startsWith("Quick:") && a.revokedAt==null && now()>=a.expiresAt
    }
    /** Status observation never sends a normal control or changes settings. */
    fun observeNative(id:String):JsonObject? = record(id).auditId?.let(port::poll)
    private fun write(r: ExecutionRecord) { save("execution:${r.executionId}",r) }

    @Synchronized fun register(id: String, proposal: JobProposal): CompiledPlan {
        return registerPlan(id, proposal, null)
    }

    /** Referenced baselines never inspect or modify the running Burp. Idle capture is read-only. */
    fun draftBaseline(sourceExecutionId: String?): BurpSnapshot {
        if(sourceExecutionId != null) return plan(sourceExecutionId).baseline
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
        val compiled = JobCompiler().compile(port.freezeInputs(proposal),port.snapshot())
        port.validateInputCoverage(compiled)
        store.transaction {
            store.put("submitted-proposal:$id",JsonPrimitive(fingerprint(proposal)))
            save("plan:$id",compiled)
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
        requireJob(stage!=ApprovalStage.RECOVERY,"USE_RECONCILIATION")
        val r = live(id); val p = plan(id)
        InputCoverage.validateRequestedScope(p.proposal)
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
    private fun acquire(id: String) {
        val active=store.get("active")?.jsonPrimitive?.contentOrNull
        requireJob(active==null || active==id,"BURP_CONTEXT_BUSY")
        store.put("active",JsonPrimitive(id))
    }
    private fun checkSnapshot(expected: BurpSnapshot, actual: BurpSnapshot, p: CompiledPlan) {
        requireJob(expected.instanceId==actual.instanceId && expected.adapterVersion==actual.adapterVersion,"INSTANCE_CHANGED")
        requireJob(actual.capabilities.containsAll(p.proposal.requiredCapabilities),"CAPABILITY_CHANGED")
        requireJob(canonical(projectDefinitions(expected.project))==canonical(projectDefinitions(actual.project)),"PROJECT_SETTINGS_CHANGED")
        val expectedDefs=cphDefinitions(expected.cph); val actualDefs=cphDefinitions(actual.cph)
        requireJob(expectedDefs.all { (k,v) -> actualDefs[k]==v },"CPH_SETTINGS_CHANGED")
        requireJob(actualDefs.filterKeys { it !in expectedDefs }.all { (k,v) ->
            k.startsWith("job:${p.proposal.jobId}:") && v.jsonObject["enabled"]?.jsonPrimitive?.booleanOrNull==false
        },"UNOWNED_OR_ENABLED_CPH_RESIDUE")
        requireJob(actual.cphOrder.filter { it in expected.cph }==expected.cphOrder,"CPH_ORDER_CHANGED")
    }
    private fun expected(p: CompiledPlan,v: CompiledVariant) = p.baseline.copy(project=v.project,cph=v.cph,cphOrder=v.cphOrder)
    private fun checkedApply(id:String,p:CompiledPlan,v:CompiledVariant,operation:String,stage:ApprovalStage) {
        permitted(id,stage)
        store.onceJson("$id:$operation",v.settingsDigest) {
            permitted(id,stage)
            port.apply(v)
            checkSnapshot(expected(p,v),port.snapshot(),p)
            JsonPrimitive(true)
        }
    }
    private fun restore(id:String,p:CompiledPlan,from:CompiledVariant,operation:String,stage:ApprovalStage): BurpSnapshot {
        checkSnapshot(expected(p,from),port.snapshot(),p)
        permitted(id,stage)
        store.onceJson("$id:$operation",p.planDigest) {
            permitted(id,stage)
            port.restore(p.baseline,p.variants.flatMap { it.variant.settings.cph.keys }.toSet())
            val actual=port.snapshot(); checkSnapshot(p.baseline,actual,p)
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
        if(r.state=="VALIDATED") return read("validation:$id")
        requireJob(r.state=="PREPARATION_APPROVED","INVALID_STATE")
        permitted(id,ApprovalStage.PREPARATION)
        checkSnapshot(p.baseline,port.snapshot(),p)
        store.transaction { acquire(id);write(r.copy(state="PREPARING")) }
        val probes=mutableListOf<ProbeEvidence>()
        val preparationOnce=mutableListOf<PreparationEvidence>()
        try {
            p.variants.forEach { v ->
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
            write(r.copy(state="RECOVERY_REQUIRED",warnings=listOf((e as? JobRejected)?.code ?: "PREPARATION_OUTCOME_UNKNOWN")))
            throw e
        }
    }
    @Synchronized fun start(id:String, fence:Long, expectedEpoch:String): ExecutionRecord {
        var r=live(id);val p=plan(id)
        requireJob(r.fence==fence && epoch==expectedEpoch,"STALE_WORKER_OR_FENCE")
        if(r.state=="RUNNING") return r
        requireJob(r.state=="EXECUTION_APPROVED","INVALID_STATE")
        InputCoverage.validateRequestedScope(p.proposal)
        permitted(id,ApprovalStage.EXECUTION)
        val report=read<ValidationReport>("validation:$id")
        requireJob(now()-report.completedAt in 0..p.proposal.validationMaxAgeSeconds,"VALIDATION_EXPIRED")
        checkSnapshot(read("prepared-baseline:$id"),port.snapshot(),p)
        val v=p.variants[r.variantIndex]
        r=r.copy(state="APPLYING",cleanupState="SETTINGS_APPLY_OUTCOME_PENDING")
        store.transaction { acquire(id);write(r) }
        var submitting=false
        try {
            checkedApply(id,p,v,"run-apply:${r.variantIndex}",ApprovalStage.EXECUTION)
            r=r.copy(cleanupState="SETTINGS_APPLIED")
            permitted(id,ApprovalStage.EXECUTION)
            write(r.copy(state="SUBMITTING"));submitting=true
            val response=store.onceJson("$id:start:${r.variantIndex}",fingerprint(v.variant)) { port.start(v.variant) }.jsonObject
            val unknown=response["status"]?.jsonPrimitive?.content!="started"
            r=r.copy(state=if(unknown) "SUBMISSION_UNKNOWN" else "RUNNING",
                auditId=response["auditId"]?.jsonPrimitive?.contentOrNull,payloadRunId=response["payloadRunId"]?.jsonPrimitive?.contentOrNull)
            requireJob(r.auditId!=null,"START_HANDLE_MISSING")
            write(r); return r
        } catch(e:Exception) {
            write(r.copy(state=if(submitting) "SUBMISSION_UNKNOWN" else "RECOVERY_REQUIRED",warnings=listOf((e as? JobRejected)?.code ?: "START_OUTCOME_UNKNOWN")))
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
        save("observation:$id:${r.variantIndex}",snapshot)
        val status=snapshot["auditStatusMessage"]?.jsonPrimitive?.contentOrNull?.lowercase()
        if(status in setOf("cancelled","canceled")) return r.copy(state="CONTROL_REQUIRED",warnings=listOf("CANCELLED_PARTIAL_RESULTS_RETAINED")).also(::write)
        if(snapshot["completed"]?.jsonPrimitive?.booleanOrNull!=true || snapshot["submissionError"]!=null) {
            return r.copy(state=if(snapshot["observationError"]!=null || snapshot["completed"]==JsonNull) "OBSERVATION_UNKNOWN" else "RUNNING").also(::write)
        }
        val v=p.variants[r.variantIndex]
        return try {
            checkSnapshot(expected(p,v),port.snapshot(),p)
            val evidence=port.collect(r.auditId!!,r.payloadRunId)
            appendEvidence(id,"result:$id:${r.variantIndex}",evidence)
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
        val r=live(id)
        val retainedAuditId=r.auditId ?: throw JobRejected("NO_LIVE_AUDIT_FOR_PARTIAL_RESULTS")
        val evidence=port.collect(retainedAuditId,r.payloadRunId)
        val partial=JsonObject(evidence+mapOf("observationKind" to JsonPrimitive("PARTIAL_OBSERVATION"),"complete" to JsonPrimitive(false)))
        val key="partial:$id:${UUID.randomUUID()}"
        appendEvidence(id,key,partial)
        return SavedResults(store).read(id)
    }
    private fun terminal(native:JsonObject):Boolean = native["auditStatusMessage"]?.jsonPrimitive?.contentOrNull?.lowercase() in setOf("cancelled","canceled") ||
        native["completed"]?.jsonPrimitive?.booleanOrNull==true

    /** Durable, digest-checked terminal evidence is usable after an installation update.
     * It never resurrects an Audit handle or proves the diagnosis complete. */
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    private fun savedTermination(id:String,audit:String,p:CompiledPlan):Boolean = try {
        SavedResults(store).read(id)["records"]!!.jsonArray.any { value ->
            val record=value.jsonObject
            if(record["auditId"]?.jsonPrimitive?.contentOrNull!=audit || !terminal(record["native"]?.jsonObject ?: return@any false)) return@any false
            val status=record["loggerStatus"]?.jsonObject ?: return@any false
            if(status["droppedEntries"]?.jsonPrimitive?.longOrNull!=0L || status["captureErrors"]?.jsonPrimitive?.longOrNull!=0L) return@any false
            val pages=record["loggerPages"]?.jsonArray ?: return@any false
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
        stopped();checkRecoveryOwnership(p,port.snapshot())
        if(r.auditId!=null && store.get("result-index:$id")==null && r.epoch==epoch) capturePartialResults(id)
        val who=approver.reviewRestore(p,r,evidenceRef) ?: throw JobRejected("HUMAN_DENIED")
        requireJob(who.isNotBlank(),"APPROVER_REQUIRED")
        stopped();val before=port.snapshot();checkRecoveryOwnership(p,before)
        val baseline=p.baseline.copy(instanceId=before.instanceId)
        val alreadyRestored=runCatching { checkSnapshot(baseline,before,p);true }.getOrDefault(false)
        try {
            if(!alreadyRestored) store.onceJson("$id:recover-settings",p.planDigest) {
                port.restore(baseline,p.variants.flatMap { it.variant.settings.cph.keys }.toSet())
                val actual=port.snapshot();checkSnapshot(baseline,actual,p)
                jobJson.encodeToJsonElement(actual)
            }
            checkSnapshot(baseline,port.snapshot(),p)
            val next=r.copy(epoch=epoch,state="FAILED_RECONCILED",cleanupState="SETTINGS_RESTORED_BUSINESS_REVIEW_REQUIRED",
                warnings=r.warnings+"BASELINE_RESTORED_NO_TARGET_REPLAY")
            store.transaction {
                save("approval:$id:RECOVERY",ApprovalRecord(UUID.randomUUID().toString(),id,p.planDigest,ApprovalStage.RECOVERY,now(),now()+3600,who))
                store.put("reconciliation:$id",buildJsonObject { put("operator",who);put("evidenceRef",evidenceRef);put("confirmedAt",now());put("previous",jobJson.encodeToJsonElement(r));put("automaticSettingsRestore",true) })
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
        checkSnapshot(p.baseline.copy(instanceId=actual.instanceId),actual,p)
        store.put("reconciliation:$id",buildJsonObject { put("operator",human);put("evidenceRef",evidenceRef);put("confirmedAt",now());put("previous",jobJson.encodeToJsonElement(r)) })
        val active=store.get("active")?.jsonPrimitive?.contentOrNull
        requireJob(active==null || active==id,"ANOTHER_EXECUTION_OWNS_CONTEXT")
        val next=r.copy(state="FAILED_RECONCILED",cleanupState="SETTINGS_RESTORED_BUSINESS_REVIEW_REQUIRED",
            warnings=r.warnings+"HUMAN_RECONCILED_NO_AUTOMATIC_REPLAY")
        store.transaction { write(next);store.put("active",JsonNull) }
        return next
    }

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
