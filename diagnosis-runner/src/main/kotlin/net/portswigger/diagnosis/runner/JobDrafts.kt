package net.portswigger.diagnosis.runner

import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.*

/** Separate metadata namespace and monitor: a worker busy in a macro or approval never locks static checks. */
class JobDrafts(private val worker: GuardedWorker, private val store: JobStore) {
    private fun validId(id: String) = requireJob(id.matches(Regex("[A-Za-z0-9_-]{1,100}")), "INVALID_DRAFT_ID")
    private fun read(id: String): JobDraft? {
        validId(id)
        return store.get("draft:$id")?.let { jobJson.decodeFromJsonElement<JobDraft>(it) }?.also {
            requireJob(it.draftDigest == draftDigest(it.draftId, it.baselineExecutionId, it.plan), "DRAFT_CHANGED")
        }
    }

    @Synchronized fun validate(id: String, proposal: JobProposal, baselineExecutionId: String?): JobDraft {
        validId(id)
        baselineExecutionId?.let { requireJob(it.matches(Regex("[A-Za-z0-9_-]{1,100}")), "INVALID_BASELINE_EXECUTION_ID") }
        read(id)?.let {
            requireJob(fingerprint(it.plan.proposal) == fingerprint(proposal) && it.baselineExecutionId == baselineExecutionId,
                "DRAFT_ID_REUSED")
            return it
        }
        // Stored execution baselines are immutable and can be read without the worker's execution monitor.
        val baseline = worker.draftBaseline(baselineExecutionId)
        return compileDraft(id,proposal,baselineExecutionId,baseline)
    }

    private fun compileDraft(id:String,proposal:JobProposal,baselineExecutionId:String?,baseline:BurpSnapshot):JobDraft {
        val plan = JobCompiler().compile(proposal, baseline)
        val record = JobDraft(id, baselineExecutionId, plan, draftDigest(id, baselineExecutionId, plan))
        store.put("draft:$id", jobJson.encodeToJsonElement(record))
        return record
    }

    /** Bind the immutable recovery request before observing a fresh baseline; retries never rebase an existing draft. */
    @Synchronized fun validateRecovery(id:String,sourceExecutionId:String,selection:RecoveryReplanSelection,
        legacyProposal:(()->JobProposal)?=null,proposal:(BurpSnapshot)->JobProposal):JobDraft {
        validId(id);validId(sourceExecutionId)
        val request=buildJsonObject {
            put("sourceExecutionId",sourceExecutionId);put("selection",jobJson.encodeToJsonElement(selection))
        }
        val key="recovery-draft-request:$id"
        val saved=store.get(key)
        val existing=read(id)
        if(saved==null && existing!=null) {
            requireJob(legacyProposal!=null && existing.baselineExecutionId==null &&
                fingerprint(existing.plan.proposal)==fingerprint(legacyProposal.invoke()),"DRAFT_ID_REUSED")
            store.put(key,request)
            return existing
        }
        requireJob(saved==null && existing==null || saved==request,"DRAFT_ID_REUSED")
        if(existing!=null) return existing
        store.put(key,request)
        val baseline=worker.draftBaseline(null)
        return compileDraft(id,proposal(baseline),null,baseline)
    }

    fun load(id: String, expectedDigest: String? = null): JobDraft {
        val record = read(id) ?: throw JobRejected("DRAFT_NOT_FOUND")
        expectedDigest?.let { requireJob(it == record.draftDigest, "DRAFT_DIGEST_MISMATCH") }
        return record
    }

    fun report(record: JobDraft): JsonObject = buildJsonObject {
        put("draftId", record.draftId); put("state", "STATIC_CHECKED"); put("draftDigest", record.draftDigest)
        record.baselineExecutionId?.let { put("baselineExecutionId", it) }
        put("proposalDigest", record.plan.proposalDigest); put("staticPlanDigest", record.plan.planDigest)
        put("baselineDigest", fingerprint(record.plan.baseline))
        put("variantCount", record.plan.variants.size); put("expandedEndpointCount", record.plan.expandedEndpoints.size)
        put("executable", false); put("semanticReviewRequired", true); put("inputsFrozen", false)
        put("targetTrafficSent", false); put("nextAction", "WHEN_CONTEXT_IDLE_PROPOSE_DRAFT_WITH_EXACT_DIGEST")
        putJsonArray("limitations") {
            add("Structural compilation only; no authentication, regex extraction, response meaning or native CPH execution is proven.")
            add("Referenced files and secret generations are not read or frozen; promotion verifies them and recompiles against a fresh baseline.")
            add("No approvals or five-probe validation evidence are created or reused.")
        }
    }
}
