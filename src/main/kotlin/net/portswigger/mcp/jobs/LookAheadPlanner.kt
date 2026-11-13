package net.portswigger.mcp.jobs

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.*
import net.portswigger.diagnosis.runner.*
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

@Serializable
private data class LookAheadTarget(
    val taskId: String,
    val jobId: String,
    val endpoint: Endpoint,
    val sourceId: String,
    val sourceRequestSha256: String
)

@Serializable
private data class LookAheadTask(
    val target: LookAheadTarget,
    val state: String = "CONFIGURATION_REQUIRED",
    val draftId: String? = null,
    val proposal: JobProposal? = null,
    val proposalDigest: String? = null,
    val draftDigest: String? = null,
    val needs: List<String> = emptyList(),
    val errorCode: String? = null,
    val checkedEpoch: String? = null,
    val checkedAuditId: String? = null,
    val checkedDuringScan: Boolean? = null,
    val windowMissed: Boolean = false,
    val promotedExecutionId: String? = null,
    val priorAttempts: List<JsonObject> = emptyList()
)

@Serializable
private data class LookAheadQueue(
    val parentExecutionId: String,
    val parentPlanDigest: String,
    val epoch: String,
    val tasks: List<LookAheadTask>
)

/** Tracks AI-authored proposals and automatically compiles them; never generates settings or calls a Burp port. */
class LookAheadPlanner(
    private val worker: GuardedWorker,
    private val store: JobStore,
    private val drafts: JobDrafts
) : AutoCloseable {
    private val lock = Any()
    private val promotionReservations = mutableMapOf<Pair<String, String>, String>()
    private val executor = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "burp-lookahead-static-check").apply { isDaemon = true }
    }
    @Volatile private var closed = false
    private val prefix = "lookahead:queue:"
    private val pendingStates = setOf("CONFIGURATION_REQUIRED", "INFORMATION_REQUIRED", "QUEUED")
    private val preScanStates = setOf("STATIC_VALIDATED", "PREPARING", "VALIDATED", "EXECUTION_APPROVED")

    private fun identifier(value: String, code: String = "INVALID_LOOKAHEAD_ID") =
        requireJob(value.matches(Regex("[A-Za-z0-9_-]{1,100}")), code)
    private fun load(parent: String): LookAheadQueue? =
        store.get(prefix + parent)?.let { jobJson.decodeFromJsonElement<LookAheadQueue>(it) }
    private fun save(queue: LookAheadQueue) = store.put(prefix + queue.parentExecutionId, jobJson.encodeToJsonElement(queue))
    private fun record(parent: String): ExecutionRecord? = runCatching { worker.record(parent) }.getOrNull()
    private fun queue(parent: String): LookAheadQueue = load(parent) ?: throw JobRejected("LOOKAHEAD_TARGETS_DECLARATION_REQUIRED")
    private fun running(queue: LookAheadQueue, current: ExecutionRecord?): Boolean =
        queue.epoch == worker.epoch && current?.epoch == worker.epoch &&
            current.planDigest == queue.parentPlanDigest && current.state == "RUNNING" && !current.auditId.isNullOrBlank()
    private fun errorCode(error: Exception): String = (error as? JobRejected)?.code ?: error.javaClass.simpleName
    private fun update(parent: String, taskId: String, transform: (LookAheadTask) -> LookAheadTask) {
        val current = queue(parent)
        requireJob(current.tasks.any { it.target.taskId == taskId }, "LOOKAHEAD_TASK_NOT_FOUND")
        save(current.copy(tasks = current.tasks.map { if (it.target.taskId == taskId) transform(it) else it }))
    }
    private fun sourceMatches(target: LookAheadTarget, proposal: JobProposal): Boolean {
        val reflection = proposal.variants.singleOrNull { it.kind == "REFLECTION" }
            ?: return false
        val material = proposal.materials.singleOrNull { it.id == reflection.request.sourceId }
            ?: return false
        return reflection.request.sourceId == target.sourceId &&
            reflection.request.sourceRequestSha256 == target.sourceRequestSha256 &&
            material.requestSha256 == target.sourceRequestSha256 && material.endpoint == target.endpoint
    }
    private fun binding(target: LookAheadTarget, proposal: JobProposal) {
        requireJob(proposal.jobId == target.jobId && sourceMatches(target, proposal), "LOOKAHEAD_TARGET_MISMATCH")
    }
    private fun existingDraft(queue: LookAheadQueue, task: LookAheadTask): JobDraft? {
        val id = task.draftId ?: return null
        val proposal = task.proposal ?: return null
        return runCatching { drafts.load(id) }.getOrNull()?.takeIf {
            it.baselineExecutionId == queue.parentExecutionId &&
                fingerprint(it.plan.proposal) == fingerprint(proposal)
        }
    }

    /** A missing queue receipt is not evidence that normal formal registration never committed. */
    private fun registeredPromotion(task: LookAheadTask): String? {
        val draftId = task.draftId ?: return null
        val draftDigest = task.draftDigest ?: return null
        for (key in store.keys("draft-origin:")) {
            val origin = store.get(key)?.jsonObject ?: throw JobRejected("LOOKAHEAD_PROMOTION_STATE_UNVERIFIED")
            if (origin["draftId"] != JsonPrimitive(draftId)) continue
            val id = key.removePrefix("draft-origin:")
            requireJob(origin["draftDigest"] == JsonPrimitive(draftDigest), "LOOKAHEAD_PROMOTION_STATE_UNVERIFIED")
            val registered = worker.record(id)
            requireJob(registered.executionId == id && worker.plan(id).planDigest == registered.planDigest &&
                store.get("submitted-proposal:$id") == JsonPrimitive(task.proposalDigest),
                "LOOKAHEAD_PROMOTION_STATE_UNVERIFIED")
            return id
        }
        return null
    }

    init {
        // Reconcile a committed immutable static result, but never replay an interrupted/old-epoch check.
        synchronized(lock) {
            store.keys(prefix).forEach { key ->
                val current = load(key.removePrefix(prefix)) ?: return@forEach
                val reconciled = current.tasks.map { task ->
                    if (task.state != "CHECKING") task else {
                        val completed = existingDraft(current, task)
                        if (completed != null) task.copy(state = "STATIC_CHECKED", draftDigest = completed.draftDigest, errorCode = null)
                        else task.copy(state = "CHECK_OUTCOME_UNKNOWN", errorCode = "LOOKAHEAD_CHECK_INTERRUPTED")
                    }
                }
                if (reconciled != current.tasks) save(current.copy(tasks = reconciled))
            }
        }
    }

    fun declare(parentExecutionId: String, targetsJson: String): JsonObject {
        identifier(parentExecutionId)
        requireJob(targetsJson.toByteArray(Charsets.UTF_8).size <= 1024 * 1024, "LOOKAHEAD_TARGETS_TOO_LARGE")
        val targets = try { jobJson.decodeFromString<List<LookAheadTarget>>(targetsJson) }
            catch (error: Exception) { throw JobRejected("INVALID_LOOKAHEAD_TARGETS") }
        requireJob(targets.size <= 100, "TOO_MANY_LOOKAHEAD_TARGETS")
        requireJob(targets.map { it.taskId }.distinct().size == targets.size &&
            targets.map { it.jobId }.distinct().size == targets.size, "DUPLICATE_LOOKAHEAD_TARGET")
        targets.forEach { target ->
            identifier(target.taskId)
            requireJob(target.jobId.matches(Regex("[A-Za-z0-9_-]{1,80}")), "INVALID_LOOKAHEAD_JOB_ID")
            target.endpoint.validate()
            requireJob(target.sourceId.isNotBlank() && target.sourceId.length <= 256 &&
                target.sourceRequestSha256.matches(Regex("[0-9a-f]{64}")), "INVALID_LOOKAHEAD_SOURCE")
        }
        synchronized(lock) {
            val old = load(parentExecutionId)
            if (old != null) requireJob(old.tasks.map { it.target } == targets, "LOOKAHEAD_DECLARATION_CHANGED")
            else {
                val parent = worker.record(parentExecutionId)
                requireJob(parent.epoch == worker.epoch, "LOOKAHEAD_PARENT_EPOCH_CHANGED")
                requireJob(targets.none { it.jobId == worker.plan(parentExecutionId).proposal.jobId }, "LOOKAHEAD_CURRENT_TARGET_REPEATED")
                save(LookAheadQueue(parentExecutionId, parent.planDigest, parent.epoch, targets.map { LookAheadTask(it) }))
            }
        }
        onRunning(parentExecutionId)
        return report(parentExecutionId)
    }

    fun submit(parent: String, taskId: String, draftId: String, proposal: JobProposal): JsonObject {
        identifier(parent); identifier(taskId); identifier(draftId)
        synchronized(lock) {
            requireJob(!closed, "LOOKAHEAD_PLANNER_CLOSED")
            val current = queue(parent)
            val task = current.tasks.singleOrNull { it.target.taskId == taskId } ?: throw JobRejected("LOOKAHEAD_TASK_NOT_FOUND")
            binding(task.target, proposal)
            val proposalHash = fingerprint(proposal)
            val unchanged = task.draftId == draftId && task.proposalDigest == proposalHash
            if (!unchanged) {
                requireJob(promotionReservations[parent to taskId] == null, "LOOKAHEAD_PROMOTION_IN_PROGRESS")
                requireJob(task.state != "CHECKING", "LOOKAHEAD_CHECK_ALREADY_SUBMITTED")
                requireJob(task.promotedExecutionId == null && registeredPromotion(task) == null, "LOOKAHEAD_ALREADY_PROMOTED")
                requireJob(task.draftId != draftId && task.priorAttempts.none { it["draftId"] == JsonPrimitive(draftId) }, "LOOKAHEAD_DRAFT_ID_REUSED")
                if (task.proposal != null) requireJob(proposal.revision > task.proposal.revision, "LOOKAHEAD_NEW_REVISION_REQUIRED")
            }
            // A successful submission remains the same historical fact after its parent ends or is promoted.
            if (unchanged && task.state == "STATIC_CHECKED") return@synchronized
            val history = if (unchanged || task.draftId == null) task.priorAttempts else task.priorAttempts + buildJsonObject {
                put("draftId", task.draftId); put("proposalDigest", task.proposalDigest!!); put("state", task.state)
                task.proposal?.let { put("revision", it.revision) }
                task.draftDigest?.let { put("draftDigest", it) }
                task.errorCode?.let { put("errorCode", it) }
                task.checkedEpoch?.let { put("checkedEpoch", it) }
                task.checkedAuditId?.let { put("checkedAuditId", it) }
                task.checkedDuringScan?.let { put("checkedDuringScan", it) }
                put("windowMissed", task.windowMissed)
            }
            // An explicit submission may bind a separately validated immutable draft after the window was missed.
            // This only reads a result; it never performs a late/old-epoch compilation or claims concurrent work.
            val existing = runCatching { drafts.load(draftId) }.getOrNull()?.takeIf {
                it.baselineExecutionId == parent && fingerprint(it.plan.proposal) == proposalHash
            }
            if (existing != null) {
                val parentRecord = record(parent)
                val missed = task.windowMissed || current.epoch != worker.epoch || parentRecord?.state !in preScanStates + setOf("RUNNING", "OBSERVATION_UNKNOWN")
                update(parent, taskId) { it.copy(state = "STATIC_CHECKED", draftId = draftId, proposal = proposal,
                    proposalDigest = proposalHash, draftDigest = existing.draftDigest, needs = emptyList(), errorCode = null,
                    checkedEpoch = if (unchanged) it.checkedEpoch else null,
                    checkedAuditId = if (unchanged) it.checkedAuditId else null,
                    checkedDuringScan = false, windowMissed = missed, priorAttempts = history) }
                return@synchronized
            }
            if (unchanged) return@synchronized
            requireJob(current.epoch == worker.epoch && record(parent)?.epoch == worker.epoch, "LOOKAHEAD_PARENT_EPOCH_CHANGED")
            update(parent, taskId) { it.copy(state = "QUEUED", draftId = draftId, proposal = proposal,
                proposalDigest = proposalHash, draftDigest = null, needs = emptyList(), errorCode = null,
                checkedEpoch = null, checkedAuditId = null, checkedDuringScan = null, windowMissed = false, priorAttempts = history) }
        }
        onRunning(parent)
        return report(parent)
    }

    fun information(parent: String, taskId: String, needs: List<String>): JsonObject {
        identifier(parent); identifier(taskId)
        requireJob(needs.isNotEmpty() && needs.size <= 100 && needs.distinct().size == needs.size &&
            needs.all { it.isNotBlank() && it.length <= 2000 }, "LOOKAHEAD_INFORMATION_REQUIRED")
        synchronized(lock) {
            update(parent, taskId) { task ->
                requireJob(promotionReservations[parent to taskId] == null, "LOOKAHEAD_PROMOTION_IN_PROGRESS")
                requireJob(task.state !in setOf("CHECKING", "STATIC_CHECKED"), "LOOKAHEAD_CHECK_ALREADY_SUBMITTED")
                task.copy(state = "INFORMATION_REQUIRED", needs = needs, errorCode = null)
            }
        }
        return report(parent)
    }

    /** Called after actual start/poll; reads only immutable plans and stored execution metadata. */
    fun onRunning(parent: String) {
        try {
            synchronized(lock) {
                if (closed) return
                val current = load(parent) ?: return
                val parentRecord = record(parent)
                if (!running(current, parentRecord)) return
                // Planning is side-effect free: a missing first proposal must not stall a later ready proposal.
                val task = current.tasks.firstOrNull { it.state == "QUEUED" } ?: return
                update(parent, task.target.taskId) { it.copy(state = "CHECKING", checkedEpoch = worker.epoch,
                    checkedAuditId = parentRecord!!.auditId) }
                executor.submit { check(parent, task.target.taskId, task.draftId!!, task.proposal!!) }
            }
        } catch (error: Exception) {
            // Planning can never turn a current native Scan into a failed/cancelled workflow.
            runCatching { store.put("lookahead:planner-error:$parent", buildJsonObject { put("errorCode", errorCode(error)) }) }
        }
    }

    private fun check(parent: String, taskId: String, draftId: String, proposal: JobProposal) {
        try {
            val permitted = synchronized(lock) {
                val current = queue(parent)
                val task = current.tasks.single { it.target.taskId == taskId }
                if (task.state != "CHECKING" || task.draftId != draftId) return
                if (!running(current, record(parent))) {
                    update(parent, taskId) { it.copy(state = if (current.epoch != worker.epoch) "STALE_WORKER_EPOCH" else "WINDOW_MISSED", windowMissed = true) }
                    false
                } else {
                    update(parent, taskId) { it.copy(checkedDuringScan = true) }
                    true
                }
            }
            if (!permitted) return
            // No look-ahead lock or worker execution monitor is held during compilation.
            val completed = drafts.validate(draftId, proposal, parent)
            synchronized(lock) {
                update(parent, taskId) { task ->
                    requireJob(task.draftId == draftId && task.proposalDigest == fingerprint(proposal), "LOOKAHEAD_SUBMISSION_CHANGED")
                    task.copy(state = "STATIC_CHECKED", draftDigest = completed.draftDigest, errorCode = null)
                }
            }
        } catch (error: Exception) {
            runCatching { synchronized(lock) {
                update(parent, taskId) { task -> if (task.draftId != draftId) task else task.copy(
                    state = if (closed || error is InterruptedException) "CHECK_OUTCOME_UNKNOWN" else "STATIC_FAILED", errorCode = errorCode(error)) }
            } }
        } finally { onRunning(parent) }
    }

    fun requireDeclared(parent: String) {
        identifier(parent)
        requireJob(load(parent) != null, "LOOKAHEAD_TARGETS_DECLARATION_REQUIRED")
    }

    fun requirePromotion(proposal: JobProposal, draftId: String?, draftDigest: String?) {
        val matches = synchronized(lock) { store.keys(prefix).mapNotNull { load(it.removePrefix(prefix)) }
            .filter { it.epoch == worker.epoch }
            .flatMap { queue -> queue.tasks.filter {
                it.promotedExecutionId == null && sourceMatches(it.target, proposal)
            }.map { queue to it } } }
        if (matches.isEmpty()) return // Undeclared legacy/direct workflows remain unchanged.
        requireJob(draftId != null && draftDigest != null, "LOOKAHEAD_BOUND_DRAFT_REQUIRED")
        val accepted = matches.any { (queue, task) ->
            task.state == "STATIC_CHECKED" && task.draftId == draftId && task.draftDigest == draftDigest &&
                task.proposalDigest == fingerprint(proposal) && existingDraft(queue, task)?.draftDigest == draftDigest &&
                runCatching { binding(task.target, proposal) }.isSuccess
        }
        requireJob(accepted, "LOOKAHEAD_BOUND_DRAFT_REQUIRED")
    }

    private fun promotionCandidates(proposal: JobProposal, draftId: String?, draftDigest: String?): List<Pair<LookAheadQueue, LookAheadTask>> {
        if (draftId == null || draftDigest == null) return emptyList()
        val proposalHash = fingerprint(proposal)
        return store.keys(prefix).mapNotNull { load(it.removePrefix(prefix)) }.filter { it.epoch == worker.epoch }
            .flatMap { queue -> queue.tasks.filter { task ->
                task.promotedExecutionId == null && task.state == "STATIC_CHECKED" && sourceMatches(task.target, proposal) &&
                    task.target.jobId == proposal.jobId && task.draftId == draftId && task.draftDigest == draftDigest &&
                    task.proposalDigest == proposalHash
            }.map { queue to it } }
    }

    /** Reserve the selected binding, without holding the planning monitor while normal registration runs. */
    fun <T> withPromotion(proposal: JobProposal, draftId: String?, draftDigest: String?, executionId: String, register: () -> T): T {
        identifier(executionId)
        val reserved = synchronized(lock) {
            requireJob(!closed, "LOOKAHEAD_PLANNER_CLOSED")
            requirePromotion(proposal, draftId, draftDigest)
            val keys = promotionCandidates(proposal, draftId, draftDigest).map { (queue, task) ->
                requireJob(registeredPromotion(task).let { it == null || it == executionId }, "LOOKAHEAD_ALREADY_PROMOTED")
                queue.parentExecutionId to task.target.taskId
            }
            requireJob(keys.none { promotionReservations.containsKey(it) }, "LOOKAHEAD_PROMOTION_IN_PROGRESS")
            keys.forEach { promotionReservations[it] = executionId }
            keys
        }
        try {
            val registered = register()
            recordPromotion(proposal, draftId, draftDigest, executionId)
            return registered
        } finally {
            synchronized(lock) {
                reserved.forEach { key -> if (promotionReservations[key] == executionId) promotionReservations.remove(key) }
            }
        }
    }

    /** Record consumption only after the normal worker actually registered this exact draft successfully. */
    fun recordPromotion(proposal: JobProposal, draftId: String?, draftDigest: String?, executionId: String) {
        identifier(executionId)
        if (draftId == null || draftDigest == null) return
        synchronized(lock) {
            val candidates = promotionCandidates(proposal, draftId, draftDigest)
            if (candidates.isEmpty()) return
            requireJob(candidates.all { (queue, task) ->
                promotionReservations[queue.parentExecutionId to task.target.taskId].let { it == null || it == executionId }
            }, "LOOKAHEAD_PROMOTION_IN_PROGRESS")
            val registered = record(executionId)
            val origin = store.get("draft-origin:$executionId")?.jsonObject
            requireJob(registered != null && registered.epoch == worker.epoch && worker.plan(executionId).planDigest == registered.planDigest &&
                store.get("submitted-proposal:$executionId") == JsonPrimitive(fingerprint(proposal)) &&
                origin?.get("draftId") == JsonPrimitive(draftId) && origin?.get("draftDigest") == JsonPrimitive(draftDigest),
                "LOOKAHEAD_PROMOTION_NOT_REGISTERED")
            candidates.forEach { (queue, task) ->
                update(queue.parentExecutionId, task.target.taskId) { it.copy(promotedExecutionId = executionId) }
            }
        }
    }

    fun report(parent: String): JsonObject {
        identifier(parent)
        return synchronized(lock) {
            val current = load(parent)
            val parentRecord = record(parent)
            val effective = current?.tasks?.map { task ->
                val state = when {
                    task.state !in pendingStates -> task.state
                    current.epoch != worker.epoch || parentRecord?.epoch != worker.epoch -> "STALE_WORKER_EPOCH"
                    parentRecord?.state !in preScanStates + setOf("RUNNING", "OBSERVATION_UNKNOWN") -> "WINDOW_MISSED"
                    else -> task.state
                }
                task to state
            }.orEmpty()
            val next = effective.firstOrNull { it.second != "STATIC_CHECKED" }
            buildJsonObject {
                put("parentExecutionId", parent); put("declared", current != null)
                put("lastTarget", current?.tasks?.isEmpty() == true)
                put("parentState", parentRecord?.state?.let(::JsonPrimitive) ?: JsonNull)
                put("epochMatches", current != null && current.epoch == worker.epoch && parentRecord?.epoch == worker.epoch)
                put("automaticConfigurationGeneration", false); put("automaticStaticValidation", true)
                put("targetTrafficSent", false); put("executionWindowSource", "STORED_EXECUTION_METADATA")
                put("states", JsonArray(effective.map { (task, state) -> buildJsonObject {
                    put("taskId", task.target.taskId); put("jobId", task.target.jobId)
                    put("endpoint", jobJson.encodeToJsonElement(task.target.endpoint)); put("sourceId", task.target.sourceId)
                    put("sourceRequestSha256", task.target.sourceRequestSha256); put("state", state)
                    task.draftId?.let { put("draftId", it) }; task.draftDigest?.let { put("draftDigest", it) }
                    task.errorCode?.let { put("errorCode", it) }; task.checkedEpoch?.let { put("checkedEpoch", it) }
                    task.checkedAuditId?.let { put("checkedAuditId", it) }
                    task.checkedDuringScan?.let { put("checkedDuringScan", it) }
                    task.promotedExecutionId?.let { put("promotedExecutionId", it) }
                    put("promotionInProgress", promotionReservations.containsKey(parent to task.target.taskId))
                    put("windowMissed", task.windowMissed || state == "WINDOW_MISSED")
                    put("needs", JsonArray(task.needs.map(::JsonPrimitive))); put("priorAttempts", JsonArray(task.priorAttempts))
                } }))
                next?.let { put("nextTaskId", it.first.target.taskId) }
                put("agentNextAction", when {
                    current == null -> if (parentRecord?.state in preScanStates + setOf("RUNNING", "OBSERVATION_UNKNOWN"))
                        "DECLARE_NEXT_TARGETS_OR_EXPLICIT_LAST_TARGET" else "NO_REGISTERED_NEXT_TARGET_WORK"
                    next == null -> when {
                        current.tasks.isEmpty() -> "NO_NEXT_TARGET"
                        current.tasks.all { it.promotedExecutionId != null } -> "ALL_DECLARED_DRAFTS_PROMOTED"
                        else -> "WAIT_FOR_CURRENT_RESTORE_THEN_PROMOTE_BOUND_DRAFT"
                    }
                    next.second == "CONFIGURATION_REQUIRED" -> "CREATE_NEXT_CONFIGURATION_AND_SUBMIT_DIAGNOSTIC_DRAFT"
                    next.second == "INFORMATION_REQUIRED" -> "GATHER_MISSING_INFORMATION_AND_COMPLETE_NEXT_CONFIGURATION"
                    next.second == "QUEUED" -> "WAIT_FOR_CURRENT_RUNNING_WINDOW_AND_AUTOMATIC_STATIC_CHECK"
                    next.second == "CHECKING" -> "OBSERVE_AUTOMATIC_STATIC_CHECK_WITHOUT_MUTATING_CURRENT_SCAN"
                    next.second == "STATIC_FAILED" -> "CORRECT_NEXT_CONFIGURATION_AND_SUBMIT_NEW_REVISION_AND_DRAFT_ID"
                    else -> "REVIEW_MISSED_OR_STALE_PLANNING_WINDOW_NEVER_REPLAY_CURRENT_SCAN"
                })
                store.get("lookahead:planner-error:$parent")?.let { put("plannerError", it) }
            }
        }
    }

    override fun close() {
        closed = true
        executor.shutdownNow()
        executor.awaitTermination(5, TimeUnit.SECONDS)
    }
}
