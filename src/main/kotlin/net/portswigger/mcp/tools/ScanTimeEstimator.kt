package net.portswigger.mcp.tools

// >> 20261014 mniwa Estimate audit duration from comparable completed traffic counts while keeping uncertain and terminal states explicit.
import java.time.Instant
import kotlinx.serialization.json.*
import kotlinx.serialization.Serializable

// >> 20261014 mniwa Accept an evidence-backed insertion-point workload without requiring calibration scans.
@Serializable
data class ScanWorkload(
    // >> 20261014 mniwa Use the ten completed audit aggregate as an explicitly empirical default budget.
    val requestsPerInsertionPoint: Double = 34.0,
    val basis: String = "Empirical default: 9011 requests / 265 detected insertion points from ten completed audits, rounded to 34; not a universal scan requirement.",
    // << mniwa
    val workflowSeconds: Double? = null,
    val effectiveConcurrency: Double? = null,
    val lowerRequestsPerInsertionPoint: Double? = null,
    val upperRequestsPerInsertionPoint: Double? = null
) {
    fun validate() {
        require(requestsPerInsertionPoint.isFinite() && requestsPerInsertionPoint > 0 && requestsPerInsertionPoint <= 1_000_000) { "requestsPerInsertionPoint must be finite and in (0, 1000000]" }
        require(basis.isNotBlank() && basis.length <= 1000) { "basis must identify non-secret workload evidence (1..1000 characters)" }
        require(workflowSeconds == null || workflowSeconds.isFinite() && workflowSeconds > 0) { "workflowSeconds must be finite and positive" }
        require(effectiveConcurrency == null || effectiveConcurrency.isFinite() && effectiveConcurrency > 0) { "effectiveConcurrency must be finite and positive" }
        require((lowerRequestsPerInsertionPoint == null) == (upperRequestsPerInsertionPoint == null)) { "Provide both workload bounds or neither" }
        if (lowerRequestsPerInsertionPoint != null && upperRequestsPerInsertionPoint != null) {
            require(lowerRequestsPerInsertionPoint.isFinite() && upperRequestsPerInsertionPoint.isFinite() && lowerRequestsPerInsertionPoint > 0 && lowerRequestsPerInsertionPoint <= requestsPerInsertionPoint && upperRequestsPerInsertionPoint >= requestsPerInsertionPoint && upperRequestsPerInsertionPoint <= 1_000_000) { "Workload bounds must enclose the estimate and be finite positive values <= 1000000" }
        }
    }
}
// << mniwa

internal class ScanTimeEstimator(
    private val nanoTime: () -> Long = System::nanoTime,
    private val instant: () -> Instant = Instant::now
) {
    internal class Run(val key: String?, val startedAt: Instant, val startNanos: Long) {
        val observations = ArrayDeque<Pair<Long, Int>>()
        var lastCount: Int? = null
        var lastState: String? = null
        var endedNanos: Long? = null
        var trainingEligible = true
        // >> 20261008 mniwa Distinguish normal startup waiting from interruptions after audit execution begins.
        var seenActive = false
        // << mniwa
        var recorded = false
        var lastProgressNanos: Long? = null
        var workload: ScanWorkload? = null
    }
    private val histories = linkedMapOf<String, ArrayDeque<Int>>()

    fun start(key: String?): Run = Run(key, instant(), nanoTime())

    @Synchronized
    fun observe(run: Run, state: String, count: Int, errors: Int?, insertionPoints: Int, workload: ScanWorkload? = null): JsonObject {
        workload?.validate()
        if (workload != null) run.workload = workload
        val model = run.workload
        val now = nanoTime()
        val at = instant()
        val terminalSuccess = state in setOf("done", "finished", "complete", "completed")
        val cancelled = state in setOf("cancelled", "canceled")
        val active = state in setOf("scanning", "auditing", "running")
        val priorActive = run.lastState in setOf("scanning", "auditing", "running")
        if (run.lastCount == null || count != run.lastCount || !priorActive) run.lastProgressNanos = now
        if (run.lastCount != null && count < run.lastCount!!) run.trainingEligible = false
        // >> 20261008 mniwa Preserve estimation eligibility through initial queue states without restoring interrupted runs.
        val initialWaiting = !run.seenActive && count == 0 && state in setOf("queued", "waiting", "starting")
        if (!active && !terminalSuccess && !initialWaiting) run.trainingEligible = false
        if (active) run.seenActive = true
        // << mniwa
        if (!active || !priorActive || (run.lastCount != null && count < run.lastCount!!)) run.observations.clear()
        if (active) {
            run.observations.addLast(now to count)
            while (run.observations.size > 1 && now - run.observations.first().first > 120_000_000_000L) run.observations.removeFirst()
            while (run.observations.size > 128) run.observations.removeFirst()
        }
        if ((terminalSuccess || cancelled) && run.endedNanos == null) run.endedNanos = now
        val elapsed = ((run.endedNanos ?: now) - run.startNanos).coerceAtLeast(0) / 1e9
        val historyKey = run.key?.let { "$it|$insertionPoints" }
        if (terminalSuccess && !run.recorded) {
            if (run.trainingEligible && priorActive && errors == 0 && count > 0 && historyKey != null) {
                val history = histories.getOrPut(historyKey) { ArrayDeque() }
                history.addLast(count)
                while (history.size > 20) history.removeFirst()
                while (histories.size > 100) histories.remove(histories.keys.first())
            }
            run.recorded = true
        }
        run.lastCount = count
        run.lastState = state
        val samples = historyKey?.let { histories[it]?.toList() }.orEmpty().sorted()
        var reason = when {
            terminalSuccess -> "COMPLETED"
            cancelled -> "CANCELLED"
            !active -> when (state) { "paused" -> "PAUSED"; "queued", "waiting", "starting" -> "WAITING"; else -> "UNKNOWN_STATE" }
            run.key == null && model == null -> "WORKLOAD_MODEL_REQUIRED"
            !run.trainingEligible -> "INTERRUPTED_OR_COUNTER_RESET"
            errors == null -> "ERROR_METRIC_UNAVAILABLE"
            errors > 0 -> "CURRENT_NETWORK_ERRORS"
            insertionPoints <= 0 -> "NO_INSERTION_POINTS"
            model == null && samples.size < 3 -> "INSUFFICIENT_COMPARABLE_HISTORY"
            else -> "ESTIMATED"
        }
        val first = run.observations.firstOrNull()
        val window = first?.let { (now - it.first) / 1e9 } ?: 0.0
        val delta = first?.let { count - it.second } ?: 0
        val observedRate = if (window >= 5 && delta > 0) delta / window else null
        // >> 20261014 mniwa Start with a sequential workflow estimate and replace its assumed rate with observed throughput.
        val initialRate = model?.let { if (it.workflowSeconds != null) (it.effectiveConcurrency ?: 1.0) / it.workflowSeconds else null }
        // << mniwa
        val rate = observedRate ?: initialRate
        if (reason == "ESTIMATED" && rate == null) reason = if (window >= 30 && delta == 0) "NO_RECENT_PROGRESS" else "INSUFFICIENT_RATE_OBSERVATIONS"
        val stalledAfterSeconds = maxOf(30.0, (model?.workflowSeconds ?: 0.0) * 2)
        if (reason == "ESTIMATED" && (now - (run.lastProgressNanos ?: now)) / 1e9 >= stalledAfterSeconds) reason = "NO_RECENT_PROGRESS"
        val median = if (model != null) kotlin.math.ceil(insertionPoints * model.requestsPerInsertionPoint) else if (samples.isEmpty()) 0.0 else if (samples.size % 2 == 1) samples[samples.size / 2].toDouble() else (samples[samples.size / 2 - 1].toLong() + samples[samples.size / 2]) / 2.0
        if (reason == "ESTIMATED" && count >= median) reason = if (model != null) "WORKLOAD_BUDGET_EXCEEDED" else "HISTORICAL_WORKLOAD_EXCEEDED"
        if (reason == "ESTIMATED" && model == null && samples.last() > samples.first() * 1.5) reason = "HISTORY_TOO_VARIABLE"
        if (reason == "ESTIMATED" && rate != null && (!rate.isFinite() || rate <= 0 || !((median-count)/rate).isFinite() || (median-count)/rate > 315_576_000)) reason = "MODEL_TIME_OUT_OF_RANGE"
        val remaining = if (reason == "COMPLETED") 0.0 else if (reason == "ESTIMATED") (median - count) / rate!! else null
        return buildJsonObject {
            put("status", if (reason == "COMPLETED") "COMPLETED" else if (reason == "ESTIMATED") "ESTIMATED" else "UNAVAILABLE")
            put("reason", reason)
            put("startedAt", run.startedAt.toString())
            put("estimatedAt", at.toString())
            put("elapsedSeconds", elapsed)
            put("elapsedIncludesWaitingAndPauses", true)
            put("method", if (reason == "ESTIMATED") JsonPrimitive(if (model != null) if (observedRate != null) "INSERTION_POINT_BUDGET_AND_RECENT_RATE" else "INSERTION_POINT_BUDGET_AND_WORKFLOW_TIME" else "HISTORICAL_REQUEST_COUNT_AND_RECENT_RATE") else JsonNull)
            put("comparableCompletedScans", samples.size)
            put("remainingSeconds", remaining?.let { JsonPrimitive(kotlin.math.ceil(it)) } ?: JsonNull)
            val lowerTotal = if (model != null) model.lowerRequestsPerInsertionPoint?.let { kotlin.math.ceil(it * insertionPoints) } else samples.firstOrNull()?.toDouble()
            val upperTotal = if (model != null) model.upperRequestsPerInsertionPoint?.let { kotlin.math.ceil(it * insertionPoints) } else samples.lastOrNull()?.toDouble()
            put("lowerRemainingSeconds", if (reason == "ESTIMATED" && lowerTotal != null) JsonPrimitive(kotlin.math.ceil((lowerTotal-count).coerceAtLeast(0.0) / rate!!)) else JsonNull)
            put("upperRemainingSeconds", if (reason == "ESTIMATED" && upperTotal != null && (upperTotal-count).coerceAtLeast(0.0) / rate!! <= 315_576_000) JsonPrimitive(kotlin.math.ceil((upperTotal-count).coerceAtLeast(0.0) / rate)) else JsonNull)
            put("predictedFinishAt", if (reason == "ESTIMATED") JsonPrimitive(at.plusSeconds(kotlin.math.ceil(remaining!!).toLong()).toString()) else JsonNull)
            put("recentRequestsPerSecond", observedRate?.let(::JsonPrimitive) ?: JsonNull)
            put("assumedInitialRequestsPerSecond", initialRate?.takeIf { it.isFinite() }?.let(::JsonPrimitive) ?: JsonNull)
            put("estimatedTotalRequests", if (model != null && insertionPoints > 0) JsonPrimitive(median) else JsonNull)
            put("requestsPerInsertionPoint", model?.requestsPerInsertionPoint?.let(::JsonPrimitive) ?: JsonNull)
            put("workloadBasis", model?.basis?.let(::JsonPrimitive) ?: JsonNull)
            put("workflowSeconds", model?.workflowSeconds?.let(::JsonPrimitive) ?: JsonNull)
            // >> 20261014 mniwa Distinguish the initial sequential assumption and full duration from the corrected remaining duration.
            put("initialConcurrencyAssumption", if (model?.workflowSeconds != null) JsonPrimitive(model.effectiveConcurrency ?: 1.0) else JsonNull)
            put("estimatedInitialTotalSeconds", if (initialRate != null && insertionPoints > 0 && (median / initialRate).isFinite() && median / initialRate <= 315_576_000) JsonPrimitive(kotlin.math.ceil(median / initialRate)) else JsonNull)
            // << mniwa
            put("rateWindowSeconds", window)
            put("confidence", if (reason == "ESTIMATED") JsonPrimitive("LOW") else JsonNull)
            put("rangeMeaning", "Workload bounds are assumptions from the stated evidence, not a statistical confidence interval or a deadline. Missing bounds are null. Phase changes, macro waits, concurrency and additional checks may invalidate predictions.")
        }
    }
}
// << mniwa
