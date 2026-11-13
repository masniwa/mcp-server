package net.portswigger.mcp.tools

import kotlinx.serialization.Serializable
import kotlin.math.abs

@Serializable
data class PayloadTimingEvidenceRef(val runId: String, val index: Int)
@Serializable
data class PayloadTimingRoundRef(val requestedDelayMillis: Long, val normal: PayloadTimingEvidenceRef,
    val conditionTrue: PayloadTimingEvidenceRef, val conditionFalse: PayloadTimingEvidenceRef)

internal fun resolvePayloadTiming(rounds: List<PayloadTimingRoundRef>, lookup: (String) -> PayloadRunRegistry.Run): TimingComparisonResult {
    require(rounds.size in 1..60) { "Timing comparison requires 1..60 recorded rounds" }
    fun resolve(ref: PayloadTimingEvidenceRef): TimingObservation {
        val run = lookup(ref.runId)
        require(ref.index >= 0) { "Negative evidence index" }
        val item = run.execution.snapshot().getOrNull(ref.index) ?: error("Evidence index not tracked")
        // Refuse unverifiable/partial records instead of accepting caller supplied durations.
        require(item.requestSha256 != null) { "No committed evidence at referenced index" }
        run.store.read(item.index, item)
        val context = "${run.plan.sourceSha256}:${run.plan.requestSha256}:${item.positionId}:${item.mode}"
        return TimingObservation("${ref.runId}:${ref.index}", context, item.sendCallElapsedNanos,
            item.statusCode, item.state == "RESPONSE_RECEIVED")
    }
    return comparePayloadTiming(rounds.map { TimingRound(it.requestedDelayMillis,
        resolve(it.normal), resolve(it.conditionTrue), resolve(it.conditionFalse)) })
}

/** Evidence IDs and values must be resolved from the ledger by the caller, not AI estimates. */
internal data class TimingObservation(val evidenceId: String, val contextId: String,
    val elapsedNanos: Long?, val status: Int?, val responseReceived: Boolean)
internal data class TimingRound(val requestedDelayMillis: Long, val normal: TimingObservation,
    val conditionTrue: TimingObservation, val conditionFalse: TimingObservation)

@Serializable
internal data class TimingLevelResult(val requestedDelayMillis: Long, val repetitions: Int,
    val medianDeltaMillis: Double, val minDeltaMillis: Double, val maxDeltaMillis: Double,
    val controlSpreadMillis: Double, val toleranceMillis: Double)

@Serializable
internal data class TimingComparisonResult(val state: String, val reasons: List<String>,
    val levels: List<TimingLevelResult>, val evidenceIds: List<String>,
    val limitations: List<String> = listOf("CONTROL_SEMANTICS_REQUIRE_REVIEW", "ADAPTER_TIME_INCLUDES_MACROS_AND_QUEUEING",
        "BODY_AND_WIRE_CORRELATION_REQUIRED", "DELAY_PATTERN_IS_NOT_A_SQLI_VERDICT"))

/** Conservative deterministic evidence check, not a statistical confidence claim or DB oracle. */
internal fun comparePayloadTiming(rounds: List<TimingRound>): TimingComparisonResult {
    val observations = rounds.flatMap { listOf(it.normal, it.conditionTrue, it.conditionFalse) }
    val ids = observations.map { it.evidenceId }
    fun incomplete(reason: String) = TimingComparisonResult("INSUFFICIENT_EVIDENCE", listOf(reason), emptyList(), ids)
    if (rounds.isEmpty()) return incomplete("NO_ROUNDS")
    if (ids.any { it.isBlank() } || ids.distinct().size != ids.size) return incomplete("REUSED_OR_MISSING_EVIDENCE")
    if (observations.map { it.contextId }.distinct().size != 1 || observations.any { it.contextId.isBlank() })
        return incomplete("INCOMPARABLE_CONTEXT")
    if (observations.any { !it.responseReceived || it.elapsedNanos == null || it.elapsedNanos < 0 || it.status == null })
        return incomplete("MISSING_RESPONSE_OR_DURATION")
    if (rounds.any { it.requestedDelayMillis !in 1..60_000 }) return incomplete("INVALID_REQUESTED_DELAY")
    val groups = rounds.groupBy { it.requestedDelayMillis }.toSortedMap()
    if (groups.size < 2 || groups.values.any { it.size < 3 }) return incomplete("NEED_TWO_DELAY_LEVELS_AND_THREE_ROUNDS_EACH")
    if (observations.any { it.status !in 200..299 } || observations.map { it.status }.distinct().size != 1)
        return TimingComparisonResult("CONFOUNDED", listOf("STATUS_MISMATCH_OR_NON_SUCCESS_RESPONSE"), emptyList(), ids)
    fun ms(o: TimingObservation) = o.elapsedNanos!!.toDouble() / 1_000_000.0
    fun median(values: List<Double>): Double {
        val sorted = values.sorted(); val mid = sorted.size / 2
        return if (sorted.size % 2 == 1) sorted[mid] else (sorted[mid-1] + sorted[mid]) / 2
    }
    val reasons = mutableListOf<String>()
    val levels = groups.map { (delay, samples) ->
        val controls = samples.flatMap { listOf(ms(it.normal), ms(it.conditionFalse)) }
        val spread = controls.max() - controls.min()
        val tolerance = maxOf(100.0, delay * 0.25)
        val deltas = samples.map { ms(it.conditionTrue) - maxOf(ms(it.normal), ms(it.conditionFalse)) }
        if (spread > tolerance || samples.any { abs(ms(it.normal) - ms(it.conditionFalse)) > tolerance })
            reasons += "UNSTABLE_CONTROLS"
        if (deltas.any { abs(it - delay) > tolerance }) reasons += "DELAY_NOT_REPRODUCED"
        TimingLevelResult(delay, samples.size, median(deltas), deltas.min(), deltas.max(), spread, tolerance)
    }
    // A common fixed timeout at every delay must not pass as dose-dependent behavior.
    levels.zipWithNext().forEach { (a, b) ->
        if (b.requestedDelayMillis - a.requestedDelayMillis <= a.toleranceMillis + b.toleranceMillis)
            reasons += "DELAY_LEVELS_TOO_CLOSE"
        if (abs((b.medianDeltaMillis - a.medianDeltaMillis) - (b.requestedDelayMillis - a.requestedDelayMillis)) >
            maxOf(a.toleranceMillis, b.toleranceMillis)) reasons += "DELAY_SCALING_NOT_REPRODUCED"
    }
    val state = when {
        reasons.any { it == "UNSTABLE_CONTROLS" || it == "DELAY_LEVELS_TOO_CLOSE" } -> "CONFOUNDED"
        reasons.isNotEmpty() -> "DELAY_PATTERN_NOT_ESTABLISHED"
        else -> "REPRODUCIBLE_DELAY_PATTERN"
    }
    return TimingComparisonResult(state, reasons.distinct(), levels, ids)
}
