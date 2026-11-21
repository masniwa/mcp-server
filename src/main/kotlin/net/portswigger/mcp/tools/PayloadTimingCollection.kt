package net.portswigger.mcp.tools

import java.time.Instant
import java.util.concurrent.atomic.AtomicBoolean

internal data class TimingControlInput(val requestedDelayMillis: Long, val normal: ByteArray,
    val conditionTrue: ByteArray, val conditionFalse: ByteArray)
internal data class TimingControlAttempt(val index: Int, val round: Int, val role: String,
    val requestedDelayMillis: Long, val request: ByteArray)

/** Input requests must be prepared/authorized by integration; never synthesize SQL here.
 * Alternate order within rounds and interleave delay levels to reduce ordering confounds.
 */
internal class PayloadTimingCollection(inputs: List<TimingControlInput>, repetitions: Int = 3,
    private val monotonicNanos: () -> Long = System::nanoTime) {
    private val claimed = AtomicBoolean()
    private val stopped = AtomicBoolean()
    private val attempts: List<TimingControlAttempt>
    private val rows: MutableList<PayloadExecutionItem>
    @Volatile var finished = false
        private set
    init {
        require(repetitions in 3..10) { "Use 3..10 repetitions per delay level" }
        require(inputs.size in 2..6 && inputs.map { it.requestedDelayMillis }.distinct().size == inputs.size)
        require(inputs.all { it.requestedDelayMillis in 1..60_000 &&
            it.normal.isNotEmpty() && it.conditionTrue.isNotEmpty() && it.conditionFalse.isNotEmpty() })
        val normal = inputs.first().normal
        require(inputs.all { it.normal.contentEquals(normal) }) { "Normal control must be identical across delay levels" }
        require(inputs.all { !it.normal.contentEquals(it.conditionTrue) &&
            !it.normal.contentEquals(it.conditionFalse) && !it.conditionTrue.contentEquals(it.conditionFalse) })
        val planned = mutableListOf<TimingControlAttempt>()
        repeat(repetitions) { round ->
            for (input in if (round % 2 == 0) inputs else inputs.reversed()) {
                val order = if (round % 2 == 0) listOf("NORMAL", "TRUE", "FALSE") else listOf("FALSE", "TRUE", "NORMAL")
                for (role in order) {
                    val bytes = when(role) { "NORMAL" -> input.normal; "TRUE" -> input.conditionTrue; else -> input.conditionFalse }
                    planned += TimingControlAttempt(planned.size, round, role, input.requestedDelayMillis, bytes.copyOf())
                }
            }
        }
        attempts = planned
        rows = attempts.map { PayloadExecutionItem(it.index, "CONTROL:${it.requestedDelayMillis}:${it.round}:${it.role}",
            "TIMING_CONTROL", "confirmation", "PENDING") }.toMutableList()
    }
    @Synchronized fun snapshot(): List<PayloadExecutionItem> = rows.toList()
    @Synchronized private fun update(index: Int, row: PayloadExecutionItem) { rows[index] = row }
    fun stop() { stopped.set(true) }
    fun execute(maySend: () -> Boolean, send: (ByteArray) -> PayloadExchange,
        record: (PayloadExecutionItem, PayloadExchange) -> Unit): Boolean {
        if (!claimed.compareAndSet(false, true)) return false
        try {
            for (attempt in attempts) {
                val current = snapshot()[attempt.index]
                val allowed = try { !stopped.get() && maySend() } catch (_: Exception) { false }
                if (!allowed) {
                    stopped.set(true)
                    update(attempt.index, current.copy(state="NOT_SENT",reason="CONTROL_EXECUTION_STOPPED")); continue
                }
                val outgoing=attempt.request.copyOf()
                val startedAt = Instant.now().toString()
                val start = monotonicNanos()
                var elapsed: Long? = null
                try {
                    val exchange=send(outgoing)
                    elapsed=monotonicNanos()-start
                    val row=current.copy(state=if(exchange.response==null) "NO_RESPONSE" else "RESPONSE_RECEIVED",
                        reason=if(exchange.response==null) "DELIVERY_OUTCOME_UNKNOWN" else null,
                        attemptedAt=startedAt,completedAt=Instant.now().toString(),sendCallElapsedNanos=elapsed,
                        requestSha256=sha256(exchange.request),responseSha256=exchange.response?.let(::sha256),
                        submittedRequestSha256=exchange.submittedRequest?.let(::sha256),statusCode=exchange.statusCode)
                    record(row,exchange)
                    update(attempt.index,row)
                    // Failed controls invalidate the sequence. Do not continue hammering a rate-limited endpoint.
                    if(exchange.response==null || exchange.statusCode !in 200..299) stopped.set(true)
                } catch(error: Exception) {
                    update(attempt.index,current.copy(state="ERROR",reason=error.javaClass.simpleName,
                        attemptedAt=startedAt,completedAt=Instant.now().toString(),
                        sendCallElapsedNanos=elapsed ?: (monotonicNanos()-start)))
                    stopped.set(true)
                }
            }
        } finally { finished=true }
        return true
    }
    fun comparison(contextId: String, evidencePrefix: String, snapshot: List<PayloadExecutionItem> = snapshot()): TimingComparisonResult {
        val rounds=attempts.groupBy { it.requestedDelayMillis to it.round }.map { (key, group) ->
            fun observation(role: String): TimingObservation {
                val attempt=group.single { it.role==role }; val row=snapshot[attempt.index]
                return TimingObservation("$evidencePrefix:${row.index}",contextId,row.sendCallElapsedNanos,
                    row.statusCode,row.state=="RESPONSE_RECEIVED")
            }
            TimingRound(key.first,observation("NORMAL"),observation("TRUE"),observation("FALSE"))
        }
        return comparePayloadTiming(rounds)
    }
}
