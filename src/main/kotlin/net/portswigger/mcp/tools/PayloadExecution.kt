package net.portswigger.mcp.tools

import kotlinx.serialization.Serializable
import java.time.Instant
import java.util.concurrent.atomic.AtomicBoolean

/** Returned request belongs to the selected response (possibly a post-request macro).
 * submittedRequest is the pre-session-processing diagnostic input, not proof of wire bytes.
 */
internal data class PayloadExchange(val request: ByteArray, val response: ByteArray?, val statusCode: Int?,
    val submittedRequest: ByteArray? = null)

@Serializable
data class PayloadExecutionItem(
    val index: Int, val payloadId: String, val positionId: String?, val mode: String,
    val state: String, val reason: String? = null, val attemptedAt: String? = null,
    val completedAt: String? = null, val requestSha256: String? = null,
    val responseSha256: String? = null, val statusCode: Int? = null,
    val submittedRequestSha256: String? = null,
    val sendCallElapsedNanos: Long? = null
)

/** One invocation per run, safe against duplicate Scanner callbacks.
 * No network retry after an ambiguous send. Native audit success and this ledger are separate gates.
 */
internal class PayloadExecution(private val plan: PayloadWirePlan, private val monotonicNanos: () -> Long = System::nanoTime) {
    private val claimed = AtomicBoolean()
    private val stopped = AtomicBoolean()
    @Volatile var callbackFinished: Boolean = false
        private set
    private val rows = plan.candidates.mapIndexed { index, c ->
        PayloadExecutionItem(index, c.payloadId, c.positionId, c.mode,
            if (c.state == "READY") "PENDING" else c.state, c.reason)
    }.toMutableList()

    @Synchronized fun snapshot(): List<PayloadExecutionItem> = rows.toList()
    @Synchronized private fun update(index: Int, change: (PayloadExecutionItem) -> PayloadExecutionItem) {
        rows[index] = change(rows[index])
    }

    /** Used by lifecycle shutdown/cancellation; does not cancel any native audit. */
    fun stop() { stopped.set(true) }

    fun execute(
        maySend: () -> Boolean,
        send: (ByteArray) -> PayloadExchange,
        recordEvidence: (PayloadExecutionItem, PayloadExchange) -> Unit
    ): Boolean {
        if (!claimed.compareAndSet(false, true)) return false
        try {
            for (candidate in snapshot()) {
                if (candidate.state != "PENDING") continue
                val permitted = try { !stopped.get() && maySend() } catch (error: Exception) {
                    update(candidate.index) { it.copy(state = "NOT_SENT", reason = "SEND_GATE_FAILED:${error.javaClass.simpleName}") }
                    stopped.set(true)
                    continue
                }
                if (!permitted) {
                    update(candidate.index) { it.copy(state = "NOT_SENT", reason = "EXECUTION_STOPPED") }
                    stopped.set(true)
                    continue
                }
                update(candidate.index) { it.copy(state = "SENDING", attemptedAt = Instant.now().toString()) }
                var sendStarted: Long? = null
                var sendElapsed: Long? = null
                try {
                    val bytes = plan.materialize(candidate.index)
                    sendStarted = monotonicNanos()
                    val exchange = send(bytes)
                    sendElapsed = monotonicNanos() - sendStarted
                    val result = snapshot()[candidate.index].copy(
                        state = if (exchange.response == null) "NO_RESPONSE" else "RESPONSE_RECEIVED",
                        reason = if (exchange.response == null) "DELIVERY_OUTCOME_UNKNOWN" else null,
                        completedAt = Instant.now().toString(), requestSha256 = sha256(exchange.request),
                        responseSha256 = exchange.response?.let(::sha256), statusCode = exchange.statusCode,
                        submittedRequestSha256 = exchange.submittedRequest?.let(::sha256),
                        sendCallElapsedNanos = sendElapsed
                    )
                    // Evidence must be committed before the row can claim a recorded response.
                    recordEvidence(result, exchange)
                    update(candidate.index) { result }
                } catch (error: Exception) {
                    update(candidate.index) { it.copy(state = "ERROR", reason = error.javaClass.simpleName,
                        completedAt = Instant.now().toString(),
                        sendCallElapsedNanos = sendElapsed ?: sendStarted?.let { start -> monotonicNanos() - start }) }
                    // Sending or evidence capture may have succeeded partially; never automatically replay.
                    stopped.set(true)
                }
            }
        } finally {
            callbackFinished = true
        }
        return true
    }

    /** Every applicable pair must have a response, and every selected payload needs at least
     * one executed position. Only declared context incompatibility is an acceptable non-send.
     * Missing bindings, absent positions, transport/evidence failures remain incomplete.
     */
    fun allCandidatesRecorded(): Boolean = candidatesRecorded(snapshot())

    /** Explicit user deferrals remain incomplete for full coverage; expose scoped progress separately. */
    fun allNonDeferredCandidatesRecorded(): Boolean = candidatesRecorded(snapshot().filterNot { it.reason?.startsWith("USER_DEFERRED:") == true })

    private fun candidatesRecorded(current: List<PayloadExecutionItem>): Boolean {
        return callbackFinished && current.isNotEmpty() && current.all {
            it.state == "RESPONSE_RECEIVED" || (it.state == "NOT_EXECUTABLE" && it.reason == "CONTEXT_NOT_APPLICABLE")
        } && current.groupBy { it.payloadId }.values.all { group -> group.any { it.state == "RESPONSE_RECEIVED" } }
    }
}
