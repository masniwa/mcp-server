package net.portswigger.mcp.tools

// >> 20261014 mniwa Validate ETA accuracy on held-out deterministic scans and refuse predictions without comparable evidence.
import java.time.Instant
import kotlinx.serialization.json.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class ScanTimeEstimatorTest {
    private var nanos = 0L
    private val estimator = ScanTimeEstimator({ nanos }, { Instant.parse("2026-10-14T00:00:00Z").plusNanos(nanos) })
    private fun advance(seconds: Long) { nanos += seconds * 1_000_000_000 }
    private fun train(key: String = "same", count: Int = 100, errors: Int? = 0) {
        val run = estimator.start(key)
        estimator.observe(run, "scanning", 0, 0, 2)
        advance(50)
        estimator.observe(run, "finished", count, errors, 2)
    }
    private fun histories() { repeat(3) { train() } }
    private fun reason(item: JsonObject) = item["reason"]!!.jsonPrimitive.content

    @Test fun `held out stable scan estimate meets a 25 percent error criterion`() {
        histories()
        val run = estimator.start("same")
        estimator.observe(run, "scanning", 0, 0, 2)
        advance(10)
        val estimate = estimator.observe(run, "scanning", 20, 0, 2)
        assertEquals("ESTIMATED", reason(estimate))
        val predicted = estimate["remainingSeconds"]!!.jsonPrimitive.double
        val actualRemaining = 40.0
        assertTrue(kotlin.math.abs(predicted - actualRemaining) / actualRemaining <= 0.25)
        assertEquals(40.0, predicted)
        advance(40)
        val done = estimator.observe(run, "finished", 100, 0, 2)
        assertEquals("COMPLETED", reason(done))
        assertEquals(0.0, done["remainingSeconds"]!!.jsonPrimitive.double)
        advance(99)
        assertEquals(50.0, estimator.observe(run, "finished", 100, 0, 2)["elapsedSeconds"]!!.jsonPrimitive.double)
    }

    @Test fun `unknown history profile and insertion point mismatches refuse ETA`() {
        histories()
        assertEquals("WORKLOAD_MODEL_REQUIRED", reason(estimator.observe(estimator.start(null), "scanning", 1, 0, 2)))
        assertEquals("INSUFFICIENT_COMPARABLE_HISTORY", reason(estimator.observe(estimator.start("other"), "scanning", 1, 0, 2)))
        assertEquals("INSUFFICIENT_COMPARABLE_HISTORY", reason(estimator.observe(estimator.start("same"), "scanning", 1, 0, 3)))
    }

    @Test fun `minimum history and rate windows are enforced`() {
        repeat(2) { train() }
        assertEquals("INSUFFICIENT_COMPARABLE_HISTORY", reason(estimator.observe(estimator.start("same"), "scanning", 0, 0, 2)))
        train()
        val run = estimator.start("same")
        estimator.observe(run, "scanning", 0, 0, 2)
        advance(2)
        assertEquals("INSUFFICIENT_RATE_OBSERVATIONS", reason(estimator.observe(run, "scanning", 4, 0, 2)))
    }

    @Test fun `macro delays and slower throughput increase remaining estimate`() {
        histories()
        val fast = estimator.start("same")
        estimator.observe(fast, "scanning", 0, 0, 2)
        advance(10)
        val a = estimator.observe(fast, "scanning", 20, 0, 2)["remainingSeconds"]!!.jsonPrimitive.double
        val slow = estimator.start("same")
        estimator.observe(slow, "scanning", 0, 0, 2)
        advance(20)
        val b = estimator.observe(slow, "scanning", 20, 0, 2)["remainingSeconds"]!!.jsonPrimitive.double
        assertEquals(a * 2, b)
    }

    @Test fun `stalling does not retain a stale finish prediction`() {
        histories()
        val run = estimator.start("same")
        estimator.observe(run, "scanning", 0, 0, 2)
        advance(10); estimator.observe(run, "scanning", 20, 0, 2)
        advance(31)
        val stalled = estimator.observe(run, "scanning", 20, 0, 2)
        assertEquals("NO_RECENT_PROGRESS", reason(stalled))
        assertEquals(JsonNull, stalled["predictedFinishAt"])
    }

    @Test fun `pause resume waiting and unknown states never imply successful completion`() {
        histories()
        val run = estimator.start("same")
        estimator.observe(run, "scanning", 1, 0, 2)
        advance(10)
        val paused = estimator.observe(run, "paused", 2, 0, 2)
        assertEquals("PAUSED", reason(paused))
        assertEquals(JsonNull, paused["remainingSeconds"])
        advance(60)
        assertEquals("INTERRUPTED_OR_COUNTER_RESET", reason(estimator.observe(run, "running", 4, 0, 2)))
        assertEquals("WAITING", reason(estimator.observe(estimator.start("same"), "queued", 0, 0, 2)))
        assertEquals("UNKNOWN_STATE", reason(estimator.observe(estimator.start("same"), "almost completed", 100, 0, 2)))
    }

    @Test fun `cancelled scan is unavailable and is not a successful zero ETA`() {
        val result = estimator.observe(estimator.start("same"), "cancelled", 100, 0, 2)
        assertEquals("CANCELLED", reason(result))
        assertEquals(JsonNull, result["remainingSeconds"])
        assertEquals(0, result["comparableCompletedScans"]!!.jsonPrimitive.int)
    }

    // >> 20261008 mniwa Verify normal startup waits retain initial and measured estimates and successful history learning.
    @Test fun `initial queue states allow workflow estimates rate correction and completed history`() {
        listOf("queued", "waiting", "starting").forEachIndexed { index, waitingState ->
            val run = estimator.start("initial-wait")
            val model = ScanWorkload(50.0, "Observed workflow", workflowSeconds = 5.0)
            val waiting = estimator.observe(run, waitingState, 0, 0, 2, model)
            assertEquals("WAITING", reason(waiting))
            assertEquals(JsonNull, waiting["remainingSeconds"])
            advance(20)
            assertEquals("WAITING", reason(estimator.observe(run, waitingState, 0, 0, 2)))
            advance(2)
            val initial = estimator.observe(run, "scanning", 0, 0, 2)
            assertEquals("ESTIMATED", reason(initial))
            assertEquals(500.0, initial["remainingSeconds"]!!.jsonPrimitive.double)
            assertEquals("INSERTION_POINT_BUDGET_AND_WORKFLOW_TIME", initial["method"]!!.jsonPrimitive.content)
            advance(10)
            val measured = estimator.observe(run, "scanning", 20, 0, 2)
            assertEquals("ESTIMATED", reason(measured))
            assertEquals(40.0, measured["remainingSeconds"]!!.jsonPrimitive.double)
            assertEquals("INSERTION_POINT_BUDGET_AND_RECENT_RATE", measured["method"]!!.jsonPrimitive.content)
            advance(40)
            val completed = estimator.observe(run, "finished", 100, 0, 2)
            assertEquals("COMPLETED", reason(completed))
            assertEquals(0.0, completed["remainingSeconds"]!!.jsonPrimitive.double)
            assertEquals(72.0, completed["elapsedSeconds"]!!.jsonPrimitive.double)
            assertEquals(index + 1, completed["comparableCompletedScans"]!!.jsonPrimitive.int)
        }
        val next = estimator.start("initial-wait")
        assertEquals("INSUFFICIENT_RATE_OBSERVATIONS", reason(estimator.observe(next, "scanning", 0, 0, 2)))
        advance(10)
        val learned = estimator.observe(next, "scanning", 20, 0, 2)
        assertEquals("ESTIMATED", reason(learned))
        assertEquals("HISTORICAL_REQUEST_COUNT_AND_RECENT_RATE", learned["method"]!!.jsonPrimitive.content)
        assertEquals(40.0, learned["remainingSeconds"]!!.jsonPrimitive.double)
    }

    @Test fun `startup pause or unknown state and waiting after execution remain ineligible`() {
        val model = ScanWorkload(50.0, "Observed workflow", workflowSeconds = 5.0)
        listOf("paused", "unknown").forEach { state ->
            val run = estimator.start("interrupted-$state")
            estimator.observe(run, state, 0, 0, 2, model)
            estimator.observe(run, "queued", 0, 0, 2)
            assertEquals("INTERRUPTED_OR_COUNTER_RESET", reason(estimator.observe(run, "running", 0, 0, 2)))
            advance(10)
            assertEquals("INTERRUPTED_OR_COUNTER_RESET", reason(estimator.observe(run, "running", 20, 0, 2)))
            val completed = estimator.observe(run, "finished", 100, 0, 2)
            assertEquals(0, completed["comparableCompletedScans"]!!.jsonPrimitive.int)
        }
        listOf("queued", "waiting", "starting").forEach { state ->
            val alreadyExecuted = estimator.start("unobserved-start-$state")
            assertEquals("WAITING", reason(estimator.observe(alreadyExecuted, state, 10, 0, 2, model)))
            assertEquals("INTERRUPTED_OR_COUNTER_RESET", reason(estimator.observe(alreadyExecuted, "running", 11, 0, 2)))
            val unobservedCompleted = estimator.observe(alreadyExecuted, "finished", 100, 0, 2)
            assertEquals(0, unobservedCompleted["comparableCompletedScans"]!!.jsonPrimitive.int)
            val run = estimator.start("post-start-$state")
            estimator.observe(run, "scanning", 0, 0, 2, model)
            assertEquals("WAITING", reason(estimator.observe(run, state, 0, 0, 2)))
            assertEquals("INTERRUPTED_OR_COUNTER_RESET", reason(estimator.observe(run, "scanning", 1, 0, 2)))
            val completed = estimator.observe(run, "finished", 100, 0, 2)
            assertEquals(0, completed["comparableCompletedScans"]!!.jsonPrimitive.int)
        }
    }
    // << mniwa

    @Test fun `counter reset prevents misleading rate and training history`() {
        histories()
        val run = estimator.start("same")
        estimator.observe(run, "scanning", 20, 0, 2)
        advance(10)
        assertEquals("INTERRUPTED_OR_COUNTER_RESET", reason(estimator.observe(run, "scanning", 1, 0, 2)))
    }

    @Test fun `exceeded historical counts never imply zero remaining time`() {
        histories()
        val run = estimator.start("same")
        estimator.observe(run, "scanning", 0, 0, 2)
        advance(50)
        val result = estimator.observe(run, "scanning", 101, 0, 2)
        assertEquals("HISTORICAL_WORKLOAD_EXCEEDED", reason(result))
        assertEquals(JsonNull, result["remainingSeconds"])
    }

    @Test fun `variable histories and failed or unobserved training scans are excluded`() {
        train(count = 100); train(count = 101); train(count = 200)
        val run = estimator.start("same")
        estimator.observe(run, "scanning", 0, 0, 2)
        advance(10)
        assertEquals("HISTORY_TOO_VARIABLE", reason(estimator.observe(run, "scanning", 10, 0, 2)))
        train("bad", errors = 1); train("bad", errors = null)
        estimator.observe(estimator.start("bad"), "finished", 100, 0, 2)
        assertEquals("INSUFFICIENT_COMPARABLE_HISTORY", reason(estimator.observe(estimator.start("bad"), "scanning", 0, 0, 2)))
    }

    @Test fun `range is historical workload spread rather than a confidence interval`() {
        train(count = 90); train(count = 100); train(count = 110)
        val run = estimator.start("same")
        estimator.observe(run, "scanning", 0, 0, 2)
        advance(10)
        val result = estimator.observe(run, "scanning", 20, 0, 2)
        assertEquals(35.0, result["lowerRemainingSeconds"]!!.jsonPrimitive.double)
        assertEquals(45.0, result["upperRemainingSeconds"]!!.jsonPrimitive.double)
        assertEquals("LOW", result["confidence"]!!.jsonPrimitive.content)
    }

    @Test fun `reload loses historical calibration and does not guess`() {
        histories()
        val fresh = ScanTimeEstimator({ nanos }, { Instant.EPOCH })
        assertEquals("INSUFFICIENT_COMPARABLE_HISTORY", reason(fresh.observe(fresh.start("same"), "scanning", 10, 0, 2)))
    }

    @Test fun `unknown or positive current error counts suppress ETA`() {
        histories()
        assertEquals("ERROR_METRIC_UNAVAILABLE", reason(estimator.observe(estimator.start("same"), "scanning", 0, null, 2)))
        assertEquals("CURRENT_NETWORK_ERRORS", reason(estimator.observe(estimator.start("same"), "scanning", 0, 1, 2)))
    }

    // >> 20261014 mniwa Verify first-scan workload estimates, full workflow timing and rate-based updates without calibration audits.
    @Test fun `first scan can estimate from insertion workload and observed sequential workflow`() {
        val result = estimator.observe(estimator.start(null), "scanning", 0, 0, 2,
            ScanWorkload(50.0, "Observed workload evidence", workflowSeconds = 0.5, effectiveConcurrency = 1.0))
        assertEquals("ESTIMATED", reason(result))
        assertEquals(50.0, result["remainingSeconds"]!!.jsonPrimitive.double)
        assertEquals(0, result["comparableCompletedScans"]!!.jsonPrimitive.int)
        assertEquals("INSERTION_POINT_BUDGET_AND_WORKFLOW_TIME", result["method"]!!.jsonPrimitive.content)
        assertEquals(JsonNull, result["lowerRemainingSeconds"])
    }

    @Test fun `recent rate replaces nominal workflow cost rather than double counting waits`() {
        val run = estimator.start(null)
        val model = ScanWorkload(50.0, "Observed evidence", workflowSeconds = 10.0, effectiveConcurrency = 1.0, lowerRequestsPerInsertionPoint = 40.0, upperRequestsPerInsertionPoint = 60.0)
        estimator.observe(run, "scanning", 0, 0, 2, model)
        advance(10)
        val updated = estimator.observe(run, "scanning", 20, 0, 2)
        assertEquals(40.0, updated["remainingSeconds"]!!.jsonPrimitive.double)
        assertEquals(30.0, updated["lowerRemainingSeconds"]!!.jsonPrimitive.double)
        assertEquals(50.0, updated["upperRemainingSeconds"]!!.jsonPrimitive.double)
        assertEquals("INSERTION_POINT_BUDGET_AND_RECENT_RATE", updated["method"]!!.jsonPrimitive.content)
    }

    @Test fun `omitted concurrency assumes sequential execution and exceeded budget is not completion`() {
        val run = estimator.start(null)
        assertEquals("ESTIMATED", reason(estimator.observe(run, "scanning", 0, 0, 2, ScanWorkload(10.0, "Evidence", workflowSeconds = 3.0))))
        advance(10)
        val exceeded = estimator.observe(run, "scanning", 21, 0, 2)
        assertEquals("WORKLOAD_BUDGET_EXCEEDED", reason(exceeded))
        assertEquals(JsonNull, exceeded["remainingSeconds"])
        assertEquals("COMPLETED", reason(estimator.observe(run, "finished", 21, 0, 2)))
    }

    @Test fun `known long helper wait does not trigger a premature thirty second stall`() {
        val run = estimator.start(null)
        val model = ScanWorkload(50.0, "Measured long workflow", workflowSeconds = 60.0, effectiveConcurrency = 1.0)
        estimator.observe(run, "scanning", 0, 0, 2, model)
        advance(40)
        assertEquals("ESTIMATED", reason(estimator.observe(run, "scanning", 0, 0, 2)))
        advance(81)
        assertEquals("NO_RECENT_PROGRESS", reason(estimator.observe(run, "scanning", 0, 0, 2)))
    }

    @Test fun `invalid nonfinite budgets and incomplete bounds are rejected`() {
        assertThrows(IllegalArgumentException::class.java) { ScanWorkload(Double.NaN, "Evidence").validate() }
        assertThrows(IllegalArgumentException::class.java) { ScanWorkload(1.0, "").validate() }
        assertThrows(IllegalArgumentException::class.java) { ScanWorkload(1.0, "Evidence", lowerRequestsPerInsertionPoint = 0.5).validate() }
        assertThrows(IllegalArgumentException::class.java) { ScanWorkload(1.0, "Evidence", effectiveConcurrency = Double.POSITIVE_INFINITY).validate() }
    }
    // >> 20261014 mniwa Check the default budget with detected points and switch to measured rate without adding workflow cost twice.
    @Test fun `default thirty four budget starts sequentially and corrects from observed throughput`() {
        val run = estimator.start(null)
        val initial = estimator.observe(run, "scanning", 0, 0, 41, ScanWorkload(workflowSeconds = 14.924))
        assertEquals(1394.0, initial["estimatedTotalRequests"]!!.jsonPrimitive.double)
        assertEquals(20805.0, initial["estimatedInitialTotalSeconds"]!!.jsonPrimitive.double)
        assertEquals(20805.0, initial["remainingSeconds"]!!.jsonPrimitive.double)
        assertEquals(1.0, initial["initialConcurrencyAssumption"]!!.jsonPrimitive.double)
        advance(10)
        val corrected = estimator.observe(run, "scanning", 20, 0, 41)
        assertEquals(687.0, corrected["remainingSeconds"]!!.jsonPrimitive.double)
        assertEquals(2.0, corrected["recentRequestsPerSecond"]!!.jsonPrimitive.double)
        assertEquals("INSERTION_POINT_BUDGET_AND_RECENT_RATE", corrected["method"]!!.jsonPrimitive.content)
        assertEquals(20805.0, corrected["estimatedInitialTotalSeconds"]!!.jsonPrimitive.double)
    }

    @Test fun `unknown points wait and a late first read deducts completed requests`() {
        val run = estimator.start(null)
        assertEquals("NO_INSERTION_POINTS", reason(estimator.observe(run, "scanning", 0, 0, 0, ScanWorkload(workflowSeconds = 2.0))))
        val first = estimator.observe(run, "scanning", 4, 0, 2)
        assertEquals(136.0, first["estimatedInitialTotalSeconds"]!!.jsonPrimitive.double)
        assertEquals(128.0, first["remainingSeconds"]!!.jsonPrimitive.double)
    }

    @Test fun `workflow timing is required before actual rate exists`() {
        val run = estimator.start(null)
        assertEquals("INSUFFICIENT_RATE_OBSERVATIONS", reason(estimator.observe(run, "scanning", 0, 0, 2, ScanWorkload())))
        advance(10)
        assertEquals(24.0, estimator.observe(run, "scanning", 20, 0, 2)["remainingSeconds"]!!.jsonPrimitive.double)
    }
    // << mniwa
    // << mniwa
}
// << mniwa
