package net.portswigger.mcp.tools

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import java.nio.file.Files
import io.mockk.mockk

class PayloadTimingComparisonTest {
    @TempDir lateinit var root: Path
    @Test fun `references use committed timing records and reject tampering`() {
        val catalog = PayloadProfileCatalog("a".repeat(64), (0..17).map {
            ProfilePayload("p$it", "replace", "light", "$it", listOf("query")) })
        val plan = PayloadWirePlan.create("x=0".toByteArray(), catalog, "light", listOf(PayloadWirePosition("x", "query", 2, 3, 0, 1)))
        var clock=0L; var sent=0
        val execution=PayloadExecution(plan) { clock }
        val store=PayloadEvidenceStore.create(root.resolve("run"),plan)
        val run=PayloadRunRegistry.Run("run",plan,execution,store,root.resolve("run"),mockk())
        execution.execute({true}, {
            val delay=if (sent < 9) 1000L else 3000L
            clock+=(if (sent++ % 3 == 1) delay+100 else 100)*1_000_000
            PayloadExchange(it,"HTTP/1.1 200 OK\r\n\r\nnormal".toByteArray(),200)
        },store::record)
        val refs=(0..5).map { n -> PayloadTimingRoundRef(if(n<3)1000 else 3000,
            PayloadTimingEvidenceRef("run",n*3),PayloadTimingEvidenceRef("run",n*3+1),PayloadTimingEvidenceRef("run",n*3+2)) }
        assertEquals("REPRODUCIBLE_DELAY_PATTERN", resolvePayloadTiming(refs) { run }.state)
        val path=root.resolve("run/0.json")
        Files.writeString(path,Files.readString(path).replace("100000000","100000001"))
        assertThrows(IllegalArgumentException::class.java) { resolvePayloadTiming(refs) { run } }
    }
    private fun rounds(): List<TimingRound> = listOf(1000L, 3000L).flatMap { delay ->
        (1..3).map { n ->
            fun obs(role: String, ms: Long) = TimingObservation("$delay-$n-$role", "same-request-position", ms * 1_000_000, 200, true)
            TimingRound(delay, obs("normal", 100+n.toLong()), obs("true", delay+105+n), obs("false", 105+n.toLong()))
        }
    }
    @Test fun `repeated dose dependent delay is a pattern not a SQLi verdict`() {
        val r = comparePayloadTiming(rounds())
        assertEquals("REPRODUCIBLE_DELAY_PATTERN", r.state)
        assertEquals(listOf(1000.0,3000.0), r.levels.map { it.medianDeltaMillis })
        assertTrue(r.limitations.contains("DELAY_PATTERN_IS_NOT_A_SQLI_VERDICT"))
    }
    @Test fun `single pair and reused evidence cannot prove reproducibility`() {
        assertEquals("INSUFFICIENT_EVIDENCE", comparePayloadTiming(rounds().take(1)).state)
        assertTrue(comparePayloadTiming(rounds()+rounds()).reasons.contains("REUSED_OR_MISSING_EVIDENCE"))
    }
    @Test fun `common delay is not a true condition effect`() {
        val r=rounds().map { it.copy(conditionTrue=it.conditionTrue.copy(elapsedNanos=5_000_000_000),
            normal=it.normal.copy(elapsedNanos=5_000_000_000),conditionFalse=it.conditionFalse.copy(elapsedNanos=5_000_000_000)) }
        assertEquals("DELAY_PATTERN_NOT_ESTABLISHED", comparePayloadTiming(r).state)
    }
    @Test fun `one outlier cannot be hidden by the median`() {
        val r=rounds().toMutableList(); r[0]=r[0].copy(conditionTrue=r[0].conditionTrue.copy(elapsedNanos=100_000_000))
        assertEquals("DELAY_PATTERN_NOT_ESTABLISHED", comparePayloadTiming(r).state)
    }
    @Test fun `noise statuses failures and mixed contexts prevent clean pattern`() {
        val base=rounds()
        assertEquals("CONFOUNDED", comparePayloadTiming(base.map { it.copy(normal=it.normal.copy(elapsedNanos=900_000_000)) }).state)
        for (status in listOf(429,500,302,401)) assertEquals("CONFOUNDED",comparePayloadTiming(base.map {it.copy(conditionTrue=it.conditionTrue.copy(status=status))}).state)
        assertEquals("INSUFFICIENT_EVIDENCE",comparePayloadTiming(base.map {it.copy(conditionTrue=it.conditionTrue.copy(responseReceived=false))}).state)
        assertEquals("INSUFFICIENT_EVIDENCE",comparePayloadTiming(base.map {it.copy(conditionTrue=it.conditionTrue.copy(contextId="different"))}).state)
    }
}
