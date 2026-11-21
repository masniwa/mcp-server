package net.portswigger.mcp.tools

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class PayloadExecutionTest {
    private fun timedExecution(clock: () -> Long): PayloadExecution {
        val catalog = PayloadProfileCatalog("a".repeat(64), listOf(ProfilePayload("p", "replace", "light", "1", listOf("query"))))
        return PayloadExecution(PayloadWirePlan.create("x=0".toByteArray(), catalog, "light",
            listOf(PayloadWirePosition("x", "query", 2, 3, 0, 1))), clock)
    }
    @Test fun `send timing excludes gate waits and evidence writes`() {
        var now = 0L
        val run = timedExecution { now }
        run.execute({ now += 900L; true }, { now += 25L; PayloadExchange(it, byteArrayOf(1), 200) },
            { item, _ -> assertEquals(25L, item.sendCallElapsedNanos); now += 800L })
        assertEquals(25L, run.snapshot().single().sendCallElapsedNanos)
    }
    @Test fun `transport failures retain elapsed time without calling it a response time`() {
        var now = 10L
        val run = timedExecution { now }
        run.execute({true}, { now += 45L; throw java.io.IOException() }, { _, _ -> fail("must not record") })
        assertEquals("ERROR", run.snapshot().single().state)
        assertEquals(45L, run.snapshot().single().sendCallElapsedNanos)
    }
    @Test fun `evidence failure retains send duration and nonsends have no duration`() {
        var now = 0L
        val run = timedExecution { now }
        run.execute({true}, { now += 12L; PayloadExchange(it, null, null) }, { _, _ -> now += 70L; throw java.io.IOException() })
        assertEquals(12L, run.snapshot().single().sendCallElapsedNanos)
        val skipped = timedExecution { error("clock must not be read") }
        skipped.execute({false}, { error("must not send") }, { _, _ -> })
        assertNull(skipped.snapshot().single().sendCallElapsedNanos)
    }
    @Test fun `declared incompatible pairs do not block fully executed payload coverage`() {
        val source = PayloadProfileCatalog("a".repeat(64), listOf(
            ProfilePayload("q", "replace", "light", "2", listOf("query")),
            ProfilePayload("r", "replace", "light", "3", listOf("raw"))))
        val run = PayloadExecution(PayloadWirePlan.create("x=0 abc".toByteArray(), source, "light", listOf(
            PayloadWirePosition("query", "query", 2, 3, 0, 1), PayloadWirePosition("raw", "raw", 4, 7))))
        var count = 0
        run.execute({true}, { count++; PayloadExchange(it, "ok".toByteArray(), 200) }, { _, _ -> })
        assertEquals(2, count)
        assertEquals(4, run.snapshot().size)
        assertEquals(2, run.snapshot().count { it.reason == "CONTEXT_NOT_APPLICABLE" })
        assertTrue(run.allCandidatesRecorded())
    }
    @Test fun `payload with no compatible executed position remains incomplete`() {
        val source = PayloadProfileCatalog("a".repeat(64), listOf(ProfilePayload("json-only", "replace", "light", "0", listOf("json-value"))))
        val run = PayloadExecution(PayloadWirePlan.create("x=0".toByteArray(), source, "light", listOf(PayloadWirePosition("q", "query", 2, 3, 0, 1))))
        run.execute({true}, { error("must not send") }, { _, _ -> error("must not record") })
        assertFalse(run.allCandidatesRecorded())
    }
    @Test fun `failure to read native audit state cannot leave hidden pending candidates`() {
        val run = execution()
        run.execute({throw IllegalStateException("cannot read audit")}, { error("must not send") }, { _, _ -> error("must not record") })
        assertTrue(run.snapshot().all { it.state == "NOT_SENT" })
        assertEquals("SEND_GATE_FAILED:IllegalStateException", run.snapshot()[0].reason)
        assertFalse(run.allCandidatesRecorded())
    }
    private fun execution(count: Int = 3): PayloadExecution {
        val catalog = PayloadProfileCatalog("a".repeat(64), (1..count).map { ProfilePayload("p$it", "replace", "light", "$it", listOf("query")) })
        return PayloadExecution(PayloadWirePlan.create("x=0".toByteArray(), catalog, "light", listOf(PayloadWirePosition("x", "query", 2, 3, 0, 1))))
    }
    @Test fun `duplicate callbacks never replay and actual wire evidence is committed`() {
        val run = execution()
        val sent = mutableListOf<String>()
        val evidence = mutableListOf<PayloadExecutionItem>()
        assertTrue(run.execute({true}, { bytes -> sent.add(bytes.toString(Charsets.UTF_8)); PayloadExchange(bytes, "response".toByteArray(), 200) }, { item, _ -> evidence.add(item) }))
        assertFalse(run.execute({true}, { error("must not resend") }, { _, _ -> error("must not record") }))
        assertEquals(listOf("x=1", "x=2", "x=3"), sent)
        assertEquals(3, evidence.size)
        assertEquals(sha256("x=1".toByteArray()), evidence[0].requestSha256)
        assertTrue(run.allCandidatesRecorded())
    }
    @Test fun `transport exception stops subsequent sends and cannot claim completion`() {
        val run = execution()
        run.execute({true}, { throw IllegalStateException("potentially sensitive transport detail") }, { _, _ -> fail("unexpected") })
        assertEquals(listOf("ERROR", "NOT_SENT", "NOT_SENT"), run.snapshot().map { it.state })
        assertEquals("IllegalStateException", run.snapshot()[0].reason)
        assertFalse(run.allCandidatesRecorded())
    }
    @Test fun `evidence failure is not a successful recorded response`() {
        val run = execution()
        run.execute({true}, { PayloadExchange(it, byteArrayOf(1), 200) }, { _, _ -> throw java.io.IOException("disk full") })
        assertEquals("ERROR", run.snapshot()[0].state)
        assertEquals("NOT_SENT", run.snapshot()[1].state)
        assertFalse(run.allCandidatesRecorded())
    }
    @Test fun `cancellation between attempts leaves exact remaining identities`() {
        val run = execution()
        run.execute({true}, { run.stop(); PayloadExchange(it, byteArrayOf(1), 200) }, { _, _ -> })
        assertEquals(listOf("RESPONSE_RECEIVED", "NOT_SENT", "NOT_SENT"), run.snapshot().map { it.state })
        assertEquals(listOf("p2", "p3"), run.snapshot().filter { it.state == "NOT_SENT" }.map { it.payloadId })
        assertFalse(run.allCandidatesRecorded())
    }
    @Test fun `missing response is not transport success or a vulnerability decision`() {
        val run = execution(1)
        run.execute({true}, { PayloadExchange(it, null, null) }, { _, _ -> })
        assertEquals("NO_RESPONSE", run.snapshot().single().state)
        assertFalse(run.allCandidatesRecorded())
    }
}
