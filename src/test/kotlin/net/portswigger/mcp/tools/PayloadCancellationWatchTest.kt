package net.portswigger.mcp.tools

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class PayloadCancellationWatchTest {
    @Test fun `cancelling one callback leaves concurrent callback uninterrupted`() {
        val ready = CountDownLatch(2)
        val finish = CountDownLatch(1)
        val interrupted = AtomicInteger()
        val failure = java.util.concurrent.atomic.AtomicReference<Throwable?>()
        val cancelledWorker = Thread {
            try {
                PayloadCancellationWatch({ ready.count == 0L }, 10).during {
                    ready.countDown()
                    try {
                        assertFalse(finish.await(5, TimeUnit.SECONDS))
                        fail<Unit>("cancelled callback stayed blocked")
                    } catch (_: InterruptedException) { interrupted.incrementAndGet() }
                }
                assertFalse(Thread.currentThread().isInterrupted)
            } catch (t: Throwable) { failure.compareAndSet(null, t) }
            finally { finish.countDown() }
        }
        val normalWorker = Thread {
            try {
                PayloadCancellationWatch({ false }, 10).during {
                    ready.countDown()
                    assertTrue(finish.await(5, TimeUnit.SECONDS))
                    assertFalse(Thread.currentThread().isInterrupted)
                }
            } catch (t: Throwable) { failure.compareAndSet(null, t) }
        }
        cancelledWorker.start()
        normalWorker.start()
        try {
            cancelledWorker.join(7000)
            normalWorker.join(7000)
            assertFalse(cancelledWorker.isAlive)
            assertFalse(normalWorker.isAlive)
            failure.get()?.let { throw AssertionError("worker failed", it) }
            assertEquals(1, interrupted.get())
        } finally {
            finish.countDown()
            if (cancelledWorker.isAlive) cancelledWorker.interrupt()
            if (normalWorker.isAlive) normalWorker.interrupt()
        }
    }

    @Test fun `cancel releases blocked send and preserves unknown delivery without replay`() {
        val plan = PayloadWirePlan.create("x=1".toByteArray(), PayloadProfileCatalog("a".repeat(64),
            listOf(ProfilePayload("a", "replace", "light", "2", listOf("query")),
                ProfilePayload("b", "replace", "light", "3", listOf("query")))),
            "light", listOf(PayloadWirePosition("x", "query", 2, 3, 0, 1)))
        val execution = PayloadExecution(plan)
        val entered = CountDownLatch(1)
        val never = CountDownLatch(1)
        val sends = AtomicInteger()
        PayloadCancellationWatch({ entered.count == 0L }, 10).during {
            execution.execute({ true }, {
                sends.incrementAndGet()
                entered.countDown()
                assertFalse(never.await(5, TimeUnit.SECONDS), "unexpected release")
                fail<PayloadExchange>("cancellation did not release native wait")
            }, { _, _ -> fail("no response exists to record") })
        }
        assertEquals(1, sends.get())
        assertEquals(listOf("ERROR", "NOT_SENT"), execution.snapshot().map { it.state })
        assertEquals("InterruptedException", execution.snapshot()[0].reason)
        assertTrue(execution.callbackFinished)
        assertFalse(execution.allCandidatesRecorded())
        assertFalse(Thread.currentThread().isInterrupted)
    }

    @Test fun `observation failure does not cancel a normal callback`() {
        val observed = CountDownLatch(1)
        val result = PayloadCancellationWatch({ observed.countDown(); error("status unavailable") }, 10).during {
            assertTrue(observed.await(2, TimeUnit.SECONDS))
            assertFalse(Thread.currentThread().isInterrupted)
            "normal"
        }
        assertEquals("normal", result)
        assertFalse(Thread.currentThread().isInterrupted)
    }

    @Test fun `late cancellation observation cannot interrupt worker after callback returns`() {
        val checking = CountDownLatch(1)
        val release = CountDownLatch(1)
        val checked = CountDownLatch(1)
        PayloadCancellationWatch({
            checking.countDown()
            release.await(2, TimeUnit.SECONDS)
            checked.countDown()
            true
        }, 10).during { assertTrue(checking.await(2, TimeUnit.SECONDS)) }
        release.countDown()
        assertTrue(checked.await(2, TimeUnit.SECONDS))
        assertFalse(Thread.currentThread().isInterrupted)
    }

    @Test fun `preexisting caller interruption is preserved`() {
        try {
            Thread.currentThread().interrupt()
            assertEquals(1, PayloadCancellationWatch({ false }).during { 1 })
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
    }
}
