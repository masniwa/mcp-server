package net.portswigger.diagnosis.runner

import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.JobRejected
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import java.sql.DriverManager
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class JobStoreConcurrencyTest {
    @TempDir lateinit var directory:Path
    @Test fun `committed intent precedes effect while metadata and draft writes remain available and duplicate effect stays once`() {
        val entered=CountDownLatch(1);val release=CountDownLatch(1);val effects=AtomicInteger()
        val threads=Executors.newFixedThreadPool(3)
        JobStore(directory.resolve("overlap")).use { store ->
            val first=threads.submit<JsonElement> { store.onceJson("send","same-input") {
                effects.incrementAndGet();entered.countDown();check(release.await(5,TimeUnit.SECONDS));JsonPrimitive("result")
            } }
            try {
                assertTrue(entered.await(2,TimeUnit.SECONDS))
                DriverManager.getConnection("jdbc:sqlite:${store.directory.resolve("jobs.sqlite")}").use { db ->
                    db.createStatement().use { statement -> statement.executeQuery("SELECT state FROM operations WHERE id='send'").use {
                        assertTrue(it.next());assertEquals("INTENT",it.getString(1))
                    } }
                }
                val metadata=threads.submit<JsonElement?> {
                    store.put("draft:test",JsonPrimitive("static"));store.get("draft:test")
                }
                assertEquals(JsonPrimitive("static"),metadata.get(2,TimeUnit.SECONDS));assertFalse(first.isDone)
                val duplicate=threads.submit<JsonElement> { store.onceJson("send","same-input") {
                    effects.incrementAndGet();JsonPrimitive("must-not-run")
                } }
                release.countDown();assertEquals(JsonPrimitive("result"),first.get(3,TimeUnit.SECONDS))
                assertEquals(JsonPrimitive("result"),duplicate.get(3,TimeUnit.SECONDS));assertEquals(1,effects.get())
            } finally { release.countDown();threads.shutdownNow() }
        }
    }
    @Test fun `failed effect keeps intent and refuses replay even though metadata remains writable`() {
        val calls=AtomicInteger()
        JobStore(directory.resolve("failure")).use { store ->
            assertThrows(IllegalStateException::class.java) { store.onceJson("send","input") {
                calls.incrementAndGet();store.put("draft:independent",JsonPrimitive("saved"));error("unknown effect outcome")
            } }
            assertEquals("OPERATION_OUTCOME_UNKNOWN",assertThrows(JobRejected::class.java) {
                store.onceJson("send","input") { calls.incrementAndGet();JsonNull }
            }.code)
            assertEquals(1,calls.get());assertEquals(JsonPrimitive("saved"),store.get("draft:independent"))
        }
    }
    @Test fun `side effect inside metadata transaction rejects without lock inversion against an in-flight effect`() {
        val entered=CountDownLatch(1);val release=CountDownLatch(1);val threads=Executors.newFixedThreadPool(2)
        JobStore(directory.resolve("order")).use { store ->
            val first=threads.submit<JsonElement> { store.onceJson("send","input") {
                entered.countDown();check(release.await(5,TimeUnit.SECONDS));store.put("effect-returned",JsonPrimitive(true));JsonNull
            } }
            try {
                assertTrue(entered.await(2,TimeUnit.SECONDS))
                val prohibited=threads.submit<String> { assertThrows(JobRejected::class.java) {
                    store.transaction { store.onceJson("nested","input") { error("must-not-run") } }
                }.code }
                assertEquals("SIDE_EFFECT_INSIDE_METADATA_TRANSACTION",prohibited.get(2,TimeUnit.SECONDS))
                release.countDown();first.get(3,TimeUnit.SECONDS)
                assertEquals(JsonPrimitive(true),store.get("effect-returned"))
            } finally { release.countDown();threads.shutdownNow() }
        }
    }
}
