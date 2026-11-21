package net.portswigger.diagnosis.runner

import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.JobRejected
import net.portswigger.diagnosis.contract.digest
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.sqlite.SQLiteConnection
import org.sqlite.SQLiteLimits
import java.nio.file.Path
import java.sql.Connection
import java.sql.DriverManager
import java.sql.SQLException
import java.util.concurrent.atomic.AtomicInteger

class JobStoreLargeEvidenceTest {
    @TempDir lateinit var directory:Path
    private fun connection(store:JobStore):Connection = JobStore::class.java.getDeclaredField("db").let {
        it.isAccessible=true;it.get(store) as Connection
    }
    private fun constrain(store:JobStore) {
        (connection(store) as SQLiteConnection).setLimit(SQLiteLimits.SQLITE_LIMIT_LENGTH,262144)
    }
    private fun large():JsonElement = buildJsonObject {
        // Include surrogate pairs crossing potential chunk boundaries and multi-byte UTF-8.
        put("response", "a".repeat(16370)+"\uD83C\uDF4D\u65E5\u672C".repeat(100000))
        put("complete",false)
    }
    @Test fun `real SQLite scalar limit rejects old layout but chunked evidence survives restart and digest verification`() {
        val value=large();val raw=value.toString()
        JobStore(directory).use { store ->
            constrain(store)
            val db=connection(store)
            assertThrows(SQLException::class.java) {
                db.prepareStatement("INSERT INTO records(key,value,digest) VALUES('old',?,?)").use {
                    it.setString(1,raw);it.setString(2,digest(raw));it.executeUpdate()
                }
            }
            store.transaction { store.put("evidence",value);store.put("index",JsonPrimitive("evidence")) }
            assertEquals(value,store.get("evidence"))
            assertEquals(JsonPrimitive("evidence"),store.get("index"))
        }
        JobStore(directory).use { store -> constrain(store);assertEquals(value,store.get("evidence")) }
    }
    @Test fun `large committed result is read without repeating the side effect after restart`() {
        val calls=AtomicInteger();val value=large()
        JobStore(directory).use { store ->
            constrain(store)
            assertEquals(value,store.onceJson("send","input") { calls.incrementAndGet();value })
        }
        JobStore(directory).use { store ->
            constrain(store)
            assertEquals(value,store.committedOnceResult("send","input"))
            assertEquals(value,store.onceJson("send","input") { calls.incrementAndGet();JsonNull })
            assertEquals(1,calls.get())
            assertEquals("OPERATION_ID_REUSED",assertThrows(JobRejected::class.java) {
                store.onceJson("send","different") { JsonNull }
            }.code)
        }
    }
    @Test fun `failed chunk insert rolls back evidence index and preserves previous complete value with safe SQLite details`() {
        JobStore(directory).use { store ->
            store.put("evidence",large());store.put("index",JsonPrimitive("old"))
            connection(store).createStatement().use { it.execute("CREATE TRIGGER fail_chunk BEFORE INSERT ON json_chunks WHEN NEW.part=2 BEGIN SELECT RAISE(ABORT,'private-request-body'); END") }
            val error=assertThrows(JobRejected::class.java) {
                store.transaction { store.put("evidence",JsonPrimitive("b".repeat(100000)));store.put("index",JsonPrimitive("new")) }
            }
            assertEquals("STORE_SQLITE_FAILURE",error.code)
            assertEquals("RECORD_WRITE",error.safeDetails["stage"])
            assertEquals("19",error.safeDetails["sqlitePrimaryCode"])
            assertFalse(error.message!!.contains("private-request-body"))
            assertEquals(large(),store.get("evidence"));assertEquals(JsonPrimitive("old"),store.get("index"))
        }
    }
    @Test fun `corrupt missing and reordered chunks fail closed`() {
        JobStore(directory).use { store ->
            store.put("evidence",large())
            connection(store).createStatement().use { it.executeUpdate("UPDATE json_chunks SET value='x'||substr(value,2) WHERE namespace='record' AND owner='evidence' AND part=0") }
            assertEquals("CORRUPT_RECORD",assertThrows(JobRejected::class.java) { store.get("evidence") }.code)
            store.put("evidence",large())
            connection(store).createStatement().use { it.executeUpdate("DELETE FROM json_chunks WHERE namespace='record' AND owner='evidence' AND part=1") }
            assertEquals("CORRUPT_JSON_CHUNKS",assertThrows(JobRejected::class.java) { store.get("evidence") }.code)
        }
    }
    @Test fun `legacy rows and unverifiable operation digests remain unchanged and marker shaped JSON remains data`() {
        Class.forName("org.sqlite.JDBC")
        val marker=buildJsonObject { put("parts",2);put("characters",100000) }
        DriverManager.getConnection("jdbc:sqlite:${directory.resolve("jobs.sqlite")}").use { db ->
            db.createStatement().use {
                it.execute("CREATE TABLE records(key TEXT PRIMARY KEY,value TEXT NOT NULL,digest TEXT NOT NULL)")
                it.execute("CREATE TABLE operations(id TEXT PRIMARY KEY,input TEXT NOT NULL,state TEXT NOT NULL,result TEXT)")
                it.execute("INSERT INTO operations VALUES('legacy','input','COMMITTED','null')")
            }
            db.prepareStatement("INSERT INTO records VALUES('legacy',?,?)").use {
                it.setString(1,marker.toString());it.setString(2,digest(marker.toString()));it.executeUpdate()
            }
        }
        JobStore(directory).use { store ->
            assertEquals(marker,store.get("legacy"))
            assertEquals("OPERATION_RESULT_UNVERIFIABLE",assertThrows(JobRejected::class.java) {
                store.committedOnceResult("legacy","input")
            }.code)
            store.put("new-marker",marker);assertEquals(marker,store.get("new-marker"))
            store.put("replace",large());store.put("replace",JsonNull);assertEquals(JsonNull,store.get("replace"))
            connection(store).createStatement().use { statement ->
                statement.executeQuery("SELECT count(*) FROM json_chunks WHERE owner='replace'").use { it.next();assertEquals(0,it.getInt(1)) }
            }
        }
    }
    @Test fun `failed operation result persistence keeps intent and forbids replay`() {
        val calls=AtomicInteger()
        JobStore(directory).use { store ->
            connection(store).createStatement().use { it.execute("CREATE TRIGGER fail_result BEFORE INSERT ON json_chunks WHEN NEW.namespace='operation' BEGIN SELECT RAISE(ABORT,'secret'); END") }
            val error=assertThrows(JobRejected::class.java) { store.onceJson("send","input") { calls.incrementAndGet();large() } }
            assertEquals("OPERATION_RESULT_WRITE",error.safeDetails["stage"])
            assertNull(store.committedOnceResult("send","input"))
            assertEquals("OPERATION_OUTCOME_UNKNOWN",assertThrows(JobRejected::class.java) {
                store.onceJson("send","input") { calls.incrementAndGet();JsonNull }
            }.code)
            assertEquals(1,calls.get())
        }
    }
}
