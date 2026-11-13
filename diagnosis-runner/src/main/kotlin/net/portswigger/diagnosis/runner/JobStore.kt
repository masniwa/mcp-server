package net.portswigger.diagnosis.runner

import net.portswigger.diagnosis.contract.*
import kotlinx.serialization.json.*
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.sql.Connection
import java.sql.DriverManager

/** One writer per store. SQLite commits precede every side effect; interrupted intents never replay. */
class JobStore(val directory: Path) : AutoCloseable {
    // Serialize effects and shutdown separately; durable metadata stays available during network/UI waits.
    private val effects = Any()
    private val channel: FileChannel
    private val lock: java.nio.channels.FileLock
    private val db: Connection
    init {
        Files.createDirectories(directory)
        var p: Path? = directory.toAbsolutePath()
        while (p != null) {
            requireJob(!Files.isSymbolicLink(p) && !Files.readAttributes(p, java.nio.file.attribute.BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS).isOther, "UNSAFE_STORE_PATH")
            p = p.parent
        }
        channel = FileChannel.open(directory.resolve("writer.lock"), StandardOpenOption.CREATE, StandardOpenOption.WRITE)
        lock = try { channel.tryLock() ?: throw JobRejected("STORE_ALREADY_OPEN") }
        catch(e:Exception) { channel.close();throw JobRejected("STORE_ALREADY_OPEN") }
        db = try {
            Class.forName("org.sqlite.JDBC")
            DriverManager.getConnection("jdbc:sqlite:${directory.resolve("jobs.sqlite").toAbsolutePath()}").also { connection ->
                try { connection.createStatement().use { s ->
                    s.execute("PRAGMA journal_mode=WAL");s.execute("PRAGMA synchronous=FULL")
                    s.execute("CREATE TABLE IF NOT EXISTS records (key TEXT PRIMARY KEY, value TEXT NOT NULL, digest TEXT NOT NULL)")
                    s.execute("CREATE TABLE IF NOT EXISTS operations (id TEXT PRIMARY KEY, input TEXT NOT NULL, state TEXT NOT NULL, result TEXT, result_digest TEXT)")
                    val columns=s.executeQuery("PRAGMA table_info(operations)").use { rows -> buildSet { while(rows.next()) add(rows.getString("name")) } }
                    // Old committed rows have no independent digest; do not invent retroactive integrity evidence.
                    if("result_digest" !in columns) s.execute("ALTER TABLE operations ADD COLUMN result_digest TEXT")
                } } catch(e:Exception) { connection.close();throw e }
            }
        } catch(e:Exception) {
            lock.release();channel.close();throw e
        }
    }
    /** Only metadata writes belong here. A journal intent must be committed before a side effect. */
    @Synchronized fun <T> transaction(action:()->T):T {
        if(!db.autoCommit) return action()
        db.autoCommit=false
        try { val result=action();db.commit();return result }
        catch(e:Throwable) { db.rollback();throw e }
        finally { db.autoCommit=true }
    }
    @Synchronized fun put(key: String, value: JsonElement) {
        val raw = value.toString()
        db.prepareStatement("INSERT INTO records VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,digest=excluded.digest").use {
            it.setString(1,key); it.setString(2,raw); it.setString(3,digest(raw)); it.executeUpdate()
        }
    }
    @Synchronized fun get(key: String): JsonElement? = db.prepareStatement("SELECT value,digest FROM records WHERE key=?").use {
        it.setString(1,key)
        it.executeQuery().use { rows -> if (!rows.next()) null else {
            val raw = rows.getString(1)
            requireJob(digest(raw) == rows.getString(2), "CORRUPT_RECORD")
            jobJson.parseToJsonElement(raw)
        } }
    }
    @Synchronized fun keys(prefix: String): List<String> = db.prepareStatement("SELECT key FROM records ORDER BY key").use {
        it.executeQuery().use { rows -> buildList { while(rows.next()) rows.getString(1).takeIf { key -> key.startsWith(prefix) }?.let(::add) } }
    }
    fun <T> once(id: String, input: String, decode: (JsonElement)->T, encode: (T)->JsonElement, action: ()->T): T {
        // Check before taking the effects monitor to avoid metadata-transaction/effect lock inversion.
        synchronized(this) { requireJob(db.autoCommit,"SIDE_EFFECT_INSIDE_METADATA_TRANSACTION") }
        return synchronized(effects) {
          synchronized(this) {
            requireJob(db.autoCommit,"SIDE_EFFECT_INSIDE_METADATA_TRANSACTION")
            db.prepareStatement("SELECT input,state,result,result_digest FROM operations WHERE id=?").use {
            it.setString(1,id)
            it.executeQuery().use { r -> if (r.next()) {
                requireJob(r.getString(1)==input, "OPERATION_ID_REUSED")
                requireJob(r.getString(2)=="COMMITTED", "OPERATION_OUTCOME_UNKNOWN")
                val raw=r.getString(3)
                requireJob(r.getString(4)!=null,"OPERATION_RESULT_UNVERIFIABLE")
                requireJob(raw!=null && digest(raw)==r.getString(4),"CORRUPT_OPERATION_RESULT")
                return decode(jobJson.parseToJsonElement(raw))
            } }
        }
            db.prepareStatement("INSERT INTO operations(id,input,state,result,result_digest) VALUES(?,?,'INTENT',NULL,NULL)").use { it.setString(1,id);it.setString(2,input);it.executeUpdate() }
          }
        // If action or commit throws, INTENT remains durable. The caller must reconcile, never retry sending.
        val result = action()
        val raw = encode(result).toString()
          synchronized(this) {
            db.prepareStatement("UPDATE operations SET state='COMMITTED',result=?,result_digest=? WHERE id=?").use { it.setString(1,raw);it.setString(2,digest(raw));it.setString(3,id);it.executeUpdate() }
          }
          result
        }
    }
    fun onceJson(id: String, input: String, action: ()->JsonElement): JsonElement = once(id,input,{it},{it},action)
    override fun close() { synchronized(effects) { synchronized(this) { db.close(); lock.release(); channel.close() } } }
}

/** Can be opened after a restart without any native Audit handle. Does not invent missing legacy indices. */
class SavedResults(private val store: JobStore) {
    fun read(executionId: String): JsonObject {
        val index = store.get("result-index:$executionId")?.jsonArray ?: throw JobRejected("RESULTS_NOT_COMMITTED")
        return buildJsonObject {
            put("execution", store.get("execution:$executionId") ?: throw JobRejected("MISSING_EXECUTION"))
            put("diagnosisCompleted", false)
            put("records", JsonArray(index.map { ref ->
                val r = ref.jsonObject
                val value = store.get(r["key"]!!.jsonPrimitive.content) ?: throw JobRejected("MISSING_EVIDENCE")
                requireJob(fingerprint(value)==r["digest"]!!.jsonPrimitive.content,"EVIDENCE_CHANGED")
                value
            }))
        }
    }
}
