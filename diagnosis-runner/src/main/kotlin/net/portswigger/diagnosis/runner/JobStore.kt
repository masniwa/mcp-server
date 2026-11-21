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
import java.sql.SQLException

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
                    val recordColumns=s.executeQuery("PRAGMA table_info(records)").use { rows -> buildSet { while(rows.next()) add(rows.getString("name")) } }
                    if("value_encoding" !in recordColumns) s.execute("ALTER TABLE records ADD COLUMN value_encoding TEXT NOT NULL DEFAULT 'JSON'")
                    if("result_encoding" !in columns) s.execute("ALTER TABLE operations ADD COLUMN result_encoding TEXT NOT NULL DEFAULT 'JSON'")
                    s.execute("CREATE TABLE IF NOT EXISTS json_chunks (namespace TEXT NOT NULL, owner TEXT NOT NULL, part INTEGER NOT NULL, value TEXT NOT NULL, PRIMARY KEY(namespace,owner,part))")
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
    @Synchronized fun put(key: String, value: JsonElement) = sqlite("RECORD_WRITE") { transaction {
        val raw = value.toString()
        val stored=storeJson("record",key,raw)
        db.prepareStatement("INSERT INTO records(key,value,digest,value_encoding) VALUES(?,?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,digest=excluded.digest,value_encoding=excluded.value_encoding").use {
            it.setString(1,key); it.setString(2,stored.first); it.setString(3,digest(raw)); it.setString(4,stored.second); it.executeUpdate()
        }
        Unit
    } }
    @Synchronized fun get(key: String): JsonElement? = sqlite("RECORD_READ") { db.prepareStatement("SELECT value,digest,value_encoding FROM records WHERE key=?").use {
        it.setString(1,key)
        it.executeQuery().use { rows -> if (!rows.next()) null else {
            val raw = readJson("record",key,rows.getString(1),rows.getString(3))
            requireJob(digest(raw) == rows.getString(2), "CORRUPT_RECORD")
            jobJson.parseToJsonElement(raw)
        } }
    } }
    @Synchronized fun keys(prefix: String): List<String> = db.prepareStatement("SELECT key FROM records ORDER BY key").use {
        it.executeQuery().use { rows -> buildList { while(rows.next()) rows.getString(1).takeIf { key -> key.startsWith(prefix) }?.let(::add) } }
    }
    @Synchronized fun containsRecord(key:String):Boolean = sqlite("RECORD_READ") {
        db.prepareStatement("SELECT 1 FROM records WHERE key=?").use { statement ->
            statement.setString(1,key);statement.executeQuery().use { it.next() }
        }
    }
    /** Verify an authenticated JSON-string page without joining/parsing its potentially huge body. */
    @Synchronized fun verifyJsonString(key:String,referenceDigest:String):JsonObject = sqlite("EVIDENCE_VERIFY") {
        db.prepareStatement("SELECT value,digest,value_encoding FROM records WHERE key=?").use { statement ->
            statement.setString(1,key)
            statement.executeQuery().use { row ->
                requireJob(row.next(),"MISSING_EVIDENCE")
                val expected=row.getString(2);val encoding=row.getString(3);val value=row.getString(1)
                val hash=java.security.MessageDigest.getInstance("SHA-256")
                var characters=0L;var bytes=0L;var first:Char?=null;var last:Char?=null
                fun part(text:String) {
                    if(first==null) first=text.firstOrNull()
                    last=text.lastOrNull() ?: last
                    characters+=text.length
                    val raw=text.toByteArray(Charsets.UTF_8);hash.update(raw);bytes+=raw.size
                }
                if(encoding=="JSON") part(value) else {
                    requireJob(encoding=="CHUNKED_JSON_V1","UNKNOWN_STORE_ENCODING")
                    val manifest=jobJson.parseToJsonElement(value).jsonObject
                    val count=manifest.getValue("parts").jsonPrimitive.int
                    requireJob(count>0,"CORRUPT_JSON_CHUNKS")
                    db.prepareStatement("SELECT part,value FROM json_chunks WHERE namespace='record' AND owner=? ORDER BY part").use { chunks ->
                        chunks.setString(1,key)
                        chunks.executeQuery().use { rows ->
                            var index=0
                            while(rows.next()) { requireJob(rows.getInt(1)==index++ && index<=count,"CORRUPT_JSON_CHUNKS");part(rows.getString(2)) }
                            requireJob(index==count && characters==manifest.getValue("characters").jsonPrimitive.long,"CORRUPT_JSON_CHUNKS")
                        }
                    }
                }
                val actual=hash.digest().joinToString("") { "%02x".format(it) }
                requireJob(actual==expected,"CORRUPT_RECORD")
                requireJob(actual==referenceDigest,"EVIDENCE_CHANGED")
                requireJob(first=='"' && last=='"',"EVIDENCE_STRING_PAGE_REQUIRED")
                buildJsonObject { put("digest",referenceDigest);put("verified",true);put("wireEvidenceIncluded",false);put("storedJsonUtf8Bytes",bytes) }
            }
        }
    }
    fun <T> once(id: String, input: String, decode: (JsonElement)->T, encode: (T)->JsonElement, action: ()->T): T {
        // Check before taking the effects monitor to avoid metadata-transaction/effect lock inversion.
        synchronized(this) { requireJob(db.autoCommit,"SIDE_EFFECT_INSIDE_METADATA_TRANSACTION") }
        return synchronized(effects) {
          synchronized(this) {
            requireJob(db.autoCommit,"SIDE_EFFECT_INSIDE_METADATA_TRANSACTION")
            db.prepareStatement("SELECT input,state,result,result_digest,result_encoding FROM operations WHERE id=?").use {
            it.setString(1,id)
            it.executeQuery().use { r -> if (r.next()) {
                requireJob(r.getString(1)==input, "OPERATION_ID_REUSED")
                requireJob(r.getString(2)=="COMMITTED", "OPERATION_OUTCOME_UNKNOWN")
                val raw=r.getString(3)?.let { readJson("operation",id,it,r.getString(5)) }
                requireJob(r.getString(4)!=null,"OPERATION_RESULT_UNVERIFIABLE")
                requireJob(raw!=null && digest(raw)==r.getString(4),"CORRUPT_OPERATION_RESULT")
                return decode(jobJson.parseToJsonElement(raw!!))
            } }
        }
            db.prepareStatement("INSERT INTO operations(id,input,state,result,result_digest) VALUES(?,?,'INTENT',NULL,NULL)").use { it.setString(1,id);it.setString(2,input);it.executeUpdate() }
          }
        // If action or commit throws, INTENT remains durable. The caller must reconcile, never retry sending.
        val result = action()
        val raw = encode(result).toString()
          synchronized(this) {
            sqlite("OPERATION_RESULT_WRITE") { transaction {
                val stored=storeJson("operation",id,raw)
                db.prepareStatement("UPDATE operations SET state='COMMITTED',result=?,result_digest=?,result_encoding=? WHERE id=?").use {
                    it.setString(1,stored.first);it.setString(2,digest(raw));it.setString(3,stored.second);it.setString(4,id);it.executeUpdate()
                }
            } }
          }
          result
        }
    }
    fun onceJson(id: String, input: String, action: ()->JsonElement): JsonElement = once(id,input,{it},{it},action)
    /** Read proof without replaying an action or changing an interrupted/legacy operation. */
    @Synchronized fun committedOnceResult(id:String,input:String):JsonElement? =
        db.prepareStatement("SELECT input,state,result,result_digest,result_encoding FROM operations WHERE id=?").use { statement ->
            statement.setString(1,id)
            statement.executeQuery().use { row ->
                if(!row.next()) null else {
                    requireJob(row.getString(1)==input,"OPERATION_ID_REUSED")
                    if(row.getString(2)!="COMMITTED") null else {
                        val raw=row.getString(3)?.let { readJson("operation",id,it,row.getString(5)) }
                        requireJob(row.getString(4)!=null,"OPERATION_RESULT_UNVERIFIABLE")
                        requireJob(raw!=null && digest(raw)==row.getString(4),"CORRUPT_OPERATION_RESULT")
                        jobJson.parseToJsonElement(raw!!)
                    }
                }
            }
        }
    // Bound each SQLite scalar independently of the size of a complete evidence document.
    // Explicit encoding keeps ordinary JSON (including marker-shaped user data) unambiguous.
    private fun storeJson(namespace:String,owner:String,raw:String):Pair<String,String> {
        db.prepareStatement("DELETE FROM json_chunks WHERE namespace=? AND owner=?").use {
            it.setString(1,namespace);it.setString(2,owner);it.executeUpdate()
        }
        if(raw.length<=INLINE_CHARACTERS) return raw to "JSON"
        var offset=0;var part=0
        db.prepareStatement("INSERT INTO json_chunks(namespace,owner,part,value) VALUES(?,?,?,?)").use { statement ->
            while(offset<raw.length) {
                var end=minOf(offset+CHUNK_CHARACTERS,raw.length)
                if(end<raw.length && raw[end-1].isHighSurrogate() && raw[end].isLowSurrogate()) end--
                statement.setString(1,namespace);statement.setString(2,owner);statement.setInt(3,part++)
                statement.setString(4,raw.substring(offset,end));statement.executeUpdate();offset=end
            }
        }
        return buildJsonObject { put("parts",part);put("characters",raw.length) }.toString() to "CHUNKED_JSON_V1"
    }
    private fun readJson(namespace:String,owner:String,value:String,encoding:String):String {
        if(encoding=="JSON") return value
        requireJob(encoding=="CHUNKED_JSON_V1","UNKNOWN_STORE_ENCODING")
        val manifest=jobJson.parseToJsonElement(value).jsonObject
        val parts=manifest.getValue("parts").jsonPrimitive.int
        val characters=manifest.getValue("characters").jsonPrimitive.int
        requireJob(parts>0 && characters>INLINE_CHARACTERS,"CORRUPT_JSON_CHUNKS")
        val raw=StringBuilder()
        db.prepareStatement("SELECT part,value FROM json_chunks WHERE namespace=? AND owner=? ORDER BY part").use { statement ->
            statement.setString(1,namespace);statement.setString(2,owner)
            statement.executeQuery().use { rows ->
                var part=0
                while(rows.next()) {
                    requireJob(rows.getInt(1)==part++ && part<=parts,"CORRUPT_JSON_CHUNKS")
                    raw.append(rows.getString(2))
                    requireJob(raw.length<=characters,"CORRUPT_JSON_CHUNKS")
                }
                requireJob(part==parts && raw.length==characters,"CORRUPT_JSON_CHUNKS")
            }
        }
        return raw.toString()
    }
    private inline fun <T> sqlite(stage:String,action:()->T):T = try { action() } catch(error:SQLException) {
        // SQL messages can contain request bodies, credentials or paths. Only numeric codes and fixed stages escape.
        throw JobRejected("STORE_SQLITE_FAILURE",sqliteFailureDetails(error,stage))
    }
    private companion object {
        const val INLINE_CHARACTERS=65536
        const val CHUNK_CHARACTERS=16384
    }
    override fun close() { synchronized(effects) { synchronized(this) { db.close(); lock.release(); channel.close() } } }
}

/** Safe diagnostics also apply to SQLite failures raised outside record writes. Never expose SQL messages. */
fun sqliteFailureDetails(error:SQLException,stage:String):Map<String,String> = mapOf(
    "stage" to stage,"sqliteCode" to error.errorCode.toString(),"sqlitePrimaryCode" to (error.errorCode and 255).toString())

/** Can be opened after a restart without any native Audit handle. Does not invent missing legacy indices. */
class SavedResults(private val store: JobStore) {
    fun issuePageMetadata(record:JsonObject,offset:Int):Sequence<JsonElement> {
        if(record["evidencePageFormat"]!=JsonPrimitive(EVIDENCE_PAGE_FORMAT)) return pages(record,"siteMapIssues",offset).map { value ->
            buildJsonObject { put("digest",fingerprint(value));put("verified",true);put("wireEvidenceIncluded",false) }
        }
        return (record["siteMapIssues"] as? JsonArray ?: JsonArray(emptyList())).asSequence().drop(offset).map { value ->
            val ref=value.jsonObject
            store.verifyJsonString(ref.getValue("key").jsonPrimitive.content,ref.getValue("digest").jsonPrimitive.content)
        }
    }
    fun resolvePage(ref:JsonObject):JsonElement {
        val key=ref["key"]?.jsonPrimitive?.content ?: throw JobRejected("MISSING_EVIDENCE_REFERENCE")
        val value=store.get(key) ?: throw JobRejected("MISSING_EVIDENCE")
        requireJob(fingerprint(value)==ref["digest"]?.jsonPrimitive?.content,"EVIDENCE_CHANGED")
        return value
    }
    fun read(executionId: String): JsonObject {
        val collections=store.keys("evidence-collection:$executionId:").map { store.get(it)!! }
        val index = store.get("result-index:$executionId")?.jsonArray ?: if(collections.isNotEmpty()) JsonArray(emptyList()) else throw JobRejected("RESULTS_NOT_COMMITTED")
        return buildJsonObject {
            put("execution", store.get("execution:$executionId") ?: throw JobRejected("MISSING_EXECUTION"))
            put("diagnosisCompleted", false)
            put("collections",JsonArray(collections))
            put("records", JsonArray(index.map { ref ->
                val r = ref.jsonObject
                val value = store.get(r["key"]!!.jsonPrimitive.content) ?: throw JobRejected("MISSING_EVIDENCE")
                requireJob(fingerprint(value)==r["digest"]!!.jsonPrimitive.content,"EVIDENCE_CHANGED")
                value
            }))
        }
    }
}
