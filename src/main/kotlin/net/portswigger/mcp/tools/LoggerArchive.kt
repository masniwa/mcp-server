package net.portswigger.mcp.tools

import kotlinx.serialization.json.Json
import net.portswigger.mcp.schema.HttpService
import java.nio.file.*
import java.nio.file.attribute.*
import java.sql.DriverManager
import java.util.regex.Pattern

/** Per-capture disk spool. Memory eviction never deletes committed wire evidence. */
internal class LoggerArchive(directory:Path,captureId:String):AutoCloseable {
    private val db:java.sql.Connection
    init {
        val path=directory.toAbsolutePath().normalize()
        Files.createDirectories(path)
        var parent:Path?=path
        while(parent!=null) { require(!Files.isSymbolicLink(parent) && !Files.readAttributes(parent,BasicFileAttributes::class.java,LinkOption.NOFOLLOW_LINKS).isOther) { "UNSAFE_LOGGER_ARCHIVE_PATH" };parent=parent.parent }
        val acl=Files.getFileAttributeView(path,AclFileAttributeView::class.java)
        if(acl!=null) acl.acl=listOf(AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPrincipal(Files.getOwner(path))
            .setPermissions(AclEntryPermission.entries.toSet()).setFlags(AclEntryFlag.DIRECTORY_INHERIT,AclEntryFlag.FILE_INHERIT).build())
        else Files.setPosixFilePermissions(path,PosixFilePermissions.fromString("rwx------"))
        Class.forName("org.sqlite.JDBC")
        db=DriverManager.getConnection("jdbc:sqlite:${path.resolve("$captureId.sqlite")}")
        db.createStatement().use {
            it.execute("PRAGMA journal_mode=WAL");it.execute("PRAGMA synchronous=FULL")
            it.execute("CREATE TABLE IF NOT EXISTS entries(id INTEGER PRIMARY KEY,message_id INTEGER NOT NULL,pending INTEGER NOT NULL,host TEXT NOT NULL,port INTEGER NOT NULL,secure INTEGER NOT NULL,tool TEXT NOT NULL,json TEXT NOT NULL,bytes INTEGER NOT NULL)")
            it.execute("CREATE INDEX IF NOT EXISTS logger_message ON entries(message_id)")
            it.execute("CREATE INDEX IF NOT EXISTS logger_pending ON entries(pending,message_id)")
        }
    }
    @Synchronized fun put(item:LoggerHistoryItem,size:Long) {
        db.prepareStatement("INSERT INTO entries VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET message_id=excluded.message_id,pending=excluded.pending,host=excluded.host,port=excluded.port,secure=excluded.secure,tool=excluded.tool,json=excluded.json,bytes=excluded.bytes").use {
            it.setLong(1,item.id);it.setInt(2,item.messageId);it.setInt(3,if(item.responseState=="NO_RESPONSE_OBSERVED") 1 else 0)
            it.setString(4,item.httpService.host.lowercase());it.setInt(5,item.httpService.port);it.setInt(6,if(item.httpService.secure) 1 else 0)
            it.setString(7,item.tool);it.setString(8,Json.encodeToString(LoggerHistoryItem.serializer(),item));it.setLong(9,size);it.executeUpdate()
        }
    }
    private fun item(raw:String)=Json.decodeFromString(LoggerHistoryItem.serializer(),raw)
    @Synchronized fun byId(id:Long):LoggerHistoryItem? = db.prepareStatement("SELECT json FROM entries WHERE id=?").use {
        it.setLong(1,id);it.executeQuery().use { r -> if(r.next()) item(r.getString(1)) else null }
    }
    @Synchronized fun byMessage(message:Int):List<LoggerHistoryItem> = db.prepareStatement("SELECT json FROM entries WHERE message_id=? ORDER BY id LIMIT 2").use {
        it.setInt(1,message);it.executeQuery().use { r -> buildList { while(r.next()) add(item(r.getString(1))) } }
    }
    @Synchronized fun pendingId(message:Int):Long? = db.prepareStatement("SELECT id FROM entries WHERE message_id=? AND pending=1 ORDER BY id DESC LIMIT 1").use {
        it.setInt(1,message);it.executeQuery().use { r -> if(r.next()) r.getLong(1) else null }
    }
    /** Read-only retained response gaps, independent of activity/quiescence decisions. */
    @Synchronized fun responseGaps(limit:Int):Pair<Long,List<LoggerHistoryItem>> {
        require(limit in 1..1000)
        val count=db.createStatement().use { statement -> statement.executeQuery("SELECT COUNT(*) FROM entries WHERE pending=1").use { rows -> rows.next();rows.getLong(1) } }
        val entries=db.prepareStatement("SELECT json FROM entries WHERE pending=1 ORDER BY id LIMIT ?").use { statement ->
            statement.setInt(1,limit);statement.executeQuery().use { rows -> buildList { while(rows.next()) add(item(rows.getString(1))) } }
        }
        return count to entries
    }
    @Synchronized fun quiescent(services:Set<HttpService>):Boolean = db.createStatement().use { query ->
        query.executeQuery("SELECT host,port,secure,json FROM entries WHERE pending=1 AND tool IN ('SCANNER','EXTENSIONS')").use { rows ->
            var quiet=true
            while(rows.next() && quiet) quiet=services.none { it.host.equals(rows.getString(1),true) && it.port==rows.getInt(2) && it.secure==(rows.getInt(3)==1) } ||
                item(rows.getString(4)).sendCompletionState=="SEND_RETURNED"
            quiet
        }
    }
    /** A new worker may ignore older unresolved rows only for explicitly unverified maintenance. */
    @Synchronized fun quiescentAfter(services:Set<HttpService>,afterId:Long):Boolean =
        db.prepareStatement("SELECT host,port,secure,json FROM entries WHERE pending=1 AND id>? AND tool IN ('SCANNER','EXTENSIONS')").use { query ->
            query.setLong(1,afterId)
            query.executeQuery().use { rows ->
                var quiet=true
                while(rows.next() && quiet) quiet=services.none {
                    it.host.equals(rows.getString(1),true) && it.port==rows.getInt(2) && it.secure==(rows.getInt(3)==1)
                } || item(rows.getString(4)).sendCompletionState=="SEND_RETURNED"
                quiet
            }
        }
    @Synchronized fun allQuiescent():Boolean = db.createStatement().use { query ->
        query.executeQuery("SELECT json FROM entries WHERE pending=1 AND tool IN ('SCANNER','EXTENSIONS')").use { rows ->
            var quiet=true
            while(rows.next() && quiet) quiet=item(rows.getString(1)).sendCompletionState=="SEND_RETURNED"
            quiet
        }
    }
    @Synchronized fun page(count:Int,offset:Int,afterId:Long,throughId:Long,regex:Pattern?=null):List<LoggerHistoryItem> {
        val search=regex?.let(::HistoryRegex)
        val suffix=if(search==null) " LIMIT ? OFFSET ?" else ""
        return db.prepareStatement("SELECT json FROM entries WHERE id>? AND id<=? ORDER BY id"+suffix).use {
            it.setLong(1,afterId);it.setLong(2,throughId)
            if(search==null) { it.setInt(3,count);it.setInt(4,offset) }
            it.executeQuery().use { rows -> buildList {
                var matched=0
                while(size<count && rows.next()) {
                    val value=item(rows.getString(1))
                    if(search==null || search.contains(value.request) || search.contains(value.response.orEmpty()) || search.contains(value.tool) || search.contains(value.url)) {
                        if(search==null || matched++>=offset) add(value)
                    }
                }
            } }
        }
    }
    @Synchronized fun stats():Triple<Int,Long?,Long> = db.createStatement().use {
        it.executeQuery("SELECT COUNT(*),MIN(id),COALESCE(SUM(bytes),0) FROM entries").use { rows ->
            rows.next();Triple(rows.getInt(1),rows.getLong(2).let { id -> if(rows.wasNull()) null else id },rows.getLong(3))
        }
    }
    @Synchronized override fun close() { db.close() }
}
