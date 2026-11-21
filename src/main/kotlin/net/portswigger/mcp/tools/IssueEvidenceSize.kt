package net.portswigger.mcp.tools

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.*
import kotlinx.serialization.json.encodeToStream
import net.portswigger.mcp.schema.IssueDetails
import java.io.OutputStream
import java.security.MessageDigest

/** Count the exact public JSON encoding without retaining a second full HTTP/JSON copy. */
internal class JsonSizeCounter : OutputStream() {
    var bytes = 0L; private set
    var stringBytes = 2L; private set
    private val hash = MessageDigest.getInstance("SHA-256")
    override fun write(value: Int) {
        count(value);hash.update(value.toByte())
    }
    private fun count(value:Int) {
        val b=value and 255
        bytes++
        stringBytes += when(b) { 34,92,8,9,10,12,13 -> 2; in 0..31 -> 6; else -> 1 }
    }
    override fun write(value: ByteArray, offset: Int, length: Int) {
        for(i in offset until offset+length) count(value[i].toInt())
        hash.update(value,offset,length)
    }
    fun sha256():String = hash.digest().joinToString("") { "%02x".format(it) }
}

@OptIn(ExperimentalSerializationApi::class)
internal fun issueEvidenceSize(issue:IssueDetails):String {
    val counter=JsonSizeCounter()
    Json.encodeToStream(IssueDetails.serializer(),issue,counter)
    return buildJsonObject {
        put("name",issue.name);put("severity",issue.severity.name)
        put("requestResponseCount",issue.requestResponses.size)
        put("fullIssueJsonUtf8Bytes",counter.bytes)
        put("jsonStringUtf8Bytes",counter.stringBytes)
        put("fullIssueJsonSha256",counter.sha256())
        put("issueAttribution","SITE_MAP_NOT_AUDIT_SPECIFIC")
        put("wireEvidenceIncluded",false)
    }.toString()
}
