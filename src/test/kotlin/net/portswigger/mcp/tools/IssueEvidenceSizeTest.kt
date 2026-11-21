package net.portswigger.mcp.tools

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.*
import kotlinx.serialization.json.encodeToStream
import net.portswigger.diagnosis.contract.digest
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class IssueEvidenceSizeTest {
    @OptIn(ExperimentalSerializationApi::class)
    @Test fun streamingCounterMatchesFullJsonAndNestedStringIncludingEscapesAndUnicode() {
        val value=buildJsonObject { put("body",(0..127).map { it.toChar() }.joinToString("")+"日本🍍".repeat(10000)) }
        val counter=JsonSizeCounter()
        Json.encodeToStream(JsonElement.serializer(),value,counter)
        assertEquals(value.toString().toByteArray().size.toLong(),counter.bytes)
        assertEquals(JsonPrimitive(value.toString()).toString().toByteArray().size.toLong(),counter.stringBytes)
        assertEquals(digest(value.toString()),counter.sha256())
    }
}
