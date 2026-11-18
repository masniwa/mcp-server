package net.portswigger.diagnosis.contract

import kotlinx.serialization.json.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*

class JsonWireTest {
    @Test fun `JSON values survive arbitrary byte chunk decoding with ASCII wire representation`() {
        val value=buildJsonObject {
            put("日本語🚀", "本文é\u0000\r\n\\u1234\"".repeat(2000))
            put("unpaired", "\ud800")
            putJsonArray("array") { add(42);add(true);add(JsonNull);add("🌍") }
        }
        val wire=asciiJson(value.toString())
        assertTrue(wire.all { it.code<128 })
        assertEquals(value,jobJson.parseToJsonElement(wire))
        val bytes=wire.toByteArray(Charsets.UTF_8)
        for(size in listOf(1,2,3,7,1023,4096,8191)) {
            val fragmented=bytes.asList().chunked(size).joinToString("") { it.toByteArray().toString(Charsets.UTF_8) }
            assertEquals(value,jobJson.parseToJsonElement(fragmented))
        }
        assertEquals(wire,asciiJson(wire))
    }
}
