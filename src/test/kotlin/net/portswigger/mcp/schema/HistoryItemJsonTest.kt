package net.portswigger.mcp.schema

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class HistoryItemJsonTest {
    @Test
    fun `small history items are unchanged`() {
        val item = HttpRequestResponse("request", "response", "notes")

        assertEquals(Json.encodeToString(item), encodeHistoryItem(item))
    }

    @Test
    fun `large history items preserve full messages in valid JSON`() {
        val original = HttpRequestResponse(
                request = "\\\"😀".repeat(2_000),
                response = "😀".repeat(3_000),
                notes = "keep me"
            )
        val encoded = encodeHistoryItem(original)
        val item = Json.parseToJsonElement(encoded).jsonObject

        assertTrue(encoded.length > 5_000)
        assertEquals(setOf("request", "response", "notes"), item.keys)
        assertEquals(original.request, item.getValue("request").jsonPrimitive.content)
        assertEquals(original.response, item.getValue("response").jsonPrimitive.content)
        assertEquals("keep me", item.getValue("notes").jsonPrimitive.content)
    }

    @Test
    fun `truncation does not split surrogate pairs`() {
        val encoded = encodeHistoryItem(HttpRequestResponse("a" + "😀".repeat(4_000), null, null))
        val request = Json.parseToJsonElement(encoded).jsonObject.getValue("request").jsonPrimitive.content

        assertFalse(request.codePoints().anyMatch { it in 0xD800..0xDFFF })
    }

    @Test
    fun `long notes are preserved`() {
        val notes = "a".repeat(6_000)
        val item = Json.parseToJsonElement(encodeHistoryItem(HttpRequestResponse("request", "response", notes))).jsonObject
        assertEquals(notes, item.getValue("notes").jsonPrimitive.content)
    }
}
