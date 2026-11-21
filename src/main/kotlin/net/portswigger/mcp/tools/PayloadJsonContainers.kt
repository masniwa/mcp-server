package net.portswigger.mcp.tools

import kotlinx.serialization.json.Json

/** Explicit whole-container positions missed by native leaf-only JSON parameters.
 * Parse the immutable UTF-8 body and retain byte offsets; never search by value.
 */
internal fun resolvePayloadJsonContainers(bytes: ByteArray, pointers: List<String>, maxBodyBytes:Int=1024*1024): List<PayloadWirePosition> {
    if (pointers.isEmpty()) return emptyList()
    require(pointers.size <= 100 && pointers.distinct().size == pointers.size) { "Expected at most 100 distinct JSON container pointers" }
    val split = (0 until bytes.size - 3).firstOrNull { i ->
        bytes[i] == 13.toByte() && bytes[i + 1] == 10.toByte() && bytes[i + 2] == 13.toByte() && bytes[i + 3] == 10.toByte()
    } ?: error("HTTP body separator missing")
    val bodyStart = split + 4
    val body = bytes.copyOfRange(bodyStart, bytes.size)
    require(body.size <= maxBodyBytes) { "JSON container body exceeds configured byte limit" }
    val text = body.toString(Charsets.UTF_8)
    require(text.toByteArray(Charsets.UTF_8).contentEquals(body)) { "JSON body must be valid UTF-8" }
    val requested = pointers.map { pointer ->
        require(pointer.isEmpty() || pointer.startsWith('/')) { "JSON Pointer must be empty or start with /" }
        if (pointer.isEmpty()) emptyList() else pointer.substring(1).split('/').map { part ->
            require(!Regex("~(?![01])").containsMatchIn(part)) { "Invalid JSON Pointer escape" }
            part.replace("~1", "/").replace("~0", "~")
        }
    }
    val ranges = mutableMapOf<List<String>, Pair<Int, Int>>()
    var at = bodyStart
    fun whitespace() { while (at < bytes.size && bytes[at].toInt() in listOf(9, 10, 13, 32)) at++ }
    fun string(): String {
        val begin = at
        require(at < bytes.size && bytes[at] == 34.toByte()) { "Expected JSON string" }
        at++
        while (at < bytes.size) {
            val c = bytes[at++]
            require((c.toInt() and 0xff) >= 0x20) { "Unescaped control character in JSON string" }
            if (c == 92.toByte()) { require(at < bytes.size); at++ }
            else if (c == 34.toByte()) return Json.decodeFromString<String>(bytes.copyOfRange(begin, at).toString(Charsets.UTF_8))
        }
        error("Unterminated JSON string")
    }
    fun value(path: List<String>, depth: Int) {
        require(depth <= 128) { "JSON nesting exceeds 128" }
        whitespace()
        require(at < bytes.size) { "JSON value missing" }
        val begin = at
        val opening = bytes[at].toInt()
        when (opening) {
            123, 91 -> {
                at++
                whitespace()
                val closing = if (opening == 123) 125 else 93
                val keys = mutableSetOf<String>()
                var index = 0
                if (at < bytes.size && bytes[at].toInt() != closing) while (true) {
                    val key = if (opening == 123) {
                        val key = string()
                        require(keys.add(key)) { "Duplicate JSON object keys are ambiguous" }
                        whitespace()
                        require(at < bytes.size && bytes[at++].toInt() == 58) { "JSON colon missing" }
                        key
                    } else (index++).toString()
                    value(path + key, depth + 1)
                    whitespace()
                    if (at < bytes.size && bytes[at].toInt() == 44) { at++; whitespace() } else break
                }
                require(at < bytes.size && bytes[at++].toInt() == closing) { "JSON container ending missing" }
                if (path in requested) ranges[path] = begin to at
            }
            34 -> string()
            else -> { while (at < bytes.size && bytes[at].toInt() !in listOf(9, 10, 13, 32, 44, 93, 125)) at++ }
        }
    }
    value(emptyList(), 0)
    whitespace()
    require(at == bytes.size) { "Trailing JSON input" }
    validateNativeJsonValue(Json.parseToJsonElement(text))
    return requested.mapIndexed { index, path ->
        val range = ranges[path] ?: error("JSON Pointer does not identify an object or array")
        PayloadWirePosition("JSON_CONTAINER:$index:${range.first}:${range.second}", "json-value", range.first, range.second)
    }
}
