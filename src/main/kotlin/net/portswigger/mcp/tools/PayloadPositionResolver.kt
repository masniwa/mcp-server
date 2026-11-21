package net.portswigger.mcp.tools

import burp.api.montoya.http.message.params.ParsedHttpParameter
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.JsonElement

/** A method is a request-line token, never an arbitrary raw parameter value. */
internal fun resolvePayloadMethodPosition(requestBytes: ByteArray): PayloadWirePosition {
    val end = requestBytes.indexOf(32.toByte())
    require(end > 0 && requestBytes.copyOfRange(0, end).toString(Charsets.US_ASCII)
        .matches(Regex("[!#$%&'*+.^_`|~0-9A-Za-z-]+"))) { "Invalid request-line method token" }
    return PayloadWirePosition("METHOD:0:$end", "raw", 0, end, target = "method")
}

/** Resolve exact native ranges, never locate a parameter by searching for its value.
 * Names are omitted from the generated ID so credentials cannot leak through position labels.
 * Non-URL/form/JSON parameters are explicitly raw; only payloads declaring raw can use them.
 */
internal fun resolvePayloadPositions(
    requestBytes: ByteArray,
    parameters: List<ParsedHttpParameter>,
    selectors: List<AuditParameterSelector>?,
    isUrlEncodedForm: Boolean
): List<PayloadWirePosition> {
    if (selectors != null) {
        // Preserve the existing selector contract, including empty-value rejection.
        selectAuditParameters(parameters, selectors, requestBytes.size)
    }
    val chosen = parameters.withIndex().filter { (_, p) ->
        selectors == null || selectors.any { it.name == p.name() && it.type == p.type().name }
    }.sortedBy { it.value.valueOffsets().startIndexInclusive() }
    val resolved = chosen.map { (index, p) ->
        val range = p.valueOffsets()
        var start = range.startIndexInclusive()
        var end = range.endIndexExclusive()
        require(start >= 0 && end >= start && end <= requestBytes.size) { "Invalid native parameter range" }
        val type = p.type().name
        val context = when (type) {
            "URL" -> "query"
            "BODY" -> if (isUrlEncodedForm) "form" else "raw"
            "JSON" -> {
                val quotesIncluded = end - start >= 2 && requestBytes[start] == 34.toByte() && requestBytes[end - 1] == 34.toByte()
                val quotesOutside = start > 0 && end < requestBytes.size && requestBytes[start - 1] == 34.toByte() && requestBytes[end] == 34.toByte()
                when {
                    quotesIncluded -> { start++; end--; "json-string" }
                    quotesOutside -> "json-string"
                    else -> {
                        require(end > start) { "Empty JSON value range" }
                        validateNativeJsonValue(Json.parseToJsonElement(requestBytes.copyOfRange(start, end).toString(Charsets.UTF_8)))
                        "json-value"
                    }
                }
            }
            else -> "raw"
        }
        val name = if (context == "query" || context == "form") p.nameOffsets() else null
        PayloadWirePosition("$type:$index:${range.startIndexInclusive()}:${range.endIndexExclusive()}", context,
            start, end, name?.startIndexInclusive(), name?.endIndexExclusive())
    }
    require(resolved.zipWithNext().all { (a, b) -> a.valueEnd <= b.valueStart }) { "Overlapping native payload positions" }
    // Reuse all wire boundary and JSON-string validation before returning any position.
    val validationCatalog = PayloadProfileCatalog("0".repeat(64), listOf(ProfilePayload("validation", "replace", "light", "", PAYLOAD_CONTEXTS.toList())))
    PayloadWirePlan.create(requestBytes, validationCatalog, "light", resolved)
    return resolved
}

/** JsonElement parsing accepts bare tokens; do not mistake such tokens for valid numbers. */
internal fun validateNativeJsonValue(value: JsonElement) {
    when (value) {
        is JsonObject -> value.values.forEach(::validateNativeJsonValue)
        is JsonArray -> value.forEach(::validateNativeJsonValue)
        is JsonPrimitive -> require(value.isString || value.content in setOf("true", "false", "null") ||
            value.content.matches(Regex("-?(0|[1-9][0-9]*)(\\.[0-9]+)?([eE][+-]?[0-9]+)?"))) { "Malformed native JSON value" }
    }
}
