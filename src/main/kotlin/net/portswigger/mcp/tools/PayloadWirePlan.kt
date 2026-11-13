package net.portswigger.mcp.tools

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.net.URLEncoder
import java.nio.charset.StandardCharsets.UTF_8
import java.security.MessageDigest

/** Byte offsets in an immutable request snapshot. JSON string ranges exclude the quotes. */
@Serializable
data class PayloadWirePosition(
    val id: String, val context: String, val valueStart: Int, val valueEnd: Int,
    val nameStart: Int? = null, val nameEnd: Int? = null,
    val target: String = "parameter"
)

@Serializable
data class PayloadWireCandidate(
    val payloadId: String, val positionId: String?, val mode: String,
    val state: String, val reason: String? = null,
    val missingBindings: List<String> = emptyList(),
    val replaceStart: Int? = null, val replaceEnd: Int? = null,
    val replacementBase64: String? = null
)

/** Every selected ID survives planning, even when no position or binding is available. */
internal class PayloadWirePlan private constructor(
    private val original: ByteArray,
    val sourceSha256: String,
    val candidates: List<PayloadWireCandidate>
) {
    val requestSha256: String = sha256(original)

    /** Rebuild from the baseline each time: attacks never accumulate across candidates.
     * Content-Length is deliberately left to the native HttpRequest normalization layer.
     */
    fun materialize(index: Int): ByteArray {
        val item = candidates[index]
        require(item.state == "READY") { "Candidate is not sendable: ${item.reason}" }
        val start = requireNotNull(item.replaceStart)
        val end = requireNotNull(item.replaceEnd)
        val replacement = java.util.Base64.getDecoder().decode(requireNotNull(item.replacementBase64))
        return original.copyOfRange(0, start) + replacement + original.copyOfRange(end, original.size)
    }

    companion object {
        fun create(
            request: ByteArray, catalog: PayloadProfileCatalog, tier: String,
            positions: List<PayloadWirePosition>, bindings: Map<String, String> = emptyMap(),
            modes: List<String> = PAYLOAD_MODES,
            deferredPayloads: Map<String, String> = emptyMap()
        ): PayloadWirePlan {
            val baseline = request.copyOf()
            require(positions.map { it.id }.distinct().size == positions.size) { "Duplicate position IDs" }
            positions.forEach { p ->
                require(p.id.isNotBlank() && p.context in PAYLOAD_CONTEXTS) { "Invalid position identity/context" }
                require(p.target in setOf("parameter", "method")) { "Invalid position target" }
                if (p.target == "method") {
                    require(p.context == "raw" && p.valueStart == 0 && p.valueEnd > 0 &&
                        p.valueEnd < baseline.size && baseline[p.valueEnd] == 32.toByte() &&
                        baseline.copyOfRange(0, p.valueEnd).toString(UTF_8).matches(Regex("[!#$%&'*+.^_`|~0-9A-Za-z-]+"))) {
                        "Method position must delimit the request-line method token"
                    }
                }
                require(p.valueStart >= 0 && p.valueEnd >= p.valueStart && p.valueEnd <= baseline.size) { "Invalid value byte range" }
                require((p.nameStart == null) == (p.nameEnd == null)) { "Incomplete name byte range" }
                if (p.nameStart != null && p.nameEnd != null) {
                    require(p.nameStart >= 0 && p.nameEnd > p.nameStart && p.nameEnd <= p.valueStart) { "Invalid name byte range" }
                }
                if (p.context == "json-string") {
                    require(p.valueStart > 0 && p.valueEnd < baseline.size &&
                        baseline[p.valueStart - 1] == '"'.code.toByte() && baseline[p.valueEnd] == '"'.code.toByte()) {
                        "JSON string offsets must exclude both quotes"
                    }
                    // Verify that offsets delimit a complete string, rather than an escaped inner quote.
                    Json.decodeFromString<String>(baseline.copyOfRange(p.valueStart - 1, p.valueEnd + 1).toString(UTF_8))
                }
            }
            val selected = catalog.select(tier, modes)
            require(deferredPayloads.keys.all { id -> selected.any { it.id == id } }) { "Deferred IDs must belong to the selected tier and modes" }
            require(deferredPayloads.values.all { it.isNotBlank() && it.length <= 500 }) { "Each deferred ID requires a nonblank reason of at most 500 characters" }
            val result = selected.flatMap { payload ->
                val binding = bindProfilePayload(payload, bindings)
                val deferred = deferredPayloads[payload.id]?.let { "USER_DEFERRED:$it" }
                if (positions.isEmpty()) listOf(PayloadWireCandidate(payload.id, null, payload.mode, "NOT_EXECUTABLE", deferred ?: "NO_POSITIONS"))
                else positions.map { p ->
                    fun blocked(reason: String, missing: List<String> = emptyList()) =
                        PayloadWireCandidate(payload.id, p.id, payload.mode, "NOT_EXECUTABLE", reason, missing)
                    when {
                        deferred != null -> blocked(deferred)
                        (payload.category == "METHOD") != (p.target == "method") -> blocked("CONTEXT_NOT_APPLICABLE")
                        p.context !in payload.contexts -> blocked("CONTEXT_NOT_APPLICABLE")
                        payload.mode == "array" && p.context !in setOf("query", "form") -> blocked("ARRAY_REQUIRES_QUERY_OR_FORM_NAME")
                        payload.mode == "array" && p.nameEnd == null -> blocked("NAME_RANGE_REQUIRED")
                        binding.raw == null -> blocked("UNBOUND_VARIABLES", binding.missingBindings)
                        else -> {
                            val raw = binding.raw
                            val encoded = when (p.context) {
                                "query", "form" -> URLEncoder.encode(raw, UTF_8).replace("+", "%20")
                                "json-string" -> Json.encodeToString(raw).let { it.substring(1, it.length - 1) }
                                else -> raw // Keep JSON numeric spellings and deliberate malformed input verbatim.
                            }.toByteArray(UTF_8)
                            val start = when (payload.mode) { "array" -> requireNotNull(p.nameEnd); "append" -> p.valueEnd; else -> p.valueStart }
                            val end = if (payload.mode == "replace") p.valueEnd else start
                            PayloadWireCandidate(payload.id, p.id, payload.mode, "READY", replaceStart = start,
                                replaceEnd = end, replacementBase64 = java.util.Base64.getEncoder().encodeToString(encoded))
                        }
                    }
                }
            }
            return PayloadWirePlan(baseline, catalog.workbookSha256, result)
        }
    }
}

internal fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes)
    .joinToString("") { "%02x".format(it.toInt() and 255) }
