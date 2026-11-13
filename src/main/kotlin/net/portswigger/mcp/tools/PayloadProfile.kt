package net.portswigger.mcp.tools

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.util.regex.Pattern

/** Spreadsheet modes describe operations, not three copies of each payload. */
@Serializable
data class ProfilePayload(
    val id: String,
    val mode: String,
    val minimumTier: String,
    val raw: String,
    val contexts: List<String>,
    val category: String = "",
    val guidance: String = "",
    val caution: String = ""
)

@Serializable
data class PayloadProfileCatalog(
    val workbookSha256: String,
    val payloads: List<ProfilePayload>,
    val grep: List<ProfileGrep> = emptyList()
) {
    fun validate() {
        require(workbookSha256.matches(Regex("[0-9a-f]{64}"))) { "Expected the source workbook SHA-256" }
        require(payloads.isNotEmpty()) { "Payload catalog is empty" }
        require(payloads.map { it.id }.distinct().size == payloads.size) { "Duplicate payload IDs" }
        payloads.forEach {
            require(it.id.isNotBlank()) { "Blank payload ID" }
            require(it.mode in PAYLOAD_MODES) { "Unknown spreadsheet insertion mode: ${it.id}" }
            require(it.minimumTier in PAYLOAD_TIERS) { "Unknown spreadsheet tier: ${it.id}" }
            if (it.category == "METHOD") require(it.mode == "replace" && it.contexts == listOf("raw") &&
                it.raw.matches(Regex("[!#$%&'*+.^_`|~0-9A-Za-z-]+"))) { "Invalid METHOD payload: ${it.id}" }
            require(it.contexts.isNotEmpty() && it.contexts.distinct().size == it.contexts.size &&
                it.contexts.all { context -> context in PAYLOAD_CONTEXTS }) { "Invalid contexts: ${it.id}" }
        }
        require(grep.map { it.mode to it.name }.distinct().size == grep.size) { "Duplicate grep identity" }
        grep.forEach {
            require(it.mode in PAYLOAD_MODES && it.name.isNotBlank() && it.regex.isNotEmpty()) { "Invalid grep definition" }
            Pattern.compile(it.regex)
        }
    }

    /** No case/family filtering and no deduplication of equal values with distinct IDs. */
    fun select(tier: String, modes: List<String> = PAYLOAD_MODES): List<ProfilePayload> {
        validate()
        require(tier in PAYLOAD_TIERS) { "tier must be light, medium or hard" }
        require(modes.isNotEmpty() && modes.distinct().size == modes.size && modes.all { it in PAYLOAD_MODES }) {
            "modes must be a nonempty unique selection of append, replace and array"
        }
        return payloads.filter { it.mode in modes && PAYLOAD_TIERS.indexOf(it.minimumTier) <= PAYLOAD_TIERS.indexOf(tier) }
    }
}

@Serializable
data class ProfileGrep(val mode: String, val name: String, val regex: String)

/** Requires local source bytes, not merely a caller-provided digest string. */
internal fun loadPayloadProfile(catalogPath: Path?, workbookPath: Path): PayloadProfileCatalog {
    val bytes = Files.readAllBytes(workbookPath)
    if (catalogPath == null) return readPayloadWorkbook(bytes)
    val catalog = Json.decodeFromString<PayloadProfileCatalog>(Files.readString(catalogPath))
    catalog.validate()
    val actual = MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { "%02x".format(it.toInt() and 255) }
    require(actual == catalog.workbookSha256) { "Workbook changed; regenerate the payload catalog before scanning" }
    require(readPayloadWorkbook(bytes) == catalog) { "Catalog differs from the source workbook; regenerate before scanning" }
    return catalog
}

internal val PAYLOAD_TIERS = listOf("light", "medium", "hard")
internal val PAYLOAD_MODES = listOf("append", "replace", "array")
internal val PAYLOAD_CONTEXTS = setOf("query", "form", "json-string", "json-value", "raw")
private val bindingToken = Regex("__[A-Z][A-Z0-9_]*__")

@Serializable
data class PayloadBindingResult(val payloadId: String, val raw: String?, val missingBindings: List<String>)

/** Single-pass literal substitution: a replacement is never evaluated as another template. */
internal fun bindProfilePayload(payload: ProfilePayload, bindings: Map<String, String>): PayloadBindingResult {
    val tokens = bindingToken.findAll(payload.raw).map { it.value }.distinct().toList()
    val missing = tokens.filterNot { bindings.containsKey(it) }
    if (missing.isNotEmpty()) return PayloadBindingResult(payload.id, null, missing)
    return PayloadBindingResult(payload.id, bindingToken.replace(payload.raw) { bindings.getValue(it.value) }, emptyList())
}
