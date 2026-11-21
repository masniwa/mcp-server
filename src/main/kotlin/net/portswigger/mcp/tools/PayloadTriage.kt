package net.portswigger.mcp.tools

import kotlinx.serialization.Serializable
import java.util.Base64

@Serializable
internal data class PayloadResponseMetrics(val responseBytes: Int, val bodyBytes: Int?, val bodySha256: String?)

@Serializable
internal data class PayloadTriage(
    val state: String,
    val signals: List<String>,
    val response: PayloadResponseMetrics?,
    val baselineResponse: PayloadResponseMetrics?,
    val baselineStatusCode: Int?,
    val baselineResponseSha256: String?,
    val limitations: List<String>
)

/** Bytes are the selected response, not necessarily the attacked exchange after session macros.
 * Body hashes compare captured entity bytes; do not silently decompress or normalize dynamic data.
 */
internal fun payloadResponseMetrics(bytes: ByteArray): PayloadResponseMetrics {
    val separator = (0..bytes.size - 4).firstOrNull { i ->
        bytes[i] == 13.toByte() && bytes[i + 1] == 10.toByte() &&
            bytes[i + 2] == 13.toByte() && bytes[i + 3] == 10.toByte()
    }
    val body = separator?.let { bytes.copyOfRange(it + 4, bytes.size) }
    return PayloadResponseMetrics(bytes.size, body?.size, body?.let(::sha256))
}

internal fun triagePayload(item: PayloadExecutionItem, evidence: PayloadEvidenceRecord?,
    baseline: PayloadBaselineRecord?, definitions: List<ProfileGrep>): PayloadTriage {
    val signals = mutableListOf<String>()
    val limitations = mutableListOf("NOT_A_VULNERABILITY_VERDICT", "REQUIRES_CONTROL_AND_REPRODUCTION")
    val response = evidence?.responseBase64?.let { Base64.getDecoder().decode(it) }
    val baseBytes = baseline?.responseBase64?.let { Base64.getDecoder().decode(it) }
    val metrics = response?.let(::payloadResponseMetrics)
    val baseMetrics = baseBytes?.let(::payloadResponseMetrics)
    val baseGrep = observePayloadGrep(definitions, item.mode, baseBytes)
    evidence?.grep?.filter { it.state == "MATCH" }?.forEach { match ->
        signals += if (baseGrep.any { it.name == match.name && it.state == "MATCH" })
            "GREP_MATCH_ALSO_IN_BASELINE" else "GREP_MATCH"
    }
    if (evidence?.grep?.any { it.state == "ERROR" || it.state == "NOT_EVALUATED" } == true)
        limitations += "GREP_EVALUATION_INCOMPLETE"
    if (item.statusCode in 500..599) signals += "HTTP_SERVER_ERROR"
    if (item.statusCode == 429) signals += "RATE_LIMIT_RESPONSE"
    if (item.state == "ERROR" || item.state == "NO_RESPONSE") signals += "TRANSPORT_OR_EVIDENCE_FAILURE"
    if (response != null && baseBytes != null) {
        limitations += "SCANNER_BASELINE_NOT_INDEPENDENTLY_VALIDATED"
        limitations += "DYNAMIC_CONTENT_OR_MACROS_CAN_CAUSE_DIFFERENCES"
        if (item.statusCode != baseline.statusCode) signals += "STATUS_CHANGED"
        if (metrics?.bodySha256 != null && baseMetrics?.bodySha256 != null && metrics.bodySha256 != baseMetrics.bodySha256)
            signals += "BODY_CHANGED"
        if (metrics?.bodyBytes != null && baseMetrics?.bodyBytes != null && metrics.bodyBytes != baseMetrics.bodyBytes)
            signals += "BODY_LENGTH_CHANGED"
    } else limitations += "BASELINE_COMPARISON_UNAVAILABLE"
    // No threshold inferred from unrelated payloads, and never call an adapter duration SQLi.
    limitations += "PAIRED_TIMING_CONTROLS_NOT_COLLECTED"
    if (item.sendCallElapsedNanos == null) limitations += "SEND_DURATION_UNAVAILABLE"
    if (response != null && metrics?.bodyBytes == null) limitations += "BODY_BOUNDARY_UNAVAILABLE"
    val state = when {
        item.state !in setOf("RESPONSE_RECEIVED", "NO_RESPONSE", "ERROR") -> "NOT_ASSESSED"
        signals.isNotEmpty() -> "REVIEW_REQUIRED"
        else -> "NO_SIGNAL_IN_AVAILABLE_OBSERVATIONS"
    }
    return PayloadTriage(state, signals.distinct(), metrics, baseMetrics, baseline?.statusCode,
        baseline?.responseSha256, limitations.distinct())
}
