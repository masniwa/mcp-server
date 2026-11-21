package net.portswigger.mcp.tools

import burp.api.montoya.core.Range
import burp.api.montoya.http.message.params.ParsedHttpParameter
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.scanner.audit.Audit
import kotlinx.serialization.Serializable

@Serializable
data class AuditParameterSelector(val name: String, val type: String)

/** Resolve native wire offsets; never search for a secret value or silently fall back to all points. */
internal fun selectAuditParameters(
    parameters: List<ParsedHttpParameter>, selectors: List<AuditParameterSelector>, requestLength: Int
): List<Range> {
    require(selectors.isNotEmpty() && selectors.size <= 128) { "insertionPointParameters must contain 1..128 selectors" }
    require(selectors.distinct().size == selectors.size) { "Duplicate insertionPointParameters selectors" }
    val selected = selectors.flatMap { selector ->
        require(selector.name.isNotBlank() && selector.type.isNotBlank()) { "Parameter name and type must be nonblank" }
        val matches = parameters.filter { it.name() == selector.name && it.type().name == selector.type }
        require(matches.isNotEmpty()) { "Selected parameter was not found; check its exact name and native type" }
        matches.map { it.valueOffsets() }
    }.sortedBy { it.startIndexInclusive() }
    selected.forEach {
        require(it.startIndexInclusive() >= 0 && it.endIndexExclusive() > it.startIndexInclusive() && it.endIndexExclusive() <= requestLength) {
            "Selected parameter has empty or invalid wire offsets"
        }
    }
    require(selected.zipWithNext().all { (a, b) -> a.endIndexExclusive() <= b.startIndexInclusive() }) { "Selected parameter ranges overlap" }
    return selected
}

internal fun addSelectedAuditRequest(audit: Audit, request: HttpRequest, offsets: List<Range>?) {
    if (offsets == null) audit.addRequest(request) else {
        require(offsets.isNotEmpty()) { "Explicit insertion point selection cannot be empty" }
        audit.addRequest(request, offsets)
    }
}
