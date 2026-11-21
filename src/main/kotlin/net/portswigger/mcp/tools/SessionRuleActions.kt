package net.portswigger.mcp.tools

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import java.util.regex.Pattern

// >> 20261009 mniwa Build observed native validation and extension actions without sending traffic.
@Serializable
data class GenerateSessionValidationAction(
    val lookFor: String,
    val validationAction: String = "run_macro",
    val validationMacroSerialNumber: Long? = null,
    val recoveryMacroSerialNumber: Long? = null,
    val matchType: String = "literal",
    val matchIndicates: String = "valid",
    val inspectResponseBody: Boolean = true,
    val inspectHttpHeaders: Boolean = false,
    val inspectRedirectionUrl: Boolean = false,
    val caseSensitive: Boolean = false,
    val stopIfValid: Boolean = false,
    val validateEveryNumRequests: Boolean = false,
    val requestCount: Int = 1,
    val recoveryParameterNames: List<String> = emptyList(),
    val recoveryUpdateCookies: Boolean = true,
    val currentRequestIsSafeAndRepeatable: Boolean = false
)
@Serializable
data class GenerateInvokeExtensionAction(val actionName: String)

internal fun GenerateSessionValidationAction.toAction(): JsonObject {
    require(lookFor.isNotBlank()) { "An observed validity expression is required" }
    require(validationAction in setOf("run_macro", "issue_current_request"))
    require(matchType in setOf("literal", "regex") && matchIndicates in setOf("valid", "invalid"))
    require(inspectResponseBody || inspectHttpHeaders || inspectRedirectionUrl)
    require(requestCount > 0)
    require(validationMacroSerialNumber == null || validationMacroSerialNumber > 0)
    require(recoveryMacroSerialNumber == null || recoveryMacroSerialNumber > 0)
    require(recoveryParameterNames.all { it.isNotBlank() } && recoveryParameterNames.distinct().size == recoveryParameterNames.size)
    if (matchType == "regex") Pattern.compile(lookFor)
    if (validationAction == "run_macro") {
        require(validationMacroSerialNumber != null) { "Validation requires an existing macro reference" }
    } else {
        require(currentRequestIsSafeAndRepeatable) { "Current-request validation requires a verified safe repeatable request" }
        require(validationMacroSerialNumber == null)
    }
    return buildJsonObject {
        put("type", "validate_session"); put("enabled", true)
        put("validation_action", validationAction)
        validationMacroSerialNumber?.let { put("macro_serial_number", it) }
        put("look_for", lookFor); put("match_type", matchType); put("match_indicates", matchIndicates)
        put("inspect_response_body", inspectResponseBody); put("inspect_http_headers", inspectHttpHeaders)
        put("inspect_redirection_url", inspectRedirectionUrl); put("case_sensitive", caseSensitive)
        put("validate_every_num_requests", validateEveryNumRequests); put("request_count", requestCount)
        put("stop_if_valid", validationAction == "issue_current_request" || stopIfValid)
        put("perform_action_if_invalid", recoveryMacroSerialNumber != null); put("action", "run_macro")
        putJsonObject("prompt_action") { put("match_cookies", "all_except") }
        putJsonObject("run_macro_action") {
            recoveryMacroSerialNumber?.let { put("macro_serial_number", it) }
            put("invoke_extension_action", false); put("match_cookies", "all_except")
            put("match_params", "specified")
            putJsonArray("specified_params") { recoveryParameterNames.forEach { add(it) } }
            put("tolerate_url_mismatch", false); put("update_with_cookies", recoveryUpdateCookies)
            put("update_with_params", recoveryParameterNames.isNotEmpty())
        }
    }
}
internal fun GenerateInvokeExtensionAction.toAction(): JsonObject {
    require(actionName.isNotBlank() && actionName == actionName.trim()) { "Use the exact registered action name" }
    return buildJsonObject { put("type", "invoke_extension"); put("enabled", true); put("action_name", actionName) }
}
// << mniwa
