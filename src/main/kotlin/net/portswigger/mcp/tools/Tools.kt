//v0.9.3.0
package net.portswigger.mcp.tools
import burp.api.montoya.scanner.BuiltInAuditConfiguration
import burp.api.montoya.scanner.AuditConfiguration
import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.PAUSED
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.RUNNING
import burp.api.montoya.collaborator.InteractionFilter
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.encodeHistoryItem
import net.portswigger.mcp.schema.toSerializableForm
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import net.portswigger.mcp.security.HttpRequestSecurity
import net.portswigger.mcp.security.filterConfigCredentials
import java.awt.KeyboardFocusManager
import java.util.regex.Pattern
import javax.swing.JTextArea
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import java.net.HttpURLConnection
import java.net.URL
// >> 20261008 mniwa Retain active audit handles for read-only progress queries in the current server lifetime.
import burp.api.montoya.scanner.audit.Audit
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import kotlinx.serialization.json.JsonNull

internal class ActiveAuditRegistry {
    private data class Entry(val audit: Audit, val host: String, val port: Int, val protocol: String, val path: String)
    private val entries = ConcurrentHashMap<String, Entry>()

    fun register(audit: Audit, host: String, port: Int, protocol: String, path: String): String {
        val id = UUID.randomUUID().toString()
        entries[id] = Entry(audit, host, port, protocol, path)
        return id
    }

    fun snapshot(id: String): JsonObject? {
        val entry = entries[id] ?: return null
        val message = entry.audit.statusMessage()
        val normalized = message.trim().lowercase().removeSuffix(".")
        val complete = when (normalized) {
            "done", "finished", "complete", "completed" -> true
            "scanning", "auditing", "running", "paused", "queued", "waiting", "starting" -> false
            else -> null
        }
        val unsupportedMetrics = mutableListOf<String>()
        fun optionalMetric(name: String, read: () -> Int): JsonElement = try {
            JsonPrimitive(read())
        } catch (error: UnsupportedOperationException) {
            unsupportedMetrics.add(name)
            JsonNull
        }
        val errors = optionalMetric("auditErrorCount") { entry.audit.errorCount() }
        val issues = optionalMetric("auditIssueCount") { entry.audit.issues().size }
        return buildJsonObject {
            put("auditId", id)
            put("host", entry.host)
            put("port", entry.port)
            put("protocol", entry.protocol)
            put("path", entry.path)
            put("auditStatusMessage", message)
            put("completed", complete?.let(::JsonPrimitive) ?: JsonNull)
            put("auditRequestCount", entry.audit.requestCount())
            put("auditErrorCount", errors)
            put("auditInsertionPointCount", entry.audit.insertionPointCount())
            put("auditIssueCount", issues)
            put("unsupportedMetrics", buildJsonArray { unsupportedMetrics.forEach { add(it) } })
        }
    }

    fun snapshots(): JsonArray = buildJsonArray {
        entries.keys.sorted().forEach { id -> snapshot(id)?.let { add(it) } }
    }
}
// << mniwa

private suspend fun checkDataAccessOrDeny(
    accessType: DataAccessType, config: McpConfig, api: MontoyaApi, logMessage: String
): Boolean {
    val allowed = DataAccessSecurity.checkDataAccessPermission(accessType, config)
    if (!allowed) {
        api.logging().logToOutput("MCP $logMessage access denied")
        return false
    }
    api.logging().logToOutput("MCP $logMessage access granted")
    return true
}

private fun buildHttp2HeaderList(
    pseudoHeaders: Map<String, String>, headers: Map<String, String>
): List<HttpHeader> {
    val orderedPseudoHeaderNames = listOf(":scheme", ":method", ":path", ":authority")

    val fixedPseudoHeaders = LinkedHashMap<String, String>().apply {
        orderedPseudoHeaderNames.forEach { name ->
            val value = pseudoHeaders[name.removePrefix(":")] ?: pseudoHeaders[name]
            if (value != null) {
                put(name, value)
            }
        }

        pseudoHeaders.forEach { (key, value) ->
            val properKey = if (key.startsWith(":")) key else ":$key"
            if (!containsKey(properKey)) {
                put(properKey, value)
            }
        }
    }

    return (fixedPseudoHeaders + headers).map { HttpHeader.httpHeader(it.key.lowercase(), it.value) }
}

/**
 * Normalizes HTTP request line endings from MCP clients.
 *
 * MCP clients (e.g. Claude Code) often emit `\r\n` as the 4-character literal
 * sequence backslash-r-backslash-n in JSON tool parameters rather than actual
 * CR (0x0D) + LF (0x0A) bytes. The resulting text parses as a single line,
 * which strict servers (e.g. Apache-Coyote) reject with 400 Bad Request and
 * which Burp/Montoya may "repair" by injecting headers after the body
 * separator.
 *
 * Normalization is applied only to the request prelude (request line and
 * headers, up to and including the first blank line). The body is preserved
 * verbatim so that legitimate escape sequences in bodies — e.g. `\n` inside a
 * JSON string literal — and binary payloads remain byte-exact. If no blank
 * line is present, the entire content is treated as prelude.
 */
internal fun normalizeHttpContent(content: String): String {
    val preludeEnd = findPreludeEnd(content) ?: return normalizePrelude(content)
    return normalizePrelude(content.substring(0, preludeEnd)) + content.substring(preludeEnd)
}

private fun validateRawHttpRequest(content: String) {
    val normalized = content.replace("\r\n", "\n").replace("\r", "\n")
    val lines = normalized.lines()
    val requestLine = lines.firstOrNull()?.trim().orEmpty()

    require(requestLine.isNotEmpty()) {
        "Invalid HTTP request: request line is missing."
    }
    require(Regex("^[A-Z]+\\s+\\S+\\s+HTTP/\\d\\.\\d$").matches(requestLine)) {
        "Invalid HTTP request: malformed request line."
    }
    require(normalized.contains("\n\n")) {
        "Invalid HTTP request: missing blank line between headers and body."
    }

    val headerPart = normalized.substringBefore("\n\n")
    val hasHostHeader = headerPart
        .lineSequence()
        .drop(1)
        .any { it.startsWith("Host:", ignoreCase = true) }

    require(hasHostHeader) {
        "Invalid HTTP request: Host header is missing."
    }
}


private val BLANK_LINE_MARKERS = listOf(
    "\r\n\r\n",         // actual CRLF blank line
    "\n\n",              // actual LF blank line
    "\\r\\n\\r\\n",     // literal CRLF blank line
    "\\n\\n",            // literal LF blank line
)

private fun findPreludeEnd(content: String): Int? {
    var bestStart = -1
    var bestLen = 0
    for (marker in BLANK_LINE_MARKERS) {
        val idx = content.indexOf(marker)
        if (idx >= 0 && (bestStart < 0 || idx < bestStart)) {
            bestStart = idx
            bestLen = marker.length
        }
    }
    return if (bestStart < 0) null else bestStart + bestLen
}

private fun normalizePrelude(prelude: String): String = prelude
    .replace("\\r\\n", "\n")   // Literal \r\n escape sequences → LF
    .replace("\\n", "\n")      // Remaining literal \n → LF
    .replace("\\r", "")        // Remaining literal \r → remove
    .replace("\r", "")          // Actual CR → remove
    .replace("\n", "\r\n")      // All LF → proper CRLF

// >> 20261009 mniwa Accept the extension-owned Logger recorder without registering duplicate HTTP handlers.
fun Server.registerTools(api: MontoyaApi, config: McpConfig, loggerHistory: LoggerHttpHistory = LoggerHttpHistory()) {
// << mniwa
    // >> 20261008 mniwa Scope audit tracking to this server registration rather than stale global extension state.
    val activeAudits = ActiveAuditRegistry()
    // << mniwa

    mcpTool<SendHttp1Request>("Issues an HTTP/1.1 request and returns the response.") {
        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, content, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/1.1 request: $targetHostname:$targetPort")

        val fixedContent = normalizeHttpContent(content)

        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        val response = api.http().sendRequest(request)

        response?.toString() ?: "<no response>"
    }

    mcpTool<SendHttp2Request>("Issues an HTTP/2 request and returns the response. Do NOT pass headers to the body parameter.") {
        val http2RequestDisplay = buildString {
            pseudoHeaders.forEach { (key, value) ->
                val headerName = if (key.startsWith(":")) key else ":$key"
                appendLine("$headerName: $value")
            }
            headers.forEach { (key, value) ->
                appendLine("$key: $value")
            }
            if (requestBody.isNotBlank()) {
                appendLine()
                append(requestBody)
            }
        }

        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, http2RequestDisplay, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/2 request: $targetHostname:$targetPort")

        val headerList = buildHttp2HeaderList(pseudoHeaders, headers)

        val request = HttpRequest.http2Request(toMontoyaService(), headerList, requestBody)
        val response = api.http().sendRequest(request, HttpMode.HTTP_2)

        response?.toString() ?: "<no response>"
    }

    mcpUnitTool<CreateRepeaterTab>("Creates an HTTP/1.1 Repeater tab with the specified raw HTTP request and optional tab name. Make sure to use carriage returns appropriately. Prefer create_repeater_tab_http2 for modern web targets that speak HTTP/2.") {
        val fixedContent = normalizeHttpContent(content)
        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        api.repeater().sendToRepeater(request, tabName)
    }

    mcpUnitTool<CreateRepeaterTabHttp2>("Creates an HTTP/2 Repeater tab with the specified HTTP/2 request and optional tab name. Use this by default for modern web targets. Do NOT pass headers to the body parameter.") {
        val headerList = buildHttp2HeaderList(pseudoHeaders, headers)
        val request = HttpRequest.http2Request(toMontoyaService(), headerList, requestBody)
        api.repeater().sendToRepeater(request, tabName)
    }

    mcpUnitTool<SendToIntruder>("Sends an HTTP request to Intruder with the specified HTTP request and optional tab name. Make sure to use carriage returns appropriately.") {
        val fixedContent = normalizeHttpContent(content)
        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        api.intruder().sendToIntruder(request, tabName)
    }

    mcpTool<UrlEncode>("URL encodes the input string") {
        api.utilities().urlUtils().encode(content)
    }

    mcpTool<UrlDecode>("URL decodes the input string") {
        api.utilities().urlUtils().decode(content)
    }

    mcpTool<Base64Encode>("Base64 encodes the input string") {
        api.utilities().base64Utils().encodeToString(content)
    }

    mcpTool<Base64Decode>("Base64 decodes the input string") {
        api.utilities().base64Utils().decode(content).toString()
    }

    mcpTool<GenerateRandomString>("Generates a random string of specified length and character set") {
        api.utilities().randomUtils().randomString(length, characterSet)
    }

    mcpTool(
        "output_project_options",
        "Outputs current project-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        val json = api.burpSuite().exportProjectOptionsAsJson()
        if (config.filterConfigCredentials) {
            filterConfigCredentials(json)
        } else {
            json
        }
    }

    mcpTool(
        "output_user_options",
        "Outputs current user-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        val json = api.burpSuite().exportUserOptionsAsJson()
        if (config.filterConfigCredentials) {
            filterConfigCredentials(json)
        } else {
            json
        }
    }

    val toolingDisabledMessage =
        "User has disabled configuration editing. They can enable it in the MCP tab in Burp by selecting 'Enable tools that can edit your config'"

    // >> 20261008 mniwa Describe authentication lockout preparation, prepared request scopes, and MCP configuration verification.
    // >> 20261009 mniwa Require verified login and logout stages instead of accepting invalid-credential responses alone.
    mcpTool<SetProjectOptions>(
        """Sets project-level configuration in JSON format. This tool applies the supplied JSON to Burp project options.

Always call output_project_options before changing anything, and use that export as the only source of truth for the current saved shape.
Use the top-level wrapper project_options for project-level JSON.
When writing sessions.macros.macros or sessions.session_handling_rules.rules, Burp replaces the entire array. You must preserve existing entries and send the full updated array. Do not send only the new entry.

Macro creation rules:
- Build macros only from actual Proxy HTTP History request/response pairs that already show the intended flow.
- You must not manually reconstruct requests when matching history entries already exist.
- You must write the macro JSON explicitly and completely in Burp's saved shape.
- You must not omit fields that Burp saves for the same shape.
- You must use the values observed in the selected history entries. You must not let example values in this description leak into the generated macro.

Macro object schema:
- project_options.sessions.macros.macros must be an array of macro objects.
- Each macro object must contain description, serial_number, and items.
- description: string. This is the macro name shown in Burp.
- serial_number: integer. This is the macro serial number stored by Burp.
- items: array. This is the ordered list of macro items executed by the macro.

Macro object field semantics and strict requirements:
- description: must be a string. This is the macro name shown in Burp.
- serial_number: must be an integer. This is the identifier Burp stores for the macro.
- items: must be an array. This is the ordered list of macro items executed by the macro.

Macro item schema:
Each macro item must explicitly contain all of the following fields:
- accept_response_cookies
- custom_parameters
- method
- request
- request_parameters
- response
- status_code
- url
- use_request_cookies

Macro item field semantics and strict requirements:
- accept_response_cookies: must be true. This controls whether the macro item accepts cookies from the response into the macro cookie state.
- custom_parameters: must be present. Use [] when the item does not extract any value. This is the list of values extracted from this item's response for later use.
- method: must be the exact observed HTTP method. This is the HTTP method of the observed request.
- request: must be the full observed raw HTTP request, including headers, CRLFs, and body. This is the source request saved in the macro item.
- request_parameters: must be present. Use [] when the item does not define parameter handling. This is the list of destination request parameters and how each one is handled.
- response: must be the full observed raw HTTP response, including headers, CRLFs, and body. This is the source response saved in the macro item.
- status_code: must be the observed numeric HTTP status code. This is the HTTP status code of the saved response.
- url: must be the exact observed absolute URL. This is the request URL of the macro item.
- use_request_cookies: must be true. This controls whether the macro item sends the current macro cookie state with the request.

custom_parameters schema:
- custom_parameters must be an array of extraction objects.
- Each extraction object must contain all of the following fields:
  - name
  - extract_mode
  - start_at_mode
  - start_after_expression
  - start_af_offset
  - end_mode
  - end_at_delimiter
  - end_at_fixed_length
  - exclude_http_headers
  - url_encoded

custom_parameters field semantics and strict requirements:
- name: must be a string and must exactly match the destination request parameter name that receives the extracted value later. This is the carry-forward key used to map the extracted value into a later request parameter. You must not invent aliases such as token2 or user_token2 unless the actual destination request parameter is literally named that way.
- extract_mode: must be "define_start_and_end". This selects extraction by specifying the exact text immediately before and immediately after the target value.
- start_at_mode: must be "after_expression". This starts extraction immediately after start_after_expression.
- start_after_expression: must be the exact text that appears immediately before the target value in the observed raw response. This is the left boundary of the extracted value.
- start_af_offset: must be an integer. This is Burp's saved start offset field for the extraction object.
- end_mode: must be "at_delimiter". This ends extraction immediately before end_at_delimiter.
- end_at_delimiter: must be the exact text that appears immediately after the target value in the observed raw response. This is the right boundary of the extracted value.
- end_at_fixed_length: must be an integer. This is Burp's saved fixed-length field for the extraction object.
- exclude_http_headers: must be false. This controls whether HTTP headers are excluded from the extraction search area.
- url_encoded: must be false. This controls whether the extracted value is treated as URL-encoded.

request_parameters schema:
- request_parameters must be an array of parameter objects for the actual parameters present in the destination request.
- Each parameter object must contain all of the following fields:
  - name
  - original_value
  - parameter_handling
  - preset_value
  - type
- Include prior_response_index only when the carried value must be taken from an earlier matching response that is not the nearest earlier matching response.

request_parameters field semantics and strict requirements:
- name: must be the exact destination request parameter name observed in the request. This is the actual parameter name sent by the destination request.
- original_value: must be the concrete value observed in the raw request. This is the observed literal value in the saved request.
- parameter_handling:
  - must be "preset_value" when the observed destination request sends a fixed literal value for that parameter. This means the parameter stays fixed and is not carried from an earlier response.
  - must be "derive_from_prior_response" when the observed destination request sends a value that was obtained from an earlier macro response. This means the parameter value is carried forward from a prior extraction.
- preset_value: must be the concrete value observed in the raw request. This is the saved literal value for the parameter.
- type:
  - must be "url" for parameters in the URL query string. This means the parameter is located in the request URL.
  - must be "body_url_encoded" for parameters in an application/x-www-form-urlencoded body. This means the parameter is located in the URL-encoded request body.
- prior_response_index: must be an integer when included. This selects which earlier macro response item's extracted value is used for this destination request parameter. Omit this field when the carried value comes from the first response item in the macro. Use 1 when the carried value comes from the second response item in the macro. Use 2 when the carried value comes from the third response item in the macro. In a two-item macro, omit this field.

History-based macro construction rules:
- If the observed destination request sends a literal fixed value for a parameter, parameter_handling must be preset_value for that parameter.
- If the observed destination request sends a value obtained from an earlier macro response, parameter_handling must be derive_from_prior_response for that parameter.
- You must decide this from the observed request/response flow in Proxy HTTP History.
- You must preserve all parameters that are actually sent in the destination request, not only the carried parameter.
- You must not convert a literal observed value into a carried parameter.
- You must not convert a carried parameter into a fixed literal parameter.
- You must not change a destination request parameter name.

Strict prohibitions:
- You must not shorten raw requests or raw responses.
- You must not omit custom_parameters or request_parameters. Use [] when empty.
- You must not drop existing macros or rules when writing back arrays.
- You must not invent session handling rule action field names unless this description explicitly defines them.

Session handling rule construction rules:
- Build session handling rules only from actual observed Proxy HTTP History workflows and actual saved macros.
- You must not manually reconstruct requests when matching history entries already exist.
- You must write the session handling rule JSON explicitly and completely in Burp's saved shape.
- You must not omit fields that Burp saves for the same shape.
- You must use the values observed in the selected history entries and selected saved macros.
- Saved shape may not exist. If a saved shape exists, use it as a reference only. When this description fixes a field name, type, or value, you must force that exact field name, type, or value in the emitted JSON.
- Session handling rules must be written only at project_options.sessions.session_handling_rules.rules.
- project_options.sessions.session_handling_rules.rules must be an array of rule objects.

Macro, CPH, and session handling rule usage split:
- Session handling rules decide when Burp executes pre-processing, stored-effect verification, and post-processing around one diagnostic target request.
- Macros are the default mechanism for replaying observed requests.
- Pre-processing must use a session handling rule action with type "run_macro".
- Stored-effect verification must use a session handling rule action with type "run_post_request_macro".
- Post-processing must use a session handling rule action with type "run_post_request_macro".
- Use macros by default.
- Use CPH together with macros, or instead of macros, when carry-forward is required in JSON body fields, HTTP headers, path parameters, or another location that macros cannot express correctly or reliably.
- If AI judges that macro-only construction is difficult or unreliable, use CPH.
- Do not use CPH when a normal macro-only configuration is sufficient.

CPH inside a session-handling macro:
- A macro request can contain CPH placeholders in its path, headers, or body. A session handling rule executes that macro; CPH processes its outgoing request. Macro-only parameter limitations are not a reason to abandon automation before considering this composition.
- Start from the full observed request. Preserve unrelated headers and body fields. As an explicit exception to preserving the observed request as-is, replace only the dynamic destination value with the literal placeholder configured in the selected CPH handler and add an X-cphtarget header containing that handler's exact trigger. Derive identifiers from the observed workflow and the value's purpose, not from examples. Save the corresponding placeholder URL in the macro item as well.
- Read existing CPH configuration with get_cph_config, generate and import the matching handler, and call get_cph_config again before enabling the rule. Compare enabled flags, placeholder, trigger, extraction mode, named capture, replacement backreference, source request, issuer, and tool scopes with the intended settings. Use this MCP readback for configuration inspection instead of launching Computer Use for a routine visual check. Enable the CPH tool scope that actually receives macro traffic and verify it in outgoing traffic; do not assume the invoking tool and macro traffic have the same tool flag.
- Normal form-body tokens may be acquired and carried by the macro while CPH supplies a path ID. Account for CPH's additional source request: if it invalidates an earlier token, obtain the token from that same CPH response using supported cached-response extraction, or use another observed sequence that keeps the token valid. Never assume extra GET requests leave token state unchanged.
- Inspect observed list/detail responses before declaring an ID unavailable. Separately report value discovery, target selection, and dynamic insertion. Establish the ID-selection contract from history: a last-record regex selects the last record, not a registration-specific difference. Use it only when the observed ordering and isolated, sequential workflow justify that contract; handle empty lists, failed creates, and concurrent creates explicitly.
- For a create or update target needing stored-effect verification, prepare one reflection scan and a separate scan for every distinct observed verification request. Reflection returns the diagnostic target's own response; do not replace it with a verification response. Each stored-effect scan puts any required previous-run cleanup in pre-processing, acquires authentication or fresh tokens only when observed dependencies require them, sends the diagnostic target, and returns only that run's selected verification response. Do not append cleanup after verification. Preserve existing macros and unrelated rules.
- If there are N stored-effect verification requests, prepare N+1 scan configurations: one reflection run and N individual stored-effect runs. Do not substitute one macro returning its last response for individual scans of all confirmation requests. Preparation requests authorize configuration and benign verification, not starting Active Scans.
- Verify saved configuration and execute representative benign requests through Repeater/session handling, inspecting actual outgoing macro requests, substituted IDs/tokens, cleanup results, and the response returned for each scan configuration. A successful configuration import alone is not proof of working automation. If a runtime exception prevents replacement, identify the failing operation and verify it with a non-mutating probe before creating additional records. Report any workaround's prerequisites and unresolved faults.
- CPH settings may require several Send operations before they take effect. After configuration, repeat non-mutating or otherwise harmless probes and inspect actual outgoing substitution until it is stable; do not diagnose failure from the first Send alone or use repeated registrations as initialization probes. Distinguish delayed activation from a reproducible runtime exception or configuration mismatch, and report any remaining failure explicitly.
- After creating or changing macro, session handling rule, or CPH settings, perform at least five test sends per applicable workflow configuration through MCP HTTP request tools and check actual behavior on every run. Configuration readback is not a test send. Use harmless probes for CPH initialization and separately verify the complete workflow, response selection, and state restoration. Do not use Computer Use Send actions or start Active Scans for preparation-only requests.
- Imported single_response is only an observed sample, never evidence of a current ID. Verify that live extraction follows changing IDs. If the saved sample ID is used repeatedly, inspect CPH runtime/cache handling and the actually loaded CPH extension version before changing the selection regex or declaring the ID unavailable. Reloading the MCP JAR does not reload CPH Python code.
- Diagnose failures from the configuration you constructed and actual outgoing traffic. Check action order, macro references, parameter handling, pass-back, tool scopes, CPH trigger and placeholder before introducing a different extraction mode. Do not edit CPH source to work around an unproven configuration failure; use its existing supported capabilities.

History-based request role rules:
- Classify requests into exactly four roles: pre-processing, diagnostic target, stored-effect verification, and post-processing.
- All four roles must be assigned only from actual observed Proxy HTTP History.
- Diagnostic target means the attacked request sent by the invoking Burp feature.
- Pre-processing means requests required before the diagnostic target request is sent, including login, token acquisition, prerequisite registration, prerequisite data creation, and prerequisite cleanup.
- Stored-effect verification applies only when the diagnostic target creates or updates persisted content. Its purpose is to detect vulnerabilities that may manifest when a separate list, detail, page, or media response exposes attack strings, images, or other payloads saved by the diagnostic request.
- Do not add stored-effect verification for a diagnostic DELETE or other deletion operation. A GET used to check deletion success, record absence, cleanup, or preservation of existing data is a workflow validation request, not a stored-effect scan target. Do not create a separate final_response scan configuration for that validation GET. Classification follows the diagnostic operation's observed semantics, not merely its HTTP method; a POST that deletes data is also excluded.
- For a registration, creation, or update target, inspect the observed subsequent list, detail, page, and media responses before deciding whether stored-effect verification is needed. Correlate the saved content with the diagnostic operation using observed IDs and submitted values; an unrelated read request or a repeated history entry is not a distinct verification target.
- A create or update response containing an ID or echoing submitted values does not eliminate independent stored-effect verification. If another observed response exposes the corresponding saved content, include that request as a stored-effect verification target even when the diagnostic response contains the same values. A read used for cleanup ID extraction is still a verification target when it also exposes content saved by the create or update target.
- For create or update targets, record every distinct observed verification request and why it qualifies. Select reflection-only preparation only after this inspection establishes that no independent saved-content confirmation response is available or the user explicitly limits the scope to reflection. Do not infer absence from the diagnostic response alone or from an empty list obtained after cleanup.
- Post-processing means a request sent after the diagnostic target request to remove created data or restore state.
- You must not manually reconstruct requests for any of these roles when matching history entries already exist.

Fixed diagnostic-target composition rules:
- For each scan run of one diagnostic target, use exactly one applicable active session handling rule that contains that run's required pre-processing, selected verification, and post-processing.
- Prepare separate saved configurations or mutually exclusive disabled rule variants for the reflection run and each stored-effect run. Do not enable multiple overlapping variants for the same diagnostic target at once.
- Wait for a run to finish before changing the shared rule configuration; a later run must not alter the response selection of an active run. Track the selected verification request and returned response separately for every run.
- If the history-based inspection establishes that only reflection verification is needed, do not add a stored-effect verification action. This exception must not suppress an observed independent stored-effect verification target.
- If both stored-effect verification and post-processing are needed, both actions must appear explicitly in the same rule in the observed workflow order.
- If the diagnostic target is a registration or creation request, you must not use the order diagnostic target -> stored-effect verification -> post-processing when that would make post-processing the terminal step of one macro session.
- In that case, you must use an order such as pre-processing cleanup -> diagnostic target create -> stored-effect verification so that stored-effect verification is the terminal step of the macro session.

Authentication-related diagnostic workflows:
- Treat successful prerequisite login -> prerequisite logout -> diagnostic login -> post-request logout as a required preparation gate for a login diagnostic target. A rule containing only successful prerequisite login is incomplete. Inspect the resulting macro items and rule actions, then verify the actual outgoing traffic for all four stages; do not assume that creating or naming a macro proves its execution.
- Do not infer that logout can be omitted because the API uses JWT/Bearer authentication, the diagnostic credentials are invalid, logout is absent from Proxy history, the target returns HTTP 401, or the audit has zero transport errors. Inspect existing project settings and history for the application's supported logout operation and its required authentication state. Do not invent a logout endpoint or substitute local deletion of a token/cookie for an unverified server logout. If the required logout cannot be identified, automated, or verified within the authorized scope, report the missing stage and do not start this login scan with a reduced workflow.
- Five repeated HTTP 401 responses from an invalid-credential diagnostic target are not sufficient preparation evidence. Each workflow test must establish successful prerequisite authentication, prerequisite logout, preservation of diagnostic credential payloads, and post-request logout of any session created by the diagnostic target, using the application's observed responses and authentication state. Retain evidence of each stage and confirm the test account remains usable; an absent session after a failed diagnostic login must be distinguished from successful cleanup of a newly authenticated session.
- When the diagnostic target is a login request, repeated attack strings in password, user ID, email, or other credential fields can accumulate failed attempts and lock the account. Construct successful login with valid observed test credentials (pre-processing) -> logout (pre-processing) -> login with the diagnostic payload (diagnostic target) -> logout (post-processing). Use run_macro for the prerequisite login/logout and run_post_request_macro with pass_back current_response for cleanup so the scanner receives the diagnostic login response.
- Successful prerequisite authentication uses its own fixed, valid observed credentials. Do not copy the diagnostic payload into that prerequisite, and do not copy prerequisite credential values back into the diagnostic target. Limit target parameter updates to the exact observed token/state parameter names needed for the request. Verify the outgoing diagnostic password, user ID, email, and other tested fields retain their attack strings.
- Include the observed token acquisition and session-cookie transitions required by each login. After prerequisite logout, obtain fresh tokens and any new session state for the diagnostic login instead of reusing state from the completed successful login. If authentication rotates a session cookie, make the subsequent logout use the newly issued cookie. Verify response-cookie collection and macro cookie handling through actual outgoing traffic; use existing cookie jar and macro capabilities before considering CPH.
- Verify that prerequisite login actually succeeds, prerequisite logout leaves the required unauthenticated state, and post-processing logs out any session created by the diagnostic login. Run at least five MCP workflow tests after configuring the macros and rule, and check that repeated diagnostic attempts remain valid without lockout.
- The successful-login sequence is a lockout mitigation only when the application's observed behavior confirms that successful authentication resets or otherwise recovers the relevant failed-attempt state. It is not a universal account unlock. Account-, IP-, device-, time-window-, or shared throttling may persist across login/logout. If prerequisite authentication fails or lockout/throttling is observed, do not continue invalid-credential attempts and label the scan normal; report the blocked state and the unmet prerequisite.
- For other authentication-related targets, establish the authentication state required by that observed operation. A logout target requiring an authenticated session must follow successful prerequisite login; do not log out before the diagnostic logout and thereby invalidate its prerequisite.

Fixed pass-back rules:
- For reflection verification scans, the run_post_request_macro action pass_back must be "current_response".
- For stored-effect verification scans, the run_post_request_macro action pass_back must be "final_response".
- For post-processing actions, the run_post_request_macro action pass_back must be "current_response".

Session handling rule object schema:
- Each rule object must explicitly contain all of the following fields:
  - actions
  - description
  - enabled
  - exclude_from_scope
  - include_in_scope
  - named_params
  - restrict_scope_to_named_params
  - tools_scope
  - url_scope
  - url_scope_advanced_mode

Session handling rule field semantics and strict requirements:
- actions: must be an array. Use [] when the rule has no actions.
- description: must be a string. This is the session handling rule name shown in Burp.
- enabled: must be true unless the user explicitly requests a disabled rule.
- exclude_from_scope: must be present. Use [] when there are no excluded URL scope entries.
- include_in_scope: must be an array of scope entries. Use [] only when the intended rule truly has no included scope entries.
- named_params: must be present. Use [] when there are no named parameter restrictions.
- restrict_scope_to_named_params: must be false.
- tools_scope: must be an array. Allowed values are "Target", "Scanner", "Intruder", "Repeater", "Extensions", and "Sequencer". Include only observed saved values required for the intended rule. Do not invent tool names.
- url_scope: must be "custom".
- url_scope_advanced_mode: must be false.

include_in_scope schema:
- include_in_scope must be an array of scope objects.
- Each scope object must explicitly contain all of the following fields:
  - enabled
  - include_subdomains
  - prefix

include_in_scope field semantics and strict requirements:
- Derive the scope from the actual prepared diagnostic request before CPH substitution. If preparation replaces a dynamic path value with a placeholder, include that prepared placeholder URL; do not use only the obsolete history ID, a helper URL, or a broad parent API prefix merely because IDs change.
- Requests sent by MCP send_http1_request originate from Extensions; include Extensions in the tool scope of the rule being tested.
- Existing serial_number and macro_serial_number values can exceed the exact integer range of JavaScript Number. Use lossless JSON handling to preserve their exact integer tokens and types when writing complete arrays, and compare all preserved identifiers and references after readback. Do not round, renumber, or quote existing identifiers.
- Verify the prepared target's actual inclusion in at least five MCP workflow sends, with fresh prerequisite records, live path replacement, the diagnostic response, and state restoration. Standalone settings inspection does not prove scope applicability. Derive scope boundaries from the diagnostic operation and its dependencies; helper requests must not accidentally trigger the diagnostic workflow.
- enabled: must be true.
- include_subdomains: must be false.
- prefix: must be the exact absolute URL prefix for the diagnostic target request to which the rule applies.

Rule actions schema:
- actions must be an array of action objects.
- Use the run_macro action object shape for pre-processing.
- Use the run_post_request_macro action object shape for stored-effect verification.
- Use the run_post_request_macro action object shape for post-processing.

run_macro action schema:
Each run_macro action object must explicitly contain all of the following fields:
- enabled
- invoke_extension_action
- macro_serial_number
- match_cookies
- match_params
- specified_params
- tolerate_url_mismatch
- type
- update_with_cookies
- update_with_params

run_macro action field semantics and strict requirements:
- enabled: must be true unless the user explicitly requests a disabled action.
- invoke_extension_action: must be false.
- macro_serial_number: must be the integer serial_number of the selected macro in project_options.sessions.macros.macros.
- match_cookies: must be "all_except".
- match_params: must be "specified".
- specified_params: must be an array of the exact request parameter names that the macro is allowed to update in the diagnostic target request.
- tolerate_url_mismatch: must be false.
- type: must be "run_macro".
- update_with_cookies: must be true.
- update_with_params: must be true.

run_post_request_macro action schema:
Each run_post_request_macro action object must explicitly contain all of the following fields:
- enabled
- macro_serial_number
- match_params
- pass_back
- type
- update_with_params

run_post_request_macro action field semantics and strict requirements:
- enabled: must be true unless the user explicitly requests a disabled action.
- macro_serial_number: must be the integer serial_number of the selected macro in project_options.sessions.macros.macros.
- match_params: must be "all_except" for stored-effect verification and post-processing actions.
- pass_back:
  - must be "current_response" for reflection verification scans.
  - must be "final_response" for stored-effect verification scans.
  - must be "current_response" for post-processing actions.
- type: must be "run_post_request_macro".
- update_with_params: must be true.

Session handling rule construction requirements from observed workflow:
- A pre-processing action must reference a macro built from the observed pre-processing requests.
- A stored-effect verification action must reference a macro built from the observed stored-effect verification requests.
- A post-processing action must reference a macro built from the observed post-processing requests.
- You must not reference a missing macro.
- You must preserve every existing rule and send the full updated rules array when writing sessions.session_handling_rules.rules.
- You must preserve every existing macro referenced by rules when writing sessions.macros.macros.
- You must not drop unrelated rules.
- You must not invent alternative field names, alternative enum values, or alternative nested shapes for session handling rules.
- You must not output abstract guidance instead of concrete JSON-construction guidance.

Output requirements:
- Output only valid project options JSON.
- Use fixed values exactly where required above.
        """
        // << mniwa
    ) {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting project-level configuration: $json")
            api.burpSuite().importProjectOptionsFromJson(json)

            "Project configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }


    // << mniwa
    mcpTool<SetUserOptions>("Sets user-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'project_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting user-level configuration: $json")
            api.burpSuite().importUserOptionsFromJson(json)

            "User configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }

    if (api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL) {
        mcpPaginatedTool<GetScannerIssues>("Displays information about issues identified by the scanner") {
            api.siteMap().issues().asSequence().map { Json.encodeToString(it.toSerializableForm()) }
        }

        // 20260925 mniwa >> Add a tool that starts an ActiveScan for a raw HTTP request.
        // >> 20261008 mniwa Return a stable audit identifier and expose read-only progress without computer use.
        // >> 20261009 mniwa Require separate audit completion and post-scan functional replay checks with observable workflow evidence.
        // >> 20261009 mniwa Check complete authentication workflow evidence at the scan entry point before starting an audit.
        mcpTool<StartActiveScan>("Starts a Burp Suite active scan for the specified raw HTTP request. Returns auditId for get_active_scan_status. The scan uses the built-in legacy active audit checks; the optional config field is not applied. Before scanning a login diagnostic target, inspect the saved macros and applicable session handling rule and verify successful prerequisite login -> prerequisite logout -> diagnostic login -> post-request logout in actual outgoing traffic. Use valid observed test credentials only for prerequisite login; preserve attack strings in the diagnostic credential fields and pass back the diagnostic response with current_response. Confirm the rule applies to the target URL, Scanner, and diagnostic parameters, and complete at least five MCP workflow test sends verifying all four stages and subsequent account usability. A login-only prerequisite, repeated HTTP 401 responses, JWT/Bearer usage, an absent logout in Proxy history, or zero audit transport errors does not satisfy this gate. If supported logout or a required stage cannot be identified, automated, or verified, do not start this login scan; report the missing stage. Successful login/logout is not a universal counter reset or account unlock; if observed lockout/throttling persists or prerequisite authentication fails, do not continue invalid-credential attempts. For a logout diagnostic target, establish successful prerequisite login without logging out before that target. Before scanning, retain the original benign diagnostic request and its normal response under the intended macro/CPH/session-rule workflow. Keep those settings stable until this audit completes. After confirmed completion, check error/result information and resend the benign diagnostic request through that same intended workflow using an HTTP sender tool when authorized. Compare status and application/authentication/state results semantically; rotating IDs, tokens and timestamps need not be byte-identical. Inspect get_logger_http_history or its regex variant and capture status for actual macro/CPH sequence, substitutions, and cleanup. A successful resend confirms normal operation remains possible, not that every attack case was verified or no vulnerabilities exist. IDs are tracked only in the current MCP server lifetime; restarting or reloading the extension loses previous handles.") {
        // << mniwa
        // << mniwa
            // 20260925 mniwa >> Start an active scan by creating a built-in legacy active audit configuration,
            // converting the provided raw request into a Montoya HttpRequest, and adding it to the audit task.
            val usesHttps = protocol.equals("https", ignoreCase = true)

            val allowed = runBlocking {
                HttpRequestSecurity.checkHttpRequestPermission(host, port, config, request, api)
            }
            if (!allowed) {
                api.logging().logToOutput("MCP Active Scan denied: $host:$port")
                return@mcpTool "Start active scan denied by Burp Suite"
            }

            val fixedContent = normalizeHttpContent(request)
            validateRawHttpRequest(fixedContent)
            val service = HttpService.httpService(host, port, usesHttps)
            val httpRequest = HttpRequest.httpRequest(service, fixedContent)

            val auditConfiguration = AuditConfiguration.auditConfiguration(
                BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS
            )

            val audit = api.scanner().startAudit(auditConfiguration)
            audit.addRequest(httpRequest)
            val auditId = activeAudits.register(audit, host, port, protocol, fixedContent.lineSequence().first().split(' ').getOrElse(1) { "" })

            api.logging().logToOutput(
                "MCP Active Scan started: host=$host port=$port protocol=$protocol requestLength=${fixedContent.length}"
            )

            // << mniwa
            buildJsonObject {
                put("status", "started")
                put("auditId", auditId)
                put("host", host)
                put("port", port)
                put("protocol", protocol)
                put("requestLength", fixedContent.length)
                put("auditRequestCount", audit.requestCount())
                put("auditInsertionPointCount", audit.insertionPointCount())
                put("auditStatusMessage", audit.statusMessage())
            }.toString()
        }
        mcpTool<GetActiveScanStatus>("""Reads progress for Active Scans started by this MCP server without sending requests or changing scan state. Supply auditId returned by start_active_scan to read that audit, or omit it to list all tracked audits. Returns raw auditStatusMessage, request/error/insertion-point/issue counts, and completed. completed is true only for a recognized terminal success message, false for a recognized active/paused message, and null for an unrecognized message; do not treat null, a stable request count, or an empty list as completion. Optional counts unsupported by this Burp audit are null and named in unsupportedMetrics; null never means zero issues or errors. No progress percentage or ETA is provided. Unknown IDs return success=false with errorCode AUDIT_NOT_TRACKED; UI-started and pre-reload audits cannot be recovered by this tool. Poll with intervals rather than tight loops. Read the relevant audit's completed state before switching its session handling rules; use get_scanner_issues in bounded pages for issue details.""") {
            if (auditId == null) {
                buildJsonObject { put("success", true); put("audits", activeAudits.snapshots()) }.toString()
            } else {
                val snapshot = activeAudits.snapshot(auditId)
                if (snapshot == null) {
                    buildJsonObject {
                        put("success", false)
                        put("errorCode", "AUDIT_NOT_TRACKED")
                        put("auditId", auditId)
                        put("message", "Audit is not tracked by the current MCP server; reloads and UI-started audits have no retained handle.")
                    }.toString()
                } else {
                    buildJsonObject { put("success", true); put("audit", snapshot) }.toString()
                }
            }
        }
        // << mniwa
        // << mniwa


        val collaboratorClient by lazy { api.collaborator().createClient() }

        mcpTool<GenerateCollaboratorPayload>(
            "Generates a Burp Collaborator payload URL for out-of-band (OOB) testing. " +
            "Inject this payload into requests to detect server-side interactions (DNS lookups, HTTP requests, SMTP). " +
            "Use get_collaborator_interactions with the returned payloadId to check for interactions."
        ) {
            api.logging().logToOutput("MCP generating Collaborator payload${customData?.let { " with custom data" } ?: ""}")

            val payload = if (customData != null) {
                collaboratorClient.generatePayload(customData)
            } else {
                collaboratorClient.generatePayload()
            }

            val server = collaboratorClient.server()
            "Payload: $payload\nPayload ID: ${payload.id()}\nCollaborator server: ${server.address()}"
        }

        mcpTool<GetCollaboratorInteractions>(
            "Polls Burp Collaborator for out-of-band interactions (DNS, HTTP, SMTP). " +
            "Optionally filter by payloadId from generate_collaborator_payload. " +
            "Returns interaction details including type, timestamp, client IP, and protocol-specific data."
        ) {
            api.logging().logToOutput("MCP polling Collaborator interactions${payloadId?.let { " for payload: $it" } ?: ""}")

            val interactions = if (payloadId != null) {
                collaboratorClient.getInteractions(InteractionFilter.interactionIdFilter(payloadId))
            } else {
                collaboratorClient.getAllInteractions()
            }

            if (interactions.isEmpty()) {
                "No interactions detected"
            } else {
                interactions.joinToString("\n\n") {
                    Json.encodeToString(it.toSerializableForm())
                }
            }
        }
    }

    mcpPaginatedTool<GetProxyHttpHistory>("Displays items within the proxy HTTP history") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        api.proxy().history().asSequence().map { encodeHistoryItem(it.toSerializableForm()) }
    }

    mcpPaginatedTool<GetProxyHttpHistoryRegex>("Displays items matching a specified regex within the proxy HTTP history") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.proxy().history { it.contains(compiledRegex) }.asSequence()
            .map { encodeHistoryItem(it.toSerializableForm()) }
    }

    // >> 20261009 mniwa Expose correlated cross-tool traffic with history-style pagination and explicit capture limitations.
    mcpPaginatedTool<GetLoggerHttpHistory>("""Reads HTTP traffic observed by this MCP extension's HTTP handler across Proxy, Repeater, Scanner, Intruder, and Extensions, including macro and CPH traffic visible to that handler. This is MCP-captured traffic, not an export of the native Logger UI database: pre-load records and native Logger filters are not available. Supply count (1..100) and offset (non-negative); entries are ordered by monotonically increasing id, and offset applies to the current retained snapshot. Returns full raw request/response, id, captureId, messageId, tool, httpService, url, notes, requestTime, responseTime, requestObservation, and responseState. No response observed is not proof of a network failure; later reads may fill it in. Request-handler observations may precede other extensions' modifications; response entries use the response's initiatingRequest, so compare actual substitution rather than assuming registration order. Reads send no requests. Use get_logger_history_status before and after a verification window to detect reloads, capacity eviction, and capture errors; empty output or missing entries does not prove that no traffic occurred. Use small pages for large messages. Check macro order, current tokens/IDs, cleanup, and the actual diagnostic response separately; the invoking HTTP tool may return a macro-selected response different from the response recorded for the diagnostic wire request.""") {
        require(count in 1..100 && offset >= 0) { "count must be 1..100 and offset must be non-negative" }
        val allowed = runBlocking { checkDataAccessOrDeny(DataAccessType.LOGGER_HISTORY, config, api, "Logger HTTP history") }
        if (!allowed) return@mcpPaginatedTool sequenceOf("Logger HTTP history access denied by Burp Suite")
        loggerHistory.snapshot().asSequence().map { encodeHistoryItem(it) }
    }
    mcpPaginatedTool<GetLoggerHttpHistoryRegex>("""Reads the same MCP-captured cross-tool HTTP history as get_logger_http_history, filtered by a Java regular expression before applying offset/count. The regex is searched independently in raw request, raw response, tool name, and URL. count must be 1..100 and offset non-negative. Returns complete correlated entries, including pending responses; this is not native Logger UI history and cannot recover pre-load traffic. Invalid regex is an explicit tool error. Use get_logger_history_status to check captureId, droppedEntries, and captureErrors before interpreting an absent match. This read does not send HTTP requests or modify Logger filters, macros, CPH, or session handling rules.""") {
        require(count in 1..100 && offset >= 0) { "count must be 1..100 and offset must be non-negative" }
        val compiled = Pattern.compile(regex)
        val allowed = runBlocking { checkDataAccessOrDeny(DataAccessType.LOGGER_HISTORY, config, api, "Logger HTTP history") }
        if (!allowed) return@mcpPaginatedTool sequenceOf("Logger HTTP history access denied by Burp Suite")
        loggerHistory.snapshot(compiled).asSequence().map { encodeHistoryItem(it) }
    }
    mcpTool<GetLoggerHistoryStatus>("""Reads metadata for this MCP extension's cross-tool HTTP capture: captureId, source=MCP_HTTP_HANDLER, captureStartedAt, retainedEntries, firstRetainedId, latestId, droppedEntries, captureErrors, maxEntries, maxBytes, and retainedBytes. No traffic is sent. Capture persists across MCP server stop/start in the same extension manager, but extension reload changes captureId and loses history. Only the newest bounded entries are retained; oversized messages are omitted whole rather than truncated. Nonzero droppedEntries/captureErrors mean history may be incomplete. Native Logger UI entries or filters are not read. For post-scan validation, first confirm the specific audit's completion and retain its error/result information, then resend the original benign diagnostic request through its intended workflow using an HTTP sender tool. Compare the pre-scan and post-scan response semantically (status, application result, authentication/state and saved-effect response where applicable); expected rotating IDs, tokens, dates and timestamps need not be byte-identical. Check the Logger sequence and unresolved placeholders. A successful resend verifies that normal operation remains possible; it does not by itself prove audit completion, full scan coverage, cleanup of every effect, or absence of vulnerabilities.""") {
        Json.encodeToString(LoggerHistoryStatus.serializer(), loggerHistory.status())
    }
    // << mniwa

    mcpPaginatedTool<GetOrganizerItems>("Displays items within the Organizer tab") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.ORGANIZER, config, api, "Organizer")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("Organizer access denied by Burp Suite")
        }

        api.organizer().items().asSequence().map { encodeHistoryItem(it.toSerializableForm()) }
    }

    mcpPaginatedTool<GetOrganizerItemsRegex>("Displays items matching a specified regex within the Organizer tab") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.ORGANIZER, config, api, "Organizer")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("Organizer access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.organizer().items { it.contains(compiledRegex) }.asSequence()
            .map { encodeHistoryItem(it.toSerializableForm()) }
    }

    mcpPaginatedTool<GetProxyWebsocketHistory>("Displays items within the proxy WebSocket history") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")
        }

        api.proxy().webSocketHistory().asSequence()
            .map { encodeHistoryItem(it.toSerializableForm()) }
    }

    mcpPaginatedTool<GetProxyWebsocketHistoryRegex>("Displays items matching a specified regex within the proxy WebSocket history") {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.proxy().webSocketHistory { it.contains(compiledRegex) }.asSequence()
            .map { encodeHistoryItem(it.toSerializableForm()) }
    }

    mcpTool<SetTaskExecutionEngineState>("Sets the state of Burp's task execution engine (paused or unpaused)") {
        api.burpSuite().taskExecutionEngine().state = if (running) RUNNING else PAUSED

        "Task execution engine is now ${if (running) "running" else "paused"}"
    }

    mcpTool<SetProxyInterceptState>("Enables or disables Burp Proxy Intercept") {
        if (intercepting) {
            api.proxy().enableIntercept()
        } else {
            api.proxy().disableIntercept()
        }

        "Intercept has been ${if (intercepting) "enabled" else "disabled"}"
    }

    mcpTool("get_active_editor_contents", "Outputs the contents of the user's active message editor") {
        getActiveEditor(api)?.text ?: "<No active editor>"
    }

    mcpTool<SetActiveEditorContents>("Sets the content of the user's active message editor") {
        val editor = getActiveEditor(api) ?: return@mcpTool "<No active editor>"

        if (!editor.isEditable) {
            return@mcpTool "<Current editor is not editable>"
        }

        editor.text = text

        "Editor text has been set"
    }

    // 20260918 mniwa >> Generates a Burp Custom Parameter Handler (CPH) import JSON payload based on user-supplied matching, replacement, and extraction settings.
    // >> 20261008 mniwa Generate CPH configuration for macro requests and supported cached extraction.
    mcpTool<GenerateCphImportConfig>(
    """
    Generate a Burp Custom Parameter Handler (CPH) import JSON object.

    This tool must output exactly one valid JSON object for Burp CPH import and nothing else.
    Do not output Markdown, comments, explanations, headings, or code fences.

    Field semantics and strict requirements:

    - auto_encode: must be false.
    - extract_choice_index: use 0 for single extraction; use 2 only when the supported cached mode is explicitly selected and its source is verified.
    - single_request: this is the HTTP request used as the source request for value extraction. When available, use the full raw HTTP request message from Proxy HTTP history, Logger, or another observed HTTP transaction source. Preserve the message as-is. Do not summarize it, paraphrase it, truncate it, or invent it. If unavailable, this field may be an empty string. When present, it should look like a real HTTP request beginning with a method such as GET, POST, PUT, DELETE, PATCH, HEAD, or OPTIONS.
    - enable_forwarder: must be false.
    - indices_choice_index: must be 0.
    - cached_expression: must be [true, ""].
    - Exception for extractMode="cached": cachedSelection must name an existing earlier CPH tab that captures the source transaction. singleExtractExpression supplies the named-group regex for cached_expression instead. This mode performs no additional source request. Read back the tab order and verify that the earlier tab has captured a fresh response before sending the destination.
    - enabled: must be true.
    - modify_type_choice_index: must be 0.
    - issuer: must be a three-element array in the form [isHttps, sourceHost, sourcePort]. Use false for HTTP and true for HTTPS. sourceHost must be the host name of the extraction source request. sourcePort must be the port number of the extraction source request.
    - single_expression: must be a two-element array in the form [true, extractRegex]. The first element must always be true because extraction uses regex. extractRegex must be a non-empty Python-style regular expression used to extract the reusable dynamic value from the source response, or when necessary from the source request. The regex must include a named capture group, such as (?P<uuid>...) or (?<uuid>...). The named capture group should represent the actual reusable value, such as a CSRF token, state value, nonce, session-related token, hidden field value, or another dynamic parameter that must be replayed.
    - macro_expression: must be [true, ""].
    - modify_expression: must be a two-element array in the form [false, triggerValue]. The first element must always be false because the trigger must be a fixed literal string, not a regex. triggerValue must be a fixed literal trigger string in the form cphtarget:xxx. The prefix cphtarget: is fixed and mandatory. Only the xxx portion should be chosen dynamically based on the purpose of the extraction or replacement flow. xxx must be a short identifier, not a sentence or explanation. Prefer letters, digits, underscore, and hyphen only. This field defines only the trigger condition. Do not use this field to describe a host, path, endpoint, request, response, extracted value, placeholder, or replacement text. When a request containing this trigger is about to be sent, the handler sends the source request first, extracts a value from the source response, and then replaces the placeholder in the destination request.
    - forwarder: must be [false, "host", 80].
    - single_response: this is the HTTP response used as the source response for value extraction. When available, use the full raw HTTP response message from Proxy HTTP history, Logger, or another observed HTTP transaction source. Preserve the message as-is. Do not summarize it, paraphrase it, truncate it, or invent it. If unavailable, this field may be an empty string. When present, it should look like a real HTTP response beginning with HTTP/1.0, HTTP/1.1, or HTTP/2.
    - dynamic_checkbox: must be true.
    - modify_scope_choice_index: must be 1.
    - match_expression: must be a two-element array in the form [false, matchValue]. The first element must always be false because matchValue must be a fixed literal placeholder, not a regex. matchValue must specify only the fixed placeholder or fixed text to be replaced in the destination request, and it must be in the form {{yyyyy}}. The outer {{ and }} are fixed and mandatory. Only the inner yyyyy portion should be chosen dynamically based on the name of the substituted value. yyyyy must be a short identifier, not a sentence or explanation. Prefer letters, digits, underscore, and hyphen only. Do not use this field to describe a host, path, endpoint, source request, source response, extraction regex, or trigger condition.
    - static_expression: must be a two-element array in the form [true, replacementValue]. The first element must always be true. replacementValue must reference the named capture group defined in single_expression by using a Python-style backreference such as \g<uuid>. It should normally be only that backreference and nothing more. The capture name inside \g<name> must match the named capture group defined in single_expression.
    - match_indices: must be "0".
    - cached_selection: must be an empty string.
    - Exception for extractMode="cached": cached_selection must be cachedSelection, the exact earlier source tab name. For a macro GET followed by a delete request, a source tab scoped to that observed GET can cache its response; a destination tab extracts the path ID from that cache while the macro carries the token from the same GET. This avoids relying on a separately fetched or saved sample response.
    - chkbox_repeater: must be true.
    - chkbox_scanner: must be true.
    - chkbox_extender: must be true.
    - chkbox_spider: must be false.
    - chkbox_intruder: must be true.
    - chkbox_sequencer: must be false.
    - chkbox_target: must be false.
    - verbosity: must be 3.
    - chkbox_proxy: must be false.

    Behavior summary:

    1. Use single_request and single_response as the source transaction for extraction.
    2. Use single_expression to extract a reusable dynamic value from single_response, or from single_request if truly necessary, by using a named capture group.
    3. Use modify_expression as a fixed literal trigger string in the form cphtarget:xxx that activates the handler.
    4. Use match_expression as a fixed literal placeholder in the form {{yyyyy}} inside the destination request.
    5. Use static_expression to replace that placeholder with the captured value from single_expression.

    Destination request requirements:

    - These requirements also apply to requests saved inside a Burp macro and sent by a session handling rule. CPH can replace a path placeholder there even though normal macro request_parameters cannot represent path parameters.
    - Start from the observed raw macro request and edit only the dynamic value into the placeholder and add its trigger header. Keep the rest of the observed transaction intact. Enable and verify the actual CPH tool scope for macro-generated traffic.
    - A single-mode handler sends its source request at execution time. Check whether that request changes a token used by the destination. Do not create competing token acquisition sequences or claim successful automation without checking real outgoing traffic.

    - For any destination request that will be sent from Repeater, Scanner, Intruder, or any other Burp feature, always include the literal placeholder specified by match_expression at the exact position where the extracted value must be inserted.
    - The destination request must also include an HTTP header in the following form:
      X-cphtarget: cphtarget:yyy
    - The header value must exactly match modify_expression[1].
    - Do not omit either the placeholder or the X-cphtarget header.
    - match_expression defines the replacement location in the destination request.
    - modify_expression defines the handler trigger and must be carried in the X-cphtarget header of the destination request.
    - If multiple CPH handlers must be triggered for the same destination request, include all trigger values in a single X-cphtarget header as a comma-separated list.
    - Derive each trigger identifier and placeholder identifier from the current observed workflow; do not reuse identifiers from unrelated examples.
    - Each comma-separated value must exactly match a configured modify_expression[1] value.
    - If multiple values are carried forward, the destination request should also contain all corresponding match_expression placeholders at their correct replacement locations.

    Consistency rules:

    - The named capture group defined in single_expression must match the capture name referenced by static_expression.
    - modify_expression must use the exact cphtarget: prefix.
    - match_expression must use the exact {{...}} placeholder style.
    - The X-cphtarget header value in the destination request must exactly match one or more configured modify_expression[1] values.
    - Each placeholder inserted into the destination request must exactly match a configured match_expression[1] value.

    Strict prohibitions:

    - Never generate modify_expression as a regex.
    - Never generate match_expression as a regex.
    - Never use modify_expression to describe a host, URL, path, endpoint, request, response, or extracted value.
    - Never use match_expression to describe a source request, source response, trigger, regex pattern, host, or endpoint.
    - Never put explanatory text into static_expression.
    - Never omit the named capture group from single_expression.
    - Never invent unsupported field meanings.
    - Never summarize, paraphrase, truncate, or invent single_request or single_response when the raw message is available.
    - Never omit the X-cphtarget header from a destination request that is intended to trigger a CPH handler.
    - Never omit the match_expression placeholder from a destination request that is intended to receive a carried-forward dynamic value.

    Output requirements:

    - Output only one valid JSON object for Burp CPH import.
    - Do not output Markdown.
    - Do not output explanations outside the JSON.
    - Use fixed values exactly where required above.
    """.trimIndent()
    ) {
        require(tabName.isNotBlank()) { "tabName must not be blank." }
        require(modifyScopeExpression.isNotBlank()) { "modifyScopeExpression must not be blank." }
        require(matchExpression.isNotBlank()) { "matchExpression must not be blank. It should identify the placeholder or target text to replace." }
        require(replacementExpression.isNotBlank()) { "replacementExpression must not be blank." }
        require(singleExtractExpression.isNotBlank()) { "singleExtractExpression must not be blank." }
        require(issuerHost.isNotBlank()) { "issuerHost must not be blank." }
        require(issuerPort in 1..65535) { "issuerPort must be between 1 and 65535." }
        if (replacementExpression.contains("\\g<")) {
            require(singleExtractExpression.contains("(?P<")) {
                "replacementExpression uses a named backreference, but singleExtractExpression does not contain a named capture group."
            }
        }

        fun modifyTypeIndex(value: String): Int = when (value.lowercase()) {
            "requests" -> 0
            "responses" -> 1
            "both", "requests_and_responses" -> 2
            else -> 0
        }

        fun extractChoiceIndex(value: String): Int = when (value.lowercase()) {
            "single" -> 0
            "macro" -> 1
            "cached" -> 2
            else -> 0
        }

        val root = buildJsonObject {
            putJsonObject(tabName) {
                put("auto_encode", false)
                put("extract_choice_index", extractChoiceIndex(extractMode))
                put("single_request", singleRequest)
                put("enable_forwarder", false)
                put("indices_choice_index", 0)

                putJsonArray("cached_expression") {
                    add(true)
                    add(if (extractMode.equals("cached", ignoreCase = true)) singleExtractExpression else "")
                }

                put("enabled", enabled)
                put("modify_type_choice_index", modifyTypeIndex(modifyType))

                putJsonArray("issuer") {
                    add(issuerHttps)
                    add(issuerHost)
                    add(issuerPort)
                }

                putJsonArray("single_expression") {
                    add(singleExtractExpressionIsRegex)
                    add(singleExtractExpression)
                }

                putJsonArray("macro_expression") {
                    add(true)
                    add("")
                }

                putJsonArray("modify_expression") {
                    add(modifyScopeExpressionIsRegex)
                    add(modifyScopeExpression)
                }

                putJsonArray("forwarder") {
                    add(false)
                    add("host")
                    add(80)
                }

                put("single_response", singleResponse)
                put("dynamic_checkbox", dynamic)
                put("modify_scope_choice_index", 1)

                putJsonArray("match_expression") {
                    add(matchExpressionIsRegex)
                    add(matchExpression)
                }

                putJsonArray("static_expression") {
                    add(replacementExpressionIsRegex)
                    add(replacementExpression)
                }

                put("match_indices", "0")

                if (cachedSelection == null) {
                    put("cached_selection", kotlinx.serialization.json.JsonNull)
                } else {
                    put("cached_selection", cachedSelection)
                }
            }

            if (includeOptions) {
                putJsonObject("a793ab8fcc2afce5e42b3044090719ddaff19741697d93b3b7f36838dd5e825c") {
                    put("chkbox_repeater", true)
                    put("chkbox_scanner", true)
                    put("chkbox_extender", true)
                    put("chkbox_spider", false)
                    put("chkbox_intruder", true)
                    put("chkbox_sequencer", false)
                    put("chkbox_target", false)
                    put("verbosity", 3)
                    put("chkbox_proxy", false)
                }
            }
        }

        Json { prettyPrint = true }.encodeToString(root)
    }

    // << mniwa
    // 20260918 mniwa >> Sends a generated CPH import JSON payload to the local CPH extension API and imports it in keep mode.
    // >> 20261008 mniwa Prefer MCP configuration readback and reserve UI import for demonstrated API failures.
    mcpTool<ImportCphConfig>(
        """Imports a Burp Custom Parameter Handler (CPH) config JSON into the local CPH extension via HTTP API in keep mode. Use the CPH API port, not the Burp proxy port. Defaults to 127.0.0.1:17866.
Check the returned success field, then call get_cph_config and compare the returned settings with the imported JSON, including enabled flags, trigger, placeholder, extraction mode, capture and backreference, source request, issuer, and tool scopes. Use MCP readback for routine configuration verification; do not launch Computer Use merely to inspect the CPH screen. Verify actual outgoing substitution separately through MCP HTTP request tools with at least five test sends per workflow configuration. Allow for delayed activation using harmless probes before concluding failure. If a reproducible API readback error or runtime failure demonstrates that MCP cannot complete the operation, first inspect the configuration and failure evidence; only then consider a UI fallback for the unsupported operation. Do not treat the possibility of an old instance mismatch as evidence of a current mismatch. Do not edit CPH files or change extraction strategy to work around an unproven mismatch."""
    ) {
        val url = URL("http://127.0.0.1:17866/cph/import")
        val conn = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            doOutput = true
            connectTimeout = 5000
            readTimeout = 30000
            setRequestProperty("Content-Type", "application/json; charset=utf-8")
        }

        try {
            conn.outputStream.use { os ->
                os.write(json.toByteArray(Charsets.UTF_8))
            }

            val status = conn.responseCode
            val stream = if (status in 200..299) conn.inputStream else conn.errorStream
            val body = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() } ?: ""

            if (status in 200..299) {
                """{"success":true,"status":$status,"body":${jsonEscape(body)}}"""
            } else {
                """{"success":false,"status":$status,"body":${jsonEscape(body)}}"""
            }
        } catch (e: Exception) {
            val msg = e.message ?: e.javaClass.simpleName
            """{"success":false,"status":0,"body":${jsonEscape(msg)}}"""
        } finally {
            conn.disconnect()
        }
    }

    // << mniwa
    // >> 20261008 mniwa Use CPH API exports for routine settings verification before considering computer use.
    mcpTool<GetCphConfig>(
        """Reads the current Burp Custom Parameter Handler (CPH) configuration from the local CPH API. Use the CPH API port, not the Burp proxy port. Defaults to 127.0.0.1:17866 when omitted.
Use this tool before modifying CPH settings and after import_cph_config to verify their reflection in the exported configuration. Check success and compare each relevant handler's enabled flag, extraction mode, source request, issuer, trigger, placeholder, capture/backreference, and global tool scopes with the intended settings. Prefer this MCP inspection to routine Computer Use screen checks. Readback verifies configuration; separately verify runtime substitution through MCP HTTP request tools with at least five test sends per configured workflow. An API or runtime failure needs concrete evidence before considering a UI fallback; do not assume instance mismatch solely because it occurred in a previous session."""
    ) {
        // 20260930 mniwa >> Default omitted CPH API connection values to 127.0.0.1:17866.
        val effectiveHost = host ?: "127.0.0.1"
        val effectivePort = port ?: 17866
        val url = URL("http://${effectiveHost}:${effectivePort}/cph/export")
        val conn = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 5000
            readTimeout = 30000
            setRequestProperty("Accept", "application/json")
        }

        try {
            val status = conn.responseCode
            val stream = if (status in 200..299) conn.inputStream else conn.errorStream
            val body = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() } ?: ""

            if (status in 200..299) {
                body
            } else {
                """{"success":false,"status":$status,"body":${jsonEscape(body)}}"""
            }
        } catch (e: Exception) {
            val msg = e.message ?: e.javaClass.simpleName
            """{"success":false,"status":0,"body":${jsonEscape(msg)}}"""
        } finally {
            conn.disconnect()
        }
        // << mniwa
    }

    // << mniwa
    mcpTool<GetSessionHandlingRules>(
        "Reads current Session Handling Rules from Burp project options."
    ) {
        val json = exportProjectOptionsJson(api, config)
        val rules = findSessionHandlingRules(json)
        Json { prettyPrint = true }.encodeToString(rules)
    }

    mcpTool<GetMacros>(
        "Reads current Macro definitions from Burp project options."
    ) {
        val json = exportProjectOptionsJson(api, config)
        val macros = findMacros(json)
        Json { prettyPrint = true }.encodeToString(macros)
    }

    mcpTool<GetMacroDetail>(
        "Reads a Macro definition by serial number or description from Burp project options."
    ) {
        val json = exportProjectOptionsJson(api, config)
        val macro = findMacroBySelector(json, macroSerialNumber, description)
            ?: return@mcpTool """{"success":false,"message":"Macro not found"}"""
        Json { prettyPrint = true }.encodeToString(macro)
    }

    // << mniwa

}



private fun exportProjectOptionsJson(api: MontoyaApi, config: McpConfig): String {
    val json = api.burpSuite().exportProjectOptionsAsJson()
    return if (config.filterConfigCredentials) filterConfigCredentials(json) else json
}

private fun parseJsonObjectOrNull(text: String): JsonObject? =
    try {
        Json.parseToJsonElement(text).jsonObject
    } catch (_: Exception) {
        null
    }

private fun findSessionHandlingRules(projectOptionsJson: String): JsonArray {
    // 20260930 mniwa >> Collect session handling rules from both nested and flat Burp project option paths safely.
    val root = parseJsonObjectOrNull(projectOptionsJson) ?: return JsonArray(emptyList())
    val result = mutableListOf<JsonElement>()
    val seen = linkedSetOf<String>()

    fun addRule(rule: JsonElement?) {
        val ruleObject = rule as? JsonObject ?: return
        val key = buildString {
            append(ruleObject["description"]?.jsonPrimitive?.content ?: "")
            append("|")
            append(ruleObject["enabled"]?.jsonPrimitive?.content ?: "")
            append("|")
            append(ruleObject["url_scope"]?.toString() ?: "")
            append("|")
            append(ruleObject["tools_scope"]?.toString() ?: "")
            append("|")
            append(ruleObject["rule_actions"]?.toString() ?: "")
        }
        if (seen.add(key)) {
            result.add(ruleObject)
        }
    }

    fun collectRules(element: JsonElement?) {
        when (element) {
            is JsonObject -> {
                element["session_handling_rules"]?.let { rulesElement ->
                    if (rulesElement is JsonArray) {
                        rulesElement.forEach { addRule(it) }
                    }
                }
                element["rules"]?.let { rulesElement ->
                    if (rulesElement is JsonArray) {
                        rulesElement.forEach { addRule(it) }
                    }
                }
                element.values.forEach { collectRules(it) }
            }
            is JsonArray -> element.forEach { collectRules(it) }
            else -> {}
        }
    }

    collectRules(root)
    return JsonArray(result)
    // << mniwa
}

private fun findMacros(projectOptionsJson: String): JsonArray {
    // 20260929 mniwa >> Collect macros from object-safe Burp project options paths and nested rule actions.
    val root = parseJsonObjectOrNull(projectOptionsJson) ?: return JsonArray(emptyList())
    val seen = linkedSetOf<String>()
    val result = mutableListOf<JsonElement>()

    fun addMacroIfPresent(element: JsonElement?) {
        val macro = element as? JsonObject ?: return
        val serial = macro["serial_number"]?.jsonPrimitive?.content
        val desc = macro["description"]?.jsonPrimitive?.content
        val key = listOfNotNull(serial, desc).joinToString("|")
        val looksLikeMacro =
            macro.containsKey("requests") ||
            macro.containsKey("items") ||
            macro.containsKey("request_list") ||
            macro.containsKey("macro_items")
        if (looksLikeMacro && key.isNotBlank() && seen.add(key)) {
            result += macro
        }
    }

    fun visit(element: JsonElement?) {
        when (element) {
            is JsonObject -> {
                addMacroIfPresent(element)
                element["macros"]?.let { macrosElement ->
                    if (macrosElement is JsonArray) {
                        macrosElement.forEach { addMacroIfPresent(it) }
                    }
                }
                element.values.forEach { visit(it) }
            }
            is JsonArray -> element.forEach { visit(it) }
            else -> {}
        }
    }

    visit(root)
    return JsonArray(result)
    // << mniwa
}

private fun findMacroBySelector(projectOptionsJson: String, macroSerialNumber: String?, description: String?): JsonObject? {
    // 20260929 mniwa >> Resolve a macro by serial number or description from collected macro objects.
    val macros = findMacros(projectOptionsJson)
    return macros.mapNotNull { it as? JsonObject }.firstOrNull { macro ->
        val serialMatches = macroSerialNumber != null &&
            macro["serial_number"]?.jsonPrimitive?.content == macroSerialNumber
        val descMatches = !description.isNullOrBlank() &&
            macro["description"]?.jsonPrimitive?.content == description
        serialMatches || descMatches
    }
    // << mniwa
}

// 20260918 mniwa >> Escapes a string so it can be embedded safely in a JSON string value.
private fun jsonEscape(value: String): String {
    val escaped = buildString {
        append('"')
        value.forEach { ch ->
            when (ch) {
                '\\' -> append("\\\\")
                '"' -> append("\\\"")
                '\b' -> append("\\b")
                '\u000C' -> append("\\f")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> {
                    if (ch.code < 0x20) {
                        append("\\u")
                        append(ch.code.toString(16).padStart(4, '0'))
                    } else {
                        append(ch)
                    }
                }
            }
        }
        append('"')
    }
    return escaped
}
// << mniwa

fun getActiveEditor(api: MontoyaApi): JTextArea? {
    val frame = api.userInterface().swingUtils().suiteFrame()

    val focusManager = KeyboardFocusManager.getCurrentKeyboardFocusManager()
    val permanentFocusOwner = focusManager.permanentFocusOwner

    val isInBurpWindow = generateSequence(permanentFocusOwner) { it.parent }.any { it == frame }

    return if (isInBurpWindow && permanentFocusOwner is JTextArea) {
        permanentFocusOwner
    } else {
        null
    }
}

interface HttpServiceParams {
    val targetHostname: String
    val targetPort: Int
    val usesHttps: Boolean

    fun toMontoyaService(): HttpService = HttpService.httpService(targetHostname, targetPort, usesHttps)
}

@Serializable
data class SendHttp1Request(
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendHttp2Request(
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class CreateRepeaterTab(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class CreateRepeaterTabHttp2(
    val tabName: String?,
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendToIntruder(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class UrlEncode(val content: String)

@Serializable
data class UrlDecode(val content: String)

@Serializable
data class Base64Encode(val content: String)

@Serializable
data class Base64Decode(val content: String)

@Serializable
data class GenerateRandomString(val length: Int, val characterSet: String)

@Serializable
data class SetProjectOptions(val json: String)

@Serializable
data class SetUserOptions(val json: String)

@Serializable
data class SetTaskExecutionEngineState(val running: Boolean)

@Serializable
data class SetProxyInterceptState(val intercepting: Boolean)

@Serializable
data class SetActiveEditorContents(val text: String)


// 20260925 mniwa >> Add input models for the ActiveScan execution tool.
@Serializable
data class ActiveScanConfig(
    val crawlAndAudit: Boolean? = null,
    val audit: Boolean? = null,
    val crawl: Boolean? = null
)

@Serializable
data class StartActiveScan(
    val request: String,
    val host: String,
    val port: Int,
    val protocol: String,
    val config: ActiveScanConfig? = null
)
// << mniwa

// >> 20261008 mniwa Allow querying one tracked audit or listing current-server audits with no arguments.
@Serializable
data class GetActiveScanStatus(val auditId: String? = null)
// << mniwa

@Serializable
data class GetScannerIssues(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistory(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistoryRegex(val regex: String, override val count: Int, override val offset: Int) : Paginated

// >> 20261009 mniwa Define minimal history-compatible parameters for Logger traffic and capture status queries.
@Serializable
data class GetLoggerHttpHistory(override val count: Int, override val offset: Int) : Paginated
@Serializable
data class GetLoggerHttpHistoryRegex(val regex: String, override val count: Int, override val offset: Int) : Paginated
@Serializable
class GetLoggerHistoryStatus
// << mniwa

@Serializable
data class GetOrganizerItems(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetOrganizerItemsRegex(val regex: String, override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyWebsocketHistory(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyWebsocketHistoryRegex(val regex: String, override val count: Int, override val offset: Int) :
    Paginated

@Serializable
data class GenerateCollaboratorPayload(
    val customData: String? = null
)

@Serializable
data class GetCollaboratorInteractions(
    val payloadId: String? = null
)


@Serializable
data class GetCphConfig(
    val host: String? = "127.0.0.1",
    val port: Int? = 17866
)

@Serializable
data class GetSessionHandlingRules(
    val includeRawProjectOptions: Boolean = false
)

@Serializable
data class GetMacros(
    val dummy: Boolean = false
)

@Serializable
data class GetMacroDetail(
    val macroSerialNumber: String? = null,
    val description: String? = null
)

@Serializable
data class GenerateCphImportConfig(
    val tabName: String,
    val enabled: Boolean = true,
    val modifyScopeExpression: String,
    val modifyScopeExpressionIsRegex: Boolean = false,
    val modifyType: String = "requests",
    val matchExpression: String,
    val matchExpressionIsRegex: Boolean = false,
    val replacementExpression: String,
    val replacementExpressionIsRegex: Boolean = true,
    val dynamic: Boolean = true,
    val extractMode: String = "single",
    val issuerHost: String,
    val issuerPort: Int,
    val issuerHttps: Boolean = false,
    val singleRequest: String = "",
    val singleResponse: String = "",
    val singleExtractExpression: String,
    val singleExtractExpressionIsRegex: Boolean = true,
    val cachedSelection: String? = null,
    val includeOptions: Boolean = true
)

// 20260918 mniwa >> Parameters for importing a CPH configuration JSON payload through the local API.
@Serializable
data class ImportCphConfig(val json: String)
// << mniwa
