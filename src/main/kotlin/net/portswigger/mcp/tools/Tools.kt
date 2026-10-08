//v0.9.2.33
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

fun Server.registerTools(api: MontoyaApi, config: McpConfig) {

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

History-based request role rules:
- Classify requests into exactly four roles: pre-processing, diagnostic target, stored-effect verification, and post-processing.
- All four roles must be assigned only from actual observed Proxy HTTP History.
- Diagnostic target means the attacked request sent by the invoking Burp feature.
- Pre-processing means requests required before the diagnostic target request is sent, including login, token acquisition, prerequisite registration, prerequisite data creation, and prerequisite cleanup.
- Stored-effect verification means a request sent after the diagnostic target request to confirm that the supplied input or resulting effect appears in a response other than the diagnostic target response.
- Post-processing means a request sent after the diagnostic target request to remove created data or restore state.
- You must not manually reconstruct requests for any of these roles when matching history entries already exist.

Fixed diagnostic-target composition rules:
- For one diagnostic target request, create exactly one session handling rule.
- That one rule must contain the required pre-processing and, when needed, stored-effect verification and post-processing.
- You must not split one diagnostic target across multiple session handling rules.
- If only reflection verification is needed, do not add a stored-effect verification action.
- If both stored-effect verification and post-processing are needed, both actions must appear explicitly in the same rule in the observed workflow order.
- If the diagnostic target is a registration or creation request, you must not use the order diagnostic target -> stored-effect verification -> post-processing when that would make post-processing the terminal step of one macro session.
- In that case, you must use an order such as pre-processing cleanup -> diagnostic target create -> stored-effect verification so that stored-effect verification is the terminal step of the macro session.

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
    ) {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting project-level configuration: $json")
            api.burpSuite().importProjectOptionsFromJson(json)

            "Project configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }


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
        mcpTool<StartActiveScan>("Starts a Burp Suite active scan for the specified raw HTTP request.") {
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

            api.logging().logToOutput(
                "MCP Active Scan started: host=$host port=$port protocol=$protocol requestLength=${fixedContent.length}"
            )

            // << mniwa
            buildJsonObject {
                put("status", "started")
                put("host", host)
                put("port", port)
                put("protocol", protocol)
                put("requestLength", fixedContent.length)
                put("auditRequestCount", audit.requestCount())
                put("auditInsertionPointCount", audit.insertionPointCount())
                put("auditStatusMessage", audit.statusMessage())
            }.toString()
        }
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
    mcpTool<GenerateCphImportConfig>(
    """
    Generate a Burp Custom Parameter Handler (CPH) import JSON object.

    This tool must output exactly one valid JSON object for Burp CPH import and nothing else.
    Do not output Markdown, comments, explanations, headings, or code fences.

    Field semantics and strict requirements:

    - auto_encode: must be false.
    - extract_choice_index: must be 0.
    - single_request: this is the HTTP request used as the source request for value extraction. When available, use the full raw HTTP request message from Proxy HTTP history, Logger, or another observed HTTP transaction source. Preserve the message as-is. Do not summarize it, paraphrase it, truncate it, or invent it. If unavailable, this field may be an empty string. When present, it should look like a real HTTP request beginning with a method such as GET, POST, PUT, DELETE, PATCH, HEAD, or OPTIONS.
    - enable_forwarder: must be false.
    - indices_choice_index: must be 0.
    - cached_expression: must be [true, ""].
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

    - For any destination request that will be sent from Repeater, Scanner, Intruder, or any other Burp feature, always include the literal placeholder specified by match_expression at the exact position where the extracted value must be inserted.
    - The destination request must also include an HTTP header in the following form:
      X-cphtarget: cphtarget:yyy
    - The header value must exactly match modify_expression[1].
    - Do not omit either the placeholder or the X-cphtarget header.
    - match_expression defines the replacement location in the destination request.
    - modify_expression defines the handler trigger and must be carried in the X-cphtarget header of the destination request.
    - If multiple CPH handlers must be triggered for the same destination request, include all trigger values in a single X-cphtarget header as a comma-separated list.
    - Example:
      X-cphtarget: cphtarget:user_token,cphtarget:getid
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
                    add("")
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
                    put("chkbox_scanner", false)
                    put("chkbox_extender", true)
                    put("chkbox_spider", false)
                    put("chkbox_intruder", true)
                    put("chkbox_sequencer", false)
                    put("chkbox_target", false)
                    put("verbosity", 3)
                    put("chkbox_proxy", true)
                }
            }
        }

        Json { prettyPrint = true }.encodeToString(root)
    }

    // 20260918 mniwa >> Sends a generated CPH import JSON payload to the local CPH extension API and imports it in keep mode.
    mcpTool<ImportCphConfig>(
        "Imports a Burp Custom Parameter Handler (CPH) config JSON into the local CPH extension via HTTP API in keep mode. Use the CPH API port, not the Burp proxy port. Defaults to 127.0.0.1:17866."
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

    mcpTool<GetCphConfig>(
        "Reads the current Burp Custom Parameter Handler (CPH) configuration from the local CPH API. Use the CPH API port, not the Burp proxy port. Defaults to 127.0.0.1:17866 when omitted."
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

@Serializable
data class GetScannerIssues(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistory(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistoryRegex(val regex: String, override val count: Int, override val offset: Int) : Paginated

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