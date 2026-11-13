package net.portswigger.mcp.execution

import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import net.portswigger.diagnosis.contract.*
import net.portswigger.mcp.tools.AuditParameterSelector
import net.portswigger.mcp.tools.normalizeHttpContent
import net.portswigger.mcp.tools.selectAuditParameters
import net.portswigger.mcp.tools.validateRawHttpRequest
import kotlinx.serialization.json.JsonObject

/** No network or settings operations: the same native parser and exact selector resolution used by Scan. */
internal fun validateNativeInputCoverage(request:RequestPlan,exclusions:List<InputExclusion>,actions:List<JsonObject> = emptyList()) {
    InputCoverage.validateDeclarations(request.startOptions,exclusions)
    val selected=InputCoverage.selected(request.startOptions)
    if(selected==null && !InputCoverage.mayUpdateInputs(actions)) return
    try {
        val raw=normalizeHttpContent(request.request)
        validateRawHttpRequest(raw)
        checkInventoryRepresentation(raw)
        val e=request.endpoint
        val native=HttpRequest.httpRequest(HttpService.httpService(e.host,e.port,e.scheme=="https"),raw)
        val parameters=native.parameters()
        val inventory=parameters.map { InputParameter(it.name(),it.type().name) }
        requireJob(inventory.all { it.name.isNotBlank() && it.type.isNotBlank() },"NATIVE_INPUT_IDENTITY_UNAVAILABLE")
        if(raw.substringAfter("\r\n\r\n","").isNotEmpty())
            requireJob(inventory.any { it.type !in setOf("URL","COOKIE") },"NATIVE_BODY_INPUT_INVENTORY_UNAVAILABLE")
        InputCoverage.validateInventory(request.startOptions,exclusions,inventory)
        selected?.let { selectors ->
            try {
                selectAuditParameters(parameters,selectors.map { AuditParameterSelector(it.name,it.type) },native.toByteArray().length())
            } catch(e:IllegalArgumentException) { throw JobRejected("INVALID_NATIVE_INPUT_SELECTION") }
        }
        // Automatic Task selection is opaque; any native parameter may be attacked. Do not assume a token is excluded.
        InputCoverage.validateMacroPreservation(request.startOptions,actions,inventory)
    } catch(e:JobRejected) { throw e }
    catch(e:Exception) { throw JobRejected("NATIVE_INPUT_INVENTORY_UNAVAILABLE") }
}

/** Refuse opaque/encoded bodies rather than pretending a partial query/cookie inventory covers them. */
private fun checkInventoryRepresentation(raw:String) {
    val headers=raw.substringBefore("\r\n\r\n").lineSequence().drop(1).toList()
    requireJob(headers.none { it.substringBefore(':').equals("Transfer-Encoding",true) },"INPUT_INVENTORY_UNSUPPORTED_ENCODING")
    requireJob(headers.filter { it.substringBefore(':').equals("Content-Encoding",true) }
        .all { it.substringAfter(':').trim().equals("identity",true) },"INPUT_INVENTORY_UNSUPPORTED_ENCODING")
    if(raw.substringAfter("\r\n\r\n","").isEmpty()) return
    val types=headers.filter { it.substringBefore(':').equals("Content-Type",true) }
        .map { it.substringAfter(':').substringBefore(';').trim().lowercase() }
    val type=types.singleOrNull() ?: throw JobRejected("INPUT_INVENTORY_UNSUPPORTED_BODY")
    requireJob(type in setOf("application/x-www-form-urlencoded","multipart/form-data","application/json","application/xml","text/xml") ||
        type.startsWith("application/") && (type.endsWith("+json") || type.endsWith("+xml")),"INPUT_INVENTORY_UNSUPPORTED_BODY")
}
