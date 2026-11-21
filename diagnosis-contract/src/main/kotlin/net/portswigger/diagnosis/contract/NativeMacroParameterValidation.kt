package net.portswigger.diagnosis.contract

import kotlinx.serialization.json.*
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

/** Native Macro parameter handling supports URL query and URL-encoded form fields. */
fun validateNativeMacroParameters(macroName:String,itemIndex:Int,rawRequest:String,parameters:JsonArray) {
    if(parameters.isEmpty()) return
    fun reject(name:String):Nothing = throw JobRejected("MACRO_PARAMETER_LOCATION_UNSUPPORTED",mapOf(
        "macroName" to macroName.take(160).filterNot(Char::isISOControl),
        "itemIndex" to itemIndex.toString(),
        "parameterName" to name.take(160).filterNot(Char::isISOControl)))
    val head=rawRequest.substringBefore("\r\n\r\n")
    val requestTarget=head.substringBefore("\r\n").split(' ').getOrNull(1).orEmpty()
    val query=requestTarget.substringAfter('?',"").substringBefore('#')
    val body=rawRequest.substringAfter("\r\n\r\n","")
    val contentType=head.lineSequence().drop(1).firstOrNull { it.startsWith("Content-Type:",true) }
        ?.substringAfter(':')?.trim()?.substringBefore(';')?.trim().orEmpty()
    fun names(encoded:String):Set<String> = encoded.split('&').filter { it.isNotEmpty() }.map { part ->
        val name=part.substringBefore('=')
        runCatching { URLDecoder.decode(name,StandardCharsets.UTF_8) }.getOrElse { name }
    }.toSet()
    val queryNames=names(query)
    val formNames=if(contentType.equals("application/x-www-form-urlencoded",true)) names(body) else emptySet()
    for(element in parameters) {
        val parameter=element as? JsonObject ?: reject("(parameter)")
        val name=parameter["name"]?.jsonPrimitive?.contentOrNull ?: reject("(name)")
        val type=parameter["type"]?.jsonPrimitive?.contentOrNull ?: reject(name)
        when(type) {
            "url" -> if(name !in queryNames) reject(name)
            "body_url_encoded" -> if(name !in formNames) reject(name)
            else -> reject(name)
        }
    }
}
