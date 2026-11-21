package net.portswigger.diagnosis.contract

import kotlinx.serialization.json.*

/** Validate the fields consumed by CPH_Config.ConfigTab setters before any native write. */
fun validateNativeCphTab(name:String, value:JsonElement) {
    fun reject(field:String,code:String="CPH_FIELD_SHAPE_INVALID"):Nothing =
        throw JobRejected(code,mapOf("tabName" to name,"fieldName" to field))
    requireJob(name.isNotBlank() && name.length<=160 && name.none { it.isISOControl() },"CPH_TAB_NAME_INVALID")
    val tab=value as? JsonObject ?: reject("(tab)")
    val options=name==digest("options")
    val booleans=if(options) setOf("chkbox_proxy","chkbox_target","chkbox_spider","chkbox_repeater",
        "chkbox_sequencer","chkbox_intruder","chkbox_scanner","chkbox_extender") else
        setOf("enabled","auto_encode","enable_forwarder","dynamic_checkbox")
    val indices=if(options) emptyMap() else mapOf("modify_scope_choice_index" to 1,
        "modify_type_choice_index" to 2,"indices_choice_index" to 2,"extract_choice_index" to 2)
    val expressions=if(options) emptySet() else setOf("modify_expression","match_expression","static_expression",
        "single_expression","macro_expression","cached_expression")
    val sockets=if(options) emptySet() else setOf("forwarder","issuer")
    val strings=if(options) emptySet() else setOf("match_indices","single_request","single_response")
    val known=booleans+indices.keys+expressions+sockets+strings+
        if(options) setOf("verbosity") else setOf("cached_selection")
    for((field,raw) in tab) {
        if(field !in known) reject(field,"UNSUPPORTED_CPH_FIELD")
        when {
            field in booleans -> if(raw !is JsonPrimitive || raw.isString || raw.booleanOrNull==null) reject(field)
            field in indices -> if(raw !is JsonPrimitive || raw.isString || raw.intOrNull !in 0..indices.getValue(field)) reject(field)
            field=="verbosity" -> if(raw !is JsonPrimitive || raw.isString || raw.intOrNull !in 1..4) reject(field)
            field in expressions -> {
                val pair=raw as? JsonArray ?: reject(field)
                if(pair.size!=2 || pair[0] !is JsonPrimitive || pair[0].jsonPrimitive.isString ||
                    pair[0].jsonPrimitive.booleanOrNull==null || pair[1] !is JsonPrimitive || !pair[1].jsonPrimitive.isString) reject(field)
                if(field=="static_expression" && pair[1].jsonPrimitive.content.any { it=='\r' || it=='\n' })
                    reject(field,"CPH_SINGLE_LINE_CONTROL_CHARACTER")
            }
            field in sockets -> {
                val socket=raw as? JsonArray ?: reject(field)
                if(socket.size!=3 || socket[0] !is JsonPrimitive || socket[0].jsonPrimitive.isString ||
                    socket[0].jsonPrimitive.booleanOrNull==null || socket[1] !is JsonPrimitive ||
                    !socket[1].jsonPrimitive.isString || socket[2] !is JsonPrimitive ||
                    socket[2].jsonPrimitive.isString || socket[2].jsonPrimitive.intOrNull !in 1..65535) reject(field)
            }
            field in strings -> {
                if(raw !is JsonPrimitive || !raw.isString) reject(field)
                if(field=="match_indices" && raw.content.any { it=='\r' || it=='\n' })
                    reject(field,"CPH_SINGLE_LINE_CONTROL_CHARACTER")
            }
            field=="cached_selection" -> {
                if(raw!=JsonNull && (raw !is JsonPrimitive || !raw.isString)) reject(field)
                if(raw is JsonPrimitive && raw.content.any { it=='\r' || it=='\n' })
                    reject(field,"CPH_SINGLE_LINE_CONTROL_CHARACTER")
            }
        }
    }
}
