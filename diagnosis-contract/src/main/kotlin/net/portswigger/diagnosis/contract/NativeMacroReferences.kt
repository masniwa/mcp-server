package net.portswigger.diagnosis.contract

import kotlinx.serialization.json.*

/** Only explicitly inactive known actions/branches can exclude a reference; unknown shapes stay conservative. */
fun nativeMacroReferences(value:JsonElement):Set<JsonElement> = buildSet {
    fun visit(element:JsonElement) {
        when(element) {
            is JsonObject -> {
                val type=(element["type"] as? JsonPrimitive)?.contentOrNull
                if(type in setOf("run_macro","run_post_request_macro","validate_session","invoke_extension") &&
                    element["enabled"]==JsonPrimitive(false)) return
                if(!(type=="validate_session" && element["validation_action"]==JsonPrimitive("issue_current_request")))
                    element["macro_serial_number"]?.let(::add)
                element.forEach { (key,child) ->
                    if(!(type=="validate_session" && key=="run_macro_action" &&
                        element["perform_action_if_invalid"]==JsonPrimitive(false))) visit(child)
                }
            }
            is JsonArray -> element.forEach(::visit)
            else -> Unit
        }
    }
    visit(value)
}
