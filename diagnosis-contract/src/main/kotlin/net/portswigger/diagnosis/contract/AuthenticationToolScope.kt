package net.portswigger.diagnosis.contract

import kotlinx.serialization.json.*

private val toolOptions=linkedMapOf("Scanner" to "chkbox_scanner","Extender" to "chkbox_extender",
    "Proxy" to "chkbox_proxy","Target" to "chkbox_target","Spider" to "chkbox_spider",
    "Repeater" to "chkbox_repeater","Sequencer" to "chkbox_sequencer","Intruder" to "chkbox_intruder")

internal fun configuredAuthenticationTools(cph:JsonObject):List<String> {
    val options=cph[digest("options")]?.jsonObject
    return toolOptions.filterValues { options?.get(it)==JsonPrimitive(true) }.keys.toList()
}

private fun declaredTools(states:AuthenticationStates?):List<String> {
    if(states==null) return emptyList()
    val active=states.cph.values.any { it }
    requireJob(!active || states.cphTools.isNotEmpty(),"CPH_TOOL_SCOPE_REQUIRED")
    requireJob(states.cphTools.distinct()==states.cphTools && states.cphTools.all { it in toolOptions },"INVALID_CPH_TOOL_SCOPE")
    requireJob(active || states.cphTools.isEmpty(),"CPH_TOOL_SCOPE_WITHOUT_ACTIVE_HANDLER")
    return states.cphTools
}

/** Enable only the tools explicitly needed for this target; other global flags stay unchanged. */
internal fun applyAuthenticationToolScope(states:AuthenticationStates?,cph:JsonObject):JsonObject {
    val tools=declaredTools(states)
    if(tools.isEmpty()) return cph
    val key=digest("options")
    val options=cph[key]?.jsonObject ?: throw JobRejected("CPH_OPTIONS_REQUIRED")
    return JsonObject(cph+(key to JsonObject(options+tools.associate { toolOptions.getValue(it) to JsonPrimitive(true) })))
}

/** Also gate new approval/preparation/start of saved plans compiled before tool-scope declarations existed. */
fun validateAuthenticationToolScopes(plan:CompiledPlan) {
    plan.variants.forEach { variant ->
        val tools=declaredTools(variant.variant.settings.authenticationStates)
        val options=variant.cph[digest("options")]?.jsonObject
        requireJob(tools.all { options?.get(toolOptions.getValue(it))==JsonPrimitive(true) },"CPH_TOOL_SCOPE_DISABLED")
    }
}
