package net.portswigger.diagnosis.contract

import kotlinx.serialization.json.*

/** Native execution termination is distinct from acceptance or coverage of the submitted request. */
fun nativeExecutionTerminal(observation:JsonObject):Boolean {
    val status=observation["auditStatusMessage"]?.jsonPrimitive?.contentOrNull?.trim()?.lowercase()?.removeSuffix(".")
    if(status in setOf("cancelled","canceled")) return true
    if(observation["completed"]?.jsonPrimitive?.booleanOrNull==true) return true
    return observation["nativeCompleted"]?.jsonPrimitive?.booleanOrNull==true &&
        status in setOf("done","finished","complete","completed")
}

/** An inventory observation is evidence only for retained native handles; UI/pre-reload activity needs REVIEW. */
fun retainedNativeInventoryStopped(inventory:JsonObject):Boolean = runCatching {
    if(inventory["success"]!=JsonPrimitive(true)) return@runCatching false
    val audits=inventory["audits"] as? JsonArray ?: return@runCatching false
    audits.all { element ->
        val audit=element.jsonObject
        !audit["auditId"]?.jsonPrimitive?.contentOrNull.isNullOrBlank() && nativeExecutionTerminal(audit)
    }
}.getOrDefault(false)