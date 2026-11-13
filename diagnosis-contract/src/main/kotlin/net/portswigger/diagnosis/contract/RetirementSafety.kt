package net.portswigger.diagnosis.contract

import kotlinx.serialization.json.*

/** Absence is required even for disabled/renamed definitions; this does not prove old cleanup. */
fun checkRetirementSettingsAbsent(plan:CompiledPlan,actual:BurpSnapshot) {
    val ns="job:${plan.proposal.jobId}:"
    val root=actual.project["project_options"] as? JsonObject ?: actual.project
    val sessions=root["sessions"] as? JsonObject
    val macros=(sessions?.get("macros") as? JsonObject)?.get("macros") as? JsonArray ?: JsonArray(emptyList())
    val rules=(sessions?.get("session_handling_rules") as? JsonObject)?.get("rules") as? JsonArray ?: JsonArray(emptyList())
    val serials=plan.variants.flatMap { it.variant.settings.macros }.mapNotNull { it.jsonObject["serial_number"] }.toSet()
    requireJob(macros.none { value -> val m=value.jsonObject
        m["description"]?.jsonPrimitive?.contentOrNull?.startsWith(ns)==true || m["serial_number"] in serials
    },"JOB_SETTINGS_STILL_PRESENT")
    fun referencesOwnedMacro(value:JsonElement):Boolean = when(value) {
        is JsonObject -> value.any { (key,v) -> key=="macro_serial_number" && v in serials || referencesOwnedMacro(v) }
        is JsonArray -> value.any(::referencesOwnedMacro)
        else -> false
    }
    requireJob(rules.none { it.jsonObject["description"]?.jsonPrimitive?.contentOrNull?.startsWith(ns)==true || referencesOwnedMacro(it) },"JOB_SETTINGS_STILL_PRESENT")
    requireJob(actual.cph.none { (name,value) -> name.startsWith(ns) || value.jsonObject["cached_selection"]?.jsonPrimitive?.contentOrNull?.startsWith(ns)==true },"JOB_SETTINGS_STILL_PRESENT")
}
