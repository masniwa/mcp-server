package net.portswigger.diagnosis.runner

import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.canonical
import net.portswigger.diagnosis.contract.projectDefinitions
import net.portswigger.diagnosis.contract.comparableNativeCollections
import net.portswigger.diagnosis.contract.nativeRuleReadbackEquivalent

/** Burp lowercases the query of a simple session-rule URL prefix on native import. */
fun projectNativeScopeEquivalent(expected:JsonObject,actual:JsonObject):Boolean {
    val planned=comparableNativeCollections(projectDefinitions(expected))
    val observed=comparableNativeCollections(projectDefinitions(actual))
    if(canonical(planned)==canonical(observed)) return true

    fun root(project:JsonObject)=project["project_options"]?.jsonObject ?: project
    val plannedRoot=root(planned)
    val observedRoot=root(observed)
    val sessions=plannedRoot["sessions"] as? JsonObject ?: return false
    val handling=sessions["session_handling_rules"] as? JsonObject ?: return false
    val rules=handling["rules"] as? JsonArray ?: return false
    val observedRules=observedRoot["sessions"]?.jsonObject?.get("session_handling_rules")
        ?.jsonObject?.get("rules") as? JsonArray ?: return false
    if(rules.size!=observedRules.size) return false

    val adjustedRules=JsonArray(rules.mapIndexed { index, element ->
        val rule=element as? JsonObject ?: return@mapIndexed element
        val nativeRule=observedRules[index] as? JsonObject ?: return@mapIndexed element
        if(nativeRuleReadbackEquivalent(rule,nativeRule)) nativeRule else rule
    })
    val newHandling=JsonObject(handling+("rules" to adjustedRules))
    val newSessions=JsonObject(sessions+("session_handling_rules" to newHandling))
    val newRoot=JsonObject(plannedRoot+("sessions" to newSessions))
    val adjusted=if("project_options" in planned) JsonObject(planned+("project_options" to newRoot)) else newRoot
    return canonical(adjusted)==canonical(observed)
}
