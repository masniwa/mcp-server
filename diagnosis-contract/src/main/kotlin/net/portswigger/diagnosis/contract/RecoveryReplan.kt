package net.portswigger.diagnosis.contract

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import java.net.URI

@Serializable
data class RecoveryReplanSelection(val revision:Int,val ruleDescriptions:List<String> = emptyList())

/** Explicit new proposal from observed native Rule scopes; the old plan/digests are never edited. */
fun observedRecoveryProposal(plan:CompiledPlan,observed:BurpSnapshot,selection:RecoveryReplanSelection):JobProposal {
    requireJob(selection.revision>plan.proposal.revision,"RECOVERY_NEW_REVISION_REQUIRED")
    requireJob(selection.ruleDescriptions.distinct().size==selection.ruleDescriptions.size,"DUPLICATE_REPLAN_RULE")
    requireJob(plan.baseline.projectMarker!=null && observed.projectMarker==plan.baseline.projectMarker,"PROJECT_IDENTITY_UNVERIFIED")
    fun root(project:JsonObject)=project["project_options"] as? JsonObject ?: project
    val nativeRules=((root(observed.project)["sessions"] as? JsonObject)?.get("session_handling_rules") as? JsonObject)?.get("rules") as? JsonArray ?: JsonArray(emptyList())
    val found=linkedSetOf<String>()
    fun safeScope(old:JsonElement?,actual:JsonElement?):JsonElement? {
        requireJob(old is JsonArray && actual is JsonArray && old.size==actual.size,"UNSUPPORTED_NATIVE_READBACK")
        val planned=old as JsonArray;val native=actual as JsonArray
        planned.zip(native).forEach { (before,after) ->
            val b=before.jsonObject;val a=after.jsonObject
            requireJob(b-"prefix"==a-"prefix","UNSUPPORTED_NATIVE_READBACK")
            val original=b["prefix"]?.jsonPrimitive?.contentOrNull ?: throw JobRejected("UNSUPPORTED_NATIVE_READBACK")
            val value=a["prefix"]?.jsonPrimitive?.contentOrNull ?: throw JobRejected("UNSUPPORTED_NATIVE_READBACK")
            val left=runCatching { URI(original) }.getOrElse { throw JobRejected("UNSUPPORTED_NATIVE_READBACK") }
            val right=runCatching { URI(value) }.getOrElse { throw JobRejected("UNSUPPORTED_NATIVE_READBACK") }
            requireJob(original.equals(value,true) && left.rawPath==right.rawPath && left.rawAuthority.equals(right.rawAuthority,true) &&
                left.scheme.equals(right.scheme,true) && left.rawFragment==right.rawFragment,"NATIVE_SCOPE_EXPANSION_OR_TARGET_CHANGE")
        }
        return actual
    }
    val variants=plan.proposal.variants.map { variant ->
        val rules=variant.settings.rules.map { element ->
            val rule=element.jsonObject
            val name=rule["description"]?.jsonPrimitive?.contentOrNull
            if(name !in selection.ruleDescriptions) rule else {
                val actual=nativeRules.singleOrNull { it.jsonObject["description"]==JsonPrimitive(name) }?.jsonObject
                    ?: throw JobRejected("NATIVE_RULE_MISSING_OR_AMBIGUOUS")
                requireJob(rule["serial_number"]==actual["serial_number"],"NATIVE_RULE_IDENTITY_CHANGED")
                val fields=setOf("include_in_scope","exclude_from_scope")
                requireJob(rule.filterKeys { it !in fields }==actual.filterKeys { it !in fields },"UNSUPPORTED_NATIVE_READBACK")
                var changed=rule
                for(field in fields) if(rule[field]!=actual[field]) {
                    val value=safeScope(rule[field],actual[field]) ?: throw JobRejected("UNSUPPORTED_NATIVE_READBACK")
                    changed=JsonObject(changed+(field to value))
                }
                found.add(name!!);changed
            }
        }
        variant.copy(settings=variant.settings.copy(rules=JsonArray(rules)))
    }
    requireJob(found==selection.ruleDescriptions.toSet(),"REPLAN_RULE_NOT_OWNED_BY_PROPOSAL")
    return plan.proposal.copy(revision=selection.revision,variants=variants)
}