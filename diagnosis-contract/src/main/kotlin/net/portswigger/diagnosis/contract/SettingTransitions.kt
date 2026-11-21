package net.portswigger.diagnosis.contract

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*

@Serializable
data class SettingDependencyDifference(val path:String,val ownership:String,val impact:String,val expectedDigest:String?,val currentDigest:String?)

/** A phase changes only fields changed by the approved plan. Concurrent edits to those fields refuse. */
fun approvedPhaseCandidate(baseline:BurpSnapshot,approved:BurpSnapshot,current:BurpSnapshot):BurpSnapshot {
    requireJob(current.instanceId==baseline.instanceId && current.adapterVersion==baseline.adapterVersion,"INSTANCE_CHANGED")
    if(baseline.projectMarker!=null) requireJob(current.projectMarker==baseline.projectMarker,"PROJECT_IDENTITY_CHANGED")
    fun definitions(snapshot:BurpSnapshot)=recoverySettings(snapshot.copy(cph=cphDefinitions(snapshot.cph)))
    val base=definitions(baseline)
    val intended=definitions(approved)
    val now=definitions(current)
    val changes=recoveryDifferences(base,intended,intended,now)
    val patches=changes.map { difference ->
        when {
            difference.baseline==difference.approved -> difference.copy(disposition=RecoveryDisposition.KEEP)
            difference.current==difference.approved -> difference.copy(disposition=RecoveryDisposition.KEEP)
            projectedNativeRuleReadbackEquivalent(intended,now,difference.path) -> difference.copy(disposition=RecoveryDisposition.KEEP)
            difference.current==difference.baseline -> difference.copy(baseline=difference.approved,disposition=RecoveryDisposition.RESTORE_OWNED)
            projectedNativeRuleReadbackEquivalent(base,now,difference.path) -> difference.copy(baseline=difference.approved,disposition=RecoveryDisposition.RESTORE_OWNED)
            else -> throw JobRejected("OWNED_SETTING_CHANGED_BEFORE_APPLY",mapOf("path" to difference.path))
        }
    }
    val candidate=recoveryCandidateSnapshot(current,recoveryRestoreCandidate(now,patches),approved)
    val cph=JsonObject(candidate.cph.mapValues { (name,value) ->
        val tab=value.jsonObject
        if(tab["dynamic_checkbox"]==JsonPrimitive(true) && tab["extract_choice_index"]==JsonPrimitive(0)) {
            val response=current.cph[name]?.jsonObject?.get("single_response") ?: approved.cph[name]?.jsonObject?.get("single_response")
            if(response!=null) JsonObject(tab+("single_response" to response)) else tab
        } else tab
    })
    return candidate.copy(cph=cph)
}

/** Compare dependency definitions, excluding response-viewer runtime state, without expanding ownership. */
fun settingDependencyDifferences(plan:CompiledPlan,expected:BurpSnapshot,current:BurpSnapshot):List<SettingDependencyDifference> {
    fun view(snapshot:BurpSnapshot)=recoverySettings(snapshot.copy(project=projectDefinitions(snapshot.project),cph=cphDefinitions(snapshot.cph)))
    val baseline=view(plan.baseline);val planned=view(expected);val actual=view(current)
    val owned=plan.variants.flatMap { variant ->
        recoveryDifferences(baseline,view(plan.baseline.copy(project=variant.project,cph=variant.cph,cphOrder=variant.cphOrder)),null,baseline)
            .filter { it.baseline!=it.approved }.map { it.path }
    }.toSet()
    fun overlaps(path:String,other:String)=path==other || path.startsWith("$other/") || other.startsWith("$path/")
    fun projectRoot(snapshot:BurpSnapshot)=(snapshot.project["project_options"] as? JsonObject) ?: snapshot.project
    fun nativeDefinitions(snapshot:BurpSnapshot,container:String,key:String)=
        ((projectRoot(snapshot)["sessions"] as? JsonObject)?.get(container) as? JsonObject)?.get(key) as? JsonArray ?: JsonArray(emptyList())
    fun identity(value:JsonElement):String {
        val item=value.jsonObject
        return item["serial_number"]?.let { "serial:$it" } ?: "description:"+item.getValue("description").jsonPrimitive.content
    }
    val rules=nativeDefinitions(expected,"session_handling_rules","rules").associateBy(::identity)
    val currentRules=nativeDefinitions(current,"session_handling_rules","rules").associateBy(::identity)
    val endpoints=(plan.expandedEndpoints+plan.variants.map { it.variant.request.endpoint }).distinct()
    val declaredRuleNames=plan.proposal.variants.flatMap { it.settings.authenticationStates?.rules.orEmpty().keys }.toSet()
    val declaredRules=(plan.proposal.variants.flatMap { it.settings.rules }.map(::identity)+
        (rules.values+currentRules.values).filter { it.jsonObject["description"]?.jsonPrimitive?.content in declaredRuleNames }.map(::identity)).toSet()
    fun mayApply(value:JsonElement?):Boolean = value!=null &&
        if(endpoints.isEmpty()) value.jsonObject["enabled"]!=JsonPrimitive(false)
        else endpoints.any { InputCoverage.ruleMayApply(value.jsonObject,it) }
    val requiredMacros=linkedSetOf<String>()
    fun collectReferences(snapshot:BurpSnapshot) {
        val macros=nativeDefinitions(snapshot,"macros","macros").associateBy(::identity)
        // Traverse each snapshot separately: the same Macro ID may reference different sources.
        val visited=mutableSetOf<String>()
        fun references(value:JsonElement) {
            nativeMacroReferences(value).forEach { serial ->
                val id="serial:$serial"
                requiredMacros.add(id)
                if(visited.add(id)) macros[id]?.let(::references)
            }
        }
        nativeDefinitions(snapshot,"session_handling_rules","rules")
            .filter { mayApply(it) || identity(it) in declaredRules }.forEach(::references)
        // Explicit preparations remain dependencies even when their Rules are switched off.
        plan.proposal.variants.flatMap { it.settings.rules }.forEach(::references)
        plan.proposal.variants.flatMap { it.settings.macros }.forEach {
            val id=identity(it)
            requiredMacros.add(id)
            references(it)
            if(visited.add(id)) macros[id]?.let(::references)
        }
        plan.proposal.variants.flatMap { it.settings.macroPreparations }.forEach { preparation ->
            references(buildJsonObject { put("macro_serial_number",preparation.macroSerialNumber) })
        }
    }
    collectReferences(expected)
    collectReferences(current)
    fun definitionToken(path:String,container:String,key:String):String? {
        val tokens=path.drop(1).split("/").map { it.replace("~1","/").replace("~0","~") }
        val index=tokens.indices.firstOrNull { i -> tokens[i]==container && tokens.getOrNull(i+1)==key }
        return index?.let { tokens.getOrNull(it+2) }
    }
    val options=digest("options")
    val requiredCph=expected.cph.filter { (name,value) -> name==options || value.jsonObject["enabled"]==JsonPrimitive(true) }.keys.toMutableSet()
    fun addCached(name:String) {
        val tab=expected.cph[name]?.jsonObject ?: return
        if(tab["dynamic_checkbox"]!=JsonPrimitive(true) || tab["extract_choice_index"]!=JsonPrimitive(2)) return
        val source=tab["cached_selection"]?.jsonPrimitive?.contentOrNull
        if(!source.isNullOrBlank() && requiredCph.add(source)) addCached(source)
    }
    requiredCph.toList().forEach(::addCached)
    fun cphName(path:String)=path.removePrefix("/cph/").substringBefore('/').replace("~1","/").replace("~0","~")
    // Both Options and handler verbosity spinners only set their logger level (native range 1..4).
    // Keep strict definition/readback equality elsewhere; this is an execution-dependency decision only.
    fun loggingOnly(difference:RecoveryDifference):Boolean =
        difference.path.startsWith("/cph/") && difference.path.drop(1).split('/').let { it.size==3 && it.last()=="verbosity" } &&
            listOf(difference.baseline,difference.current).all { value ->
                value is JsonPrimitive && !value.isString && value.content in setOf("1","2","3","4")
            }
    val definitionDifferences=recoveryDifferences(planned,planned,planned,actual).filter { it.baseline!=it.current }.map { difference ->
        val isOwned=owned.any { overlaps(it,difference.path) }
        val disabledOwnedResidue=difference.path.startsWith("/cph/") && cphName(difference.path).let { name ->
            name.startsWith("job:"+plan.proposal.jobId+":") && name !in expected.cph && name !in requiredCph &&
                current.cph[name]?.jsonObject?.get("enabled")==JsonPrimitive(false)
        }
        val impact=when {
            disabledOwnedResidue -> "UNAFFECTED"
            isOwned -> "AFFECTED"
            loggingOnly(difference) -> "UNAFFECTED"
            difference.path.startsWith("/cph/") -> {
                val name=cphName(difference.path)
                if(name in requiredCph || current.cph[name]?.jsonObject?.get("enabled")==JsonPrimitive(true)) "AFFECTED" else "UNAFFECTED"
            }
            definitionToken(difference.path,"macros","macros")!=null ->
                if(definitionToken(difference.path,"macros","macros") in requiredMacros) "AFFECTED" else "UNAFFECTED"
            definitionToken(difference.path,"session_handling_rules","rules")!=null -> {
                val id=definitionToken(difference.path,"session_handling_rules","rules")
                if(id in declaredRules || mayApply(rules[id]) || mayApply(currentRules[id])) "AFFECTED" else "UNAFFECTED"
            }
            difference.path.contains("/sessions/") || difference.path.contains("/target/") || difference.path.contains("/resource_pools/") -> "UNKNOWN_IMPACT"
            else -> "UNKNOWN_IMPACT"
        }
        SettingDependencyDifference(difference.path,if(isOwned) "OWNED" else "NON_OWNED",impact,
            difference.baseline?.let(::fingerprint),difference.current?.let(::fingerprint))
    }
    // Identity projection intentionally excludes order from ownership. Execution dependencies must not.
    // Only the relative order of enabled Rules can change their effective application sequence.
    fun enabledRuleOrder(snapshot:BurpSnapshot)=JsonArray(nativeDefinitions(snapshot,"session_handling_rules","rules")
        .filter(::mayApply)
        .map { JsonPrimitive(identity(it)) })
    val expectedOrder=enabledRuleOrder(expected)
    val currentOrder=enabledRuleOrder(current)
    val orderDifferences=if(expectedOrder==currentOrder) emptyList() else listOf(SettingDependencyDifference(
        "/project/sessions/session_handling_rules/effective_order","NON_OWNED","AFFECTED",fingerprint(expectedOrder),fingerprint(currentOrder)))
    return definitionDifferences+orderDifferences
}
