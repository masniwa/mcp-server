package net.portswigger.diagnosis.contract

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*

/** Operator selects existing observations, never arbitrary replacement JSON or stop attestations. */
@Serializable
data class RecoverySelection(val snapshotDigest:String, val decisions:Map<String,String> = emptyMap(), val resumeOperationId:String? = null)

/** Restoration target is independent of ownership: retained authentication may survive cleanup. */
fun recoveryDestinations(differences:List<RecoveryDifference>,destination:JsonObject):List<RecoveryDifference> = differences.map { difference ->
    if(difference.baseline==difference.approved) difference else {
        var value:JsonElement?=destination
        for(token in difference.path.drop(1).split("/").map { it.replace("~1","/").replace("~0","~") })
            value=(value as? JsonObject)?.get(token)
        difference.copy(restoration=value,restorationSpecified=true)
    }
}

fun recoverySettings(snapshot:BurpSnapshot):JsonObject = buildJsonObject {
    put("project",recoveryProjectView(collectionIdentityView(snapshot.project)));put("cph",cphDefinitions(snapshot.cph))
}

/** Missing historic readback remains missing: current-only additions cannot establish their own provenance. */
fun recoveryEvidenceDifferences(baseline:BurpSnapshot,approved:BurpSnapshot,applied:BurpSnapshot?,current:BurpSnapshot,beforeApply:BurpSnapshot?=null):List<RecoveryDifference> {
    val differences=recoveryDifferences(recoverySettings(baseline),recoverySettings(approved),applied?.let(::recoverySettings),recoverySettings(current))
    if(applied!=null) {
        val before=beforeApply?.takeIf { it.instanceId==applied.instanceId && it.projectMarker==baseline.projectMarker && applied.projectMarker==baseline.projectMarker &&
            it.adapterVersion==applied.adapterVersion }?.let(::recoverySettings)
        val observed=recoverySettings(applied)
        fun valueAt(root:JsonObject,path:String):JsonElement? {
            var value:JsonElement?=root
            for(token in path.drop(1).split("/").map { it.replace("~1","/").replace("~0","~") })
                value=(value as? JsonObject)?.get(token)
            return value
        }
        return differences.map { difference ->
            // Preserved pre-apply values (including only the known native scope readback) never expand ownership.
            if(before!=null && difference.baseline==difference.approved &&
                difference.disposition==RecoveryDisposition.UNKNOWN_OWNER &&
                (valueAt(before,difference.path)==difference.applied || projectedNativeRuleReadbackEquivalent(before,observed,difference.path)))
                difference.copy(disposition=RecoveryDisposition.KEEP) else difference
        }
    }
    return differences.map { difference ->
        if(difference.baseline==null && difference.approved==null && difference.current!=null &&
            (difference.path.startsWith("/cph/") || difference.path.contains("/sessions/")))
            difference.copy(disposition=RecoveryDisposition.UNKNOWN_OWNER) else difference
    }
}

/** Supply empty identity maps before diffing, so adding the first definition never owns its container. */
private fun collectionIdentityView(project:JsonObject):JsonObject {
    fun root(value:JsonObject):JsonObject {
        var sessions=(value["sessions"] as? JsonObject) ?: JsonObject(emptyMap())
        for((container,key) in listOf("macros" to "macros","session_handling_rules" to "rules")) {
            val fields=(sessions[container] as? JsonObject) ?: JsonObject(emptyMap())
            if(key !in fields) sessions=JsonObject(sessions+(container to JsonObject(fields+(key to JsonArray(emptyList())))))
        }
        return JsonObject(value+("sessions" to sessions))
    }
    return if(project["project_options"] is JsonObject) JsonObject(project+("project_options" to root(project.getValue("project_options").jsonObject))) else root(project)
}
private fun definitionArray(path:List<String>) = path.takeLast(2) in listOf(listOf("macros","macros"),listOf("session_handling_rules","rules"))
private fun definitionId(value:JsonElement):String {
    val item=value as? JsonObject ?: throw JobRejected("NATIVE_DEFINITION_IDENTITY_UNAVAILABLE")
    return item["serial_number"]?.let { "serial:$it" }
        ?: item["description"]?.jsonPrimitive?.contentOrNull?.let { "description:$it" }
        ?: throw JobRejected("NATIVE_DEFINITION_IDENTITY_UNAVAILABLE")
}
/** Known native definitions use exact integer/string identities; ordering is taken from current readback. */
private fun recoveryProjectView(value:JsonElement,path:List<String> = emptyList()):JsonElement = when {
    definitionArray(path) && value is JsonArray -> {
        val ids=value.map(::definitionId)
        requireJob(ids.distinct().size==ids.size,"AMBIGUOUS_NATIVE_DEFINITION_IDENTITY")
        JsonObject(ids.zip(value).toMap())
    }
    value is JsonObject -> JsonObject(value.mapValues { (key,child) -> recoveryProjectView(child,path+key) })
    else -> value
}
private fun restoreProjectView(value:JsonElement,current:JsonElement?,baseline:JsonElement?,path:List<String> = emptyList()):JsonElement {
    if(definitionArray(path) && value is JsonObject) {
        val currentIds=(current as? JsonArray).orEmpty().map(::definitionId)
        val baselineIds=(baseline as? JsonArray).orEmpty().map(::definitionId)
        val order=currentIds.filter { it in value }.toMutableList()
        baselineIds.filter { it in value && it !in order }.forEach { id ->
            val next=baselineIds.dropWhile { it!=id }.drop(1).firstOrNull { it in order }
            order.add(if(next==null) order.size else order.indexOf(next),id)
        }
        requireJob(order.toSet()==value.keys,"NATIVE_DEFINITION_ORDER_UNAVAILABLE")
        return JsonArray(order.map { value.getValue(it) })
    }
    return if(value is JsonObject) JsonObject(value.mapValues { (key,child) ->
        restoreProjectView(child,(current as? JsonObject)?.get(key),(baseline as? JsonObject)?.get(key),path+key)
    }) else value
}

/** Explicit conflict resolution is bound to a complete immutable current snapshot by the worker. */
fun selectedRecoveryCandidate(current:JsonObject,differences:List<RecoveryDifference>,decisions:Map<String,String>):JsonObject {
    requireJob(decisions.keys.all { key -> differences.any { it.path==key } },"UNKNOWN_RECOVERY_PATH")
    requireJob(decisions.values.all { it in setOf("KEEP_CURRENT","RESTORE_BASELINE") },"INVALID_RECOVERY_DECISION")
    val resolved=differences.map { diff ->
        requireJob(diff.disposition!=RecoveryDisposition.UNKNOWN_OWNER,"AMBIGUOUS_OWNERSHIP")
        val decision=decisions[diff.path]
        requireJob(diff.disposition !in setOf(RecoveryDisposition.CONFLICT_REVIEW,RecoveryDisposition.UNKNOWN_OWNER) || decision!=null,
            "RECOVERY_DIFFERENCES_REQUIRE_REVIEW")
        // Non-owned deletion/change is preserved. Recreating a missing saved CPH definition requires an explicit decision.
        if(decision=="RESTORE_BASELINE") {
            requireJob(diff.disposition!=RecoveryDisposition.CONFLICT_REVIEW ||
                listOf(diff.baseline,diff.approved,diff.current).none { it is JsonArray || it is JsonObject } ||
                diff.baseline==null && diff.approved is JsonObject && diff.current is JsonObject &&
                diff.path.contains("/sessions/") && definitionId(diff.approved)==definitionId(diff.current),
                "COMPOUND_IDENTITY_RECONCILIATION_REQUIRED")
            requireJob(diff.baseline!=diff.approved || diff.current==null && diff.path.startsWith("/cph/") && diff.baseline!=null,
                "NON_OWNED_CHANGE_MUST_BE_PRESERVED")
            if(diff.baseline==diff.approved && diff.current==null && diff.path.startsWith("/cph/")) {
                val definition=diff.baseline as? JsonObject ?: throw JobRejected("MISSING_CPH_DEFINITION_UNAVAILABLE")
                requireJob("enabled" in definition,"MISSING_CPH_OPTIONS_REQUIRE_SEPARATE_REVIEW")
                diff.copy(baseline=JsonObject(definition+("enabled" to JsonPrimitive(false))),disposition=RecoveryDisposition.RESTORE_OWNED)
            } else diff.copy(disposition=RecoveryDisposition.RESTORE_OWNED)
        } else if(decision=="KEEP_CURRENT") diff.copy(disposition=RecoveryDisposition.KEEP) else diff
    }
    return recoveryRestoreCandidate(current,resolved.map { diff ->
        if(diff.restorationSpecified && diff.disposition==RecoveryDisposition.RESTORE_OWNED) diff.copy(baseline=diff.restoration) else diff
    })
}

/** Native partial import: known identity-checked definition arrays are emitted atomically on EDT; opaque shapes stay blocked. */
fun recoveryProjectPatch(current:JsonObject,target:JsonObject):JsonObject = projectPatch(current,target,emptyList())

private fun projectPatch(current:JsonObject,target:JsonObject,path:List<String>):JsonObject {
    requireJob((current.keys-target.keys).isEmpty(),"PROJECT_SECTION_REMOVAL_UNVERIFIED")
    return JsonObject(target.mapNotNull { (key,value) ->
        val before=current[key]
        if(before==value) null else {
            requireJob(before !is JsonArray && value !is JsonArray || definitionArray(path+key),"PROJECT_ARRAY_SERIALIZATION_UNVERIFIED")
            if(definitionArray(path+key) && value is JsonArray) {
                val identities=value.map(::definitionId)
                requireJob(identities.distinct().size==identities.size,"AMBIGUOUS_NATIVE_DEFINITION_IDENTITY")
            }
            key to if(value is JsonObject) projectPatch(before as? JsonObject ?: JsonObject(emptyMap()),value,path+key) else value
        }
    }.toMap())
}

/** Current activity facts are independent from missing historical responses and cumulative errors. */
fun recoveryActivityBlockers(observation:JsonObject):List<String> = buildList {
    if(observation["activeTrackedMcpSends"]?.jsonPrimitive?.intOrNull!=0) add("CURRENT_MCP_ACTIVITY_UNVERIFIED_OR_ACTIVE")
    if(observation["captureHealth"]!=JsonPrimitive("NO_WINDOW_LOSS_OBSERVED")) add("CURRENT_CAPTURE_UNVERIFIED")
    val activity=(observation["cphActivity"] as? JsonObject)?.get("active") as? JsonObject
    if(activity==null || activity.keys!=setOf("http_handler","helper_send") ||
        activity.values.any { (it as? JsonPrimitive)?.intOrNull!=0 }) add("CURRENT_CPH_ACTIVITY_UNVERIFIED_OR_ACTIVE")
    // Macro and UI/pre-reload Task stop require a separate trusted REVIEW, never an AI input flag.
}

/** Historical rows and background Logger progress are not a current-activity fence. */
fun recoveryTrafficFence(observation:JsonObject):JsonObject = JsonObject(observation.filterKeys {
    it in setOf("captureId","checkpointId","checkpointValid","captureHealth","windowCaptureErrors",
        "windowDroppedEntries","activeTrackedMcpSends","cphActivity","cphActivityError")
})

fun recoveryCandidateSnapshot(current:BurpSnapshot,settings:JsonObject,baseline:BurpSnapshot):BurpSnapshot {
    var cph=JsonObject(settings.getValue("cph").jsonObject.mapValues { (name,value) ->
        val tab=value.jsonObject
        if(tab["dynamic_checkbox"]==JsonPrimitive(true) && tab["extract_choice_index"]==JsonPrimitive(0)) {
            val response=current.cph[name]?.jsonObject?.get("single_response") ?: baseline.cph[name]?.jsonObject?.get("single_response")
            if(response!=null) JsonObject(tab+("single_response" to response)) else tab
        } else tab
    })
    val visiting=linkedSetOf<String>()
    fun includeMissingDependency(name:String) {
        requireJob(visiting.add(name),"CPH_RESTORE_DEPENDENCY_CYCLE")
        val tab=cph.getValue(name).jsonObject
        if(tab["dynamic_checkbox"]==JsonPrimitive(true) && tab["extract_choice_index"]==JsonPrimitive(2)) {
            val source=tab["cached_selection"]?.jsonPrimitive?.contentOrNull ?: throw JobRejected("CPH_RESTORE_DEPENDENCY_MISSING")
            if(source !in cph) {
                val saved=baseline.cph[source] as? JsonObject ?: throw JobRejected("CPH_RESTORE_DEPENDENCY_MISSING")
                requireJob("enabled" in saved,"CPH_RESTORE_DEPENDENCY_INVALID")
                cph=JsonObject(cph+(source to JsonObject(saved+("enabled" to JsonPrimitive(false)))))
                includeMissingDependency(source)
            } else {
                requireJob(source !in visiting,"CPH_RESTORE_DEPENDENCY_CYCLE")
                val saved=baseline.cph[source]
                if(source in current.cph && saved!=null) requireJob(
                    cphDefinitions(JsonObject(mapOf(source to JsonObject(saved.jsonObject-"enabled"))))==cphDefinitions(JsonObject(mapOf(source to JsonObject(cph.getValue(source).jsonObject-"enabled")))),
                    "CPH_RESTORE_DEPENDENCY_CONFLICT")
                includeMissingDependency(source)
            }
        }
        visiting.remove(name)
    }
    val restoredRoots=cph.keys.filter { name -> name !in current.cph ||
        cphDefinitions(JsonObject(mapOf(name to JsonObject(cph.getValue(name).jsonObject-"enabled"))))!=
            cphDefinitions(JsonObject(mapOf(name to JsonObject(current.cph.getValue(name).jsonObject-"enabled")))) }.toSet()
    restoredRoots.forEach(::includeMissingDependency)
    val requiredCph=cphDependencyClosure(cph,activeCphNames(cph)+restoredRoots)
    val order=current.cphOrder.filter { it in cph }.toMutableList()
    baseline.cphOrder.filter { it in cph && it !in order }.forEach { name ->
        val next=baseline.cphOrder.dropWhile { it!=name }.drop(1).firstOrNull { it in order }
        order.add(if(next==null) order.size else order.indexOf(next),name)
    }
    requireJob(order.toSet()==cph.keys && order.size==cph.size,"CPH_ORDER_INCONSISTENT")
    cph.forEach { (name,value) ->
        val source=(value as? JsonObject)?.get("cached_selection")?.jsonPrimitive?.contentOrNull
        if(name in requiredCph && value.jsonObject["dynamic_checkbox"]==JsonPrimitive(true) && value.jsonObject["extract_choice_index"]==JsonPrimitive(2))
            requireJob(!source.isNullOrBlank() && source in order && order.indexOf(source)<order.indexOf(name),"CPH_RESTORE_DEPENDENCY_ORDER")
    }
    return current.copy(project=explicitNativeCollectionClears(current.project,comparableNativeCollections(restoreProjectView(settings.getValue("project"),current.project,baseline.project).jsonObject)),cph=cph,cphOrder=order)
}
