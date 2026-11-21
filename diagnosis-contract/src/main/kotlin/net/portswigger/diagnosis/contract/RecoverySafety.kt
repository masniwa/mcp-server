package net.portswigger.diagnosis.contract

import kotlinx.serialization.json.*

/** A failed partial apply may change owned definitions, never unrelated settings. */
fun checkRecoveryOwnership(plan:CompiledPlan,actual:BurpSnapshot) {
    val base=plan.baseline;val ns="job:${plan.proposal.jobId}:";val options=digest("options")
    requireJob(actual.adapterVersion==base.adapterVersion && actual.capabilities.containsAll(plan.proposal.requiredCapabilities),"RECOVERY_CONTEXT_CHANGED")
    if(base.projectMarker!=null) requireJob(actual.projectMarker==base.projectMarker,"PROJECT_IDENTITY_CHANGED")
    val owned=(plan.variants.flatMap { it.variant.settings.cph.keys }+base.cph.keys.filter { it.startsWith(ns) }).filter { it.startsWith(ns) }.toSet()
    val baseDefs=cphDefinitions(base.cph);val currentDefs=cphDefinitions(actual.cph)
    requireJob(currentDefs.keys.all { it in baseDefs || it in owned || it==options && plan.variants.any { v -> options in v.cph } },"UNOWNED_CPH_TAB_DURING_RECOVERY")
    val switchedCph=plan.proposal.variants.flatMap { it.settings.authenticationStates?.cph.orEmpty().keys }.toSet()
    requireJob(baseDefs.filterKeys { it !in owned && it!=options }.all { (k,v) -> currentDefs[k]==v ||
        k in switchedCph && plan.variants.any { cphDefinitions(it.cph)[k]==currentDefs[k] }
    },"UNRELATED_CPH_CHANGED")
    requireJob(currentDefs[options]==baseDefs[options] || plan.variants.any { cphDefinitions(it.cph)[options]==currentDefs[options] },"UNRELATED_CPH_OPTIONS_CHANGED")
    requireJob(actual.cphOrder.filter { it !in owned && it!=options }==base.cphOrder.filter { it !in owned && it!=options },"UNRELATED_CPH_ORDER_CHANGED")

    var candidate=actual.project
    fun root(p:JsonObject)=p["project_options"]?.jsonObject ?: p
    fun replaceRoot(p:JsonObject,r:JsonObject)=if("project_options" in p) JsonObject(p+("project_options" to r)) else r
    val baseRoot=root(base.project);var currentRoot=root(candidate)
    val originalSessions=(baseRoot["sessions"] as? JsonObject) ?: JsonObject(emptyMap())
    var currentSessions=(currentRoot["sessions"] as? JsonObject) ?: JsonObject(emptyMap())
    for((container,key) in listOf("macros" to "macros","session_handling_rules" to "rules")) {
        val before=originalSessions[container] as? JsonObject
        val now=currentSessions[container] as? JsonObject
        val switchedRules=plan.proposal.variants.flatMap { it.settings.authenticationStates?.rules.orEmpty().keys }.toSet()
        fun unowned(o:JsonObject?,normalize:Boolean=false)=(o?.get(key) as? JsonArray).orEmpty().filterNot {
            it.jsonObject["description"]?.jsonPrimitive?.contentOrNull?.startsWith(ns)==true
        }.map { definition ->
            val name=definition.jsonObject["description"]?.jsonPrimitive?.contentOrNull
            if(normalize && container=="session_handling_rules" && name in switchedRules) {
                val original=before?.get(key)?.jsonArray?.singleOrNull { it.jsonObject["description"]==JsonPrimitive(name) }
                requireJob(original==definition || plan.variants.any { variant ->
                    root(variant.project)["sessions"]?.jsonObject?.get(container)?.jsonObject?.get(key)?.jsonArray?.contains(definition)==true
                },"UNRELATED_PROJECT_DEFINITION_CHANGED")
                original ?: throw JobRejected("UNRELATED_PROJECT_DEFINITION_CHANGED")
            } else definition
        }
        requireJob(unowned(before)==unowned(now,true),"UNRELATED_PROJECT_DEFINITION_CHANGED")
        val originalMetadata:Map<String,JsonElement> = before?.filterKeys { it!=key } ?: emptyMap()
        val currentMetadata:Map<String,JsonElement> = now?.filterKeys { it!=key } ?: emptyMap()
        requireJob(originalMetadata==currentMetadata,"UNRELATED_PROJECT_DEFINITION_CHANGED")
        currentSessions=JsonObject(if(before==null) currentSessions-container else currentSessions+(container to before))
    }
    currentRoot=JsonObject(if("sessions" !in baseRoot && currentSessions.isEmpty()) currentRoot-"sessions" else currentRoot+("sessions" to currentSessions))
    if(plan.variants.any { it.variant.settings.serialScannerRequests }) {
        val currentPools=currentRoot["resource_pools"]
        requireJob(currentPools==baseRoot["resource_pools"] || plan.variants.any {
            it.variant.settings.serialScannerRequests && root(it.project)["resource_pools"]==currentPools
        },"UNRELATED_RESOURCE_POOL_SETTINGS_CHANGED")
        currentRoot=JsonObject(if("resource_pools" in baseRoot) currentRoot+("resource_pools" to baseRoot.getValue("resource_pools")) else currentRoot-"resource_pools")
    }
    candidate=replaceRoot(candidate,currentRoot)
    // Scope is also compiler-owned only when it exactly matches a compiled variant.
    fun restoreTarget(current:JsonObject,baseline:JsonObject,approved:List<JsonObject>):JsonObject {
        requireJob(current["target"]==baseline["target"] || approved.any { it["target"]==current["target"] },"UNRELATED_TARGET_SETTINGS_CHANGED")
        return JsonObject(if("target" in baseline) current+("target" to baseline.getValue("target")) else current-"target")
    }
    val approvedProjects=plan.variants.map { it.project }+listOfNotNull(plan.restorationBaseline?.project)
    candidate=replaceRoot(candidate,restoreTarget(root(candidate),baseRoot,approvedProjects.map(::root)))
    if("project_options" in candidate) candidate=restoreTarget(candidate,base.project,approvedProjects)
    requireJob(canonical(projectDefinitions(candidate))==canonical(projectDefinitions(base.project)),"UNRELATED_PROJECT_SETTINGS_CHANGED")
}
