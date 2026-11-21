package net.portswigger.diagnosis.contract

import kotlinx.serialization.json.*

/** Select only disabled definitions from the formal baseline for the same saved Project. */
fun selectRestartCphRestore(saved:BurpSnapshot,current:BurpSnapshot,requested:Set<String>):Pair<BurpSnapshot,Set<String>> {
    val options=digest("options")
    requireJob(saved.projectMarker!=null && current.projectMarker==saved.projectMarker,"PROJECT_IDENTITY_UNVERIFIED")
    requireJob(current.instanceId!=saved.instanceId,"CPH_RESTART_NOT_OBSERVED")
    requireJob(saved.adapterVersion==current.adapterVersion && current.capabilities.containsAll(saved.capabilities),"RECOVERY_CONTEXT_CHANGED")
    requireJob(canonical(projectDefinitions(saved.project))==canonical(projectDefinitions(current.project)),"PROJECT_SETTINGS_CHANGED")
    requireJob(current.cph[options]==saved.cph[options] && current.cphOrder.count { it==options }==1,"CPH_OPTIONS_CHANGED")
    requireJob(saved.cph.keys==saved.cphOrder.toSet() && saved.cphOrder.size==saved.cph.size &&
        current.cph.keys==current.cphOrder.toSet() && current.cphOrder.size==current.cph.size,"CPH_ORDER_INCONSISTENT")
    requireJob(current.cph.all { (name,value) -> saved.cph[name]==value },"UNRELATED_CPH_CHANGED")
    requireJob(current.cphOrder==saved.cphOrder.filter { it in current.cph },"UNRELATED_CPH_ORDER_CHANGED")
    requireJob(requested.isNotEmpty() && requested.all { name ->
        name.startsWith("job:") && name !in current.cph && saved.cph[name]?.jsonObject?.get("enabled")==JsonPrimitive(false)
    },"CPH_RESTORE_TARGET_INVALID")
    val selected=linkedSetOf<String>()
    fun add(name:String) {
        if(name in current.cph || name in selected) return
        val tab=saved.cph[name]?.jsonObject ?: throw JobRejected("CPH_RESTORE_DEPENDENCY_MISSING")
        requireJob(tab["enabled"]==JsonPrimitive(false),"CPH_RESTORE_DEPENDENCY_ENABLED")
        val dependency=tab["cached_selection"]?.jsonPrimitive?.contentOrNull
        if(!dependency.isNullOrBlank()) {
            requireJob(dependency in saved.cphOrder && saved.cphOrder.indexOf(dependency)<saved.cphOrder.indexOf(name),
                "CPH_RESTORE_DEPENDENCY_ORDER")
            add(dependency)
        }
        selected.add(name)
    }
    requested.forEach(::add)
    val names=current.cph.keys+selected
    val order=saved.cphOrder.filter { it in names }
    val config=JsonObject(order.associateWith { current.cph[it] ?: saved.cph.getValue(it) })
    return current.copy(cph=config,cphOrder=order) to selected
}
