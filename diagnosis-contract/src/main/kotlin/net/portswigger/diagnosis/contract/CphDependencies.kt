package net.portswigger.diagnosis.contract

import kotlinx.serialization.json.*

/** Active handlers plus explicitly authored/restored roots; inactive unrelated tabs are not dependencies. */
fun cphDependencyClosure(config:JsonObject,roots:Set<String>):Set<String> {
    val required=linkedSetOf<String>()
    val visiting=mutableSetOf<String>()
    fun visit(name:String) {
        requireJob(name !in visiting,"CPH_CACHE_REFERENCE_CYCLE")
        if(name in required) return
        val tab=config[name] as? JsonObject ?: throw JobRejected("CPH_CACHE_REFERENCE_ORDER")
        visiting.add(name)
        if(tab["dynamic_checkbox"]==JsonPrimitive(true) && tab["extract_choice_index"]==JsonPrimitive(2)) {
            val source=tab["cached_selection"]?.jsonPrimitive?.contentOrNull
            requireJob(!source.isNullOrBlank(),"CPH_CACHE_REFERENCE_REQUIRED")
            visit(source!!)
        }
        visiting.remove(name);required.add(name)
    }
    roots.forEach(::visit)
    return required
}

fun activeCphNames(config:JsonObject):Set<String> = config.filter { (name,value) ->
    name!=digest("options") && value.jsonObject["enabled"]!=JsonPrimitive(false)
}.keys
