package net.portswigger.diagnosis.contract

import kotlinx.serialization.json.*

/** Only native Macro/Rule empty collection wrappers; other missing/null/default values stay distinct. */
fun comparableNativeCollections(project:JsonObject):JsonObject {
    fun strip(root:JsonObject):JsonObject {
        val sessions=root["sessions"] as? JsonObject ?: return root
        var result=sessions
        for((container,key) in listOf("macros" to "macros","session_handling_rules" to "rules")) {
            val definition=result[container] as? JsonObject ?: continue
            if(definition.keys==setOf(key) && definition[key] is JsonArray && definition[key]!!.jsonArray.isEmpty()) result=JsonObject(result-container)
        }
        return JsonObject(if(result.isEmpty()) root-"sessions" else root+("sessions" to result))
    }
    return if(project["project_options"] is JsonObject) JsonObject(project+("project_options" to strip(project.getValue("project_options").jsonObject))) else strip(project)
}

/** Omitted fields are not deletions in native partial import. Clear only known collection containers. */
fun explicitNativeCollectionClears(current:JsonObject,target:JsonObject):JsonObject {
    fun shape(before:JsonObject,after:JsonObject):JsonObject {
        val oldSessions=before["sessions"] as? JsonObject ?: return after
        var sessions=(after["sessions"] as? JsonObject) ?: JsonObject(emptyMap())
        for((container,key) in listOf("macros" to "macros","session_handling_rules" to "rules")) {
            val old=oldSessions[container] as? JsonObject ?: continue
            if(container !in sessions) {
                requireJob(old.keys==setOf(key),"PROJECT_SECTION_METADATA_REMOVAL_UNSUPPORTED")
                sessions=JsonObject(sessions+(container to buildJsonObject { put(key,JsonArray(emptyList())) }))
            }
        }
        return JsonObject(after+("sessions" to sessions))
    }
    return if(current["project_options"] is JsonObject && target["project_options"] is JsonObject)
        JsonObject(target+("project_options" to shape(current.getValue("project_options").jsonObject,target.getValue("project_options").jsonObject)))
    else shape(current,target)
}