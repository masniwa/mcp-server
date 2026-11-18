package net.portswigger.diagnosis.contract

import kotlinx.serialization.json.*

private fun root(project:JsonObject)=project["project_options"]?.jsonObject ?: project
private fun sessions(project:JsonObject)=root(project)["sessions"]?.jsonObject ?: JsonObject(emptyMap())
private fun definitions(project:JsonObject,container:String,key:String)=
    sessions(project)[container]?.jsonObject?.get(key)?.jsonArray.orEmpty()

/** Explicit reviewed selection; never infer persistence from a description or a successful HTTP status. */
internal fun authenticationRestoration(plan:CompiledPlan):BurpSnapshot {
    val selection=plan.proposal.authenticationRetention!!
    val baseline=plan.baseline
    val ns="job:${plan.proposal.jobId}:"
    requireJob(selection.ruleDescriptions.isNotEmpty() && selection.ruleDescriptions.distinct()==selection.ruleDescriptions &&
        selection.ruleDescriptions.all { it.startsWith(ns) } && selection.cphNames.distinct()==selection.cphNames,
        "INVALID_AUTHENTICATION_RETENTION")
    fun selected(values:List<JsonElement>,id:String,key:(JsonObject)->String):JsonObject? {
        val matches=values.map { it.jsonObject }.filter { key(it)==id }
        requireJob(matches.map(::canonical).distinct().size<=1,"RETAINED_AUTHENTICATION_CONFLICT")
        return matches.firstOrNull()
    }
    val allRules=plan.proposal.variants.flatMap { it.settings.rules }
    val baselineRules=definitions(baseline.project,"session_handling_rules","rules")
    requireJob(selection.ruleDescriptions.none { name -> baselineRules.any { it.jsonObject["description"]==JsonPrimitive(name) } },
        "RETAINED_AUTHENTICATION_ALREADY_PRESENT")
    val rules=selection.ruleDescriptions.map { name ->
        selected(allRules,name) { it["description"]!!.jsonPrimitive.content }
        ?: baselineRules.singleOrNull { it.jsonObject["description"]==JsonPrimitive(name) }?.jsonObject
        ?: throw JobRejected("RETAINED_AUTHENTICATION_RULE_MISSING")
    }
    rules.forEach { rule ->
        requireJob(rule["enabled"]==JsonPrimitive(true) && rule["actions"]?.jsonArray?.any {
            it.jsonObject["type"]==JsonPrimitive("validate_session") && it.jsonObject["enabled"]!=JsonPrimitive(false)
        }==true,"RETAINED_AUTHENTICATION_VALIDATION_REQUIRED")
    }
    val baselineMacros=definitions(baseline.project,"macros","macros")
    val allMacros=plan.proposal.variants.flatMap { it.settings.macros }
    val macros=linkedMapOf<String,JsonObject>()
    fun references(element:JsonElement) {
        when(element) {
            is JsonObject -> {
                element["macro_serial_number"]?.let { serial ->
                    val id=serial.toString()
                    if(id !in macros) {
                        val macro=selected(allMacros,id) { it["serial_number"]!!.toString() }
                            ?: baselineMacros.singleOrNull { it.jsonObject["serial_number"]==serial }?.jsonObject
                            ?: throw JobRejected("MISSING_MACRO_REFERENCE")
                        macros[id]=macro
                        references(macro)
                    }
                }
                element.values.forEach(::references)
            }
            is JsonArray -> element.forEach(::references)
            else -> Unit
        }
    }
    rules.forEach(::references)
    val available=linkedMapOf<String,JsonElement>()
    fun cphDefinition(name:String):JsonElement {
        return available.getOrPut(name) {
            val values=plan.proposal.variants.mapNotNull { it.settings.cph[name] }
            requireJob(values.map { canonical(cphDefinitions(JsonObject(mapOf(name to it)))) }.distinct().size<=1,
                "RETAINED_AUTHENTICATION_CONFLICT")
            values.firstOrNull() ?: baseline.cph[name] ?: throw JobRejected("RETAINED_CPH_MISSING_OR_UNOWNED")
        }
    }
    val retainedNames=linkedSetOf<String>()
    fun retainCph(name:String) {
        requireJob(name in baseline.cph || name.startsWith(ns),"RETAINED_CPH_MISSING_OR_UNOWNED")
        if(!retainedNames.add(name)) return
        val tab=cphDefinition(name).jsonObject
        if(tab["dynamic_checkbox"]==JsonPrimitive(true) && tab["extract_choice_index"]==JsonPrimitive(2)) {
            retainCph(tab["cached_selection"]!!.jsonPrimitive.content)
        }
    }
    selection.cphNames.forEach(::retainCph)
    if(retainedNames.isNotEmpty()) {
        requireJob(selection.retainTargetScope || plan.proposal.variants.all { it.settings.targetScope==null },
            "RETAINED_CPH_TARGET_SCOPE_REQUIRED")
        digest("options").takeIf { it in baseline.cph || plan.proposal.variants.any { v -> it in v.settings.cph } }
            ?.let { name -> available[name]=baseline.cph[name] ?: cphDefinition(name);retainedNames.add(name) }
    }
    requireJob(!selection.retainTargetScope || retainedNames.isNotEmpty(),"RETAINED_SCOPE_WITHOUT_CPH")
    val oldSessions=sessions(baseline.project)
    fun container(name:String,key:String,existing:List<JsonElement>,extra:List<JsonElement>):Pair<String,JsonElement> =
        name to JsonObject(oldSessions[name]?.jsonObject.orEmpty()+
            (key to JsonArray(existing+extra.filter { e -> existing.none { canonical(it)==canonical(e) } })))
    val keptSessions=JsonObject(oldSessions+mapOf(
        container("session_handling_rules","rules",baselineRules,rules.map { JsonObject(it+("enabled" to JsonPrimitive(false))) }),
        container("macros","macros",baselineMacros,macros.values.toList())
    ))
    var project=baseline.project
    val newRoot=JsonObject(root(project)+("sessions" to keptSessions))
    project=if("project_options" in project) JsonObject(project+("project_options" to newRoot)) else newRoot
    // Retain only the approved scope additions, never temporary resource pools or unrelated options.
    if(selection.retainTargetScope) {
        fun mergeTarget(destination:JsonObject,sources:List<JsonObject>):JsonObject {
            var target=destination["target"]?.jsonObject ?: JsonObject(emptyMap())
            sources.mapNotNull { it["target"]?.jsonObject?.get("scope")?.jsonObject }.forEach { scope ->
                val old=target["scope"]?.jsonObject ?: JsonObject(emptyMap())
                val merged=JsonObject(old+scope+listOf("include","exclude").associateWith { key ->
                    JsonArray((old[key]?.jsonArray.orEmpty()+scope[key]?.jsonArray.orEmpty()).distinct())
                })
                target=JsonObject(target+("scope" to merged))
            }
            return if(target.isEmpty()) destination else JsonObject(destination+("target" to target))
        }
        val mergedRoot=mergeTarget(root(project),plan.variants.map { root(it.project) })
        project=if("project_options" in project) mergeTarget(JsonObject(project+("project_options" to mergedRoot)),plan.variants.map { it.project }) else mergedRoot
    }
    val cph=JsonObject(baseline.cph+retainedNames.associateWith { name ->
        val value=available.getValue(name)
        when {
            name==digest("options") -> baseline.cph[name] ?: value
            name in baseline.cph -> value
            else -> JsonObject(value.jsonObject+("enabled" to JsonPrimitive(false)))
        }
    })
    // Topological cache dependencies first; baseline-relative order remains unchanged.
    val order=mutableListOf<String>();val visiting=mutableSetOf<String>()
    fun orderTab(name:String) {
        if(name in order) return
        requireJob(visiting.add(name),"RETAINED_CPH_CYCLE")
        val tab=cph.getValue(name).jsonObject
        if(tab["dynamic_checkbox"]==JsonPrimitive(true) && tab["extract_choice_index"]==JsonPrimitive(2))
            orderTab(tab["cached_selection"]!!.jsonPrimitive.content)
        visiting.remove(name);order.add(name)
    }
    (baseline.cphOrder+retainedNames).filter { it!=digest("options") }.forEach(::orderTab)
    if(digest("options") in cph) order.add(digest("options"))
    return baseline.copy(project=project,cph=cph,cphOrder=order)
}

/** Shared definitions now come from the retained baseline; leave all transient work in each variant. */
internal fun withoutRetainedDefinitions(job:JobProposal,retained:BurpSnapshot,initial:List<CompiledVariant>):JobProposal {
    val ruleNames=job.authenticationRetention!!.ruleDescriptions.toSet()
    val serials=definitions(retained.project,"macros","macros").map { it.jsonObject["serial_number"] }.toSet()
    return job.copy(authenticationRetention=null,variants=job.variants.mapIndexed { index,variant ->
        val settings=variant.settings
        val retainedRules=settings.rules.filter { it.jsonObject["description"]?.jsonPrimitive?.content in ruleNames }
        val retainedCph=settings.cph.filterKeys { name -> name in retained.cph && name!=digest("options") }.filter { (name,value) ->
            cphDefinitions(JsonObject(mapOf(name to JsonObject(value.jsonObject-"enabled"))))==
                cphDefinitions(JsonObject(mapOf(name to JsonObject(retained.cph.getValue(name).jsonObject-"enabled"))))
        }
        val activeCph=retainedCph.values.any { it.jsonObject["enabled"]!=JsonPrimitive(false) } ||
            settings.authenticationStates?.cph.orEmpty().values.any { it }
        val states=AuthenticationStates(
            retainedRules.associate { it.jsonObject["description"]!!.jsonPrimitive.content to it.jsonObject["enabled"]!!.jsonPrimitive.boolean }+
                settings.authenticationStates?.rules.orEmpty(),
            retainedCph.mapValues { it.value.jsonObject["enabled"]?.jsonPrimitive?.booleanOrNull ?: true }+
                settings.authenticationStates?.cph.orEmpty(),
            settings.authenticationStates?.cphTools?.takeIf { it.isNotEmpty() }
                ?: if(activeCph) configuredAuthenticationTools(initial[index].cph) else emptyList())
        variant.copy(settings=settings.copy(
            rules=JsonArray(settings.rules.filter { it.jsonObject["description"]?.jsonPrimitive?.content !in ruleNames }),
            macros=JsonArray(settings.macros.filter { it.jsonObject["serial_number"] !in serials }),
            authenticationStates=states.takeIf { it.rules.isNotEmpty() || it.cph.isNotEmpty() },
            cph=JsonObject(settings.cph.filter { (name,value) -> if(name in retainedCph) false else retained.cph[name]?.let {
                cphDefinitions(JsonObject(mapOf(name to it)))!=cphDefinitions(JsonObject(mapOf(name to value)))
            } ?: true })
        ))
    })
}
