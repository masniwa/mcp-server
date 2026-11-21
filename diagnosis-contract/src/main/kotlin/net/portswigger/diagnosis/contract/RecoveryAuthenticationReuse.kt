package net.portswigger.diagnosis.contract

import kotlinx.serialization.json.*

/** Reuse only definitions justified by the saved retention plan and the fresh Project snapshot. */
fun reuseRecoveredAuthentication(plan:CompiledPlan,proposal:JobProposal,current:BurpSnapshot):JobProposal {
    val saved=plan.restorationBaseline ?: return proposal
    val selection=plan.proposal.authenticationRetention ?: return proposal
    requireJob(plan.baseline.projectMarker!=null && current.projectMarker==plan.baseline.projectMarker,"PROJECT_IDENTITY_UNVERIFIED")
    fun definitions(snapshot:BurpSnapshot,container:String,key:String):List<JsonElement> {
        val root=(snapshot.project["project_options"] as? JsonObject) ?: snapshot.project
        return ((root["sessions"] as? JsonObject)?.get(container) as? JsonObject)?.get(key)?.jsonArray.orEmpty()
    }
    fun macroId(value:JsonElement)=value.jsonObject.getValue("serial_number")
    fun ruleName(value:JsonElement)=value.jsonObject.getValue("description").jsonPrimitive.content
    val savedMacros=definitions(saved,"macros","macros")
    val currentMacros=definitions(current,"macros","macros")
    val savedRules=definitions(saved,"session_handling_rules","rules")
    val currentRules=definitions(current,"session_handling_rules","rules")
    val originalMacroIds=definitions(plan.baseline,"macros","macros").map(::macroId).toSet()
    val retainedCph=cphDependencyClosure(saved.cph,selection.cphNames.toSet())
    fun sameMacro(left:JsonElement,right:JsonElement):Boolean {
        fun view(value:JsonElement)=projectDefinitions(buildJsonObject {
            putJsonObject("sessions") { putJsonObject("macros") { put("macros",JsonArray(listOf(value))) } }
        })
        return view(left)==view(right)
    }
    fun cphView(name:String,value:JsonElement)=cphDefinitions(JsonObject(mapOf(name to JsonObject(value.jsonObject-"enabled"))))
    return proposal.copy(variants=proposal.variants.mapIndexed { index,variant ->
        val settings=variant.settings
        val reusedRules=linkedMapOf<String,Boolean>()
        val rules=settings.rules.filter { rule ->
            val name=ruleName(rule)
            val observed=currentRules.filter { ruleName(it)==name }
            if(observed.isEmpty() || name !in selection.ruleDescriptions) true else {
                requireJob(observed.size==1,"NATIVE_RULE_MISSING_OR_AMBIGUOUS")
                val retained=savedRules.singleOrNull { ruleName(it)==name }?.jsonObject
                    ?: throw JobRejected("RECOVERY_REPLAN_RULE_NOT_RETAINED")
                val actual=observed.single().jsonObject
                val enabled=actual["enabled"] ?: throw JobRejected("RECOVERY_REPLAN_RULE_CONFLICT")
                requireJob(nativeRuleReadbackEquivalent(JsonObject(retained+("enabled" to enabled)),actual) &&
                    nativeRuleReadbackEquivalent(JsonObject(rule.jsonObject+("enabled" to enabled)),actual),"RECOVERY_REPLAN_RULE_CONFLICT")
                reusedRules[name]=rule.jsonObject.getValue("enabled").jsonPrimitive.boolean
                false
            }
        }
        val macros=settings.macros.filter { macro ->
            val observed=currentMacros.filter { macroId(it)==macroId(macro) }
            if(observed.isEmpty() || macroId(macro) in originalMacroIds) true else {
                val retained=savedMacros.singleOrNull { macroId(it)==macroId(macro) }
                requireJob(observed.size==1 && retained!=null && sameMacro(retained,observed.single()) &&
                    sameMacro(macro,observed.single()),"RECOVERY_REPLAN_MACRO_CONFLICT")
                false
            }
        }
        val reusedCph=linkedMapOf<String,Boolean>()
        val cph=settings.cph.filter { (name,value) ->
            val observed=current.cph[name]
            val retained=saved.cph[name]
            if(name !in retainedCph || observed==null || retained==null) true else {
                requireJob(cphView(name,retained)==cphView(name,observed) && cphView(name,value)==cphView(name,observed),"RECOVERY_REPLAN_CPH_CONFLICT")
                reusedCph[name]=value.jsonObject["enabled"]?.jsonPrimitive?.booleanOrNull ?: true
                false
            }
        }
        val prior=settings.authenticationStates
        requireJob(reusedRules.all { (name,value) -> prior?.rules?.get(name)?.let { it==value } ?: true } &&
            reusedCph.all { (name,value) -> prior?.cph?.get(name)?.let { it==value } ?: true },"RECOVERY_REPLAN_STATE_CONFLICT")
        val cphStates=reusedCph+prior?.cph.orEmpty()
        val active=cphStates.values.any { it }
        val states=AuthenticationStates(reusedRules+prior?.rules.orEmpty(),cphStates,
            if(!active) emptyList() else prior?.cphTools?.takeIf { it.isNotEmpty() }
                ?: configuredAuthenticationTools(plan.variants[index].cph))
        variant.copy(settings=settings.copy(macros=JsonArray(macros),rules=JsonArray(rules),cph=JsonObject(cph),
            authenticationStates=states.takeIf { it.rules.isNotEmpty() || it.cph.isNotEmpty() }))
    })
}
