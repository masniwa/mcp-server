package net.portswigger.diagnosis.contract

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*

/** Exact native identity. Parameter names and native types are case sensitive. No values are retained. */
@Serializable data class InputParameter(val name:String,val type:String)
@Serializable data class InputExclusion(val name:String,val type:String,val reason:String)

/** Structural checks shared with a native, traffic-free inventory check at formal registration. */
object InputCoverage {
    /** A newly compiled explicit selection must preserve the independently declared request in every variant. */
    fun validateRequestedScope(job:JobProposal) {
        val requested=job.requestedInputParameters
        requireJob(requested.size<=128 && requested.all { it.name.isNotBlank() && it.type.isNotBlank() },"INVALID_REQUESTED_INPUT_PARAMETERS")
        requireJob(requested.distinct().size==requested.size,"DUPLICATE_REQUESTED_INPUT_PARAMETER")
        val selections=job.variants.map { selected(it.request.startOptions) }
        if(requested.isEmpty()) {
            requireJob(selections.all { it==null },"REQUESTED_INPUT_PARAMETERS_REQUIRED")
            return
        }
        selections.forEach { selection ->
            requireJob(selection!=null,"REQUESTED_INPUT_SELECTION_REQUIRED")
            requireJob(selection!!.toSet()==requested.toSet(),"REQUESTED_INPUT_COVERAGE_MISMATCH")
        }
    }

    fun selected(options:JsonObject):List<InputParameter>? {
        val value=options["insertionPointParameters"] ?: return null
        val selectors=value as? JsonArray ?: throw JobRejected("INVALID_INPUT_SELECTION")
        requireJob(selectors.size in 1..128,"INVALID_INPUT_SELECTION")
        val result=selectors.map {
            val selector=it as? JsonObject ?: throw JobRejected("INVALID_INPUT_SELECTION")
            requireJob(selector.keys==setOf("name","type"),"INVALID_INPUT_SELECTION")
            val name=selector["name"] as? JsonPrimitive
            val type=selector["type"] as? JsonPrimitive
            requireJob(name?.isString==true && type?.isString==true,"INVALID_INPUT_SELECTION")
            InputParameter(name!!.content,type!!.content).also { p ->
                requireJob(p.name.isNotBlank() && p.type.isNotBlank(),"INVALID_INPUT_SELECTION")
            }
        }
        requireJob(result.distinct().size==result.size,"DUPLICATE_INPUT_SELECTION")
        return result
    }

    fun validateDeclarations(options:JsonObject,exclusions:List<InputExclusion>) {
        val selected=selected(options)
        requireJob(exclusions.isEmpty() || selected!=null,"INPUT_EXCLUSIONS_REQUIRE_SELECTION")
        val excluded=exclusions.map { InputParameter(it.name,it.type) }
        requireJob(excluded.distinct().size==excluded.size,"DUPLICATE_INPUT_EXCLUSION")
        requireJob(exclusions.all { it.name.isNotBlank() && it.type.isNotBlank() && it.reason.isNotBlank() && it.reason.length<=1000 },"INPUT_EXCLUSION_REASON_REQUIRED")
        requireJob(excluded.none { it in selected.orEmpty() },"SELECTED_INPUT_EXCLUDED")
    }

    /** Inventory is supplied by Montoya, never reconstructed from an incomplete raw HTTP parser. */
    fun validateInventory(options:JsonObject,exclusions:List<InputExclusion>,inventory:List<InputParameter>) {
        validateDeclarations(options,exclusions)
        val selected=selected(options) ?: return
        val available=inventory.toSet()
        requireJob(selected.all { it in available },"SELECTED_INPUT_NOT_FOUND")
        val excluded=exclusions.map { InputParameter(it.name,it.type) }.toSet()
        requireJob(excluded.all { it in available },"EXCLUDED_INPUT_NOT_FOUND")
        requireJob(available-selected.toSet()==excluded,"INPUT_EXCLUSION_REQUIRED")
    }

    /** Native update restrictions are by name, so a different location/type cannot protect an attacked name. */
    fun mayUpdateInputs(actions:List<JsonObject>):Boolean = actions.any { action ->
        action["enabled"]!=JsonPrimitive(false) && when(action["type"]) {
            JsonPrimitive("run_macro") -> action["update_with_params"]!=JsonPrimitive(false)
            JsonPrimitive("validate_session") -> action["perform_action_if_invalid"]!=JsonPrimitive(false) &&
                action["action"]==JsonPrimitive("run_macro") &&
                (action["run_macro_action"] as? JsonObject)?.get("update_with_params")!=JsonPrimitive(false)
            else -> false
        }
    }

    fun validateMacroPreservation(options:JsonObject,actions:List<JsonObject>,automaticInventory:List<InputParameter>?=null) {
        val selected=selected(options) ?: automaticInventory ?: return
        val names=selected.map { it.name }.toSet()
        fun checkMacro(action:JsonObject) {
            if(action["enabled"]==JsonPrimitive(false) || action["update_with_params"]==JsonPrimitive(false)) return
            requireJob(action["update_with_params"]==JsonPrimitive(true),"MACRO_INPUT_UPDATE_UNSPECIFIED")
            val specified=action["specified_params"]?.let { value ->
                val values=value as? JsonArray ?: throw JobRejected("INVALID_MACRO_INPUT_UPDATE")
                values.map { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content ?: throw JobRejected("INVALID_MACRO_INPUT_UPDATE") }.toSet()
            }.orEmpty()
            val overwritten=when(action["match_params"]) {
                JsonPrimitive("specified") -> names.intersect(specified)
                JsonPrimitive("all_except") -> names-specified
                else -> throw JobRejected("MACRO_INPUT_UPDATE_UNSPECIFIED")
            }
            requireJob(overwritten.isEmpty(),"MACRO_OVERWRITES_DIAGNOSTIC_INPUT")
        }
        actions.forEach { action ->
            if(action["enabled"]!=JsonPrimitive(false)) when(action["type"]) {
                JsonPrimitive("run_macro") -> checkMacro(action)
                JsonPrimitive("validate_session") -> if(action["perform_action_if_invalid"]!=JsonPrimitive(false) && action["action"]==JsonPrimitive("run_macro")) {
                    val recovery=action["run_macro_action"] as? JsonObject ?: throw JobRejected("MACRO_INPUT_UPDATE_UNSPECIFIED")
                    checkMacro(recovery)
                }
                else -> Unit
            }
        }
    }

    /** Same conservative rule applicability used by compilation, including inherited native rules. */
    fun applicableActions(project:JsonObject,target:Endpoint):List<JsonObject> {
        val root=project["project_options"] as? JsonObject ?: project
        val rules=(root["sessions"] as? JsonObject)?.get("session_handling_rules") as? JsonObject
        return (rules?.get("rules") as? JsonArray).orEmpty().map { it.jsonObject }
            .filter { ruleMayApply(it,target) }.flatMap { (it["actions"] as? JsonArray).orEmpty() }
            .map { it.jsonObject }.filter { it["enabled"]!=JsonPrimitive(false) }
    }

    /** Unknown/advanced scopes are potentially applicable; exclusions are never used to skip a guard. */
    fun ruleMayApply(rule:JsonObject,target:Endpoint):Boolean {
        if(rule["enabled"]?.jsonPrimitive?.booleanOrNull==false) return false
        val tools=rule["tools_scope"] as? JsonArray
        if(tools!=null && tools.none { it.jsonPrimitive.content in setOf("Scanner","Extensions") }) return false
        if(rule["url_scope"]?.jsonPrimitive?.content!="custom" || rule["url_scope_advanced_mode"]?.jsonPrimitive?.booleanOrNull==true) return true
        val includes=rule["include_in_scope"] as? JsonArray ?: return true
        return includes.any { entry ->
            val e=entry.jsonObject
            if(e["enabled"]?.jsonPrimitive?.booleanOrNull==false) false else try {
                val prefix=endpoint(e["prefix"]!!.jsonPrimitive.content)
                val host=prefix.host.equals(target.host,true) || e["include_subdomains"]?.jsonPrimitive?.booleanOrNull==true && target.host.endsWith(".${prefix.host}",true)
                host && prefix.port==target.port && prefix.scheme==target.scheme && target.path.startsWith(prefix.path)
            } catch(exception:Exception) { true }
        }
    }
}
