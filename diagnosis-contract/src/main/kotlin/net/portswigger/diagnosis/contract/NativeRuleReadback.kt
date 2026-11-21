package net.portswigger.diagnosis.contract

import kotlinx.serialization.json.*
import java.util.Locale

/** Identity-projected settings only; never normalize an arbitrary similarly named JSON container. */
internal fun projectedNativeRuleReadbackEquivalent(reference:JsonObject,observed:JsonObject,path:String):Boolean {
    val tokens=path.drop(1).split("/").map { it.replace("~1","/").replace("~0","~") }
    val container=when {
        tokens.take(5)==listOf("project","project_options","sessions","session_handling_rules","rules") -> 3
        tokens.take(4)==listOf("project","sessions","session_handling_rules","rules") -> 2
        else -> return false
    }
    val ruleTokens=tokens.take(container+3)
    if(ruleTokens.size!=container+3) return false
    fun rule(root:JsonObject):JsonObject? {
        var value:JsonElement?=root
        for(token in ruleTokens) value=(value as? JsonObject)?.get(token)
        return value as? JsonObject
    }
    return rule(reference)?.let { before -> rule(observed)?.let { nativeRuleReadbackEquivalent(before,it) } }==true
}

/** Only the observed native simple-scope query lowercasing; every other field stays exact. */
fun nativeRuleReadbackEquivalent(expected:JsonObject,actual:JsonObject):Boolean {
    if(expected==actual) return true
    if(expected["url_scope_advanced_mode"]!=JsonPrimitive(false)) return false
    var adjusted=expected
    for(field in listOf("include_in_scope","exclude_from_scope")) {
        if(expected[field]==actual[field]) continue
        val scopes=expected[field] as? JsonArray ?: return false
        val observed=actual[field] as? JsonArray ?: return false
        if(scopes.size!=observed.size) return false
        val values=scopes.zip(observed).map { (planned,native) ->
            val before=planned as? JsonObject ?: return false
            val after=native as? JsonObject ?: return false
            val prefix=(before["prefix"] as? JsonPrimitive)?.contentOrNull ?: return false
            val result=(after["prefix"] as? JsonPrimitive)?.contentOrNull ?: return false
            val query=prefix.indexOf('?')
            if(prefix!=result && !(query>=0 && prefix.substring(0,query+1)==result.take(query+1) &&
                prefix.substring(query+1).lowercase(Locale.ROOT)==result.drop(query+1))) return false
            JsonObject(before+("prefix" to JsonPrimitive(result)))
        }
        adjusted=JsonObject(adjusted+(field to JsonArray(values)))
    }
    return adjusted==actual
}
