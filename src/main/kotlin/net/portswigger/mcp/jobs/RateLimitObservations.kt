package net.portswigger.mcp.jobs

import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.CompiledPlan
import java.time.Instant

/** Summarizes received responses only. It never interprets application success or retries a check. */
internal object RateLimitObservations {
    private fun JsonObject.text(key:String)=(this[key] as? JsonPrimitive)?.contentOrNull
    private fun instant(row:JsonObject,key:String)=row.text(key)?.let { runCatching { Instant.parse(it) }.getOrNull() }
    private fun status(row:JsonObject):Int? {
        if(row.text("responseState")!="RESPONSE_RECEIVED") return null
        val response=row.text("response") ?: return null
        return response.substringBefore("\r\n").split(' ').takeIf { it.firstOrNull()?.startsWith("HTTP/")==true }
            ?.getOrNull(1)?.toIntOrNull()?.takeIf { it in 100..599 }
    }
    private fun key(row:JsonObject)=row.text("captureId") to (row["id"] as? JsonPrimitive)?.longOrNull
    private fun reference(row:JsonObject)=buildJsonObject {
        put("captureId",row.getValue("captureId"));put("id",row.getValue("id"))
    }
    private fun context(row:JsonObject):List<JsonElement>? {
        val line=row.text("request")?.substringBefore("\r\n")?.split(' ') ?: return null
        if(line.size!=3 || !line[1].startsWith('/') || row["httpService"] !is JsonObject || row.text("tool").isNullOrBlank()) return null
        return listOf(row.getValue("httpService"),row.getValue("tool"),JsonPrimitive(line[0]),JsonPrimitive(line[1]))
    }
    fun summarize(flows:JsonArray):JsonObject? {
        val entries=flows.flatMap { (it as? JsonObject)?.get("entries") as? JsonArray ?: JsonArray(emptyList()) }.mapNotNull { it as? JsonObject }
        var unresolved=0
        val rows=entries.groupBy(::key).mapNotNull { (key,versions) ->
            val requests=versions.map { listOf(it["request"],it["httpService"],it["tool"],it["requestTime"]) }.distinct()
            val received=versions.filter { status(it)!=null }
            val responses=received.map { listOf(it["response"],it["responseTime"]) }.distinct()
            if(key.first.isNullOrBlank() || key.second==null || requests.size!=1 || responses.size>1) { unresolved++;null }
            else received.firstOrNull() ?: versions.first()
        }
        val limited=rows.filter { status(it)==429 }
        if(entries.none { status(it)==429 }) return null
        val laterResponses=rows.filter { status(it) in 200..399 }.groupBy { key(it).first to context(it) }
        val observations=limited.sortedWith(compareBy({ it.text("captureId") },{ key(it).second })).map { row ->
            val signature=context(row);val responseAt=instant(row,"responseTime")
            val requestAt=instant(row,"requestTime")
            val temporalSource=signature!=null && requestAt!=null && responseAt!=null && responseAt>=requestAt
            val following=if(!temporalSource) null else laterResponses[key(row).first to signature].orEmpty().filter { later ->
                val laterRequest=instant(later,"requestTime");val laterResponse=instant(later,"responseTime")
                key(later).second!!>key(row).second!! && laterRequest!=null && laterResponse!=null &&
                    laterRequest>=responseAt && laterResponse>=laterRequest
            }.minByOrNull { key(it).second!! }
            buildJsonObject {
                put("response429Evidence",reference(row))
                put("timestampOrderAvailable",temporalSource)
                put("later2xx3xxEvidence",following?.let(::reference) ?: JsonNull)
                following?.let { put("laterStatusCode",status(it)!!) }
            }
        }
        return buildJsonObject {
            put("observed429Count",limited.size);put("unresolvedEvidenceEntries",unresolved);put("scope","ALL_SUPPLIED_FLOW_ENTRIES")
            put("observations",JsonArray(observations));put("configurationSource","NOT_PROVIDED")
            put("actualTaskPoolAssignmentVerified",false);put("authenticationOrApplicationRecoveryProven",false)
            put("sameFailedCheckRetryProven",false);put("automaticBackoffObserved",JsonNull)
            put("interpretation","OBSERVATIONS_ONLY_REVIEW_AFFECTED_INTERVALS_AND_EXISTING_NATIVE_STATE")
        }
    }
    /** The approved plan describes saved settings, never the actual native Task pool assignment. */
    fun savedDefaultPools(plan:CompiledPlan):JsonArray = JsonArray(plan.variants.map { variant ->
        val root=variant.project["project_options"] as? JsonObject ?: variant.project
        val pools=root["resource_pools"] as? JsonObject
        val pool=pools?.get("default_resource_pool") as? JsonObject
        buildJsonObject {
            put("variantId",variant.variant.id);put("settingsDigest",variant.settingsDigest)
            put("defaultPoolPresent",pool!=null)
            pool?.let {
                listOf("auto_backoff","auto_backoff_after_429_status_returned","concurrent_request_limit_enabled","concurrent_request_limit").forEach { field ->
                    val value=pool[field] as? JsonPrimitive
                    if(value!=null && !value.isString &&
                        (if(field=="concurrent_request_limit") value.intOrNull!=null else value.booleanOrNull!=null)) put(field,value)
                }
            }
        }
    })
}
