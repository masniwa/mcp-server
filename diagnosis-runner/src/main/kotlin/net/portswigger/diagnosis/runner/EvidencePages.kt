package net.portswigger.diagnosis.runner

import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.*
import java.util.UUID

const val EVIDENCE_PAGE_FORMAT = "STORE_REFERENCES_V1"
val evidenceSources = setOf("loggerPages","payloadPages","siteMapIssues")
interface EvidenceStreamingPort {
    fun collectTo(auditId:String,payloadRunId:String?,save:(String,JsonElement)->JsonElement):JsonObject
}

/** Every page is durable before its producer reads the next. Interrupted collections remain discoverable. */
class EvidencePageWriter(private val store:JobStore,private val executionId:String,private val auditId:String) {
    private val key="evidence-collection:$executionId:${UUID.randomUUID()}"
    private val pages=evidenceSources.associateWith { mutableListOf<JsonElement>() }
    fun save(source:String,page:JsonElement):JsonElement {
        requireJob(source in evidenceSources,"UNKNOWN_EVIDENCE_SOURCE")
        val digest=fingerprint(page)
        val pageKey="evidence-page:$executionId:$source:$digest"
        val ref=buildJsonObject { put("key",pageKey);put("digest",digest) }
        store.transaction {
            if(!store.containsRecord(pageKey)) store.put(pageKey,page)
            else if(page is JsonPrimitive && page.isString) store.verifyJsonString(pageKey,digest)
            else requireJob(fingerprint(store.get(pageKey)!!)==digest,"EVIDENCE_CHANGED")
            store.put(key,JsonObject(manifest("COLLECTING")+(source to JsonArray(pages.getValue(source)+ref))))
        }
        pages.getValue(source).add(ref)
        return ref
    }
    private fun manifest(state:String)=buildJsonObject {
        put("auditId",auditId);put("state",state);put("evidencePageFormat",EVIDENCE_PAGE_FORMAT)
        put("diagnosisCompleted",false)
        pages.forEach { (source,refs) -> put(source,JsonArray(refs.toList())) }
    }
    fun finish(errors:JsonObject):String {
        store.put(key,JsonObject(manifest(if(errors.isEmpty()) "COLLECTED" else "PARTIAL")+("collectionErrors" to errors)))
        return key
    }
}

/** Legacy inline pages remain readable; new references never reinterpret arbitrary legacy JSON. */
fun SavedResults.pages(record:JsonObject,source:String,skipPages:Int=0):Sequence<JsonElement> {
    requireJob(source in evidenceSources,"UNKNOWN_EVIDENCE_SOURCE")
    val pages=(record[source] ?: if(source=="loggerPages") record["logger"]?.jsonObject?.get("pages") else null) as? JsonArray ?: JsonArray(emptyList())
    return if(record["evidencePageFormat"]==JsonPrimitive(EVIDENCE_PAGE_FORMAT)) pages.asSequence().drop(skipPages).map { resolvePage(it.jsonObject) }
        else pages.asSequence().drop(skipPages)
}
