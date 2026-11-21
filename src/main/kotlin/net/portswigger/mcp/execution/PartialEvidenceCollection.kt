package net.portswigger.mcp.execution

import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.JobRejected
import net.portswigger.diagnosis.contract.loggerCaptureWindow
import net.portswigger.diagnosis.contract.loggerCaptureWindowHealthy

/** Independent read-only observations. One unavailable source never discards another source. */
internal fun collectPartialEvidence(
    auditId:String,
    payloadExpected:Boolean,
    native:()->JsonObject,
    payloadPages:((JsonObject)->Unit)->Unit,
    loggerStatus:()->JsonObject,
    loggerPages:(JsonObject,(JsonElement)->Unit)->Unit,
    issues:((JsonElement)->Unit)->Unit,
    loggerCheckpoint:JsonObject?=null,
    savePage:((String,JsonElement)->JsonElement)?=null
):JsonObject {
    val errors=linkedMapOf<String,JsonElement>()
    val errorDetails=linkedMapOf<String,JsonElement>()
    fun <T> observe(source:String,read:()->T):T? = try { read() } catch(error:Exception) {
        errors[source]=JsonPrimitive((error as? JobRejected)?.code ?: error.javaClass.simpleName)
        (error as? JobRejected)?.safeDetails?.takeIf { it.isNotEmpty() }?.let { details ->
            errorDetails[source]=buildJsonObject { details.forEach { (key,value) -> put(key,value) } }
        }
        null
    }
    val observedNative=observe("native",native)
    val payload=mutableListOf<JsonElement>()
    var callbacksFinished=true;var payloadCompleted=true
    observe("payload") { payloadPages {
        callbacksFinished=callbacksFinished && it["payloadCallbackFinished"]==JsonPrimitive(true) && it["timingControlsFinished"]!=JsonPrimitive(false)
        payloadCompleted=payloadCompleted && it["completed"]==JsonPrimitive(true)
        payload.add(savePage?.invoke("payloadPages",it) ?: it)
    } }
    val status=observe("loggerStatus",loggerStatus)
    val logs=mutableListOf<JsonElement>()
    status?.let { observe("loggerPages") { loggerPages(it) { page -> logs.add(savePage?.invoke("loggerPages",page) ?: page) } } }
    val observedIssues=mutableListOf<JsonElement>()
    observe("issues") { issues { observedIssues.add(savePage?.invoke("siteMapIssues",it) ?: it) } }
    val quiescent=errors.isEmpty() && observedNative?.get("completed")==JsonPrimitive(true) &&
        (!payloadExpected || payload.isNotEmpty()) && callbacksFinished
    val window=if(loggerCheckpoint!=null && status!=null) loggerCaptureWindow(loggerCheckpoint,status) else null
    val loggerComplete=if(loggerCheckpoint!=null) loggerCaptureWindowHealthy(window) else
        (status?.get("droppedEntries") as? JsonPrimitive)?.longOrNull==0L &&
            (status?.get("captureErrors") as? JsonPrimitive)?.longOrNull==0L
    val complete=quiescent && payloadCompleted && loggerComplete
    return buildJsonObject {
        put("auditId",auditId);put("native",observedNative ?: JsonNull)
        if(savePage!=null) put("evidencePageFormat","STORE_REFERENCES_V1")
        put("payloadPages",JsonArray(payload));put("siteMapIssues",JsonArray(observedIssues))
        put("issueAttribution","SITE_MAP_NOT_AUDIT_SPECIFIC")
        put("loggerStatus",status ?: JsonNull);put("loggerPages",JsonArray(logs))
        put("loggerWindow",window ?: JsonNull)
        put("collectionErrors",JsonObject(errors));put("complete",complete);put("quiescent",quiescent)
        if(errorDetails.isNotEmpty()) put("collectionErrorDetails",JsonObject(errorDetails))
        put("diagnosisCompleted",false);put("businessCleanupVerified",false)
    }
}
