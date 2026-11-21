package net.portswigger.diagnosis.contract

import kotlinx.serialization.json.*

const val LEGACY_SCAN_START_DENIED="Start active scan denied by Burp Suite"
private val beforeAuditStages=setOf("INPUT_DECODING","PRECHECK","PERMISSION_CHECK","REQUEST_PREPARATION","PAYLOAD_PREPARATION")
private val startCode=Regex("[A-Z][A-Z0-9_]{0,99}")
fun scanStartErrorCode(result:JsonObject):String? = (result["errorCode"] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull?.takeIf(startCode::matches)

/** Safe public diagnostics; the complete response remains separately digest-checked in the operation record. */
fun scanStartSummary(result:JsonObject):JsonObject = buildJsonObject {
    put("responseDigest",fingerprint(result))
    for(key in listOf("status","stage","causeClass","cleanupErrorClass","localPreparationCleanup")) {
        val value=(result[key] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull
        if(value!=null && value.matches(Regex("[A-Za-z][A-Za-z0-9_$]{0,159}"))) put(key,value)
    }
    scanStartErrorCode(result)?.let { put("errorCode",it) }
    for(key in listOf("nativeAuditCreated","submissionAttempted"))
        result[key]?.takeIf { it==JsonPrimitive(true) || it==JsonPrimitive(false) || it==JsonNull }?.let { put(key,it) }
    put("submissionErrorObserved",result["submissionError"]?.let { it!=JsonNull } ?: false)
    put("observationErrorObserved",result["observationError"]?.let { it!=JsonNull } ?: false)
}

/** Producer-side observation only. No AI approval/stop input can supply this result. */
fun scanStartNotSubmitted(code:String,stage:String,causeClass:String?=null):JsonObject {
    requireJob(stage in beforeAuditStages && startCode.matches(code),"INVALID_START_REJECTION")
    return buildJsonObject {
        put("status","not_submitted");put("nativeAuditCreated",false);put("submissionAttempted",false)
        put("errorCode",code);put("stage",stage)
        causeClass?.let { put("causeClass",it) }
    }
}

/** Incomplete or contradictory proof remains unknown; old committed operations are never rewritten. */
fun provenNoAuditStart(result:JsonObject):Boolean {
    val code=scanStartErrorCode(result)
    val stage=(result["stage"] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull
    return result["status"]==JsonPrimitive("not_submitted") &&
        result["nativeAuditCreated"]==JsonPrimitive(false) && result["submissionAttempted"]==JsonPrimitive(false) &&
        listOf("submissionError","observationError").all { result[it]==null || result[it]==JsonNull } &&
        listOf("completed","nativeCompleted").all { result[it]==null || result[it]==JsonNull || result[it]==JsonPrimitive(false) } &&
        (result["auditId"]==null || result["auditId"]==JsonNull) && stage in beforeAuditStages &&
        code!=null && startCode.matches(code)
}
