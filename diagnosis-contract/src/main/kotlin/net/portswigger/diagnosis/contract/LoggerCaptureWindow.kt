package net.portswigger.diagnosis.contract

import kotlinx.serialization.json.*

/** Historical counters remain evidence; only a valid, loss-free current window is complete. */
fun loggerCaptureWindowHealthy(before:JsonObject,after:JsonObject):Boolean {
    fun number(value:JsonObject,key:String)=(value[key] as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull?.takeIf { it>=0 }
    val capture=(before["captureId"] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull
    if(capture.isNullOrBlank() || after["captureId"]!=before["captureId"]) return false
    val lower=number(before,"latestId") ?: return false
    val upper=number(after,"latestId") ?: return false
    if(upper<lower) return false
    return listOf("captureErrors","droppedEntries").all { key ->
        val initial=number(before,key)
        initial!=null && number(after,key)==initial
    }
}

fun loggerCaptureWindow(before:JsonObject,after:JsonObject):JsonObject = buildJsonObject {
    put("before",before);put("after",after)
    put("captureHealth",if(loggerCaptureWindowHealthy(before,after)) "NO_WINDOW_LOSS_OBSERVED" else "WINDOW_INCOMPLETE_OR_UNVERIFIED")
    put("historicalEvidencePreserved",true)
}

/** Recompute from immutable observations, never trust a caller-supplied health label. */
fun loggerCaptureWindowHealthy(window:JsonObject?):Boolean {
    val before=window?.get("before") as? JsonObject ?: return false
    val after=window["after"] as? JsonObject ?: return false
    return loggerCaptureWindowHealthy(before,after)
}
