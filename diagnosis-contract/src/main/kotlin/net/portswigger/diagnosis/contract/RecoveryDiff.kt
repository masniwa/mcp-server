package net.portswigger.diagnosis.contract

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*

@Serializable
enum class RecoveryDisposition { KEEP, RESTORE_OWNED, CONFLICT_REVIEW, UNKNOWN_OWNER }

/** Missing properties are Kotlin null, distinct from an explicit JSON null. */
@Serializable
data class RecoveryDifference(
    val path: String,
    val baseline: JsonElement?,
    val approved: JsonElement?,
    val applied: JsonElement?,
    val current: JsonElement?,
    val disposition: RecoveryDisposition,
    val restoration:JsonElement? = null,
    val restorationSpecified:Boolean = false
)

/**
 * Pure four-way comparison. Arrays are atomic until their adapter supplies stable identities.
 * Applied values may establish a native readback difference, never expand approved ownership.
 * No normalization, imports, approval, traffic or lock changes occur here.
 */
fun recoveryDifferences(
    baseline: JsonObject,
    approved: JsonObject,
    applied: JsonObject?,
    current: JsonObject
): List<RecoveryDifference> {
    val result = mutableListOf<RecoveryDifference>()
    fun visit(path: String, before: JsonElement?, planned: JsonElement?, observed: JsonElement?, now: JsonElement?) {
        val values = listOfNotNull(before, planned, observed, now)
        if (before is JsonObject && planned is JsonObject && now is JsonObject &&
            (observed == null || observed is JsonObject)) {
            val keys = values.flatMap { (it as JsonObject).keys }.toSortedSet()
            for (key in keys) {
                val token = key.replace("~", "~0").replace("/", "~1")
                visit("$path/$token", (before as? JsonObject)?.get(key),
                    (planned as? JsonObject)?.get(key), (observed as? JsonObject)?.get(key),
                    (now as? JsonObject)?.get(key))
            }
            return
        }
        if (before == planned && before == observed && before == now) return
        val disposition = when {
            before == planned && now == before -> RecoveryDisposition.KEEP
            before == planned && observed != null && observed != before -> RecoveryDisposition.UNKNOWN_OWNER
            before == planned -> RecoveryDisposition.KEEP
            now == before -> RecoveryDisposition.KEEP
            now == planned -> RecoveryDisposition.RESTORE_OWNED
            else -> RecoveryDisposition.CONFLICT_REVIEW
        }
        result.add(RecoveryDifference(path, before, planned, observed, now, disposition))
    }
    visit("", baseline, approved, applied, current)
    return result
}

/** Build a candidate only. The service must separately prove stop safety and obtain REVIEW. */
fun recoveryRestoreCandidate(current: JsonObject, differences: List<RecoveryDifference>): JsonObject {
    requireJob(differences.none { it.disposition in setOf(RecoveryDisposition.CONFLICT_REVIEW,
        RecoveryDisposition.UNKNOWN_OWNER) }, "RECOVERY_DIFFERENCES_REQUIRE_REVIEW")
    fun replace(value: JsonObject, tokens: List<String>, replacement: JsonElement?): JsonObject {
        val key = tokens.first()
        if (tokens.size == 1) return JsonObject(if (replacement == null) value - key else value + (key to replacement))
        val child = value[key] as? JsonObject ?: throw JobRejected("RECOVERY_PATH_CHANGED")
        val updated = replace(child, tokens.drop(1), replacement)
        return JsonObject(value + (key to updated))
    }
    var candidate = current
    for (difference in differences.filter { it.disposition == RecoveryDisposition.RESTORE_OWNED }) {
        requireJob(difference.path.startsWith("/"), "RECOVERY_PATH_CHANGED")
        val tokens = difference.path.drop(1).split("/").map { it.replace("~1", "/").replace("~0", "~") }
        var actual: JsonElement? = current
        for (token in tokens) actual = (actual as? JsonObject)?.get(token)
        requireJob(actual == difference.current, "CURRENT_CONTEXT_CHANGED")
        candidate = replace(candidate, tokens, difference.baseline)
    }
    return candidate
}