package net.portswigger.mcp.tools

import kotlinx.serialization.Serializable

@Serializable
data class PayloadTimingLevel(val requestedDelayMillis: Long, val trueValue: String, val falseValue: String)
@Serializable
data class PayloadTimingControls(val positionId: String, val levels: List<PayloadTimingLevel>,
    val mode: String = "replace", val repetitions: Int = 3)

/** Explicit confirmation inputs are separate from the unchanged spreadsheet selection. */
internal fun prepareTimingCollection(bytes: ByteArray, positions: List<PayloadWirePosition>,
    options: PayloadTimingControls): PayloadTimingCollection {
    require(options.levels.size in 2..6 && options.repetitions in 3..10) { "Use 2..6 levels and 3..10 repetitions" }
    require(options.mode in listOf("append", "replace")) { "Timing controls require append or replace" }
    val position = positions.singleOrNull { it.id == options.positionId }
        ?: error("Timing control position must be an exact preflight position ID")
    require(position.target == "parameter" && position.context in listOf("query", "form", "json-string", "json-value")) {
        "Timing controls require a parsed query, form or JSON value position"
    }
    fun materialize(value: String): ByteArray {
        require(value.toByteArray(Charsets.UTF_8).size <= 65536) { "Timing control value too large" }
        val catalog=PayloadProfileCatalog("0".repeat(64), listOf(ProfilePayload("CONFIRMATION",options.mode,"light",value,listOf(position.context))))
        val plan=PayloadWirePlan.create(bytes,catalog,"light",listOf(position))
        require(plan.candidates.single().state == "READY") { "Timing control has unresolved bindings" }
        return plan.materialize(0)
    }
    return PayloadTimingCollection(options.levels.map { TimingControlInput(it.requestedDelayMillis,
        bytes,materialize(it.trueValue),materialize(it.falseValue)) },options.repetitions)
}
