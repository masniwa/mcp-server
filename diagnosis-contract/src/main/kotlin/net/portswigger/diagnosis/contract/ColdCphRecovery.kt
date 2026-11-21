package net.portswigger.diagnosis.contract

import kotlinx.serialization.json.*

/** This candidate is checked BEFORE a separate trusted human review; never a normal ownership exception. */
fun checkColdCphRecoveryOwnership(plan:CompiledPlan,actual:BurpSnapshot) {
    val options=digest("options")
    val factory=buildJsonObject {
        listOf("repeater","scanner","extender","spider","intruder","sequencer","target","proxy").forEach {
            put("chkbox_$it",it in setOf("repeater","proxy"))
        }
        put("verbosity",3)
    }
    requireJob(actual.instanceId!=plan.baseline.instanceId && plan.baseline.cph.keys.any { it!=options } &&
        actual.cph==JsonObject(mapOf(options to factory)) && actual.cphOrder==listOf(options),
        "COLD_CPH_RECOVERY_NOT_AVAILABLE")
    // Reinsert only the trusted saved baseline for the ownership check. All Project,
    // capability, scope and resource-pool conflicts still use the ordinary strict guard.
    checkRecoveryOwnership(plan,actual.copy(cph=plan.baseline.cph,cphOrder=plan.baseline.cphOrder))
}
