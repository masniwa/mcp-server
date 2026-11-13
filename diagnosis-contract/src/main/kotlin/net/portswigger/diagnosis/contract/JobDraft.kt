package net.portswigger.diagnosis.contract

import kotlinx.serialization.Serializable

/** An immutable static-check result, never an ExecutionRecord, approval or runtime validation. */
@Serializable data class JobDraft(
    val draftId: String,
    val baselineExecutionId: String?,
    val plan: CompiledPlan,
    val draftDigest: String
)

fun draftDigest(id: String, baselineExecutionId: String?, plan: CompiledPlan): String = fingerprint(
    listOf(id, baselineExecutionId.orEmpty(), plan.proposalDigest, plan.planDigest, fingerprint(plan.baseline))
)
