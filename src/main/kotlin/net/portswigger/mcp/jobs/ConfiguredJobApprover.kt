package net.portswigger.mcp.jobs

import net.portswigger.diagnosis.contract.*
import net.portswigger.diagnosis.runner.HumanApprover

/** Authority comes from the selected installation, never approved=true in AI JSON. */
class ConfiguredJobApprover(private val delegate:HumanApprover,private val quick:Boolean):HumanApprover {
    private fun actor()="Quick:${System.getProperty("user.name")}"
    override fun review(plan:CompiledPlan,stage:ApprovalStage,report:ValidationReport?) =
        if(quick) actor() else delegate.review(plan,stage,report)
    override fun reviewRecovery(plan:CompiledPlan,record:ExecutionRecord,evidenceRef:String) =
        if(quick) actor() else delegate.reviewRecovery(plan,record,evidenceRef)
    override fun reviewRestore(plan:CompiledPlan,record:ExecutionRecord,evidenceRef:String) =
        if(quick) actor() else delegate.reviewRestore(plan,record,evidenceRef)
    override fun reviewContinuation(plan:CompiledPlan,record:ExecutionRecord,report:ValidationReport) =
        if(quick) actor() else delegate.reviewContinuation(plan,record,report)
    override fun reviewRetirement(plan:CompiledPlan,record:ExecutionRecord,evidenceRef:String,currentDigest:String) =
        if(quick) null else delegate.reviewRetirement(plan,record,evidenceRef,currentDigest)
}
