package net.portswigger.mcp.jobs

import net.portswigger.diagnosis.contract.*
import net.portswigger.diagnosis.runner.HumanApprover

/** Authority comes from the selected installation, never approved=true in AI JSON. */
class ConfiguredJobApprover(private val delegate:HumanApprover,private val quick:Boolean):HumanApprover {
    override fun reviewReconciliation(plan:CompiledPlan,record:ExecutionRecord,evidenceRef:String,summary:kotlinx.serialization.json.JsonObject) =
        if(quick) null else delegate.reviewReconciliation(plan,record,evidenceRef,summary)
    override fun reviewInstallation(message:String) = if(quick) null else delegate.reviewInstallation(message)
    private fun actor()="Quick:${System.getProperty("user.name")}"
    override fun review(plan:CompiledPlan,stage:ApprovalStage,report:ValidationReport?) =
        if(quick) actor() else delegate.review(plan,stage,report)
    override fun reviewStint(stintId:String,plans:List<CompiledPlan>,reports:List<ValidationReport>) = if(quick) null else delegate.reviewStint(stintId,plans,reports)
    override fun reviewRecovery(plan:CompiledPlan,record:ExecutionRecord,evidenceRef:String) =
        if(quick) actor() else delegate.reviewRecovery(plan,record,evidenceRef)
    override fun reviewRestore(plan:CompiledPlan,record:ExecutionRecord,evidenceRef:String) =
        if(quick) actor() else delegate.reviewRestore(plan,record,evidenceRef)
    override fun reviewColdCphRestore(plan:CompiledPlan,record:ExecutionRecord,evidenceRef:String,currentDigest:String) =
        if(quick) null else delegate.reviewColdCphRestore(plan,record,evidenceRef,currentDigest)
    override fun reviewUnverifiedRestore(plan:CompiledPlan,record:ExecutionRecord,evidenceRef:String,currentDigest:String,coldCph:Boolean) =
        if(quick) null else delegate.reviewUnverifiedRestore(plan,record,evidenceRef,currentDigest,coldCph)
    override fun reviewContinuation(plan:CompiledPlan,record:ExecutionRecord,report:ValidationReport) =
        if(quick) actor() else delegate.reviewContinuation(plan,record,report)
    override fun reviewRetirement(plan:CompiledPlan,record:ExecutionRecord,evidenceRef:String,currentDigest:String) =
        if(quick) null else delegate.reviewRetirement(plan,record,evidenceRef,currentDigest)
    override fun reviewCphPrune(names:List<String>,evidenceRef:String,currentDigest:String,targetDigest:String) =
        if(quick) null else delegate.reviewCphPrune(names,evidenceRef,currentDigest,targetDigest)
    override fun reviewRestartCphRestore(sourceExecutionId:String,names:List<String>,evidenceRef:String,currentDigest:String,targetDigest:String) =
        if(quick) null else delegate.reviewRestartCphRestore(sourceExecutionId,names,evidenceRef,currentDigest,targetDigest)
}
