package net.portswigger.mcp.jobs
import kotlinx.serialization.json.encodeToJsonElement

import net.portswigger.diagnosis.contract.*
import net.portswigger.diagnosis.runner.HumanApprover
import net.portswigger.diagnosis.runner.ReviewArtifacts
import net.portswigger.diagnosis.runner.reviewProjection
import java.nio.file.Path
import java.util.concurrent.FutureTask
import javax.swing.*

internal fun reviewRequestedInputSummary(proposal:JobProposal):String=buildString {
    val requested=proposal.requestedInputParameters
    if(requested.isNotEmpty()) {
        appendLine("依頼入力（計画の独立宣言）：${requested.size}項目")
        requested.forEach { appendLine("依頼入力：${it.name} [${it.type}]") }
        append("原本のユーザー依頼と照合してください。除外理由や別Scanの予定では、この範囲を縮小できません。")
    } else if(proposal.variants.any { InputCoverage.selected(it.request.startOptions)!=null }) {
        append("依頼入力：未宣言（旧保存計画の表示。新規の明示的な入力選択には独立した依頼入力宣言が必要です）")
    } else append("依頼入力：自動選択（明示的な入力選択なし）")
}

internal fun reviewVariantSummary(variant:ScanVariant,requested:List<InputParameter> = emptyList()):String=buildString {
    val selected=InputCoverage.selected(variant.request.startOptions)
    appendLine("診断入力：${selected?.joinToString { "${it.name} [${it.type}]" } ?: "自動選択（insertionPointParameters未指定）"}")
    if(selected!=null) appendLine("選択入力数：${selected.size}項目")
    if(requested.isNotEmpty()) appendLine("依頼入力との一致：${if(selected?.toSet()==requested.toSet()) "一致" else "不一致（送信不可）"}")
    if(variant.inputExclusions.isEmpty()) appendLine("明示除外：なし")
    else variant.inputExclusions.forEach { appendLine("明示除外：${it.name} [${it.type}]、理由：${it.reason}") }
    append("開始前の一度だけの準備：${variant.preparationOnce.size}件（各リクエストのMacroとは別。5回以上の検証送信には数えません）")
}

class SwingJobApprover(private val directory:Path,private val owner:()->java.awt.Component?={null},
    private val phase:(String)->Unit={}) : HumanApprover {
    private fun confirm(message:String,title:String):String? {
        return if(ReviewApprovalDialog.show(owner(),title,listOf(ApprovalPage("操作内容",message)),
                "内容と対象を確認し、許可する場合は「操作を許可する」にチェックしてOKを押してください。"))
            System.getProperty("user.name") else null
    }
    private fun await(task:FutureTask<String?>,stage:String):String? {
        phase("AWAITING_${stage}_APPROVAL")
        try {
            if(SwingUtilities.isEventDispatchThread()) task.run() else SwingUtilities.invokeLater(task)
            return task.get()
        } finally { phase("RUNNING") }
    }
    override fun reviewRestore(plan:CompiledPlan,record:ExecutionRecord,evidenceRef:String):String? {
        val task=FutureTask<String?> {
            val message="実行ID：${record.executionId}、Audit：${record.auditId}\n計画：${plan.planDigest}\n証拠：$evidenceRef\n"+
                "終了・取消と関連通信の停止を照合した後、このジョブが変更した設定だけを元へ復元します。\n"+
                "Scanの開始・再開・取消、正常再送、対象データやセッションの削除は行いません。\n"+
                "他の操作による設定変更を検出した場合は上書きせず停止します。"
            confirm(message,"診断ジョブの設定復元")
        }
        return await(task,"RECOVERY")
    }
    override fun reviewRetirement(plan:CompiledPlan,record:ExecutionRecord,evidenceRef:String,currentDigest:String):String? {
        val task=FutureTask<String?> {
            confirm("保守対象の旧実行：${record.executionId}、旧Audit：${record.auditId}\n証拠：$evidenceRef\n現在の設定の照合値：$currentDigest\n"+
                "現在のProjectでDashboardを確認し、旧Auditを含むActive Scanと関連Macro・CPH通信が稼働していないことを確認してください。\n"+
                "旧Projectから切り替わり、旧ジョブの所有設定が現在のProjectに残っていないことを確認してください。\n"+
                "旧実行の排他所有だけを解除し、RETIRED_UNVERIFIED（診断・旧終了・復元・業務回収は未確認）として保持します。\n"+
                "現在の設定は保存したまま変更しません。旧結果・台帳は保持し、Scan制御・HTTP送信・設定Importは行いません。\n"+
                "旧Projectの終了や回復を確認済みとは扱いません。稼働中・状態不明の現在のTaskがある場合は承認しないでください。",
                "保守：旧実行の所有記録を未確認のまま終了")
        }
        return await(task,"RETIREMENT")
    }
    override fun reviewContinuation(plan:CompiledPlan,record:ExecutionRecord,report:ValidationReport):String? {
        val task=FutureTask<String?> {
            val message="実行ID：${record.executionId}、既存Audit：${record.auditId}\n計画：${plan.planDigest}\n"+
                "承認済みの設定と入力は変更されていません。Burpの画面で、同じAuditと現在の状態を確認してください。\n"+
                "このAuditの継続と、その後の承認済みの正常再送・設定復元を、さらに${plan.proposal.executionApprovalMaxAgeSeconds}秒間許可します。\n"+
                "新しいAuditの開始、過去の検査の再実行、APIによる一時停止Taskの再開は行いません。"
            confirm(message,"同じ診断Auditの継続確認")
        }
        return await(task,"CONTINUATION")
    }
    override fun reviewRecovery(plan:CompiledPlan,record:ExecutionRecord,evidenceRef:String):String? {
        val task=FutureTask<String?> {
            val message="実行ID：${record.executionId}、直前の状態：${record.state}、Audit：${record.auditId}\n"+
                "証拠：$evidenceRef\n計画：${plan.planDigest}\n"+
                "Burpの画面で、対象Auditの終了または取消、関連するMacro・CPH通信の終了、元設定の復元を確認してください。\n"+
                "旧実行を失敗・回復確認済みとして記録します。\n"+
                "Scanの再開・取消・再作成は行いません。業務データの復元は別途確認が必要です。"
            confirm(message,"手動回復の確認")
        }
        return await(task,"RECOVERY")
    }
    override fun review(plan:CompiledPlan,stage:ApprovalStage,report:ValidationReport?):String? {
        val artifacts=ReviewArtifacts(directory)
        val planFile=artifacts.write(jobJson.encodeToJsonElement(plan),"plan")
        val reportFile=report?.let { artifacts.write(jobJson.encodeToJsonElement(it),"validation") }
        val prompt=FutureTask<String?> {
            val text=buildString {
                val stageName=when(stage) { ApprovalStage.PREPARATION -> "準備（設定反映・検証送信）";ApprovalStage.EXECUTION -> "実行（Scan・結果保存・正常再送・設定復元）";ApprovalStage.RECOVERY -> "回復確認" }
                appendLine("診断ジョブ：${plan.proposal.jobId}、改訂：${plan.proposal.revision}")
                appendLine("承認段階：$stageName    計画：${plan.planDigest}")
                appendLine("アカウント：${plan.proposal.session.accountRef}")
                appendLine("セッション確認の判断：${plan.proposal.session.validationDecision}：${plan.proposal.session.decisionReason}")
                appendLine(reviewRequestedInputSummary(plan.proposal))
                appendLine("後処理：${plan.proposal.cleanupPolicy}")
                appendLine("承認の有効時間：${if(stage==ApprovalStage.EXECUTION) plan.proposal.executionApprovalMaxAgeSeconds else 3600L}秒。取消し・設定や入力の変更・検証の鮮度による停止条件は維持します。")
                if(plan.variants.any { it.variant.settings.serialScannerRequests })
                    appendLine("逐次実行：Default resource poolの同時実行数を一時的に1へ変更し、各段階の終了後に元へ戻します。共有する別Taskが動作中でないことを確認してください。")
                appendLine("BurpのScannerは派生リクエストを送る場合があります。この承認はネットワーク通信を制限する機能ではありません。")
                appendLine("一時停止・再開・取消は、対象を確認してBurpの画面で操作する必要があります。")
                appendLine("送信先：");plan.expandedEndpoints.forEach { appendLine(it.url()) }
                appendLine("診断構成：");plan.variants.forEach {
                    appendLine("${it.variant.id}：${it.variant.kind}、設定=${it.settingsDigest}、検証分岐=${it.variant.requiredBranches}")
                    appendLine(reviewVariantSummary(it.variant,plan.proposal.requestedInputParameters))
                }
                plan.proposal.limitations.forEach { appendLine("制約：$it") }
                appendLine("承認前に、保護された保存先のBurp設定と証拠を確認してください。")
                appendLine("計画の原本：$planFile")
                reportFile?.let { appendLine("検証証拠の原本：$it") }
                if(report!=null) {
                    appendLine("検証送信の証拠：${report.probes.size}件、報告=${fingerprint(report)}")
                    appendLine("一度だけの準備の証拠：${report.preparationOnce.size}件（5回以上の検証送信の件数には含めません）")
                    appendLine("実通信のMacro・CPH置換、診断入力の保持、返却Response、後処理を確認してください。")
                    appendLine("HTTP応答の取得や5回の送信だけでは、意図した動作の成功は証明できません。")
                    appendLine("残存するCPHタブ：${report.residualCphTabs}")
                }
            }
            val nativeView=kotlinx.serialization.json.Json { prettyPrint=true }.encodeToString(
                kotlinx.serialization.json.JsonElement.serializer(),reviewProjection(jobJson.encodeToJsonElement(plan)))
            val duration=if(stage==ApprovalStage.EXECUTION) plan.proposal.executionApprovalMaxAgeSeconds else 3600L
            val explanation="計画・設定・実通信の証拠を確認し、この段階を${duration}秒間許可します。許可する場合は「操作を許可する」にチェックしてOKを押してください。"
            if(ReviewApprovalDialog.show(owner(),"診断ジョブの人間による承認",listOf(
                    ApprovalPage("対象範囲と証拠",text),ApprovalPage("Burp設定（保護対象の値はハッシュ表示）",nativeView,false)),explanation))
                System.getProperty("user.name") else null
        }
        return await(prompt,stage.name)
    }
}
