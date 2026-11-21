package net.portswigger.mcp.jobs
import kotlinx.serialization.json.*

import net.portswigger.diagnosis.contract.*
import net.portswigger.diagnosis.runner.HumanApprover
import net.portswigger.diagnosis.runner.ReviewArtifacts
import net.portswigger.diagnosis.runner.reviewProjection
import java.nio.file.Path
import java.util.concurrent.FutureTask
import javax.swing.*

internal fun reviewAuthenticationSummary(plan:CompiledPlan):String=buildString {
    val selection=plan.proposal.authenticationRetention
    if(selection!=null) {
        appendLine("再利用のため保持する認証Rule：${selection.ruleDescriptions}")
        appendLine("参照先Macroを自動保持。CPH：${selection.cphNames}（キャッシュ参照先も保持）")
        appendLine("新規の保持Rule・CPHは終了時に無効化してBurpに残します。Check session is validとMacroの定義は保持します。")
        appendLine("Target scopeの追加も保持：${selection.retainTargetScope}。一時的なresource poolは元へ戻します。")
        appendLine("準備未完了での回復は元のbaselineへ戻します。検証完了後の回復は認証定義を保持します。")
    } else if(plan.proposal.variants.any { variant -> variant.settings.rules.any { rule ->
        rule.jsonObject["actions"]?.jsonArray?.any { it.jsonObject["type"]==JsonPrimitive("validate_session") }==true
    } }) {
        appendLine("認証定義の保持指定なし：新規Rule・Macroは復元時に取り除きます。再利用して残す場合は計画を修正してください。")
    }
    plan.proposal.variants.forEach { variant -> variant.settings.authenticationStates?.let { states ->
        appendLine("${variant.id} 再利用認証Ruleの有効/無効：${states.rules}")
        appendLine("${variant.id} 再利用CPHの有効/無効：${states.cph}")
        appendLine("${variant.id} CPHに必要なTool範囲：${states.cphTools}（実行中のみ有効化し、終了後は元のOptionsへ戻します）")
    } }
}

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
    override fun reviewReconciliation(plan:CompiledPlan,record:ExecutionRecord,evidenceRef:String,summary:JsonObject):String? =
        await(FutureTask {
            confirm("実行：${record.executionId}、旧Audit：${record.auditId}\n証拠：$evidenceRef\n$summary\n"+
                "各JSON pathの保持・復元と照合値を確認してください。値は秘密を含むためdigestで表示しています。\n"+
                "同じ保存Projectであり、UI起点・旧参照のTaskを含む共有設定利用先、Macro、CPHと関連通信が停止していることを独立した証拠で確認してください。空の一覧やLogger停滞だけでは承認しないでください。\n"+
                "旧プロセス終了確認が必要と表示された場合は、保存Project/runtimeを保全した停止保守で旧Burpプロセスが終了した証拠も照合してください。\n"+
                "旧応答欠落・開始結果不明・診断不完全を保持し、選択した設定だけを整理して排他を解除します。旧Scanは再送しません。業務回収は未確認です。\n"+
                "後続は最新baselineから明示した新revisionを提案し、準備REVIEW・全必要分岐の検証・意味レビュー後に別のExecution REVIEWを受けてください。",
                "共通回復：項目別整理と独立した停止証拠の確認")
        },"COMMON_RECOVERY")
    override fun reviewInstallation(message:String):String? = await(FutureTask { confirm(message,"初回能力検証・登録") },"INSTALLATION")
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
                "他の操作による設定変更を検出した場合は上書きせず停止します。\n"+reviewAuthenticationSummary(plan)
            confirm(message,"診断ジョブの設定復元")
        }
        return await(task,"RECOVERY")
    }
    override fun reviewColdCphRestore(plan:CompiledPlan,record:ExecutionRecord,evidenceRef:String,currentDigest:String):String? {
        val task=FutureTask<String?> {
            confirm("実行ID：${record.executionId}、旧Audit：${record.auditId}\n証拠：$evidenceRef\n現在の設定の照合値：$currentDigest\n"+
                "CPHは再起動後の初期Optionsだけで、保存済みのハンドラーがありません。\n"+
                "現在のProjectが保全した同じProjectであり、Dashboardに稼働・状態不明のAuditやMacro・CPH通信がないことを確認してください。\n"+
                "この実行の正式な保存baselineから、CPH全定義・順序・Optionsと元のProject設定を復元します。\n"+
                "残っている別ハンドラーや変更されたOptions、他のProject設定変更は上書きしません。承認中の変更も拒否します。\n"+
                "過去の応答未観測・失敗記録は保持します。HTTP送信・Scan開始・再開・業務データ回収は行いません。",
                "保守：再起動で失われたCPH定義と元設定の復元")
        }
        return await(task,"RECOVERY")
    }
    override fun reviewUnverifiedRestore(plan:CompiledPlan,record:ExecutionRecord,evidenceRef:String,currentDigest:String,coldCph:Boolean):String? {
        val task=FutureTask<String?> {
            confirm("旧実行：${record.executionId}、旧Audit：${record.auditId}\n証拠：$evidenceRef\n現在設定：$currentDigest\n"+
                "現在のProjectとDashboardを確認し、稼働中・状態不明のAuditとMacro・CPH通信がないことを確認してください。\n"+
                (if(coldCph) "再起動でCPH定義が全て欠落した既知の初期状態から、保存baselineの定義を戻します。\n" else "")+
                "保存された元設定を復元します。対象HTTP送信やScan操作、業務データの回収は行いません。\n"+
                "旧補助通信の終了は証明できません。旧応答未観測と診断不完了を保持し、通常recover成功として記録しません。\n"+
                "設定やProjectが承認中に変わった場合は停止します。",
                "保守：旧通信終了未確認の設定復元")
        }
        return await(task,"UNVERIFIED_RECOVERY")
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
    override fun reviewCphPrune(names:List<String>,evidenceRef:String,currentDigest:String,targetDigest:String):String? {
        val task=FutureTask<String?> {
            confirm("削除対象：無効な診断ジョブ所有CPH定義 ${names.size}件\n"+
                names.joinToString("\n")+"\n\n証拠：$evidenceRef\n現在設定：$currentDigest\n削除後設定：$targetDigest\n"+
                "現在のProjectで稼働・状態不明のAudit、関連Macro・CPH通信、管理ジョブの排他所有がないことを確認してください。\n"+
                "表示した無効CPH定義だけを削除し、Project設定・Options・残すCPH定義と順序は変更しません。\n"+
                "HTTP送信、Scan開始・再開・取消、業務データ削除、診断台帳削除は行いません。",
                "保守：使用しないCPH定義の削除")
        }
        return await(task,"CPH_PRUNE")
    }
    override fun reviewRestartCphRestore(sourceExecutionId:String,names:List<String>,evidenceRef:String,currentDigest:String,targetDigest:String):String? {
        val task=FutureTask<String?> {
            confirm("保存元実行：$sourceExecutionId\n復元する無効CPH定義：${names.size}件\n"+
                names.joinToString("\n")+"\n\n証拠：$evidenceRef\n現在設定：$currentDigest\n復元後設定：$targetDigest\n"+
                "同じ保存Projectであること、Dashboardに稼働・状態不明のAuditとMacro・CPH通信がないことを確認してください。\n"+
                "正式baselineにある選択定義と必要な依存元だけを順序どおり復元します。その他の欠落定義は復元しません。\n"+
                "Project設定、Options、既存CPH定義、HTTP通信、Scan、診断台帳は変更しません。",
                "保守：再起動で欠けた無効CPH定義の復元")
        }
        return await(task,"CPH_RESTART_RESTORE")
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
    override fun reviewStint(stintId:String,plans:List<CompiledPlan>,reports:List<ValidationReport>):String? {
        val artifacts=ReviewArtifacts(directory)
        val finalReview=reports.isNotEmpty()
        val pages=plans.mapIndexed { i,p ->
            val source=artifacts.write(jobJson.encodeToJsonElement(p),"plan")
            ApprovalPage("${i+1}. ${p.proposal.jobId}",buildString {
                appendLine("改訂 ${p.proposal.revision}　計画 ${p.planDigest}")
                appendLine("設定・検証通信の原本：$source")
                appendLine(reviewAuthenticationSummary(p))
                p.expandedEndpoints.forEach { appendLine(it.url()) }
                p.variants.forEach { appendLine("${it.variant.id}　分岐 ${it.variant.requiredBranches}　設定 ${it.settingsDigest}") }
                reports.getOrNull(i)?.let {
                    p.variants.forEach { v ->
                        appendLine("${v.variant.id} Project設定：${artifacts.write(v.project,"project")}")
                        appendLine("${v.variant.id} CPH設定：${artifacts.write(v.cph,"cph")}")
                        appendLine("CPH順序：${v.cphOrder}")
                    }
                    appendLine("全検証証拠：${artifacts.write(jobJson.encodeToJsonElement(it),"validation")}")
                    appendLine("検証 ${it.probes.size}件　復元 ${it.restored}　残存CPH ${it.residualCphTabs}")
                }
            })
        }
        val label=if(finalReview) "全証拠と実行順の確認（開始操作なし）" else "設定反映と検証通信の承認（有効時間1時間）"
        return await(FutureTask {
            if(ReviewApprovalDialog.show(owner(),"スティント $stintId",pages,
                "$label。選択された${plans.size}件を表示順に確認してください。")) System.getProperty("user.name") else null
        },if(finalReview) "STINT_FINAL" else "STINT_PREPARATION")
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
                appendLine(reviewAuthenticationSummary(plan))
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
