package net.portswigger.mcp.tools

/** A review inventory, never a final vulnerability report. No raw HTTP, regex text or matches. */
internal fun payloadReviewReport(runId: String, requestDigest: String,
    rows: List<Pair<PayloadExecutionItem, PayloadTriage>>, executionCompleted: Boolean,
    timingRows: List<PayloadExecutionItem> = emptyList(), timingComparison: TimingComparisonResult? = null): String {
    fun cell(value: String?) = value.orEmpty().replace("&", "&amp;").replace("<", "&lt;")
        .replace(">", "&gt;").replace("|", "&#124;").replace("\r", " ").replace("\n", " ")
        .replace("`", "&#96;").replace("[", "&#91;").replace("]", "&#93;")
    return buildString {
        appendLine("# 追加ペイロードの確認用レポート")
        appendLine()
        appendLine("**診断未完了：このレポートは観測と追加確認候補の一覧です。確定脆弱性の報告ではありません。**")
        appendLine()
        appendLine("実行ID：${cell(runId)}。対象リクエストSHA-256：${cell(requestDigest)}。")
        appendLine("実行・証拠収集の完了：$executionCompleted。予定候補：${rows.size}件。")
        val states = rows.groupingBy { it.first.state }.eachCount().toSortedMap()
        appendLine("実行状態：" + states.entries.joinToString("、") { "${cell(it.key)}=${it.value}" })
        appendLine("追加確認候補：${rows.count { it.second.state == "REVIEW_REQUIRED" }}件。")
        appendLine()
        appendLine("信号なしは安全の証明ではありません。正常・異常対照、反復、Logger照合、保存結果・後処理の確認が必要です。")
        appendLine("所要時間はBurp送信adapter全体で、Macro・待機等を含み得ます。単発遅延やHTTP 500では脆弱性を確定しません。")
        appendLine("Scanner baselineの妥当性も検証してください。脆弱性の確定判断は別途必要です。")
        appendLine()
        appendLine("| 証拠番号 | Payload ID | 位置 | 方法 | 実行状態・理由 | 観測信号 | HTTP | 送信処理ms | 本文byte | 応答SHA-256 |")
        appendLine("|---|---|---|---|---|---|---|---|---|---|")
        rows.forEach { (item, triage) ->
            val duration = item.sendCallElapsedNanos?.let { java.math.BigDecimal.valueOf(it, 6).toPlainString() } ?: "未計測"
            val signals = triage.signals.ifEmpty { listOf(triage.state) }.joinToString(", ")
            appendLine("| ${item.index} | ${cell(item.payloadId)} | ${cell(item.positionId)} | ${cell(item.mode)} | " +
                "${cell(item.state)} ${cell(item.reason)} | ${cell(signals)} | ${item.statusCode ?: "—"} | $duration | " +
                "${triage.response?.bodyBytes ?: "—"} | ${cell(item.responseSha256)} |")
        }
        appendLine()
        appendLine("証拠番号は同じ実行の結果indexに対応します。通信はMCPのincludeWireEvidenceで取得し、認証情報の取扱いに注意してください。")
        appendLine("各項目の不足条件はtriage.limitationsを参照してください。Grep一致や差分の再現性、原因、影響を確認してから判断理由を付けて報告します。")
        appendLine()
        appendLine("## 時間差の追加対照")
        if (timingComparison == null) {
            appendLine("この実行には時間差の追加対照は設定されていません。所要時間だけでSQLiとは判断できません。")
        } else {
            appendLine("比較結果：${cell(timingComparison.state)}。理由：${cell(timingComparison.reasons.joinToString(", "))}。")
            appendLine("遅延パターンはSQLi確定ではありません。正常・成立・不成立の入力の意味、実通信、本文、認証、Macroや負荷の影響を確認してください。")
            appendLine("対照はExcelのPayload件数に加算しません。未送信・失敗・不足条件を含めて確認してください。")
            appendLine()
            appendLine("| 指定遅延ms | 反復数 | 差の中央値ms | 最小ms | 最大ms | 対照の変動ms | 許容差ms |")
            appendLine("|---|---|---|---|---|---|---|")
            timingComparison.levels.forEach { level ->
                appendLine("| ${level.requestedDelayMillis} | ${level.repetitions} | ${level.medianDeltaMillis} | ${level.minDeltaMillis} | ${level.maxDeltaMillis} | ${level.controlSpreadMillis} | ${level.toleranceMillis} |")
            }
            appendLine()
            appendLine("差は各反復の成立条件 − max(正常, 不成立条件)です。許容差は統計的な信頼区間ではありません。")
            appendLine("証拠は同じrunのtiming-controls台帳にあり、本体のindexとは別です。対照IDはCONTROL:指定遅延ms:0始まり反復番号:NORMAL/TRUE/FALSEです。")
            appendLine()
            appendLine("| 対照証拠番号 | 対照ID | 状態・理由 | HTTP | 送信処理ms | 応答SHA-256 |")
            appendLine("|---|---|---|---|---|---|")
            timingRows.forEach { item ->
                val duration = item.sendCallElapsedNanos?.let { java.math.BigDecimal.valueOf(it, 6).toPlainString() } ?: "未計測"
                appendLine("| timing:${item.index} | ${cell(item.payloadId)} | ${cell(item.state)} ${cell(item.reason)} | ${item.statusCode ?: "—"} | $duration | ${cell(item.responseSha256)} |")
            }
            appendLine()
            appendLine("不足条件・制約：${cell(timingComparison.limitations.joinToString(", "))}。")
        }
    }
}
