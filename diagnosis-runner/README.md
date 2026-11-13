# 診断ジョブ実行サービス

このモジュールはMCPに組み込まれ、`diagnosis-contract` の契約を使って設定適用、準備検証、人間承認、Scan開始、証拠保存、設定回復を実行します。通常のAI操作は公開MCP `diagnostic_job` と `diagnostic_draft` を使用します。外部のモデルAPIや別runnerプロセスを必須にしません。

導入とローカルruntimeの説明は [LOAD.md](../LOAD.md) を参照してください。

## 公開MCPでの順序

1. 実際に観測した通信と識別子を読み取ります。
2. `propose` に完全な設定案を提出します。
3. `prepare` を人間が承認し、必要な分岐ごとに5回以上の検証と設定復元を確認します。
4. 全通信で認証・動的値・入力保持・返却応答・後処理を確認します。
5. 新規 `execute` の前に現在のexecutionIdで `plan_next` を呼び、残対象を依頼順に宣言します。最後も `nextTargetsJson="[]"` を指定します。
6. 確認したvalidationDigestで `execute` を開始し、人間が実行を承認します。Scan中は次設定を `diagnostic_draft submit_next` に提出します。

返されたoperationIdを使い、同じ操作を観測します。結果不明の操作を別IDで再送せず、拒否後の承認画面を自動再表示しません。静的合格は対象通信を送った証明ではありません。設定回復でアプリケーション側のデータやセッションが回収されたと判断しないでください。

## 任意のCLIクライアント

```powershell
.\gradlew.bat :diagnosis-runner:installDist
.\diagnosis-runner\run-job.ps1 -Action status -ExecutionId example_execution
```

`run-job.ps1` はMCPの `runtime/settings.json` とローカルの資格情報を読みます。Burpを起動するスクリプトではありません。`prepare` や `run` は通信を伴うため、接続確認だけの目的で実行しないでください。通常のMCP操作とCLIを同じ実行へ競合させず、REVIEWの承認と実行の排他を維持してください。

この公開ツリーには開発用のテスト・fixture・診断証拠は含めていません。各Toolの入力形式・操作条件は公開Tool Descriptionで確認してください。
