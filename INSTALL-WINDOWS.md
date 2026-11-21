# Windowsでの新規導入と初回検証

この手順は、Burp Professional・Claude Code・Git for Windows・Java 21以上・Jython standaloneを用意した、新しいWindows環境を対象にします。BurpとClaude Codeは同じWindows上で動かします。既設環境を初期化する手順ではありません。MCPは通常のREVIEW版だけを使います。

## GitHubから取得する

PowerShellで、まだ存在しない作業場所を選びます。例のパスは利用するPCに合わせて変更してください。

```powershell
$setupRoot = Join-Path $env:USERPROFILE 'Desktop/Burp-diagnosis'
if (Test-Path -LiteralPath $setupRoot) { throw '既存の作業場所です。別の新規フォルダーを指定してください。' }
New-Item -ItemType Directory -Path $setupRoot | Out-Null
Set-Location -LiteralPath $setupRoot
git clone https://github.com/masniwa/mcp-server.git
if ($LASTEXITCODE -ne 0) { throw 'MCP clone failed' }
git clone https://github.com/masniwa/burp-cph.git
if ($LASTEXITCODE -ne 0) { throw 'CPH clone failed' }
git -C mcp-server rev-parse HEAD
git -C burp-cph rev-parse HEAD
git -C mcp-server status --short
git -C burp-cph status --short
Test-Path mcp-server/build/libs/burp-mcp-all.jar
Get-FileHash mcp-server/build/libs/burp-mcp-all.jar -Algorithm SHA256
Copy-Item mcp-server/diagnosis/AGENTS.md,mcp-server/diagnosis/CLAUDE.md,mcp-server/diagnosis/spec.md,mcp-server/diagnosis/read.me,mcp-server/diagnosis/quicksetup.txt -Destination $setupRoot
New-Item -ItemType Directory -Path (Join-Path $setupRoot 'temp') | Out-Null
```

表示した2つのコミットとJARのhashを保存してください。過去の開発PCの`runtime`・Project・台帳・認証情報・`.claude`をコピーしません。CPHに含まれる`runtime/cph-connection.json`は秘密を含まない相対参照であり、ローカル生成される認証情報とは別です。配布JARがない場合は導入を止めます。

## ロードするJARとCPHの参照先を揃える

フォルダー名を決めてから、実際にBurpへロードするJARとCPHフォルダーを指定します。別名でcloneした場合は、この2つの値を実配置に合わせます。標準名の別cloneを自動探索して選ぶことはありません。

```powershell
$selectedMcpJar = Join-Path $setupRoot 'mcp-server/build/libs/burp-mcp-all.jar'
$selectedCphRoot = Join-Path $setupRoot 'burp-cph'
& "$setupRoot/mcp-server/configure-runtime.ps1" -McpJar $selectedMcpJar -CphRoot $selectedCphRoot
```

既定は読取り専用です。`expectedRuntime`と`configuredRuntime`、`pairingMatches`を確認します。初回の`profileState=NOT_INITIALIZED`は正常で、資格情報はまだ作りません。`INVALID`・`PARTIAL`・`NOT_REVIEW`、`managedCredentialRedirectPresent=true`は別途確認が必要です。`launchOverridesPresent=true`の場合は終了コード2で起動環境の確認を要求し、値そのものは表示しません。このシェルの環境と稼働中Burpが引き継いだ環境は別なので、出力だけで実効状態を断定しません。

新規導入ではBurp起動前に、次で参照を設定します。既設環境では診断を終了・保全し、許可された停止保守でのみ行います。`-WhatIf`で変更なしの確認もできます。

```powershell
& "$setupRoot/mcp-server/configure-runtime.ps1" -McpJar $selectedMcpJar -CphRoot $selectedCphRoot -Configure -BurpStopped
if ($LASTEXITCODE -ne 0) { throw 'Runtime接続設定を確認してください。診断は開始しません。' }
```

Burpプロセス・既定ポートの待受・確認不能・起動環境の上書きがある場合は書込みを拒否します。バックアップは親ディレクトリーの`temp/runtime-connection`へ保存し、CPH接続ファイルの`runtimeDirectory`だけを変更します。既存の秘密・settings・台帳・能力登録は変更しません。同じ参照なら書込み・バックアップを重複しません。

親フォルダー全体を移動した場合は相対参照が維持されます。片方だけの改名・移動、ロードするJARの変更時は同じコマンドで再確認・設定してください。別ドライブ間では絶対参照になるため、移動時は再設定します。接続先が消えたCPHは管理認証を解除して起動せず、`CPH_RUNTIME_PROFILE_MISSING`で停止します。MCPを先にロードし、このPC用のruntime生成後にCPHをロードしてください。

これらはファイルの確認・設定です。MCPとCPHは起動時の認証情報を保持するため、稼働中の反映確認を代替しません。診断中の拡張再ロードは禁止です。

## BurpとClaude Codeを接続する

1. Burp Professionalで、このPCの新しい診断用Projectを開きます。既設Projectの置換はしません。
2. Extensions → Add → Javaで`mcp-server/build/libs/burp-mcp-all.jar`をロードします。表示名は`Burp MCP Server -re`です。MCPが`runtime/settings.json`と保護された`operator-secrets.json`をローカル生成します。
3. BurpのPython環境へJython standalone JARを指定し、Extensions → Add → Pythonで`burp-cph/CustomParamHandler_marged_api_v0.2.py`をロードします。表示名は`Custom Parameter Handler -re v0.3`です。
4. MCPタブで実効モードREVIEW、接続先`127.0.0.1:9876`を確認します。検証用Projectで設定の変更を許可する場合は、人間が「Enable tools that can edit your config」を有効にしてから初回検証に進みます。無効のまま準備するとCONFIG_EDITING_DISABLEDで停止します。履歴・Loggerの参照要求も人間が確認します。環境変数による旧管理設定が残っている場合は、実効保存先・モードを確認してから進めます。
5. 診断用プロジェクト直下で次を実行します。既存の同名接続がある場合は重複登録せず設定を確認してください。

```powershell
Set-Location -LiteralPath $setupRoot
claude --version
claude mcp add --transport sse --scope project burp http://127.0.0.1:9876
claude mcp get burp
claude
```

Claude Codeの最初の画面でプロジェクトとMCP接続を確認し、`/mcp`で接続を確認します。`CLAUDE.md`の`@AGENTS.md`と同じ場所の`spec.md`を全文読み込ませ、使用中の3文書と`temp`の絶対パスを示させます。公開`get_cph_config`で`success=true`かつ`managed=true`、新しいファイル方式では`connectionDiagnostics.runtimeMatches=true`を確認します。falseなら参照先不一致、nullなら環境変数方式・旧CPH等で照合不能なので、一致と断定せず起動設定・対応版を確認します。403 CPH_AUTH_REQUIREDは接続認証の失敗です。実ロード先と起動環境を調べ、秘密のコピー・管理解除・診断中の再ロードで回避しません。秘密値は表示させません。接続設定の形式は[Claude Code公式MCP説明](https://code.claude.com/docs/en/mcp)、文書Importは[公式memory説明](https://code.claude.com/docs/en/memory)を参照してください。

## 空の能力一覧から検証・登録する

Dashboard上部に「Task execution is paused」が表示されている場合は、対象Projectの他のTaskも確認してからタスク実行を再開します。全体停止中はAudit IDが発行されても通信は待機します。初期状態の`verifiedCapabilities`は空が正常です。名前を手動追加して`UNSUPPORTED_CAPABILITY`を回避しません。Dashboardで他のScan・補助通信がなく、同じ設定やresource poolを他Taskが使用していないことを人間が確認します。

Claude Codeへ次を依頼します。

```text
公開diagnostic_jobのDescriptionを確認し、初回導入検証を行ってください。
最初にaction=verify_scanner_workflow、executionId=install-normal-01、operationId=install-normal-op-01を呼び、
返された同じoperationIdをaction=operationで追跡してください。
承認待ちになったら、対象と段階を知らせ、Burpの人間承認を待ってください。
成功後にresultsとevidenceの全ページを取得し、auditId、SCANNER通信、正常再送、設定復元を確認してください。
次にaction=verify_dynamic_workflow、executionId=install-dynamic-01、operationId=install-dynamic-op-01を同じ方法で実行してください。
runtimeや資格情報の手動編集、承認の自動操作、途中の拡張再ロードはしないでください。
```

これらのIDは新しい環境での例です。既に使ったIDで再実行しません。対象URLや計画JSONは渡しません。サーバーがこのPC内のランダムなパスと自動割当ポートのHTTP fixtureを作り、観測した通信から固定の単一対象計画を作成します。開発環境の過去のテスト入力や外部サイトは不要です。

各検証には、ローカル対象の初回確認、準備、実行、登録の人間承認があります。人間がBurpの画面で内容を確認し、「操作を許可する」へチェックしてOKを押します。チャットへの「OK」やAIのクリックでは代替しません。準備時は5回の正常通信、実行時は1つのnative Audit・保存結果・正常再送・設定復元を確認します。動的経路は一回限りtokenの毎回の取得とCPH置換を使い、SCANNER起点の成功通信と取得元の応答を照合します。通常の計画で未登録能力を要求するチェックは維持されます。

`operation.state=SUCCEEDED`と`result.registeredForNextLoad=true`、`result.auditId`を記録します。終了後の`execution.auditId`がnullでも、保存結果と検証結果のAudit IDは残ります。`results`・`evidence`の保存通信はローカルの証拠です。生通信を第三者へ共有する場合は資格情報を含まないことを確認します。

`FAILED`・`OUTCOME_UNKNOWN`・タイムアウト・拒否は成功ではありません。同じexecutionId/operationIdの状態と結果を確認します。実行が不完全なら、nativeと補助通信の停止を確認し、`diagnostic_job recover`へexecutionIdと停止根拠のevidenceRefを渡し、人間承認で設定を復元します。Scanの停止は対象を確認したBurp UI操作で行います。新しいIDで自動再送したり、台帳を編集したりしません。

両検証が終了し、設定復元、排他所有者null、稼働Auditと補助通信なしを確認した後に、導入保守としてMCPだけをUnload/Loadし、登録した能力を読み込みます。CPHを再ロードしません。Project・CPH・設定を保全し、導入検証中や通常診断中のreloadは禁止です。

```powershell
& "$setupRoot/mcp-server/check-install.ps1" -CphRoot "$setupRoot/burp-cph" -DynamicWorkflow
```

このチェックはローカルファイルと登録名の確認です。実効モード、接続、承認、実通信の証拠は上記の実行結果で別途確認します。

## 実対象の通常計画と動的計画

ローカルfixtureの合格は、任意サイトの認証、Macro、cached抽出や業務データ復元の合格を意味しません。許可されたテスト対象について正常操作をProxyへ記録し、Request ID・機能・対象パラメーター・許可範囲・所有データの後処理を指定します。公開ToolのDescriptionと診断用`spec.md`に従い、各対象で次を実施します。

1. 観測通信から通常計画、必要な場合はMacro／Rule／CPHを含む動的計画を作り、`propose`する。
2. `prepare`の人間承認後、全variant・全必要分岐で5回の検証と設定復元、認証・入力保持・動的値・確認応答・後処理の実通信を確認する。
3. `validation`の全ページを読み、返されたvalidationDigestを保存する。`plan_next`に残対象を宣言し、最後にも`nextTargetsJson="[]"`を指定する。
4. そのvalidationDigestで`execute`し、Burpの人間承認後に同じoperationIdを追跡する。発行されたAudit IDは実行中に保存する。
5. native終了・保存結果・全evidenceページ・正常再送・設定復元・排他所有者解放を確認する。脆弱性の判断と業務データの後処理は別に完了させる。

結果には、2つの配布コミット、JAR hash、通常／動的のexecutionId・operationId・Audit ID・validationDigest・登録記録・復元結果・未確認事項を記録します。実機Burpを使わないテストのauditIdは模擬値であり、実Scan成立の証拠として報告しません。

## Claude DesktopのChatで検証する場合

Burpへ接続済みのChatでは、「空の能力一覧から検証・登録する」の依頼文を使用できます。Claude Codeのプロジェクト文書の自動読込は前提にできないため、新しいチャットには配布された診断用AGENTS.mdとspec.mdを添付してください。Chat側のツール使用許可の後、検証用Burpで同じexecutionIdのREVIEWを確認します。進捗を再照会する際は、action=operationに元のexecutionIdとoperationIdの両方を渡します。ChatとClaude Codeのどちらで検証したかを結果に記録してください。
