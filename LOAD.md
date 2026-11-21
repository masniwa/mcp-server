# Extensionsでの選択ロード

同じポートを使うため、MCPサーバーは1つ、CPHも1つだけロードします。現在のProject・設定・診断結果を保持し、実行中のScanがない状態で切り替えます。

共有キャッシュを使う各variantにはsettings.serialScannerRequests=trueを明示します。実行サービスがDefault resource poolの実効同時リクエスト上限1を準備・Scan・正常再送中に適用し、各段階後に元値へ戻します。別Task・他Toolが同じpoolやCPHを利用していないことを先に確認します。省略した旧ジョブでは実効上限1を外部で維持する前提が残ります。

| 選択する版 | Extensionsで選択するファイル | 表示名 |
| --- | --- | --- |
| 従来MCP（Java） | `../mcp-server/build/libs/burp-mcp-all.jar` | Burp MCP Server |
| 改修MCP（Java） | `../mcp-server -re/build/libs/burp-mcp-all.jar` | Burp MCP Server -re |
| 従来CPH（Python） | `../burp-cph/CustomParamHandler_marged_api_v0.2.py` | Custom Parameter Handler |
| 改修CPH（Python） | `../burp-cph -re/CustomParamHandler_marged_api_v0.2.py` | Custom Parameter Handler -re v0.3 |

通常のBurp起動後、Extensions → Addでファイルを選択します。tempのJARや専用のBurp起動スクリプトは使用しません。MCPクライアントの既存SSE/stdio接続は維持し、既定の接続先は127.0.0.1:9876です。

MCP -reはインストール先のruntime/settings.jsonとruntime/operator-secrets.jsonを読み、管理モードで開始します。初回は必要なファイルを作成します。新環境の能力設定は、オペレーターが実機確認してから有効にします。資格情報はJARへ埋め込まず、画面やチャットへ表示しません。

本運用はauthorizationMode: "REVIEW"です。ロード後のMCPタブでも実効モードを確認し、異なる場合は診断を開始せずオペレーターへ確認します。診断依頼は従来どおりRequest IDを指定し、認証・Macro・CPHを確認してActiveScanを依頼できます。


CPH -reの`runtime/cph-connection.json`は、MCP -reのruntimeを相対パスで参照します。最初の導入ではMCP -reを先にロードしてプロファイルを作り、次にCPH -reをロードします。MCP -reのジョブには認証付き管理APIのCPH -reが必要で、従来CPHを管理APIの代用として受け付けません。

参照設定に対応する配布版では、ロード前に`configure-runtime.ps1 -McpJar <実際のJAR> -CphRoot <CPHフォルダー>`で照合し、停止保守中だけ`-Configure -BurpStopped`で実配置から参照を生成します。片方だけの改名・移動やロード先変更時は再確認します。新しいCPHは明示参照先が欠落すると認証なしで起動せず停止します。起動後のget_cph_configでsuccess・managedとconnectionDiagnostics.runtimeMatchesを確認し、nullを一致としません。設定ファイルの変更だけで起動中の認証情報は更新されず、診断中に再ロードしません。具体的な操作はINSTALL-WINDOWS.mdへ集約します。

従来MCPは従来の直接操作を維持します。従来CPHとの組合せでは認証設定は不要です。この配置では`../mcp-server/runtime/cph-connection.json`も同じ認証設定を参照するため、CPH -reを使ったまま従来MCPへ切り替えることもできます。資格情報は127.0.0.1/localhostの17866番以外へ送らず、redirectも追跡しません。

CPHをRemove/Unloadした場合、またはCPHのコード変更を反映する場合は、AGENTS.md 4.2のRemove → Burp終了確認 → 再起動 → Addに従います。設定Importだけの場合は再起動不要です。MCPの切り替えだけで、同じCPH -reを再読み込みする必要はありません。

## 配置とジョブ操作

- `runtime/settings.json`：保存先・入力root・確認済み能力・worker接続先。
- `runtime/operator-secrets.json`：別々のworker/CPH資格情報。共有・コミットしない。
- `runtime/jobs`：新しい診断ジョブと入力。
- `runtime/worker-store`：新運用の操作台帳と保存結果。
- `runtime/client-runs`：runnerの実行記録。
- `verification`：検証結果・ビルド記録・過去の証拠アーカイブ。

AIは公開MCP diagnostic_jobでpropose→prepare→全検証証拠の確認→plan_next→executeの順に操作します。plan_nextでは現在のexecutionIdに依頼順の残対象をnextTargetsJsonで宣言し、最後の対象もnextTargetsJson="[]"を明示します。返されたoperationIdで同じ非同期操作の経過を取得します。準備・実行・設定回復にはBurpの人間承認を使います。対象別のMacro／Rule／CPHと動的更新を維持し、停止後の設定復元は同Toolのrecoverを使います。通常のImportや履歴取得をUIへ迂回しません。

互換の外部クライアントとしてdiagnosis-runner/run-job.ps1も利用できます。このスクリプトはローカル資格情報を読み、Burpは起動しません。prepareも検証通信を伴います。人間承認の画面操作を自動化しないでください。

旧tempのworker台帳と中断したRequest ID 68の記録は過去の証拠として保全し、新しいworker-storeへ混在させません。中断した診断は完了ではなく、業務データ・セッション・設定の最終状態は別途確認が必要です。自動でScanを再開しません。

## ビルド

両MCPの各ディレクトリでGradle Wrapperの`embedProxyJar`を使います。MCP -reのrunner配布物は`:diagnosis-runner:installDist`で生成します。検証方法は`testing.md`、ジョブ契約と制約は`diagnosis-runner/README.md`を参照してください。
