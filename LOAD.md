# ロードとローカル設定

## 配置

このリポジトリを `mcp-server`、対応するCPHリポジトリを同じ親フォルダーの `burp-cph` に置きます。MCPのロード元は `build/libs/burp-mcp-all.jar`、CPHのロード元は `../burp-cph/CustomParamHandler_marged_api_v0.2.py` です。CPH側の `runtime/cph-connection.json` は `../../mcp-server/runtime` を参照します。配置名を変更する場合は、この相対パスも変更してください。

JARを `build/libs` からロードすると、このリポジトリ直下がインストールrootになります。別の場所へJAR単体を移動した場合はJARの親がrootとなるため、既存runtimeを使う意図で無断移動しないでください。

## 初回起動

1. Java 21で動作するBurpを起動し、MCP拡張をロードします。
2. `runtime/settings.json` と `runtime/operator-secrets.json` がローカル生成されます。settingsの初期モードはREVIEW、能力の初期値は空です。
3. BurpのPython環境へJython standalone JARを設定し、CPH v0.3をロードします。MCPとCPHはそれぞれ1つだけロードします。
4. MCPタブでREVIEW、公開 `get_cph_config` で `success=true` と `managed=true` を確認します。
5. [INSTALL-WINDOWS.md](INSTALL-WINDOWS.md)に従い、公開diagnostic_jobのverify_scanner_workflow、必要な場合のverify_dynamic_workflowで初回能力を検証・登録します。初回確認・準備・実行・登録は人間がBurp画面で承認します。名称を手動追加して受付拒否を回避しません。終了・設定復元・通信停止を確認した後のMCPだけの保守reloadで登録を読み込みます。CPHはreloadしません。

MCPの既定接続先は `http://127.0.0.1:9876`、認証付きCPH APIは `127.0.0.1:17866` です。既存の環境変数による高度な起動設定を残している場合は、インストール先runtimeより優先されることがあるためオペレーターが実効設定を確認してください。

## ローカルに生成されるもの

| パス | 用途 |
| --- | --- |
| `runtime/settings.json` | 保存先・入力root・実機確認済み能力 |
| `runtime/operator-secrets.json` | workerとCPHの別々の資格情報 |
| `runtime/jobs` | 診断用の正式入力 |
| `runtime/worker-store` | 状態・台帳・HTTP証拠 |
| `runtime/client-runs` | 任意のCLI runnerの実行記録 |

これらは個別環境の情報であり、Gitへ追加しません。保護された保存先とバックアップを用意し、進行中の台帳・復元用snapshotを不具合回避のために削除・編集しないでください。

## 通常の実行

公開MCPでは `propose → prepare → 全検証証拠の確認 → plan_next → execute` の順に進めます。`plan_next` は現在のexecutionIdに依頼順の残対象を宣言し、最後にも `nextTargetsJson="[]"` を指定します。準備・実行・回復・長時間継続の画面承認は人間が操作します。Scan中の次設定は `diagnostic_draft submit_next` を使用し、現在設定に適用しません。

共有CPHキャッシュを利用するvariantは `settings.serialScannerRequests=true` を明示し、同じCookie・CPH・resource poolを使う他Taskや同アカウントのテストとの競合を避けます。個別の設定・通信・業務状態は対象ごとに検証します。

## 更新

実行中のAudit・補助通信・未完了の設定回復がないことを確認し、現在のProject・履歴・設定を保存してから更新します。CPHコードの更新やUnload後は、Burpプロセスを終了してから再起動し、保存済みProjectを開き直して更新版をロードします。同一プロセスでの繰返しCPH再ロードを復旧手段にしません。設定Importだけの場合は再起動不要です。

MCPだけの更新でも、証拠・状態・復元の確認と保守の承認を分けて行います。再ロード後に失われるnative Audit handleを、Scan終了の証拠や新Scanの再送許可として扱いません。
