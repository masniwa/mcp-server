# Burp MCP Server -re 1.4.17

新しいWindows PCからの導入は [INSTALL-WINDOWS.md](INSTALL-WINDOWS.md) を使用してください。GitHubからの取得、Claude Code接続、空の能力一覧からの人間承認付き通常／動的検証、証拠付き登録、設定復元までを説明しています。診断用の独立した4文書は[diagnosis/read.me](diagnosis/read.me)に同梱しています。

Burp SuiteとAIクライアントをMCPで接続し、診断用Macro・Session Handling Rule・CPHの設定、検証、ActiveScan、証拠保存、設定回復を管理する拡張です。通常運用は人間承認付きの **REVIEW** モードです。

## 配布物

ビルド済みの拡張JARを [build/libs/burp-mcp-all.jar](build/libs/burp-mcp-all.jar) に含めています。Java 21を使用してください。対応する [CPH v0.3](https://github.com/masniwa/burp-cph) と組み合わせて管理APIを利用します。自動テストと実機検証の区別は[testing.md](testing.md)を参照してください。

```text
installation/
├─ mcp-server/
│  ├─ build/libs/burp-mcp-all.jar
│  └─ runtime/                       # 初回ロード時にローカル生成
└─ burp-cph/
   ├─ CustomParamHandler_marged_api_v0.2.py
   ├─ CPH_API_v0_2.py
   ├─ CPH_Managed.py
   └─ runtime/cph-connection.json
```

CPHのファイル名は配置互換性のためv0.2のままですが、ロード後の表示名はv0.3です。

## 導入

1. 両リポジトリを上記の兄弟フォルダーとして配置します。
2. BurpのExtensionsでJava拡張として `build/libs/burp-mcp-all.jar` をロードします。表示名は `Burp MCP Server -re` です。
3. MCPが `runtime/settings.json` とローカル専用の資格情報を生成してから、CPH側のREADMEに従ってCPHをロードします。
4. MCPタブの実効モードがREVIEWであることを確認します。必要な設定編集・履歴・Logger参照の許可はオペレーターが操作します。
5. AIクライアントの接続先は既定で `http://127.0.0.1:9876` です。CPHの設定APIは `127.0.0.1:17866` です。外部ホストへの公開を前提にしません。

実機確認済みの能力の初期値は空です。公開diagnostic_jobのverify_scanner_workflow／verify_dynamic_workflowは、固定のloopback対象だけを検証し、人間の画面承認と保存証拠に基づいて能力を登録します。通常計画の能力チェックを省略しません。過去の診断用runtimeや資格情報をコピーしたり、能力名の手動追加で受付拒否を回避したりしないでください。ローカルfixtureの成功と、実対象の認証・Macro・業務状態の成功は別です。

詳細は [LOAD.md](LOAD.md)、実行サービスは [diagnosis-runner/README.md](diagnosis-runner/README.md) を参照してください。各Toolの入力条件・手順・確認方法は公開Tool Descriptionにあります。

## ソースからのビルド

Java 21のJDKを用意し、リポジトリ直下でGradle Wrapperを実行します。

```powershell
.\gradlew.bat embedProxyJar
```

```bash
./gradlew embedProxyJar
```

本体は `diagnosis-contract` と `diagnosis-runner` を参照します。`libs/mcp-proxy-all.jar` は組込みproxyの入力です。これらを除いた単一モジュールとしてのビルドは想定しません。

## 診断時の境界

AIは観測済みの通信から対象別の設定案を作り、公開MCPの `diagnostic_job` を使います。直接の設定Import・送信・Scan開始で管理境界を迂回しません。準備と実行の人間承認、必要な分岐ごとの5回以上の検証、全証拠の意味確認を行います。設定ImportやHTTP 200だけでは認証・置換・診断の成立を証明しません。

新しい `execute` の前に現在の `executionId` へ `plan_next` を行い、依頼順の残対象を `nextTargetsJson` で宣言します。最後の対象にもJSON文字列 `"[]"` を指定します。Scan中はAIが次の設定を作成して `diagnostic_draft` の `submit_next` へ提出し、サービスが静的検査します。静的合格を実機検証や実行承認の代わりにしません。

## この公開ツリーの範囲

運用・ビルドに必要なソース、設定定義、Wrapper、依存JAR、配備JAR、ライセンスと導入文書を含みます。開発用テスト、診断Project、HTTP記録、検証fixture、実行台帳、個別環境のruntime、キャッシュ、バックアップは含みません。このツリーでテストTaskを実行しても、開発環境の全回帰を再実行したことにはなりません。

配布JARのSHA-256は `e308e84df618fd7517671f4a4f0c0335d7b138a5a26c5870a860c2a0a6444f48` です。MCP 1.4.15とCPH v0.3は開発環境の全688テスト合格後に配備された版です。新しい診断対象の動作保証は対象別の検証で確認してください。

## ライセンス

[PortSwigger/mcp-server](https://github.com/PortSwigger/mcp-server)を基にした改修です。GNU GPL v3の条件と著作権表示は [LICENSE](LICENSE) を参照してください。
