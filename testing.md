# 配布版の検証範囲

## 1.4.20のruntime接続

実際に選択するMCP JARとCPHフォルダーを指定して参照を照合し、停止保守時に相対参照だけを生成する。親フォルダー全体の移動、片方だけの改名と再設定、複数clone、新規runtime、日本語・空白パス、既定REVIEW、環境変数の上書き、稼働・待受・照会失敗時の拒否、WhatIf、バックアップ・冪等性、秘密非表示を回帰する。CPH接続先の欠落で認証なしの起動へ落とさず、旧CPHや環境変数方式の参照照合不能はnullとする。異なるruntimeを報告したCPHは通常ジョブでも拒否する。

`scripts/tests/test_runtime_connection.py`は製品CLIを隔離cloneへコピーして実行し、OSの状態照会だけを子プロセス内で模擬する。製品へのテスト用迂回フラグはない。`CphConnectionTest`は起動時参照、runtimeの一致・不一致・不明、403案内、通常ジョブ拒否と秘密非表示を確認する。PowerShellチェックの成功はファイル状態であり、稼働中Burpのモード・参照・通信を証明しない。

配布checkoutの178件（MCP19・契約77・runner82、failure/error/skip=0）とGradle Wrapperのtest・embedProxyJarが成功した。開発側ではJVM611件、CPython70件、PowerShell12件、Jython12件が成功し、実SSEで公開get_cph_configの403案内と対象送信・設定変更0件を確認した。check-installの不正なsettings JSONも内容を表示せずに拒否する。ソースと再ビルドJARはmanifestのビルド情報以外が一致する。配布バイナリは1.4.20 REVIEWで、hashはSHA256SUMSを参照する。

今回の1.4.20は稼働中Burpへ配備していない。実機能力検証や実対象の認証・Macro・CPH動作へ合格範囲を広げず、導入先ではINSTALL-WINDOWS.mdに従って起動時の参照一致を確認する。以下の1.4.19以前の配備記録は当時の版の検証である。

## 1.4.19の認証設定保持・切替

認証Ruleの保持、検証・回復Macroの整数参照、CPHキャッシュ依存と順序、待機時の無効化、対象別の有効化、元のRule順序、必要なcphToolsの宣言とOptions反映・復元を回帰します。宣言漏れ・不正Tool名・必要Toolが無効な保存planは送信前に拒否し、旧wire形式の読取り・回復を維持します。

契約とworkerの回帰テスト、および公開SSEのAuthenticationRetentionMcpWorkflowTestを同梱します。後者は実際のMCPプロトコルとproduction workerを模擬Burp senderへ接続し、承認前の送信0件、必要分岐の検証、各probe/start前のScanner／Extenderフラグ、終了後のOptions復元、同一操作の二重開始防止と次対象での再利用を確認します。実Burpの認証や置換を実証する試験ではありません。配布前に、開発runtimeを含まない配布checkoutで既存WrapperのtestとembedProxyJarを実行します。

別PCでは下記の初回導入検証を別途行います。開発PCの認証情報・登録済み能力・診断証拠を配布物へコピーしません。

配布checkoutで172件（MCP13・契約77・runner82、failure/error/skip=0）とtest／embedProxyJarが成功しました。回帰で参照する架空のJSON例も同梱しています。JARを含む送信候補と入れ子proxyを走査し、開発PCのruntime資格情報・個人パス・実診断先・診断データの混入がないことを確認しました。ビルド済み1.4.19 REVIEW JARとSHA256SUMSを同梱し、CPH v0.3の相対参照が新規配置のmcp-server/runtimeへ解決することを確認しています。この配布検証で別PCのBurp実機を操作したわけではありません。初回能力検証は導入先で行います。

公開productionソースは原本JARのソース一式と改行を除いて一致し、再ビルドJARとロード確認済み原本の全エントリーを比較してmanifestのビルド日時等以外が同一であることを確認しました。同梱するバイナリ自体は原本JARをそのまま使用し、元のmanifestのBuilt-Byを含むビルドメタデータも保持しています。SHA-256は `5fd13d6b5e59358a62a918d0b746555a7a5465d7f3a9f785a168fa2eb694a5ab` です。ソースから再ビルドした場合はmanifestの日時等によりhashが変わるため、cloneした同梱JARの一致確認にはSHA256SUMSを使用してください。

新規導入・実機検証の手順は[INSTALL-WINDOWS.md](INSTALL-WINDOWS.md)に集約します。本書はテストの意味と未確認範囲を定義します。

```powershell
.\gradlew.bat test embedProxyJar
```

同梱のInstallationVerificationTestは、実際のloopback HTTP fixture、production GuardedWorker・JobStore・非同期diagnostic_jobサービスと、模擬Burp portを使用します。通常／動的の固定計画、5回の準備、承認段階、模擬Audit ID、保存結果、正常再送、設定復元、証拠付き登録と次回loadを検証します。初回と登録時の人間拒否、使用中context、SCANNER以外の通信、重複操作、通常計画の能力検査を確認します。テストの承認者は模擬であり、通常運用の人間承認を省略する設定ではありません。

InstalledRuntimeTestは、新規ローカル設定・秘密生成、秘密の保持、モードの検査、インストール先基準のパスとroot外への逸脱拒否を検証します。既存の開発runtimeや認証情報はテスト入力にしません。

これらは実Burp ProfessionalのScanner／Macro／CPHや、ログイン済みClaude Codeの操作判断を実行するテストではありません。模擬Audit IDや自動テストの成功を実機能力登録の証拠へ流用してはいけません。運用環境では公開diagnostic_jobの初回検証を人間承認付きで実行し、実通信と復元を確認します。実対象の認証、Macro、cached抽出、所有データの後処理は対象別に検証します。

## Windows実機検証（2026-11-17）

別PCを想定し、同じWindows上でGitHubから取得した配布物、新規Burp Project、独立したBurpデータ領域を使った。開発用runtime・認証情報はコピーせず、Claude DesktopのChatから公開diagnostic_jobを呼び出した。検証時のHEADはMCP 3fee498、CPH 6749817。実行JARはMCP 6443ee0でビルドした1.4.17、SHA-256は133129e81d70e3f3162b3a150edd9ead9b38bf4682f019fc2b0311dbecb90b65。

| 計画 | executionId | 実Audit ID | 保存されたLogger証拠 |
|---|---|---|---|
| 通常 | install-normal-1417-b | f950e2ef-46bb-4596-9d0c-6c7aa132ce12 | 288件（SCANNER 287件） |
| 動的CPH | install-dynamic-1417 | 6312b366-087b-4803-8dcb-24d2786e1aa8 | 439件（SCANNER 263件） |

両計画で準備5回、段階別の人間承認、実Audit、保存結果2レコードと全証拠ページ、正常再送、設定復元、排他解放、能力登録を確認した。動的計画は一回限りtokenの取得元応答とSCANNERの成功通信を照合した。Dashboardは2件完了・待機0・実行中0。MCP単独の再ロード後に公開statusとCPHの管理接続を確認した。物理的な別PCでの再試験と、認証済みClaude Codeのツール選択は今回の実施範囲外である。
