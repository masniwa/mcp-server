# 配布版の検証範囲

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
