# 配布版の検証範囲

新規導入・実機検証の手順は[INSTALL-WINDOWS.md](INSTALL-WINDOWS.md)に集約します。本書はテストの意味と未確認範囲を定義します。

```powershell
.\gradlew.bat test embedProxyJar
```

同梱のInstallationVerificationTestは、実際のloopback HTTP fixture、production GuardedWorker・JobStore・非同期diagnostic_jobサービスと、模擬Burp portを使用します。通常／動的の固定計画、5回の準備、承認段階、模擬Audit ID、保存結果、正常再送、設定復元、証拠付き登録と次回loadを検証します。初回と登録時の人間拒否、使用中context、SCANNER以外の通信、重複操作、通常計画の能力検査を確認します。テストの承認者は模擬であり、通常運用の人間承認を省略する設定ではありません。

InstalledRuntimeTestは、新規ローカル設定・秘密生成、秘密の保持、モードの検査、インストール先基準のパスとroot外への逸脱拒否を検証します。既存の開発runtimeや認証情報はテスト入力にしません。

これらは実Burp ProfessionalのScanner／Macro／CPHや、ログイン済みClaude Codeの操作判断を実行するテストではありません。模擬Audit IDや自動テストの成功を実機能力登録の証拠へ流用してはいけません。運用環境では公開diagnostic_jobの初回検証を人間承認付きで実行し、実通信と復元を確認します。実対象の認証、Macro、cached抽出、所有データの後処理は対象別に検証します。
