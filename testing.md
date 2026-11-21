# 診断ジョブ方式の検証

## 依頼入力の固定と429判断

依頼入力と範囲外除外の分離、新規compile・新承認・prepare・新規startでの集合一致、旧保存planの読取り／回復と既存Audit継続、人間の確認表示、429と期待403の判断を保存fixtureで検証する。LegacyRequestedScopeWorkflowTestの5件と、必須classpath fixtureを含むRateLimitObservationsTestの7件を追加した。全560件・failure/error/skip=0、1.4.12のREVIEWビルドとMCPだけの保守ロード、公開Toolでの入力範囲の拒否／静的合格・限定した429集計を確認した。全109件の公開照合、新規正式送信・Scanner成立は未検証。合格条件・証拠・結果と限界は[親のtesting.md](../testing.md)の「2026-11-13 依頼した入力範囲の固定と429判断」へ集約する。今回の保守による新Scan・対象への追加テスト送信は0件で、後続の診断Goalと下記の配備済み540件履歴から分ける。

## 診断入力・一度だけの準備・承認画面

InputCoverageTest／InputCoverageCompilerTest／NativeInputCoverageTestでnative入力の欠落・除外理由・前処理更新競合と正式登録前の拒否を、RepeatedMacroPreparationTest／OncePreparationSerializationTest／MontoyaPreparationOnceTest／OncePreparationWorkflowTestで固定Cookie失効Macro・一度だけの送信順序・証拠・互換性・結果不明時の非再送を確認する。ReviewApprovalDialogTestは長文・小画面・大きい文字・モニター作業領域・確認欄とキー操作を検証する。具体的ケース、540件の結果、隔離ビルド、通常-reの保守ロード、実回復画面の可視確認と承認付き設定回復、業務回収・新規送信等の未確認範囲は[親のtesting.md](../testing.md)の「2026-11-13 診断入力・一度だけの準備・承認画面」へ集約する。

## Scan中の下書き検証

`JobDraftPlanningTest`・`DraftMcpWorkflowTest`・`JobStoreConcurrencyTest`で、既存JobCompilerによる静的検証、実行中Scan／Macro待機との並行、公開MCPでの正式化、最新条件の拒否、承認と5回検証の維持、耐久INTENTと重複副作用防止を確認する。手順・合格条件・版別結果は[親のtesting.md](../testing.md)の「下書きと正式ジョブの分離」へ集約する。今回は実Burp・CPH API・診断対象に接続しない。

## 2026-11-12 旧排他所有の保守整理

通常recoverの終了・復元条件は維持する。追加したretireの人間確認・現在設定保持・未知の旧終了の保持・拒否条件・MCP非同期待機と冪等性、native inventoryのケースと全445件回帰の結果は、親testing.mdの「旧コンテキスト退役の保守」を正とする。配備と実機退役は別に確認する。

## 2026-11-12 診断で観測した不整合

ネストした回復Macroのnative空配列省略、未対応Scan configの送信前拒否、履歴・診断JSONのASCII伝送、明示した長時間承認、適用中のcleanupStateと失効時のnextActionを検証する。1.4.4候補のケース・全回帰結果・未配備の制約は、親testing.mdの同日節を正とする。

本書はコピー先`mcp-server -re`に追加した実装の検証方法です。既存機能の合格条件は親の`testing.md`を維持します。実装構成・操作契約は[diagnosis-runner/README.md](diagnosis-runner/README.md)に記載します。

## 2026-11-07 逐次実行と回復の回帰

SettingsPlan.serialScannerRequestsは省略時にserialized JSONへ追加せず、既存定義・digestを維持する。JobCompilerTestでは両project root形式・scope併用・未知poolフィールド/custom pools保持・不足拒否を確認する。WorkflowTestでは準備5回・Audit開始・正常再送時の実効上限1と、各段階後の元設定10への完全復元を確認する。検証後の手動変更は開始を拒否し、部分適用失敗・Cancel後の回復は診断送信を増やさず元poolを復元する。承認値と異なる遅延設定等の手動変更は回復でも拒否する。

初回の回復2ケースは修正前にUNRELATED_PROJECT_SETTINGS_CHANGEDで再現し、RecoverySafetyへ承認済みpool全体の照合を追加して解決した。生成・配布上の問題は実装不具合と区別して親testing.mdへ記録する。実機結果は親testing.mdを正とし、無通信テストの合格を実Scan完了とは扱わない。

## 2026-11-06 運用改善の回帰

通常-reの単体・モック結合を実行し、JAR内のdiagnostic-profile.propertiesと実効runtime設定がREVIEWであることを確認する。既存台帳・証拠を消去せず、配備・実通信・設定復元の確認と無通信試験を区別する。

| 対象 | 合格条件 |
| --- | --- |
| DiagnosticJobServiceTest | 承認待ち中も同じMCPで状態取得できる。承認後は別クライアントなしでScan・収集・正常再送・復元まで継続し、同一operationId再取得で重複開始しない。拒否後はoperation/status双方で明示的な再指示を待つ。再ロードしたRUNNING intentはOUTCOME_UNKNOWNで再実行しない |
| ManagedMcpIntegrationTest | 実MCP tools/listで管理中の直接送信/設定変更はdiagnostic_jobへ誘導され、読取りは維持する。JobProposal/SessionPlanの形式、branchSetup.startOptions={}、共有CPHキャッシュのconcurrent_request_limit=1という前提が説明に含まれる。実MCPで直接変更が拒否され、HTTP送信とScan開始は0回 |
| InstalledRuntimeTest / ExtensionBootstrapTest | 通常-reのJAR既定と実効設定のREVIEWを確認し、人間承認と管理境界を保持する。直接の設定・送信を許可しない |
| LoggerArchiveTest | メモリ退避後の過去履歴・遅延応答・大型メッセージを完全取得し、固定id範囲と正規表現を適用できる。保存障害はcaptureErrorsに残し、空の正常履歴と扱わない |
| MontoyaAdapterTest | 過去500記録があっても今回のprobe範囲だけを保存する。開始前のcapture情報不足・欠落を送信前に拒否し、従来のnative envelope照合を維持する |
| WorkflowTestのrecover | Cancel/終了と補助通信停止の確認後だけ元設定へ戻す。probe/startは0回。稼働中・別所有・無関係な設定変更・終了不明を拒否する。失われたhandleの再作成をしない |
| NativeDefaultComparisonTest | prior_response_index=0のnative省略を比較でき、別index・未知項目・原本JSONを変えない |
| ToolsKtTest / NativeRequestMetadataTest | 実MCP dispatchでincludeBinaryの不正UTF-8を含むnative bytesを復元でき、名前・型・offsetを値の読出しなしに取得する。HTTP送信0回。既存のフラグ省略・ID照合・許可拒否の互換性を維持する |

CPHの`test_response_definition.py`と`tests/response_definition.jython`は本体の実アクセサーを抽出して実行する。表示欄が遅延・既定18バイトへ戻ってもImportした完全応答が維持されること、実行時SINGLE応答の更新、全256バイト値、legacy挙動を確認する。JythonはJava byte[]を使う。これだけで実BurpのImport・Scanner callbackの合格とはしない。

```powershell
java '-Djava.awt.headless=true' '-Dpython.cachedir=../temp/review-fixes-20261106/jython-cache' -jar C:/jython2.7.4/jython.jar -B '../burp-cph -re/tests/response_definition.jython'
```

Request62のCookie受渡しは、保存した旧Auditの246フロー・94リダイレクトで旧設定の94不一致を再現し、修正案で全件解消することを本体の未編集scope/modify関数で検証する。正常→リダイレクト→Cookieなし失敗→GET派生の5周期も確認する。回収94Cookieの188要求について元の組合せを保持する。実callbackの順序・新規Scannerの後処理・実際の失効は実機で別途確認し、旧Auditを成功に変更しない。

## 実行範囲

初回段階は、純粋な契約検証、MontoyaとCPHをモック化した実行、SQLiteの障害・再起動検証、ループバックの模擬HTTP/MCP接続、CPH APIハンドラーのメモリ上の検証、Jython構文・ビューア検証です。その後のユーザー指示により、専用127.0.0.1:18084での配備・実通信・native Scanner・管理モード・人間承認付きrunnerを追加検証しています。SMTP/IMAP・外部コールバックは使用しません。実機結果と未完了項目は親の`testing.md`冒頭を参照し、モック合格と区別します。

`MontoyaAdapterTest`は実際の`get_active_scan_status`の`success/audit`形式を使い、単一Auditの取出し、未知の完了状態・submissionErrorの保持、欠落・別Audit IDの拒否を確認します。Collectorのfixtureも同じnative形式にし、直下の仮定を再導入しないようにします。日本語ポップアップは実機で文字表示・原本参照・チェック欄・承認後の状態を確認し、翻訳によって許可範囲や既存の承認判定を変更しません。

`ManagedLoggerCapacityTest`は実際のmanagerが登録したHTTP recorderへ6,000件を記録し、管理モードでは欠落0、従来モードでは従来上限による1,000件の欠落が明示されることを確認します。両モードの64MiB上限と対象送信0回も確認します。Tool説明の回帰では、Macro取得元index省略が先頭応答を指し、前処理追加時にindexを更新する必要があることを公開Descriptionで確認します。

`JobCompilerTest`は、共通Optionsを含む新タブの順序へ既存タブを追加したとき、全処理タブの相対順序を維持してOptionsだけをnative Exportと同じ末尾へ置くことを確認します。Options位置の扱いによって取得元より前のdestinationを許容しないことも独立して検証します。元の提案JSONの順序は保持し、CompiledPlanの実行順を承認画面へ提示します。

HTTPクライアントとMCP接続を検証するテストだけはループバックの一時ポートにテスト用サーバーを起動します。その先のMontoya／対象はモックです。CPHの認証テストはサーバーを起動せず、ハンドラーをメモリ上で呼び出します。

## Kotlinと既存回帰

プロジェクトのGradle Wrapperを使用します。既存テストのExcel fixtureが未設定だと一部がassumption skipになるため、全回帰では保全したverification/fixturesのExcelとcatalogを明示します。元Excelは変更しません。

```powershell
$env:PAYLOAD_TEST_WORKBOOK = (Resolve-Path 'verification\fixtures\workbook.xlsx').Path
$env:PAYLOAD_TEST_CATALOG = (Resolve-Path 'verification\fixtures\catalog.json').Path
.\gradlew.bat test embedProxyJar :diagnosis-runner:installDist --offline
```

fixtureの生成には既存`scripts/export_payload_catalog.py`を使います。今回使用するfixtureはPayload670件、Grep23件、SHA-256 `9a2a83de3f2e9c3361025b1ef2564d29c4e8215dd62c1560c0ef2fb78fe69009`です。これはExcelの読み込み・計画・モック送信の回帰であり、実Scanの代用ではありません。

| テスト | 主な合格条件 |
| --- | --- |
| `JobCompilerTest` | 決定的計画、native root・既存Scopeの保全、整数IDの無損失、未知schema・項目・無視されるconfigの拒否、観測材料digest、Macro・CPH参照順序、既存CPH sourceの再利用、保存先の網羅、Session検証の前提 |
| `WorkflowTest` | 未承認で副作用0回、各構成・分岐5回、動的応答更新の許容、反射＋保存構成の独立実行、人間拒否、期限・入力・検証証拠変更の拒否、fencing・排他、開始不明時再送0回、観測失敗の同一Audit追跡、部分結果・保存結果・再起動・証拠改変検出、手動回復照合、runnerとHTTPプロトコル、公開JSON例 |
| `ManagedBoundaryTest` | 既存の副作用Toolを管理モードで拒否し、認証済みworkerは同一実装を使用、既存データアクセス承認の維持、管理設定の不足拒否、CPH tokenの任意hostへの流出防止 |
| `ManagedMcpIntegrationTest` | 実MCPトランスポートで直接送信・設定変更を拒否し、native送信・Scan・importが0回。worker HTTP routeは専用tokenなしで403、本文上限超過で413、再起動時の非loopback bindを拒否 |
| `MontoyaAdapterTest` | native JSON・CPH順序・既存HTTP senderへの引数保持、Logger欠落検出、Payload全ページ収集とIssue帰属、入力freezeと改変検出、秘密世代照合、既存設定編集の許可維持 |
| 既存テスト群 | 認証・Macro／Rule／CPH生成、ID参照、Logger、通常Montoya開始、Payload tier/mode/位置/保留/対照/証拠、ETA、MCP/Proxyの従来挙動を維持 |

すべてのテストでfailed/error/skipを区別し、XMLから件数を集計します。JUnit taskのUP-TO-DATEやGradleのSKIPPED taskを、テストケースの成功件数へ加算しません。式本体のJUnitテストもUnit戻り値にし、定義したテストが実際に発見・実行された件数と照合します。

追加レビューの回帰では、収集中の承認失効・手動設定変更、未完了callbackの待機、人間の継続承認中の変更、metadata更新の原子性と副作用の分離、操作結果digestと旧schema移行、不変な複数観測、canonicalな承認資料とLoggerの秘匿表示を検証します。契約は、既存設定経由の範囲外通信、native動的設定の能力要求、別Ruleでの前処理と保存確認、必須nativeフィールド、明示した観測元からのMacro変換、二重encodingのパストラバーサル拒否と正当なpercentの保持を確認します。HTTP redirectを使うCPH資格情報の転送もローカルモックで拒否を確認します。

`Http1SenderTest`は実機で観測したnative exchange表示と生Responseの相違を再現します。同じ送信結果から公開Toolの従来表示とworkerの選択済みResponseを別々に取得し、Response本文中の表示区切りに似た文字も保持すること、承認拒否時の送信0回、Response欠落時の拒否を確認します。生Responseを返すだけのモックでnative表示の契約を代用しません。

`JobCompilerTest`と`WorkflowTest`では、native exportで省略される空の`specified_params`に限った比較と、準備・実行・復元の成立を検証します。非空の選択一覧、他のaction/match mode、未知フィールドを変更したnegative caseは引き続き相違とします。実機のraw差分と定義一致は親tempの`native-readback-verification.json`に分けて記録します。

## CPHコピーの検証

`../burp-cph -re`は元CPHの独立コピーです。認証・起動時管理モード・機密ログ抑制・設定Importの修正を含み、既存の動的抽出・置換を維持します。

```powershell
..\Integrale_mocks\.venv\Scripts\python.exe -m unittest discover -s '../burp-cph -re/tests' -v
java -Dpython.cachedir=../temp/relocation-jython-cache -jar C:/jython2.7.4/jython.jar -B '../burp-cph -re/tests/managed_api.jython'
```

上記のCPythonは既存環境を例示しています。Python3の25ケースとJython APIの8ケースはサーバー未起動で、tokenなし・不一致・legacy互換・keep Import・wire JSONのタブ順序・Unicode名・Swing EDT・内側失敗・ログ抑制・body制限・配置先プロファイルを確認します。cached参照の欠落は一度の単一タブImportで再設定し、競合や再設定失敗は成功にしないこと、互換モードでは追加Importしないことも検証します。無効タブや一時的な静的モードでも設定済み参照を保持し、未設定の無効タブへ新たな参照を要求しないことを含めます。Jythonの標準HTTPモジュールは内部イベントループを初期化しますが、テストはlisten/connectしません。

native Importの順序回帰は、CPythonのリストモデルに加えて以下の実Swing 3ケースを実行します。実装からload_config・get_config_tabs・move_tab・cached選択復元を読み込み、Burp全体をimportせずEDT上で実行します。過去のImportと復元によるSwing内部component順の変化まで再現し、旧処理の順序不一致を確認します。既存4タブの全24順列、新規タブ追加、未指定タブの保持、主タブとビューアの件数を照合します。管理モードは一覧を固定して移動先順に処理し、互換モードでは元処理を維持します。

```powershell
java '-Djava.awt.headless=true' '-Dpython.cachedir=../temp/relocation-jython-cache' -jar C:/jython2.7.4/jython.jar -B '../burp-cph -re/tests/native_import_order.jython'
```

既存CPHビューア5ケースは、`CPH_TEST_SOURCE`をこのコピーの本体に向け、親`burp-cph/tests/test_emv_viewer.py`をheadlessで実行します。6個のCPH PythonソースもJythonでcompileし、importやAPI起動を伴わせません。構文合格と実Burpでの動作合格を区別します。

## 実機承認後に確認する項目

以下は今回のモック合格に含めません。

- 管理モードの実機導入と、人間用承認画面の表示・操作・取消。
- 更新CPHのRemove→Burp終了確認→nothing.burpで再起動→Addと、正しい管理API実体への接続。
- 最終構成ごとの5回以上のMCP送信と、実Scanner起点のMacro／Rule／CPH、診断入力・返却応答・後処理の照合。
- 同一Audit内の並列試行とキャッシュ・アカウントの隔離、他Task／Tool通信との干渉。
- Pause／Resume／Cancel、停止確認、native handle喪失後のUI照合、誤設定時の新規再診断。
- native派生通信・リダイレクト・外部作用を含む許可範囲。厳密な送信制限が必要なら外部制限も検証。
- OS主体・ACL・秘密設定の配備、業務データの実際の復元、脆弱性の診断判断。

能力フラグを設定しただけ、5回のHTTP応答、正常再送、JAR生成だけで、これらを確認済みへ変更しません。前処理失敗時の全native送信抑止は現行の既知制約として保持し、保証が必要なJobを未検証のまま実行しません。

初回結果は`verification/archives/decoupling-verification.zip`内の`verification.json`、追加レビュー後の結果と証拠一覧は`decoupling-review-20261105.zip`内の`verification.json`と親`testing.md`に保全しています。当時のtemp参照は各ZIP内の相対パスを指します。

## 選択ロードと再配置の回帰

InstalledRuntimeTestは配置先プロファイルの生成・再読込み・不完全設定と保存先逸脱の拒否、ExtensionBootstrapTestはMontoyaが渡す選択JARパスからの起動を確認します。LocalCphCredentialsTestは両MCPで任意プロファイル・ループバック固定・資格情報不足の拒否を確認します。実ロードでは管理モード表示、workerの認証境界と保存先、既存CPHの状態を読み取りで確認します。CPH切替を保留した場合は診断テスト準備完了にしません。
## 2026-11-20 完了済み診断の不要CPH定義整理

REVIEW専用`diagnostic_job.prune_cph`のidle・全名承認・無効な`job:`定義限定・snapshot固定・厳密readback・Project／Options／台帳／通信非変更を追加した。CPH通常Importのkeep modeでは削除できないため、管理APIに削除直前の全設定照合と指定タブだけの削除を追加した。`CphPruningWorkflowTest`、`CphPruneMcpTest`と`CphConnectionTest`を含む実fixture付き全621件がfailure/error/skip=0、MCP 1.4.24の`embedProxyJar`が成功した。CPH APIの単体73件も成功した。具体的条件、実機のr5回復・97キーから82 handler削除の対象選定、配備後確認は[親のtesting.md](../testing.md)の同名節を正とする。

