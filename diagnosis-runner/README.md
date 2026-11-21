# 診断ジョブ実行サービス

## 再利用する認証設定の保持と対象別切替

新規の`authenticationRetention`は、承認済みの認証Rule・参照Macro・選択CPHとキャッシュ依存先を復元後もBurpへ残します。新規Rule・CPHは待機時に無効化し、Check session is validの定義は保持します。AIは各対象の直前に必要性を判断し、`settings.authenticationStates`で既存定義の有効/無効を選びます。保持するだけで次対象のログインや通信は発生しません。既存Optionsと一時resource poolはbaselineへ戻し、追加Target scopeの保持は明示指定します。

保持によって各構成のRule順序は変更しません。再利用CPHを有効にする場合はcphToolsで必要な通信起点を宣言し、Scanner側の処理にScanner、補助通信に必要ならExtenderを含めます。実行中はそのOptionsフラグを有効にし、終了時は元値へ戻します。指定漏れや無効なScopeのまま、新規承認・準備・開始へは進みません。古い記録の読取り・回復と既存Auditの観測は維持します。

全variantを共有定義込みで再検証し、既存のREVIEW・各必要分岐の5回以上の通信検証・排他・設定競合検出を維持します。途中で失敗した準備は元のbaselineへ回復し、検証完了後は認証定義を保持したbaselineへ回復します。旧保存ジョブの動作とdigestは変更しません。正確な入力形式と依存先の指定条件は公開Tool Description、仕様は親spec.md第2.3章、回帰と未配備範囲は親testing.mdを確認します。

## 下書きの先行検証

公開MCPの`diagnostic_draft`は、次の設定を既存JobCompilerで構造検証する独立した計画経路です。Scan中は既存実行の保存済み復元先（認証保持時は保持後のbaseline）を参照し、ライブ設定や通信へ触れません。入力形式と条件は同Toolの公開Descriptionで完結します。旧runnerの直接registerを下書き検証に使わず、CLIによる通常の正式実行は維持します。

下書きのSTATIC_CHECKEDは実行・承認・実機検証とは別で、正式runtimeのdraft:名前空間に不変ID/digest付きで保存します。現在ジョブの後処理・復元後、diagnostic_jobのproposeで新executionId・draftId・draftDigestを指定して正式化します。最新baselineと元入力で再検証し、以後の承認・5回検証・証拠確認・実行の手順は同じです。構造検証は抽出・認証・実CPHの動作証明ではありません。

## 入力範囲と準備通信の分離

依頼された診断入力を理由付き除外だけで減らさず、明示的な挿入点指定はCookieを含むnativeパラメータの全件を対象または依頼範囲外の除外へ分けます。依頼入力を独立宣言して各構成と一致させる仕様は[親spec.md第2.7章](../../spec.md)、実装・配備・公開静的検証の到達点は親testing.mdを確認します。選択済み入力を前処理・条件付き回復Macroで上書きせず、正式登録のnative検証と下書きの構造検証を区別します。古い所有セッションの固定値による回収等は、観測元と対象範囲を確認した`preparationOnce`へ分けます。毎回のMacroへ固定Cookieの失効を埋め込まず、毎回必要な動的値はMacro／CPHで引き継ぎます。一度だけの送信失敗は既存の回復手順へ進め、結果不明時は別IDで自動再送しません。

依頼入力宣言のない旧保存明示planは、対応版で新しい承認・prepare・Scan開始を拒否します。旧記録のdecode・読取り・capture・recoverと、既存RUNNING Auditの冪等参照・観測・継続承認更新は維持します。保存planを直接編集して拒否を回避せず、新しい計画で依頼範囲を明示します。

入力形式は公開Tool Description、責務と限界は[親spec.md第2.6章](../../spec.md)、回帰と実機の到達点は[親testing.md](../../testing.md)を参照します。REVIEWの人間承認と全証拠の意味確認は維持します。

## 導入と既存実行

通常の導入は[選択ロード手順](../LOAD.md)に従い、Burp起動後にMCP -reのJARと`../../burp-cph -re`のCPHをロードします。管理設定・資格情報・実行記録はMCP -reの`runtime`、過去の検証証拠は`verification`へ配置します。tempの起動スクリプトは使用しません。

版付きJSONと実行処理を分離するサービスです。AIはHTTP解析・対象別の設定案・証拠の判断を担当し、実行サービスは検証・適用・実行・保存・復元を担当します。AI用の通常経路はMCP `diagnostic_job`で、独立JVM runnerも同じworkerを利用する互換クライアントとして維持します。モデルAPIには依存せず、既存のHTTP送信・Montoya Scan開始・Macro／Rule／CPHを再利用します。

HTTP/1.1の公開MCP Toolは従来どおりnative exchangeの表示文字列を返します。ジョブはこの表示を解析せず、同じ承認・正規化・送信処理の型付き結果から選択済みResponseを受け取ります。Macroが返却したResponseと診断Request自体のwire Responseは、Loggerと合わせて区別します。

管理モードではHTTP証拠を`workerStore/http-capture/<captureId>.sqlite`へ保存し、メモリは20,000件・64MiB以内に抑えます。メモリから退避しても保存済み証拠を欠落と数えず、遅い応答もmessageIdで対応付けます。従来モードは5,000件・64MiBの従来保持方式を維持します。`get_logger_history_status`は保存方式、メモリ量・退避数と欠落・保存エラーを区別します。保存エラーを完全収集として扱わず、ディスク残量・保存期間の管理は運用上必要です。

Loggerのページ取得は`afterId`より後、`throughId`以下の固定範囲を指定できます。準備検証は各送信の前後、Scan結果は開始時から収集時の範囲だけを保存し、毎回それ以前の全履歴を再取得しません。診断中の再ロードをログ容量の対処にしません。拡張をアンロードすると生きたAudit handleは失われ、保存済み証拠だけを読めてもScanの継続・再実行はできません。

## MCPによるジョブ操作とモード

`diagnostic_job`は直接設定変更・送信を禁じる管理境界の内側で、検証済みのジョブ操作を提供します。通常のAIフローは次の順です。

1. `get_proxy_http_request_by_id`で観測元を取得する。`includeParameters=true`でnativeの名前・型・値範囲を確認し、バイナリは`includeBinary=true`を使う。画面表示の文字列でファイルを再構成したり、ファイル名の診断位置を推測したりしない。
2. `action=propose`へ完全な`proposalJson`と一意の`executionId`を渡す。`operationId`は再試行でも同じものを使う。
3. `prepare`を開始し、返されたoperationIdを`operation`で確認する。一度だけの準備を指定した場合は各構成の設定適用後に先行して実行し、その後に各構成・分岐の5回以上の検証と設定復元を行う。
4. `validation`をoffset/countで全件取得し、実際の認証・動的値・診断入力保持・選択応答・後処理を確認する。`preparationOnce`と`totalPreparationOnce`がある場合は、反復probesとは独立したページ窓で一度だけの証拠も全件確認する。両方を結び付けた`validationDigest`を記録する。一度だけの通信は5回に数えず、executeで再送しない。
5. 新規`execute`の前に`action=plan_next`へ現在の`executionId`と`nextTargetsJson`で依頼順の残対象を宣言する。最後の対象も`nextTargetsJson="[]"`を明示する。この操作は即時の計画メタデータ登録で、対象送信やScan開始ではない。
6. 確認した`validationDigest`で`execute`を開始する。承認後もサービス内で継続し、各構成のScanを一度だけ開始する。`status`と`operation`は通信を送らず、状態と次の操作を返す。Scan中は`agentNextAction`に従って次設定を作成し、`diagnostic_draft submit_next`へ提出する。`results`と`evidence`で保存済み結果・生通信をページ取得する。

副作用のある操作は即座にoperationIdを返し、承認待ちでMCP呼出しを保持しません。承認待ちは`AWAITING_*_APPROVAL`、承認後は`RUNNING`として追跡します。拒否後は`WAIT_FOR_EXPLICIT_USER_RETRY`で止まり、同じ操作の再取得で承認画面やScanを増やしません。拡張再ロードで中断した操作は`OUTCOME_UNKNOWN`とし、自動再送しません。`advance`は正常再送・復元を進め得るため、読取り専用の状態確認に使いません。

本運用は通常のmcp-server -reとREVIEWを使用します。runtime/settings.json等のオペレーター設定とMCPタブの実効モードを照合し、REVIEWでなければ診断を開始しません。ジョブJSONから承認方式を変更しません。

- REVIEW：準備・実行・回復・長時間継続をBurpの日本語画面で人間が承認する。

対象ごとに観測したnative Macro／Rule／CPHを作成でき、固定テンプレートへ置き換えません。Pause／Resume／Cancelと拡張配備・再起動は既存のUI操作を維持します。

単体・モック結合・ローカルMCP/HTTPプロトコル・Jython互換検証に加え、追加指示によりJARとCPHコピーをBurpへ配備しました。専用127.0.0.1:18084で動的Macro/CPH、人間承認付き準備とScan、独立runnerの結果保存・正常再送・設定復元を確認しています。Cookie削除試験では攻撃対象Cookieを戻さず、後処理だけへログイン応答Cookieを渡す構成を確認しました。反射・保存詳細JSON・保存一覧JSON・保存HTMLの4構成と所有データ/セッション回収も完了しています。版別の証拠・未検証能力・残存する無効タブの範囲は親`testing.md`冒頭と`../verification/archives/decoupling-live-20261105.zip`を参照します。

## データと責務

`diagnosis-contract`の`JobProposal`がAIと実行処理の境界です。診断判断はAIが行い、実行側が対象・参照・構成・承認・順序を検証します。

| フィールド | 内容 |
| --- | --- |
| `schemaVersion`, `jobId`, `revision` | 現在の版は1。実行IDはジョブIDと別で、一つの実行に一つ割り当てる |
| `targetPolicy` | scheme／host／port／pathと、pathPrefixを許可するか。prefixはパスの区切りを確認する |
| `materials` | 観測したRequest／Response、送信先、ID、テキストのUTF-8 SHA-256。wire bytesのハッシュとは区別する |
| `session` | 認証要否、Check session is validのUSE/OMITと理由、アカウント参照、秘密の世代。USEでは読み取り用の観測済みvalidationSourceIdとnative actionが必要 |
| `dynamicBindings` | 取得元、抽出規則、挿入先、時点、依存、失敗方針。AIが設計根拠を説明するための情報 |
| `variants` | 反射確認1構成と、保存結果確認先ごとの独立構成。各構成にRequestとnative設定を持つ |
| `storedVerificationSourceIds` | 今回の保存結果確認先の完全な一覧。構成数との一致を検証する |
| `requiredCapabilities` | 必要な能力。AIによる宣言だけでは有効にならず、Burp起動時のオペレーター設定と照合する |
| `cleanupPolicy`, `limitations` | 所有データの扱い、副作用、未対応条件 |

`variants[].settings`のmacros／rulesはBurpのnative JSONを保持します。既存配列を保持してジョブ所有項目を追加し、既存Macroへの参照も使用できます。`targetScope`は既存include/excludeを保持して追加します。新しいadvanced scopeの変更は現在拒否します。既存advanced scopeを変更せず利用する場合は保持します。

共有CPHキャッシュを使う構成には`variants[].settings.serialScannerRequests=true`を明示します。実行サービスは観測済みのDefault resource poolの上限だけを1・有効へ変更し、他の設定・custom poolsを保持します。準備・実行・正常再送の設定digestへ含め、各段階後に元のpoolを含むbaselineへ復元します。poolが取得できない場合は推測せず拒否します。これはProject全体のpool設定なので、利用する別Taskが動作中でないことを先に確認します。省略時は既存の動作・保存定義のdigestを維持し、上限1を外部で維持する従来の前提も残ります。TaskのPause/Resume/Cancelは変更しません。

新規Macro itemとRuleには既存Burp形式の必須フィールドを含めます。適用される既存Ruleが参照するMacroと、有効な既存CPHの派生通信も対象範囲を検証します。判断できない高度なRuleの適用範囲は保守的に扱います。保存結果のpost-request actionは適用されるRule全体で一つ、最後に実行される構成を要求し、認証・前処理を別Ruleへ分けることは許可します。

Burp 2026.10の読戻しでは`type=run_macro`かつ`match_params=specified`の空の`specified_params`が省略されます。この観測済みの差だけを設定定義の比較とdigestで同一視します。計画のnative JSON自体は保持し、非空の選択一覧、他モード、未知フィールドの変更は無視しません。

観測Requestから動的Macroを作る場合は`settings.macroPreparations`に変換根拠を指定できます。各要素は`macroSerialNumber`、0始まりの`itemIndex`、`sourceId`、`sourceRequestSha256`、`substitutions: [{before, after}]`と任意の`cphTrigger`です。置換元は各段階で一意に一致する必要があり、順にリテラル置換した結果へ`X-cphtarget`を追加したRequestがnative itemと完全一致することを検証します。元Responseと送信先service・methodは保持し、変換後も対象範囲を照合します。指定のない新規Macroは観測Request／Responseとの完全一致を要求します。動的なnative設定を含む場合、`dynamicBindings`の省略によって実機検証能力の要求を回避することはできません。

nativeの`request_parameters[].prior_response_index`を省略すると取得元は先頭の応答（index 0）です。最も近い応答を自動選択する指定ではありません。前処理の追加・並べ替え後は取得元indexを更新し、実際の送信値をその応答へ照合します。ジョブの形式検証やHTTP応答の存在は、認証・保存・削除の意味検証を代行しません。

CPHは既存のJSON形式のままです。`issuer`／`forwarder`は`[isHttps, host, port]`、抽出元は既存のsingle／macro／cachedを保持します。CPHキー順は通常のJSONオブジェクトのキーソートでは保持できないため、`cphOrder`を必須にしています。既存のsourceタブも参照でき、使用する既存タブをcphOrderへ列挙して新しいdestinationより前に置きます。新規タブとMacro／Ruleの名前は`job:<jobId>:`で始めます。CPH Optionsのキーは現行実装どおりSHA-256(options)です。共通Optionsは処理タブではなくnative Exportで常に末尾へ出るため、結合後の実行順でも末尾に配置します。取得元・置換先を含む全処理タブ間の順序は変更・無視しません。管理APIは、Importの移動処理で消えた設定済みのcached参照を、無効タブや一時的な静的モードでも復元し、空でない別参照への競合は上書きせず拒否します。

管理モードのCPH Importは、既存タブの一覧を固定してから移動先の順に並べます。移動中の現在indexを使うiteratorをそのまま走査すると、過去のImport履歴によってタブを飛ばしたり順序を崩したりするためです。未指定タブは元の相対順で後ろに保持し、従来の互換モードの並べ替え処理は維持します。適用後の順序・設定定義の完全な読戻しを必須とし、不一致時は送信しません。

抽出・置換を`dynamicBindings`から別エンジンへ再実装しません。AIが作成したnative設定を検証・承認して反映し、既存Macro／CPHが試行ごとに値を更新します。single抽出の実行時response表示だけは定義の比較から除外し、固定の抽出材料や他の設定を一律に除外しません。

requiredBranchesは各5回以上検証します。normal以外の分岐には状態を作る観測済みRequestをbranchSetupへ指定します。送信回数やHTTP成功だけで判定せず、全ての実通信・アカウント・入力保持・返却Response・後処理を確認し、人間が最終承認します。

`request.startOptions`は既存`start_active_scan`のinsertionPointParameters／payloadProfile／etaProfile／workloadをそのまま受け渡します。従来無視されるconfigは新ジョブでは拒否します。Payloadのworkbook/catalogは承認前にローカルスナップショットへ固定し、既存plan_payload_scanで全ページの計画を確認します。後からファイルが変われば開始を拒否します。tier省略、Hard、保留、timingControlsの従来の意味は変更しません。

## 承認と状態

次はREVIEWによる人間承認と実行の段階です。

1. 草案を静的検証して不変のCompiledPlanを保存する。
2. Burp側の人間用画面で、設定反映と検証通信を承認する。
3. 各variant・分岐について既存MCP送信経路で5回検証し、設定を復元して証拠を保存する。
4. 人間が実際の証拠と最終構成を確認し、Scanと終了後の正常再送・設定復元を承認する。
5. runnerが構成を順に実行し、前のAudit終了・結果収集・正常再送・設定復元後に次へ進む。

準備承認は1時間です。実行承認はJobProposalの`executionApprovalMaxAgeSeconds`（1〜86400秒、省略時3600秒）で指定し、人間の確認画面にも秒数を表示します。同じAuditの継続承認にもこの時間を使います。省略した既存計画のserialized JSONとdigestは変わりません。検証結果には独立して`validationMaxAgeSeconds`を適用し、次構成の開始時にも鮮度を確認します。期限切れ後の自動延長は行いません。設定・正本・秘密世代・対象・報告内容を変更して承認を使い回すことはできません。token／Cookie／作成IDの正常な更新は承認対象の定義と分離しています。

準備完了、native Audit終了、証拠収集、業務状態の復元、脆弱性の判断は独立した状態です。結果の`diagnosisCompleted`は自動でtrueにしません。Site map全体のIssueをAudit固有のIssue件数へ読み替えません。Payload結果は全ページ、Loggerは欠落状態を含めて保存します。

Auditが終了してもPayload callbackやtiming controlが残っていれば、正常再送・設定復元・次構成への移行を待機します。結果収集中や人間の承認画面表示中に承認期限・設定・入力が変わった場合も、後続の副作用を開始しません。

## 障害時

SQLiteの操作台帳へintentを保存してから副作用を開始します。処理直後の切断・保存失敗ではUNKNOWNを残し、同じ操作を自動再送しません。別実行IDでUNKNOWNを迂回することも、Burp側の排他で防ぎます。

状態と排他・承認の更新はmetadata transactionでまとめ、副作用のintentをその未確定transactionへ含めません。台帳の保存結果もdigestを照合し、digestのない旧行は自動利用を拒否します。待機・継続中の複数回の観測は不変の別証拠として保存し、過去の索引を上書きで壊しません。

runner停止はBurpの停止ではありません。承認失効・取消・観測失敗でも、native Auditが続いている可能性を表示します。Pause／ResumeはTask単位、Cancelは対応Audit item単位の既存UI操作を使用します。新しい個別制御Toolや全体engine操作への代替は追加していません。

長時間の同じAuditには`renew_continuation`で人間の継続承認を取得できます。実体・設定・入力が一致する既存Auditだけを追跡し、新規Scanや検証通信の再送には置き換えません。次のvariantの開始には検証の鮮度を引き続き適用し、状態不明の開始や失われたhandleをこの操作で復活させません。

`reconcile`は人間が正しいAuditの終了、補助通信の終了、元設定への復元を確認した後の照合です。元実行を失敗・回復済みとして記録し、Scanを再開・再作成しません。誤設定の修正では従来どおり旧AuditのCancel、修正版の再検証・再承認、新Auditでの再診断が必要です。

MCP recoverはCancel済み等の旧実行について、終了証拠・補助通信終了・設定の所有を確認し、人間の復元承認後に元設定だけを戻します。evidenceRefは終了確認の記録を指します。診断通信・Scan制御・業務データ削除は行いません。digest検証済みの終了記録があっても失われたAuditを再開しません。終了不明・別所有・手動変更・未完了通信は拒否し、復元成功後も旧実行はFAILED_RECONCILEDとして残します。

設定比較ではBurpが省略する空のspecified_paramsと、derive_from_prior_responseのprior_response_index=0だけを既定値として正規化します。提案・保存原本は変更せず、別indexや未知の項目の差は引き続き競合とします。CPH管理モードのsingle_response定義は表示欄ではなく内部応答データからImport/Exportし、表示更新の遅延・タブ移動で固定の抽出材料を失わないようにします。既存互換モードの表示欄を使う挙動は維持します。

CPH keep Importでは追加タブを削除できないため、終了時は所有タブを無効化し、残存を記録します。これを完全削除と表示しません。手動変更との競合では自動上書きを行いません。設定の復元と業務データの復元も別に報告します。

逐次実行を明示したジョブの失敗回復では、現在のresource pools全体が元設定または承認済みの構成と完全一致するときだけ元値へ戻します。遅延・custom pools・未知フィールドなどの手動変更を、同時実行数の変更に含めて無視しません。これは通信前の部分適用失敗と、終了・取消確認済みのAuditの両方に適用します。

保存結果は、索引とdigestを照合してBurp参照が失われても読み取れます。新索引のない過去の証拠に、完全性確認済みの根拠を捏造しません。実行中の部分結果はresults／refresh_resultsで取得でき、診断の完了には数えません。

## 配布物と起動設定

明示的に許可された保守用の公開MCP `diagnostic_job.retire`は、旧epochの排他所有について人間の現在Project確認を受け、`RETIRED_UNVERIFIED`として所有だけを解除します。現在のtracked Auditに稼働・不明状態がある場合、旧handleが残る場合、補助通信や旧所有Macro・Rule・CPH/参照が残る場合は拒否します。人間はUI起点・再ロード前のAuditも確認し、承認前後の現在snapshotが変われば拒否します。設定反映・復元・native制御・HTTP送信はせず、旧記録・証拠と現在snapshotを保全します。旧終了・復元・業務回収・診断完了を確認済みにはしません。`status.context`で実際の排他所有者を読み取れます。正常な回復は従来のrecoverを使い、通常の診断依頼を保守の許可へ広げません。

配布物の生成だけを行うコマンド（Burpは起動しません）：

```powershell
.\gradlew.bat test embedProxyJar :diagnosis-runner:installDist
```

JARは`build/libs/burp-mcp-all.jar`、runnerは`diagnosis-runner/build/install/diagnosis-runner/`、CPH -reは兄弟ディレクトリ`../burp-cph -re/`です。元の`../burp-cph`は維持します。元のMCPには、同じCPH -reへ接続するための任意のローカル資格情報読込みだけを追加しています。

通常はBurpが渡すロード済みJARの配置からruntimeを特定します。以下の環境変数は高度な起動設定との互換入力です。起動・配備の権限はユーザー指示と運用規則に従います。実機の版別結果、現在の状態と未完了項目は親の`testing.md`冒頭へ集約します。

| 設定 | 用途 |
| --- | --- |
| `BURP_DIAG_MANAGED=1` | 高度な起動設定の互換入力。通常は未設定でインストール先runtimeによる管理モード。明示的な0は互換モード |
| `BURP_DIAG_AUTHORIZATION_MODE` | 高度な起動設定の互換入力。本運用ではREVIEWを使用し、MCPタブで実効値を確認 |
| `BURP_DIAG_WORKER_TOKEN` | runner専用資格情報。32文字以上。AI用MCPへ渡さない |
| `BURP_DIAG_CPH_TOKEN` | CPH専用資格情報。worker tokenと別の32文字以上の値 |
| `BURP_DIAG_STORE` | 高度な起動設定でのworkerの絶対保存先。通常はruntime/settings.jsonのworkerStoreを使用 |
| `BURP_DIAG_INPUT_ROOTS` | 承認するローカル入力root。Windowsでは`;`区切り |
| `BURP_DIAG_SECRET_GENERATIONS` | 必要な場合、オペレーターが保護するJSONの絶対パス。`provider/handle: generation`の文字列mapで、承認した秘密参照の世代を操作前に照合する |
| `BURP_DIAG_VERIFIED_CAPABILITIES` | 実機確認済みのSCANNER_WORKFLOW、EXCLUSIVE_CONTEXT、必要ならDYNAMIC_WORKFLOW_VERIFIED等を`,`区切りで設定 |
| `BURP_DIAG_WORKER_URL` | runnerが接続するループバックの`/diagnosis/worker`。既定は127.0.0.1:9876 |

能力設定は人間による実機確認の表明であり、環境変数を指定しただけで機能を検証したことにはなりません。特に同一Audit内の試行隔離、同じCPH/アカウントへの他Tool通信、前処理失敗時の送信抑止を別々に確認します。未対応拒否だけを既存動的機能の維持の合格に数えません。

秘密の世代mapは既存設定や外部credential providerの参照を固定するためのものです。秘密値を返すAPIではなく、OTP生成や任意の秘密ストアを新たに実装したものではありません。世代を指定したジョブは、provider情報が未設定または不一致なら開始しません。

管理モードでは既存MCPの直接書込み・送信・Scan開始をサーバー側で拒否し、CPH APIも認証します。実効モードは起動時に確認し、AIがジョブから解除しません。既存のデータアクセス承認とジョブの人間承認を区別します。

workerはMCP再起動時もloopback bindを要求し、要求本文を16MiBまでに制限します。CPH接続ではHTTP redirectへ資格情報を転送しません。CPHコピーのAPIはUnicodeのタブ名とJSON順序を保持し、Import／Exportを直列化してSwing EDT上で設定へアクセスします。実Burpでの読戻し一致は別途確認が必要です。

REVIEWの設定反映には既存のEnable tools that can edit your configを有効にします。管理モードのAI用MCPに直接書込み権限が戻るわけではありません。承認画面は保護表示と人間が読める原本参照を提示します。

runnerの操作は`prepare <executionId> <client-store> <job.json>`、`run <executionId> <client-store>`、`status`、`poll`、`results`、`revoke`、`reconcile <executionId> <client-store> <evidenceRef>`です。prepareも検証通信を伴うため、実機検証の承認前に実行しないでください。標準出力には秘密を含む結果を表示せず、保存先だけを返します。

CPHコードを変更した版の読み込みには、AGENTS.mdのRemove→Burp終了確認→nothing.burpで再起動→Addを適用します。既存CPHへ稼働中に上書きしてはいけません。

この実装の承認分離はプロトコル上の境界です。同じOS権限の任意コードや画面操作を人間と区別する保証はありません。必要な運用ではサービス用OS主体・ACL・別端末の承認を用意します。生成したSQLite/生通信ファイルには秘密が含まれ得るため、人間が保護された保存先を配備してください。ネットワークの厳密な送信制限も別の能力であり、Target scopeをファイアウォールとは扱いません。
