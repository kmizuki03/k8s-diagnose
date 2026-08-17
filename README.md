# k8s-diagnose Go版 説明書

Kubernetesの状態をread-onlyで取得し、異常、診断不能、原因候補を分離して報告する診断CLIです。Python版の出力スキーマ、CI方針、Root Cause相関、SQLite履歴と互換性を保ちつつ、Kubernetes API取得を`kubectl` subprocessから`client-go`の型付きクライアントへ移行しています。

Go版の主な目的は次の4点です。

- `apierrors.IsNotFound` / `IsForbidden` / `IsTimeout`などによる構造化エラー分類
- `resource.Quantity`とKubernetes公式`PodRequests()`による数量・リソース計算
- List APIの`limit` / `continue`ページング、QPS/Burst、並列取得による大規模クラスタ対応
- 単一バイナリ、型付きFinding、ルールレジストリ、自動RBAC生成による配布・保守性の向上

## 1. 動作要件

- 実行時: 有効なkubeconfigまたはin-cluster相当の認証情報
- ビルド時: `go.mod`とCIが指定するGo 1.25.13以上。別minor系列を使う場合も、その系列の最新security patchを使用
- `kubectl`: 通常診断には不要。`--debug`の対話実行時のみ必要
- `curl` / `jq` / `openssl` / `nc`: 不要

Kubeconfigの`exec` credential pluginを使っている場合は、そのplugin本体（例: クラウドCLI）は実行環境に必要です。

## 2. ビルドと起動

```bash
make build
./k8s-diagnose --version
./k8s-diagnose --help
```

`make build`はGit tag（tagがなければcommit hash、変更中は`-dirty`付き）をバイナリへ注入します。また、端末に別のGoが入っていても、既定では`go.mod`に記載したパッチ版を`GOTOOLCHAIN`で使用します。別の修正版を明示する場合は、例えば`make GOTOOLCHAIN=go1.26.6 build`とします。直接ビルドする場合は次のように同じ値を渡せます。

```bash
VERSION=$(./scripts/version.sh)
go build -trimpath \
  -ldflags "-s -w -X github.com/kmizuki03/k8s-diagnose/internal/config.Version=$VERSION" \
  -o k8s-diagnose .

make test
make clean   # ルートのk8s-diagnoseだけを削除
make fclean  # 上記に加えdist、ルート直下のDB・coverage・*.outを削除
make re      # fclean後にバイナリを再ビルド
```

`make` / `make build`は、Goソース、`go.mod`、`go.sum`、バージョンスクリプト、Makefileのいずれにも変更がなければ再リンクしません。既存バイナリを必ず作り直す場合は`make re`を使用します。

CIや配布工程で明示的なバージョンを使う場合は、クリーンな環境で`K8S_DIAGNOSE_VERSION=v3.0.0 make build`を実行します。既存バイナリがある環境でバージョンだけを変えて作り直す場合は、`K8S_DIAGNOSE_VERSION=v3.0.0 make re`を使用してください。

### 実運用向けの配布物を作る

```bash
make package

# Linux AMD64向けを明示して作る例
GOOS=linux GOARCH=amd64 K8S_DIAGNOSE_VERSION=v3.0.0 make package
```

生成物はGit管理外の`dist/releases/`へまとめられます。

```text
dist/releases/k8s-diagnose_VERSION_OS_ARCH/
├── k8s-diagnose              # Windowsではk8s-diagnose.exe
├── README.md
├── VERSION
├── CONTENTS.txt
├── k8s-diagnose.ini
├── baseline.example.ini
├── log-signatures.example.ini
└── rbac/
```

同じ内容の`tar.gz`とSHA-256ファイルも生成します。配布ディレクトリにはGoソース、`*_test.go`、CI定義、レビュー資料、開発スクリプトを含めません。`*_test.go`は配布バイナリには元々組み込まれませんが、ソースリポジトリでは回帰検査に必要で、Goでは対象パッケージと同じ場所に置くため追跡を継続します。

個人用の設計メモやレビュー原稿は`.local/notes/`へ置きます。`.local/`全体はGit管理外です。生成済み配布物を作り直す場合は、`make fclean`の後に`make package`を実行してください。

## 3. 説明書を読まずに始める

使う人に合わせて、同じ診断エンジンへ3つの入口を用意しています。

### 初めて・久しぶり: 引数なしの対話メニュー

```bash
./k8s-diagnose
```

引数なしで対話端末から実行すると、まず診断対象を選ぶ画面が開きます。`↑` / `↓`とEnterまたは`→`で操作でき、選んだモードで利用できる追加機能だけを次に表示します。戻る操作は`b`だけに統一しています。値入力画面では`b`と入力してEnterを押すと直前の項目へ戻り、`q`はメニューを終了します。

```text
何を診断しますか？
  クラスタ全体
  Podを1つ選んで詳しく
  Pod一覧だけ
  quick / ci / deep
  設定を変更する
```

例えばPod個別を選んだ場合だけ接続確認とdebugを提示し、接続確認を有効にした場合だけローカルポートとHTTPパスを尋ねます。全体診断ではPod個別専用の接続確認を表示しません。したがって、無効な組み合わせを覚えて避ける必要がありません。パイプ入力など対話端末でない引数なし実行は、後方互換のため従来どおり`all`として実行します。

### 慣れた人: 1語のプリセット

```bash
./k8s-diagnose quick   # 短時間のtriage、text、一度だけ
./k8s-diagnose ci      # triage、JSON、確定異常でexit 1
./k8s-diagnose deep    # 全体診断＋失敗Podログ＋未使用候補
```

対象などは通常のフラグで上書きできます。

```bash
./k8s-diagnose quick -n prod
./k8s-diagnose ci --output-file result.json
./k8s-diagnose deep --no-cmd
```

### 上級者・CI: モード別コマンドまたは従来フラグ

```bash
# モード名を直接指定
./k8s-diagnose all --logs --unused
./k8s-diagnose pod --connect --connect-path /ready
./k8s-diagnose list -n prod
./k8s-diagnose triage --output sarif --output-file result.sarif

# 従来形式もそのまま利用可能
./k8s-diagnose -a -n prod
./k8s-diagnose --triage --output json --output-file result.json
./k8s-diagnose -s
./k8s-diagnose -s -n prod --connect
```

ヘルプも段階化されています。ルートの`--help`は入口だけを短く表示し、各コマンドのhelpは関係するオプションだけを表示します。全フラグのリファレンスは`advanced`にあります。

```bash
./k8s-diagnose --help
./k8s-diagnose pod --help
./k8s-diagnose all --help
./k8s-diagnose advanced --help
```

## 4. 診断モード

| モード | 分かりやすい指定 | 従来指定 | 用途 |
|---|---|---|---|
| 全体診断 | `all` | `-a`, `--all` | Pod一覧、全ルール、Root Cause、Health/Coverage |
| Pod選択 | `pod` | `-s`, `--select` | 一覧上でNamespace検索とPod名検索を個別編集し、上下矢印＋Enterで選択。ログ、任意の接続確認/debug |
| Pod一覧 | `list` | `-p`, `--list`, `--pods` | Pod表と件数だけを取得。Pod API以外は要求しない |
| トリアージ | `triage` | `--triage` | CIや初動向けのコンパクトな診断 |

モードは同時に1つだけ指定できます。引数なしの対話端末ではガイドを表示し、非対話環境での未指定時は`all`です。`quick` / `ci` / `deep`は上表のモードへ安全な設定一式を重ねるプリセットです。

## 5. オプション一覧

### 対象とAPI負荷

| オプション | 既定 | 説明 |
|---|---:|---|
| `-n, --namespace NAME` | 全namespace | 対象namespace |
| `--context NAME` | current-context | kubeconfig context |
| `--kubeconfig FILE` | 標準探索 | kubeconfigパス |
| `--timeout SEC` | `15` | 1 API要求のタイムアウト |
| `--workers N` | `4` | 独立取得の並列数、1〜16 |
| `--qps N` | `10` | client-go rate limiterのQPS |
| `--burst N` | `20` | client-go rate limiterのBurst |
| `--page-size N` | `500` | List APIの1ページ件数、1〜5000 |

### 追加診断

| オプション | 説明・制約 |
|---|---|
| `--logs` | 異常Podのcurrent/previousログを取得。RunningでもReady未達・直近再起動/OOM等があれば対象。`-a`専用 |
| `--unused` | ConfigMap / Secret / PVC / ServiceAccountの未使用候補。`-a`専用 |
| `--events-limit N` | text表示するWarning Event数。既定20 |
| `--restart-threshold N` | 直近24時間の再起動警告閾値。既定5 |
| `--node-heartbeat-timeout SEC` | Node Lease停滞判定秒数。既定180。`-a` / `--triage`のみ |
| `--log-signatures FILE` | カスタムログシグネチャINI。`-s`または`-a --logs` |
| `--log-signature-lines N` | 解析する末尾行数、1〜5000。既定200 |
| `--connect` | `-s`でProbe/Pod直接/Serviceの転送先ポートを一時port-forwardにより単発確認。追加確認なし。port-forwardはPodへ直接つなぐため、ClusterIP経由の経路は検証しない |
| `--connect-port PORT` | ローカル先頭ポート、1024〜65535。`--connect`必須 |
| `--connect-path PATH` | `/`で始まるHTTP pathの上書き。`--connect`必須 |
| `--debug` | 診断後に対話debugメニュ。`-a` / `-s`のtext出力のみ |
| `--debug-image IMAGE` | debug image。既定`busybox:1.36`。`--debug`必須 |
| `--debug-profile NAME` | kubectl debug profile。既定`general`。`--debug`必須 |

### 表示・CI・レポート

| オプション | 既定 | 説明 |
|---|---:|---|
| `--tail N` | `30` | text表示ログ行数。明示指定は`-s`または`-a --logs` |
| `--no-mask` | mask有効 | 対話端末のtext出力だけマスクを無効化。pipe/redirectおよび永続出力との組み合わせはエラー |
| `--cmd`, `--no-cmd` | 表示 | text出力で、各診断項目の見出し直後・結果本文の前に等価kubectlコマンドを表示／非表示 |
| `--api-requests`, `--no-api-requests` | 非表示 | text出力末尾の「実行したKubernetes API要求」を表示／非表示。既定は非表示で、`--api-requests`または`[display] show_api_requests = true`で表示 |
| `-w, --watch SEC` | 無効 | `-a` / `--triage`の定期実行。1以上 |
| `--exit-zero` | 無効 | 所見があってもexit 0。引数/API/保存/通知エラーは1。`--list`では使用不可 |
| `--output FORMAT` | `text` | `text`, `json`, `sarif`, `junit`, `mermaid`, `dot` |
| `--output-file FILE` | stdout | 構造化出力の保存先 |
| `--save-snapshot FILE` | 無し | report/v1 JSON snapshotをatomic保存 |
| `--diff FILE` | 無し | 前回snapshotと比較 |
| `--save-cluster-snapshot FILE` | 無し | 診断元のクラスタ状態（入力）をマスクして保存。`--list`では使用不可 |
| `--load-cluster-snapshot FILE` | 無し | 保存したクラスタ状態で再診断。クラスタ接続不要 |
| `--baseline FILE` | 無し | 期限・理由付き承認所見INI。`-a` / `-s` / `--triage` |
| `--fail-on LEVEL` | `issue` | `issue`, `warning`, `unavailable`, `any`, `none`。明示指定は`-a` / `--triage` |
| `--max-issues N` | 無し | fail-on対象所見の許容件数。`-a` / `--triage` |
| `--config FILE` | `./k8s-diagnose.ini`（存在時） | 別のINI設定ファイルを指定。Go標準`flag`互換の`-config FILE` / `-config=FILE`も受理 |
| `--no-config` | 無効 | カレントディレクトリの`k8s-diagnose.ini`を自動読込しない |
| `--version` |  | バージョン表示 |

`--output-file`、`--save-snapshot`、`--save-cluster-snapshot`、`--history-db`は互いに別ファイルへ保存してください。また、設定・差分・baseline・ログシグネチャ・明示指定したkubeconfig・`--load-cluster-snapshot`と同じ実体（symlink / hard linkを含む）は、入力ファイルの上書きを防ぐため拒否します。

#### クラスタ状態の保存と再生（不具合報告・回帰テスト用）

`--save-snapshot`は診断の**結果**を保存しますが、`--save-cluster-snapshot`は診断の**入力**であるクラスタ状態そのものを保存します。報告者がクラスタを直した後でも、受け取った側が同じ指摘を再現できます。

```bash
# 報告する側: 指摘が出た状態を保存する
./k8s-diagnose -a --save-cluster-snapshot snapshot.json

# 受け取った側: クラスタに接続せずに同じ診断を再現する
./k8s-diagnose -a --load-cluster-snapshot snapshot.json
```

- 保存時に既存のマスク方針（`redact`）を適用します。環境変数の値、annotation中の資格情報、`name: DB_PASSWORD` のようなname/value形式の値もマスクします。異なる秘匿値を再生時に同一値と誤認しないよう、保存ごとの一時HMACによる非可逆な識別子だけを残します（鍵と元値は保存しません）
- クラスタの内部構成を含むため、ファイルは`0600`で書き出します
- 再生時はKubernetes APIへ接続せず、kubeconfigも不要です。保存元contextが記録されている場合は、接続先を`CONTEXT（保存済みクラスタ状態）`と表示します
- 保存ファイルには取得時の診断モード、namespace範囲、`--unused`の有無を記録します。部分取得したデータをクラスタ全体と誤認しないよう、再生時は保存時と同じモード・`-n/--namespace`・`--unused`指定が必要です。一致しない場合は診断を開始せずエラーにします
- `-s --load-cluster-snapshot`では、保存済みのPod一覧から選択し、選択後の構成・状態診断も保存データだけで行います。コンテナログ自体はクラスタ状態ファイルへ保存しないため、現在／前回ログは理由付きの`確認不能`としてCoverageへ反映します
- 接続が前提の`--connect`、`--debug`、`--logs`、および`--watch`とは併用できません
- 過去状態を現在の運用履歴や新規アラートとして扱わないよう、`--history-db`と`--webhook-url-env`も再生時は使用できません。副作用のない`--diff`、構造化出力、結果snapshot保存、CI終了条件は利用できます
- スキーマは`k8s-diagnose/cluster-snapshot/v2`で、`schema`が一致しないファイルは読み込みを拒否します。v2では安全な再生に必要な取得範囲を必須情報として保持します

受け取ったスナップショットはそのまま回帰テストのフィクスチャやベンチマーク入力として使えます。

`--watch`は所見によって途中終了せず、Ctrl-Cを正常終了として扱うため、`--exit-zero`、`--fail-on`、`--max-issues`は併用できません。`--exit-zero`と`--fail-on/--max-issues`、および`--fail-on none`と`--max-issues`も、片方の指定が意味を失うためエラーにします。

### 履歴と通知

| オプション | 既定 | 説明 |
|---|---:|---|
| `--history-db FILE` | 無し | Python版と互換のSQLite履歴DB |
| `--history-window N` | `12` | 同一context/namespace/modeの分析回数 |
| `--flap-threshold N` | `3` | 異常/正常の遷移回数閾値 |
| `--restart-growth N` | `3` | restartCount増加量の閾値 |
| `--history-retain N` | `1000` | DB全体の最大保持実行数 |
| `--webhook-url-env NAME` | 無し | HTTPS webhook URLを格納した環境変数名 |
| `--webhook-format TYPE` | `generic` | `generic`またはSlack Incoming Webhook向け`slack` |
| `--webhook-timeout SEC` | `5` | 送信タイムアウト |

Webhookは`--diff`、`--history-db`、`--watch`のいずれかと併用します。新規またはissueへ悪化した所見だけ通知します。`abnormal → unknown → abnormal`は既存異常の再確認とし、再通知しません。

CLIとINIのどちらでも、`--webhook-format` / `--webhook-timeout`に相当する値には`--webhook-url-env`が必要です。`--history-window` / `--flap-threshold` / `--restart-growth`は`--history-db`または`--watch`、`--history-retain`は`--history-db`と組み合わせます。配布設定例では従属オプションを空欄にして組み込み既定値を使用し、機能を有効にするときだけ値を明示します。

Webhook URLはHTTPS必須、userinfo/fragment/制御文字禁止です。HTTP 3xxのredirectは追従しません。通知失敗はexit 1ですが、それより前にhistory/snapshot/reportを保存するため診断証跡は失われません。URLは運用者が管理する信頼済み設定を前提とし、localhost・プライベートIP・link-localを一律には拒否しません。外部入力からWebhook URL環境変数を書き換えられないようにしてください。

### 端末表示と色

対話端末では`--help`と診断結果をANSIカラーで表示します。Pod一覧は正常Podを緑2色のゼブラ、待機・要注意を黄色、確定異常を赤で表示します。Root Causeは確定を赤、原因候補を黄色、要確認を紫、修正候補を明るい緑で強調します。

text形式の診断結果には「診断内容（実施状況）」セクションを表示します。実施できた項目は`検査内容 → 対象 → 結果`の順で並び、結果には`所見なし`、`確定異常`、`警告`、`要確認`の件数を表示します。ConfigMapやSecretなどの一覧取得に成功した場合は対象件数を示し、0件なら`この診断範囲には存在しません`と明示して取得不能と区別します。ConfigMapは、各namespaceへ通常自動注入される`kube-root-ca.crt`とその他の件数を分けるため、アプリ用ConfigMapが0件なのに「ConfigMapがある」ように見えることもありません。所見がある項目では、その直後に手動確認用コマンドも表示します。具体的な所見本文は続く重大度別一覧へ集約し、同じ文章を二重表示しません。確認不能な項目は共通理由ごとにまとめ、全件の詳細は「確認できなかった項目」に表示します。補助的に取得するEndpointSliceやStorageClassなどは親ルールの異常判定と混同せず、`追加情報を取得済み`または理由付きの`確認不能`として示します。コマンドは`--no-cmd`または`show_commands = false`で非表示にできます。`実施済み`は異常がないという意味ではなく、判定処理を実行できたことを表します。

引数なしのガイド、設定エディタ、`-s`のPod選択はすべて`↑` / `↓`とEnterまたは`→`で操作します。複数選択ではSpaceまたはEnterでチェックを切り替えます。戻るキーは`b`、終了キーは`q`です。戻るための選択行は表示しません。最初の「何を診断しますか？」は余白を抑え、一般的な23行以上の端末では8項目をページ分割せず全件表示します。Pod選択では、一覧を表示したまま`n`でNamespace、`/`または`f`でPod名を検索でき、`r`で両方を続けて編集、`c`で条件消去できます。Pod一覧での`b`は検索前の一覧へ戻る操作で、検索していないときは戻り先がないため案内に表示せず、押しても終了しません。対話端末では選択UI全体を代替スクリーンへ描画するため、決定・終了後は一覧と操作案内を消して元の画面へ戻してから診断結果を表示します。Pod数やその他のメニュー項目が端末高を超える場合は、選択行を中心に表示範囲を自動スクロールします。

パイプ、ファイルredirect、構造化出力ではANSIコードを自動的に出しません。端末でも色を止める場合は標準の`NO_COLOR`を設定してください。

```bash
NO_COLOR=1 ./k8s-diagnose -a
```

## 6. 主な診断内容

- Pod/container: CrashLoopBackOff、ImagePullBackOff、現在/直近終了のOOMKilled、Ready、Pending、native sidecar、DisruptionTarget、PodReadyToStartContainers、直近再起動（debug用ephemeral containerの終了はPod異常にしない）
- Workload: Deployment / ReplicaSet / StatefulSet / DaemonSetのreplica、ProgressDeadlineExceeded、ReplicaFailure、CronJob suspend
- Scheduling/Node: nodeSelector、required nodeAffinity、taint/toleration、cordon、Node状態taint、Node Lease heartbeat、CPU/Memory/HugePages/extended resource、Pod数上限、Pod overhead、in-place resize、PVC、schedulingGate、nominatedNodeName
- Service: selector、EndpointSlice ready/terminating+serving、Endpoints fallback、named targetPort、数値targetPortの未宣言（候補扱い）、LoadBalancer pending
- 依存: optionalを考慮したSecret/ConfigMapオブジェクトとキー、PVC、ServiceAccount、PriorityClass、RuntimeClass。参照先リソース自体が無い場合は、種別・namespace・名前・参照元を明示します。`optional: true`ならPod起動を妨げないため確定異常にはせず「要確認」とし、必須参照と同じ対象を併記している場合は必須側だけを表示します。オブジェクトは存在するのに参照キーだけ無い場合も、キー名の誤りが疑われる候補として報告します。Secret Volume、projected Volume、CSI `nodePublishSecretRef`、従来型VolumeプラグインのSecret参照も追跡。欠落imagePullSecretはNode資格情報等でpull可能なためwarning
- ConfigMap: 参照は解決できてもコンテナへ反映されない状態を診断します。同じ変数名が複数の`envFrom`や`env`から設定されてConfigMapの値が使われないキー衝突（値が実際に異なる場合のみ・候補扱い）、`subPath`マウント（ConfigMapを更新してもファイルが差し替わらない・候補扱い）、1オブジェクト上限1MiBへの接近を確認します。Kubernetes 1.34では緩和済み環境変数名が既定で有効なため、数字で始まるConfigMapキーを異常扱いしません。また、kubeletの`envFrom`が展開するのは`data`だけであり、`binaryData`を環境変数や衝突元として扱いません
- Storage/TLS: WaitForFirstConsumer、PVC Lost/resize condition、PV Failed/Released/Pending、Ingressが参照するOpaque Secretを含むPEM/DERバンドル全証明書、TLSキー欠落・空データ・秘密鍵不正・証明書との不一致、期限切れ/有効開始前
- Ingress/Webhook/API: backend/TLS/IngressClass参照、Admission Webhook Service、APIService、CRD condition、API warning header、readyz/livez（各endpointを独立してCoverageへ計上）
- Policy: ResourceQuota使用率、PodDisruptionBudget、NetworkPolicy selector適用状況
- メトリクス: `metrics.k8s.io/v1beta1`からNode使用量とCPU上位10 Podを取得（NodeとPodを別々にCoverageへ計上）
- 構成リスク: `:latest`/タグなしimage、CPU/Memory requests未設定、livenessProbe未設定（Job Podを除外）。Pod-level requestsがあるresourceはcontainer未設定を候補にしない。同一コンテナで同じ環境変数名が異なる値で複数回定義されている場合は、後の定義だけが採用され先の値が捨てられるため候補として報告（値が同じ重複は報告しない）
- ログ: OOM、Go panic、Python Traceback、x509期限切れ、address in use、通信失敗等のシグネチャ

Pending解析は偽陽性を抑えるため「5分以上継続」「PodScheduled=UnschedulableまたはFailedScheduling Event」「未評価制約なし」「配置可能Node 0」が揃った時だけissueにします。podAffinity / podAntiAffinity / topologySpreadConstraints / hostPort / DRA / custom schedulerを無理に確定せず、未評価として示します。全namespace Pod、PVC、StorageClass、Eventなど任意入力の取得に失敗してもnodeSelector・taint等の評価は続け、欠けた部分だけCoverageを下げます。Pending PVCが明示指定したStorageClassが存在しない場合は、一般的な未Bound警告ではなく確定異常として示します。

Kubernetes timestampを使う経過時間判定（Pod/Pending/Namespace/LoadBalancer/PV/NetworkPolicy/TLS/Probe待機）は、端末時計のずれによる誤判定を避けるためAPI ServerのHTTP `Date`を共通基準にします。`Date`が返らない環境だけローカル時刻へフォールバックします。

ResourceQuotaは90%以上100%未満をcandidate、hard到達時をwarningとして扱います。CPU/Memoryの実使用量は`metrics.k8s.io`から取得し、`kubectl top`相当のNode一覧とCPU上位10 Podを表示します。metrics-server未導入、RBAC拒否、API障害はクラスタ異常ではなく診断不能として扱い、Node/PodそれぞれのCoverageだけを下げます。これはrequests/allocatableを使うScheduling診断とは別機能です。

Service endpoint判定はEndpointSliceを主経路にします。core/v1 EndpointsはKubernetes v1.33以降deprecatedですが、EndpointSlice取得不能時や旧環境との互換性のためread-only fallbackとしてのみ保持しています。名前付き`targetPort`はKubernetes本体と同様に通常コンテナとrestartable init sidecarだけを対象とし、Serviceと`containerPort`のprotocol一致も確認します。名前解決に失敗した場合は、Serviceポート、selector、一致したPod、Pod側に存在する同protocolのcontainerPort名、EndpointSliceでの確認結果を検出根拠として表示します。UDP/SCTP ServiceをTCP接続確認へ流用しません。

## 7. Root Causeとスコア

Findingは`code`, `severity`, `resource`, `stable_key`, `confidence`, `evidence`を持ちます。IDは`code + resource + stable_key/reason`から生成し、経過時間や回数を含む自由文はIDに使わないため、diffが毎回ノイズになりません。

依存グラフは例えば次を相関します。

```text
Secret / ConfigMap / PVC
  └─ Pod
      ├─ ReplicaSet → Deployment
      └─ EndpointSlice → Service → Ingress

PersistentVolume → PVC → Pod
Job → CronJob
Service → Admission Webhook
```

確信度90%以上を「根本原因」、60〜89%を「原因候補」、60%未満を「関連候補 / 要確認」と表示します。各Root Causeの詳細には、判定ルール、対象リソース、照合に使用した設定値や状態を「検出理由・根拠」として表示します。クラスタHealthは同一根本原因の波及症状を重複減点しません。Coverageはクラスタの健全性ではなく、実施できた診断ルールの割合です。text出力ではHealthとCoverageを別々の横棒ゲージとして表示し、HealthのA〜D評価、Coverageの確認済み件数、重大度別の所見件数を同じスコアカード内で確認できます。

`-s`はクラスタHealthの見出しだけを変えた値ではなく、選択Pod専用の「Pod総合スコア」を計算します。100点を`ライフサイクル 15`、`Ready・Condition 15`、`コンテナ稼働 20`、`再起動・ログ 10`、`Resources・構成 5`、`Scheduling・Node 8`、`依存リソース 7`、`Storage 4`、`Probe・接続 6`、`Service・Endpoint 4`、`NetworkPolicy 2`、`Ingress・TLS 4`の12項目へ分けます。phase/Ready、各コンテナの実状態、直近再起動・OOM・ログ所見、requests/limitsとメモリ使用率、Node/Scheduling、ConfigMap/Secret/PVC等の依存、Probe設定と単発接続結果、選択Podを実際に参照するService/Endpoint/NetworkPolicy/Ingress、関連TLS証明書の期限切れ・30日以内の期限を反映します。確認不能はクラスタ異常として減点せずCoverageへ分離します。選択時のService・Endpoint・Ingress・PVC・Secret・ConfigMap・NetworkPolicy・EventはPodとの参照関係で絞るため、同じnamespaceにある無関係なリソースはこのスコアへ入りません。

## 8. 接続確認の仕様

対話ガイドで「接続確認」を選ぶか、CLIで`-s --connect`を指定した時点を実行への同意として扱います。接続確認は一時的なport-forwardトンネルを作成しますが、実行直前の追加確認は求めません。対話ガイドでは選択欄にこの注意を表示します。

- readiness / liveness / startup Probeをそれぞれ独立して列挙
- startupProbe完了待ちやinitialDelaySeconds中のProbeは「未実施」と表示
- HTTP/HTTPS Probeはpath, scheme, httpHeaders, timeoutSecondsを引き継ぐ
- `httpHeaders`の`Host`は再現するが、`httpGet.host` / `tcpSocket.host`は接続先そのものの指定なので、Podへのport-forwardでは同じ経路を再現できず「未実施（診断不能）」として表示
- User-Agent / AcceptをProbe側が明示した場合は明示値を優先
- response bodyはkubeletに合わせ10KiBまで
- アプリの応答本文は改行を保ったままマスクして端末にだけ表示します。確認に失敗した対象は全文（上限あり）、成功した対象は1行のプレビューを出すため、「200だが中身はエラーページ」を見分けられます。画像などバイナリの本文はバイト列を出さず種別とサイズだけを示します。Finding・snapshot・履歴・Webhookには従来どおりstatus code / Content-Type / 読取byte数だけを保存
- HTTP 2xx/3xxを成功、別host redirectと10回超は追従せず注意扱い
- HTTP ProbeのないポートはHTTPを送らずTCP接続のみを確認します。port-forwardのローカル側は転送先へ到達する前に接続を受け付けるため、`net.Dial`の成功だけでは待ち受けの有無を判定できません。接続後の読み取りで判定し、即座に切断された場合は「トンネルは確立したが転送先が待ち受けていない」として失敗、要求待ちのまま維持された場合を成功とします。port-forward自身が報告した理由も併記します
- 「Pod直接」と「Serviceの転送先ポート」を別々に表示。ポートの出所が違うだけで、どちらもPodへの直接接続
- 両者が同じポートに解決した場合は比較対象がないため、port-forwardを1本共有して同じ結果を再掲（二重にトンネルを張らない）
- 対話端末では、確認結果の後に**ポートとパスを指定した追加確認**ができます。マニフェストが宣言していないポート（管理用・メトリクス等）や、実際に配信しているパスを、同じport-forward経由でその場で確認できます。空欄でEnterすると終了します

```text
▎ポートとパスを指定して確認
  例: 9000（TCP接続のみ） / 8080/healthz / http://localhost:8080/secure / https://8443/metrics
  空欄のままEnterで終了します。
  確認先: http://localhost:8080/secure
    ✔ 手動確認 http://localhost:8080/secure -> HTTP 200
      HTTP/1.1 200 OK
      Cache-Control: no-store
      Content-Type: application/json; charset=utf-8
      Location: /login
      Server: nginx/1.25.3
      Set-Cookie: <masked>
      X-Request-Id: 7f3c1a20
      （本文 15バイト）
```

  `curl -i`と同じく応答行とヘッダをそのまま表示します。どのハンドラが応答したか、リダイレクト先はどこか、キャッシュや認証のヘッダはどうかは、手でエンドポイントを叩くときに見たいものそのものだからです。ヘッダは名前順に整列し、資格情報を含みうるヘッダ（`Set-Cookie`など）は値をマスクします。応答行・ヘッダは端末表示だけに使い、Finding・snapshot・履歴・Webhookには従来どおりstatus code / Content-Type / 読取byte数しか保存しません

  `curl`へ渡すURLをそのまま貼れます。ホストは`localhost` / `127.0.0.1`（ループバック）だけを受け付け、それ以外のホストは無視せずエラーにします。確認は必ず選択したPodへのport-forward経由で行うため、別の宛先を渡されたまま黙ってPodを確認すると、聞かれていない問いに答えることになるためです。ポートだけを指定した場合はTCP接続のみを確認します。HTTPを話さないポートへHTTP要求を送っても、健全かどうかの判断材料にならないためです。手動確認は探索用なので、2xx以外でも確定異常とは扱いません
- 再現用のport-forward / curlは、**確認できなかった対象にのみ**表示します。成功した確認まで並べると結果本文より長くなり、どのコマンドがどの確認のものか読み取れなくなるためです
- HTTP確認では`kubectl port-forward`に続けて、実際に送った要求と同じ`curl`（scheme・path・Probeのヘッダを含む。httpsは検証をスキップする`-k`付き）も表示するため、手元でそのまま再現できます。TCP確認は要求を送らないためcurlは表示しません。資格情報を含みうるヘッダ（`Authorization`など）は値を表示せず、省略した旨だけを末尾のコメントとして付けます
- Service由来の対象には`kubectl port-forward service/NAME LOCAL:SERVICEPORT`も併記します。診断自体は対象Podへ固定してトンネルを張りますが、`service/`形式ではkubectlがselector・Endpoint・ServiceポートからtargetPortへの解決を行うため、Pod固定の確認では通らない解決経路を手元で確認できます（kubectlが選ぶPodは診断対象と異なる場合があります）
- ローカル先頭ポート+オフセットが65535を超える場合はcluster issueでなくunavailable

これは1回のport-forward模擬です。kubeletの`failureThreshold` / `successThreshold`による連続判定を再現しないため、失敗はwarningかつ低確信度の原因候補であり、それだけでKubernetesの確定異常とはしません。またService確認はClusterIPを通すネットワークテストではなく、Serviceのselector/targetPortで選ばれるPodへのport-forward確認です。

## 9. 終了コード

| code | 意味 |
|---:|---|
| `0` | CI失敗条件内、`-s`の正常終了、または`--exit-zero` |
| `1` | fail-on/max-issues超過、API診断不能のポリシー該当、引数/設定/保存/Webhookエラー |
| `130` | Ctrl-Cで通常実行を中断。watchのCtrl-Cは`0` |

`-s`でPod一覧をRBAC/APIエラーにより取得できない場合は`1`です。利用者が`q`で終了した場合は`0`です。選択したPodの確定異常は`--exit-zero`がなければ`1`です。

## 10. 設定ファイル

[`k8s-diagnose.ini`](./k8s-diagnose.ini)に全設定例があります。カレントディレクトリにこの名前の通常ファイルがあれば、`--config`を書かなくても自動で読み込みます。

```bash
# 対話で現在値を確認し、同じINIへ保存
./k8s-diagnose config

# 指定したINIを対話編集（存在しなければ新規作成）
./k8s-diagnose config --config ./team.ini

# 組み込み既定値から新規作成
./k8s-diagnose config --no-config

# ファイルを手編集して明示使用する方法も継続
./k8s-diagnose --config ./k8s-diagnose.ini

# 一時的に自動読込を無効化
./k8s-diagnose quick --no-config
```

設定エディタでは、最初に「対象・API」「診断」「接続確認」「表示」「レポート・CI」「履歴」「通知」へ分類し、選んだカテゴリの値だけを表示します。文字列・数値は説明、現在値、操作方法、入力欄を分けて表示し、空Enterは変更なし、`-`はその項目を組み込み既定値へ戻します。true/falseを直接入力する必要はなく、真偽値は「有効」「無効」「組み込み既定値」の3択です。

変更値または真偽値の選択をEnterで確定すると、その場で検証してINIへ自動保存します。最後に別の「保存する」操作はありません。保存に失敗した値は画面上の候補にも反映しません。保存は一時ファイルへの書込み・同期後にrenameするatomic方式で、権限は`0600`です。

対話編集とファイル直編集はどちらも同じ設定カタログ・値パーサ・組み合わせ検証を通ります。未知のsection/key、壊れた引用符、モード上意味を持たない組み合わせは無視せずエラーにします。対話保存では空白、`#`、`;`、引用符を含む値を安全に再読込できるよう引用して記録します。

設定の優先順位は次のとおりです。後ろほど優先されます。

```text
組み込み既定値
  → ./k8s-diagnose.ini（または--config FILE）
    → quick / ci / deepなどのプリセット
      → 明示したCLIフラグ
```

このため、一度INIへ保存したnamespaceやAPI設定は次回から自動で効きつつ、`quick -n staging`のような一時上書きもできます。

## 11. Baselineとログシグネチャ

- [`baseline.example.ini`](./baseline.example.ini): 承認済み所見。`code`, `expires`, `reason`が必須で、namespace/workload/resourceのいずれかで範囲を限定
- [`log-signatures.example.ini`](./log-signatures.example.ini): 組み込みシグネチャの無効化と、warning/candidateのカスタム正規表現

Baselineは所見を削除しません。`acknowledged=true`、理由、期限をCLI/JSON/SARIF/JUnitに残し、CI判定とWebhookのみから除外します。`workload`は健康なownerを含む依存グラフから最外側のDeployment / StatefulSet / DaemonSet / Job / CronJobへ解決するため、PodやReplicaSetの再作成後も一致します。共有依存先が複数Workloadへ波及する場合は、全Workloadがルールに一致するときだけ承認します。期限切れはwarningとして再表示します。

ログシグネチャはマスク前の生ログで一致判定し、Evidenceへ保存する行は常にマスクします。カスタムルールはログだけで確定異常と断定しないよう、warningまたはcandidateのみ指定できます。

## 12. 実際に使用するAPIと対応kubectlコマンド

Go版の通常診断は`kubectl`コマンドを起動しません。下表の「対応kubectl」は、client-goが行うAPI要求と同等の内容を人が手動確認するためのコマンドです。既定の`--cmd`表示では、冒頭へ一括表示せず、Pod一覧、メトリクス、Warning Event、ログ、個別所見、接続確認など、対応する診断項目の見出し直後・結果本文の前に必要なコマンドだけを表示します。説明ラベルは挟まず、`$ kubectl ...`をそのまま表示します。個別所見が具体的なリソースを示す場合は、例えば`kubectl get pod NAME -n NAMESPACE -o json`のように対象を絞ります。

client-goが実際に送ったHTTP method/path/queryは、診断結果を読み終えた後の技術情報「実行したKubernetes API要求」として末尾に表示できます。デバッグ用の情報で常時表示すると診断結果が埋もれるため既定では非表示で、`--api-requests`または設定ファイルで有効にします。確認用kubectlの表示は`show_commands`で独立して制御できます。従来の設定との互換性のため、`show_api_requests`を省略した古いINIで`show_commands = false`が指定されている場合は実API要求も非表示のままにしますが、`show_commands = true`が既定オフの実API要求を有効化することはありません。

```ini
[display]
show_commands = true
show_api_requests = false
```

`--context`、`--kubeconfig`、`--timeout`、namespace、Listの`--chunk-size`は確認用コマンドへ反映されます。いずれも表示するだけで自動実行はしません。

namespace指定時は`-A`を`-n NAMESPACE`に置き換えてください。Listは全て`--chunk-size`/継続token相当のページングを使います。

| 目的 | API resource/path | 対応kubectl |
|---|---|---|
| 接続・Pod権限のpreflight | `GET /api/v1/pods?fieldSelector=metadata.name%3D__k8s_diagnose_preflight__&limit=1` | `kubectl get pods -A --field-selector=metadata.name=__k8s_diagnose_preflight__ -o name` |
| Pod | core/v1 `pods` | `kubectl get pods -A -o json` |
| Pod実使用量 | metrics.k8s.io/v1beta1 `pods` | `kubectl get --raw='/apis/metrics.k8s.io/v1beta1/pods'`（namespace指定時は`.../namespaces/NAMESPACE/pods`） |
| Node | core/v1 `nodes` | `kubectl get nodes -o json` |
| Node実使用量 | metrics.k8s.io/v1beta1 `nodes` | `kubectl get --raw='/apis/metrics.k8s.io/v1beta1/nodes'` |
| Node heartbeat | coordination.k8s.io/v1 `leases` (`kube-node-lease`) | `kubectl get leases.coordination.k8s.io -n kube-node-lease -o json` |
| Service | core/v1 `services` | `kubectl get services -A -o json` |
| legacy Endpoint fallback | core/v1 `endpoints` | `kubectl get endpoints -A -o json` |
| EndpointSlice | discovery.k8s.io/v1 `endpointslices` | `kubectl get endpointslices.discovery.k8s.io -A -o json` |
| PVC | core/v1 `persistentvolumeclaims` | `kubectl get persistentvolumeclaims -A -o json` |
| PV | core/v1 `persistentvolumes` | `kubectl get persistentvolumes -o json` |
| ConfigMap | core/v1 `configmaps` | `kubectl get configmaps -A -o json` |
| Secretキー/TLS | core/v1 `secrets` | `kubectl get secrets -A -o json` |
| ServiceAccount | core/v1 `serviceaccounts` | `kubectl get serviceaccounts -A -o json` |
| Namespace | core/v1 `namespaces` | `kubectl get namespaces -o json` |
| Event | core/v1 `events` | `kubectl get events -A -o json` |
| ResourceQuota | core/v1 `resourcequotas` | `kubectl get resourcequotas -A -o json` |
| LimitRange | core/v1 `limitranges` | `kubectl get limitranges -A -o json` |
| Deployment | apps/v1 `deployments` | `kubectl get deployments.apps -A -o json` |
| StatefulSet | apps/v1 `statefulsets` | `kubectl get statefulsets.apps -A -o json` |
| DaemonSet | apps/v1 `daemonsets` | `kubectl get daemonsets.apps -A -o json` |
| ReplicaSet | apps/v1 `replicasets` | `kubectl get replicasets.apps -A -o json` |
| Job | batch/v1 `jobs` | `kubectl get jobs.batch -A -o json` |
| CronJob | batch/v1 `cronjobs` | `kubectl get cronjobs.batch -A -o json` |
| HPA | autoscaling/v2 `horizontalpodautoscalers` | `kubectl get horizontalpodautoscalers.autoscaling -A -o json` |
| Ingress | networking.k8s.io/v1 `ingresses` | `kubectl get ingresses.networking.k8s.io -A -o json` |
| IngressClass | networking.k8s.io/v1 `ingressclasses` | `kubectl get ingressclasses.networking.k8s.io -o json` |
| NetworkPolicy | networking.k8s.io/v1 `networkpolicies` | `kubectl get networkpolicies.networking.k8s.io -A -o json` |
| StorageClass | storage.k8s.io/v1 `storageclasses` | `kubectl get storageclasses.storage.k8s.io -o json` |
| PDB | policy/v1 `poddisruptionbudgets` | `kubectl get poddisruptionbudgets.policy -A -o json` |
| PriorityClass | scheduling.k8s.io/v1 `priorityclasses` | `kubectl get priorityclasses.scheduling.k8s.io -o json` |
| RuntimeClass | node.k8s.io/v1 `runtimeclasses` | `kubectl get runtimeclasses.node.k8s.io -o json` |
| Validating Webhook | admissionregistration.k8s.io/v1 | `kubectl get validatingwebhookconfigurations.admissionregistration.k8s.io -o json` |
| Mutating Webhook | admissionregistration.k8s.io/v1 | `kubectl get mutatingwebhookconfigurations.admissionregistration.k8s.io -o json` |
| aggregated API | apiregistration.k8s.io/v1 `apiservices` | `kubectl get apiservices.apiregistration.k8s.io -o json` |
| CRD | apiextensions.k8s.io/v1 `customresourcedefinitions` | `kubectl get customresourcedefinitions.apiextensions.k8s.io -o json` |
| API Server health | `GET /readyz?verbose`, `GET /livez?verbose` | `kubectl get --raw='/readyz?verbose'`, `kubectl get --raw='/livez?verbose'` |
| current/previous log | Pod log subresource | `kubectl logs POD -n NS -c CONTAINER --tail=N` / `--previous`（全コンテナを個別表示） |
| port-forward | `POST .../pods/POD/portforward` (SPDY) | `kubectl port-forward pod/POD LOCAL:REMOTE -n NS` |

Secret APIは値も返しますが、Go版は取得直後に通常Secretをキー名集合へ射影します。TLS Secretは`tls.crt`のみ証明書解析用に保持し、レポートへ証明書バイトを出力しません。

ログはコンテナごとに末尾最大512KiBを保持して解析・表示します。Pod全体を1つの512KiBへ切り詰めないため、マルチコンテナPodでも後方のコンテナによって先頭コンテナのログが消えません。

`--debug`のみ、次の外部コマンドをargv配列で実行します。shellは介しません。

本体がin-cluster ServiceAccountで動いていても、子プロセスの`kubectl debug`は利用可能なkubeconfig/contextを使うため、本体と異なる認証主体になる場合があります。画面に表示する`kubectl auth can-i`はdebug側の主体に対する確認です。

```bash
kubectl debug --help
kubectl auth can-i update pods/ephemeralcontainers -n NAMESPACE
kubectl auth can-i create pods -n NAMESPACE
kubectl debug POD -n NAMESPACE -it --image=IMAGE --target=CONTAINER --profile=PROFILE -- sh
kubectl debug POD -n NAMESPACE -it --image=IMAGE --copy-to=NAME --share-processes --same-node --profile=PROFILE -- sh
```

## 13. RBAC

[`rbac/`](./rbac/)に通常診断、`--connect`、`--debug`を分離したRole/ClusterRoleがあります。通常診断はread-only、connectは`create pods/portforward`、debugは`create pods` / `update pods/ephemeralcontainers`です。

RBACはルールレジストリのPermission定義から生成します。

```bash
# default namespace向けを再生成
go run ./cmd/rbac --namespace default --output-dir rbac

# CIで実体とコードの一致を確認
go run ./cmd/rbac --namespace default --output-dir rbac --check
```

適用例:

```bash
kubectl apply -f rbac/k8s-diagnose-clusterrole.yaml
kubectl create clusterrolebinding k8s-diagnose-reader \
  --clusterrole=k8s-diagnose-reader \
  --serviceaccount=diagnostics:k8s-diagnose
```

Secretのオブジェクト/キー確認とTLS診断には`get/list secrets`が必要です。これはRBAC上強い権限なので、Secret診断が不要な環境では該当規則を削除し、Coverage低下を許容してください。詳細は[`rbac/README.md`](./rbac/README.md)を参照してください。

## 14. テストとPython/Go比較

```bash
# unit / regression
go test ./...

# fuzz corpusの通常回帰実行（go test ./...にも含まれる）
go test ./internal/config ./internal/redact ./internal/report ./internal/rules

# 任意: 各fuzz targetを実際に探索
go test ./internal/redact -run=^$ -fuzz=FuzzMaskSecrets -fuzztime=30s
go test ./internal/config -run=^$ -fuzz=FuzzLoadINI -fuzztime=30s
go test ./internal/report -run=^$ -fuzz=FuzzDecodeDocument -fuzztime=30s
go test ./internal/rules -run=^$ -fuzz=FuzzLoadLogAnalyzer -fuzztime=30s

# data race
go test -race ./...

# static checks
go vet ./...
go install honnef.co/go/tools/cmd/staticcheck@v0.7.0
make lint

# module checksum / read-only build
go mod verify
go build -mod=readonly ./...

# staticcheck / govulncheck / gosecがインストール済みなら実行
go install honnef.co/go/tools/cmd/staticcheck@v0.7.0
go install golang.org/x/vuln/cmd/govulncheck@v1.6.0
go install github.com/securego/gosec/v2/cmd/gosec@v2.28.0
make security

# GitHub Actions定義
go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
actionlint -color=false

# CycloneDX SBOM、依存ライセンス一覧、再配布用ライセンス文書をdistへ生成
go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.10.0
go install github.com/google/go-licenses/v2@v2.0.1
make supply-chain

# 一括
./scripts/run-ci-tests.sh
```

リポジトリには[`.github/workflows/go-ci.yml`](./.github/workflows/go-ci.yml)も含まれます。GitHub Actionsではsecurity scannerを導入したうえで同じ一括スクリプトを実行し、scanner未導入による静かなskipを禁止します。さらに`dist/supply-chain/`へ配布バイナリ、CycloneDX JSON SBOM、`THIRD_PARTY_NOTICES.csv`、再配布用ライセンス文書を生成し、`k8s-diagnose-supply-chain` artifactとして保存します。SBOMはCycloneDXの`app`モードで、実際のビルド制約を評価し、main componentのバージョンをGit情報から決定します。そのため生成は`.git`を含むGit checkout内で実行する必要があり、ZIPへ展開しただけのディレクトリは対象外です。ローカル生成は`cyclonedx-gomod`と`go-licenses`を事前にインストールし、出力先が存在しない状態で`make supply-chain`を実行してください。ビルド・SBOM・ライセンス解析には既定で`go.mod`記載のパッチ版Goを共通利用するため、端末に入っている別バージョンのGoによって結果が変わりません。特殊な環境では`K8S_DIAGNOSE_SUPPLY_GOTOOLCHAIN`、ライセンス解析だけを変える場合は`K8S_DIAGNOSE_LICENSE_GOTOOLCHAIN`で明示上書きできます。NOTICE生成では自プロジェクトを除外し、依存ライブラリだけを対象にします。この処理は本プロジェクト自体のライセンスを設定するものではありません。

Python版とGo版の実クラスタ結果を比較:

```bash
./scripts/compare-python-go.py --python /path/to/python/k8s-diagnose.py
./scripts/compare-python-go.py --python /path/to/python/k8s-diagnose.py --mode all --namespace prod
```

比較は文言やruntime固有IDではなく、CIに影響する`severity + code + resource + confidence`、Health、診断不能件数、CIポリシーと実終了コード、Root Causeの`classification + confidence + cause code + resource + 影響リソース集合`で行います。Go版にはPython版より独立診断が多いため、Coverageの分母が異なる場合は取得失敗件数の一致を既定の意味上パリティとし、百分率まで要求する場合は`--strict-coverage`を指定します。API warningなどGo側の追加candidateは既定の比較から除外します。必要なら`--include-candidates`を使います。大規模クラスタで終了コード確認用の追加実行を省く場合は`--skip-exit-code`を指定します。

## 15. Python版からの移行

- JSON schema: `k8s-diagnose/report/v1`を維持
- SQLite: `PRAGMA user_version=1` / `diagnostic_runs`を維持し、同じDBを読み書き可能
- Baseline / log-signature / 主設定INI: 同じ形式
- 出力: text / JSON / SARIF / JUnit / Mermaid / DOT
- 出力パリティ: 自由文の完全一致ではなく、診断意味、CI判定、スコア、Root Causeを一致対象とする

Go版は`kubectl get ... --limit`を構築しないため、kubectlが`unknown flag: --limit`を返す問題は発生しません。ページサイズはKubernetes ListOptionsの`Limit`とAPIの`continue`で処理します。

## 16. セキュリティと注意事項

- 通常診断はAPIへのGET/LISTのみ。`--connect`はport-forward subresource、`--debug`は明示確認後に変更操作
- subprocessは`--debug`の`kubectl`のみ。`shell=true`相当は使用しない
- Secret値は射影し、ログ/HTTP body/EvidenceはAuthorization、Bearer、JSONキー、環境変数形式のpassword/token/secret/access key、credential URI、JWT、private key、主要vendor tokenをマスク
- `--no-mask`が解除するのは対話端末の表示だけ。JSON/SARIF/JUnit、snapshot、SQLite履歴、Webhookは常にマスク
- HTTPS Probeは、kubeletのHTTP probeと同様に証明書検証を行わない。通常の汎用HTTPSクライアントの振る舞いではない
- Webhook URLはコマンド行に直書きせず環境変数で渡す
- 履歴SQLiteとatomic保存レポートは0600で作成する

## 17. ディレクトリ構成

```text
k8s-diagnose/
├─ main.go                    CLI entrypoint / signal handling
├─ cmd/rbac/                  RBAC manifest generator
├─ internal/
│  ├─ app/                  mode orchestration + guided menu/settings UI
│  ├─ baseline/             acknowledgement rules
│  ├─ config/               CLI + INI + validation + help
│  ├─ connect/              typed port-forward + HTTP/TCP probes
│  ├─ console/              color, display width, zebra, masking
│  ├─ history/              Python-compatible SQLite + trends
│  ├─ jsonutil/             report/history共通のJSON accessor・unknown判定
│  ├─ kube/                  client-go, paging, collection, errors
│  ├─ model/                 Finding / State / RootCause
│  ├─ notify/                no-redirect HTTPS webhook
│  ├─ redact/                永続出力共通の強制マスク
│  ├─ rbac/                  rules-to-RBAC generator
│  ├─ report/                JSON/SARIF/JUnit/Mermaid/DOT/diff
│  └─ rules/                 診断、ログ解析、依存グラフ、Root Cause、Scheduling
├─ rbac/                       generated manifests
├─ scripts/                    CI and Python/Go parity
└─ *_test.go                  unit/regression tests
```
