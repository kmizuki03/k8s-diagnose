package config

import (
	"fmt"
	"strings"
)

// HelpTopic resolves a command or legacy mode flag to its focused help page.
func HelpTopic(args []string) string {
	if command := CommandName(args); command != "" {
		return command
	}
	for _, arg := range args {
		switch strings.SplitN(arg, "=", 2)[0] {
		case "-a", "--all":
			return "all"
		case "-s", "--select":
			return "pod"
		case "-p", "--list", "--pods":
			return "list"
		case "--triage":
			return "triage"
		}
	}
	return ""
}

// HelpStyledFor returns progressively disclosed help. The empty topic is the
// concise landing page; advanced keeps the complete legacy reference.
func HelpStyledFor(prog, topic string, color bool) string {
	if topic == "advanced" {
		return HelpStyled(prog, color)
	}
	plain := commandHelp(prog, topic)
	return colorizeHelp(plain, prog, color)
}

func commandHelp(prog, topic string) string {
	switch topic {
	case "all":
		return fmt.Sprintf(`%s all — クラスタ全体診断

使い方:
  %s all [オプション]
  %s -a [オプション]            従来形式も利用可能

対象・API:
  -n, --namespace NAME          対象namespace（省略時は全て）
      --context NAME            kubeconfig context
      --kubeconfig FILE         kubeconfigファイル
      --timeout SEC             API要求タイムアウト
      --workers N               並列取得数 1〜16
      --qps N / --burst N       client-goのAPI流量
      --page-size N             List APIページサイズ

このモードの追加診断:
      --logs                    失敗Podのログ
      --unused                  未使用リソース候補
      --tail N                  --logsの表示行数
      --log-signatures FILE     --logsの追加シグネチャ
      --log-signature-lines N   ログ解析行数
      --events-limit N          Warning Event表示数
      --restart-threshold N     再起動警告閾値
      --node-heartbeat-timeout SEC
      --debug                   診断後にdebugメニュー
      --debug-image IMAGE       debug用image
      --debug-profile NAME      kubectl debug profile
  -w, --watch SEC              定期再診断

レポート・CI・履歴:
      --output FORMAT           text/json/sarif/junit/mermaid/dot
      --output-file FILE        構造化レポート保存先
      --save-snapshot FILE      今回結果を保存
      --diff FILE               前回snapshotと比較
      --baseline FILE           承認済み所見INI
      --fail-on LEVEL           issue/warning/unavailable/any/none
      --max-issues N            許容件数
      --history-db FILE         SQLite履歴
      --history-window N        履歴分析回数
      --flap-threshold N        フラッピング遷移数
      --restart-growth N        restartCount増加閾値
      --history-retain N        DB保持実行数
      --webhook-url-env NAME    差分・履歴・watch通知
      --webhook-format TYPE     generic/slack
      --webhook-timeout SEC     通知タイムアウト

共通:
      --config FILE / --no-config
      --cmd / --no-cmd / --no-mask / --exit-zero
      --api-requests / --no-api-requests

主な組み合わせ:
  --tail / --log-signaturesは--logsが必要です。
  --debugはtextの一度実行専用、--watchと構造化--outputは併用できません。
  --exit-zero、--fail-on/--max-issues、--watchは互いに失敗方針が衝突する組み合わせを拒否します。
  Webhookは--diff、--history-db、--watchのいずれかが必要です。

例:
  %s all --logs --unused
  %s all --output json --output-file result.json

全フラグ: %s advanced --help
`, prog, prog, prog, prog, prog, prog)
	case "pod":
		return fmt.Sprintf(`%s pod — Podを選んで個別診断

使い方:
  %s pod [オプション]
  %s -s [オプション]            従来形式も利用可能

選択操作:
  一覧上でnを押すとNamespace、/またはfを押すとPod名を部分一致検索
  ↑/↓で選択し、Enterまたは→で決定。rは両検索、cは条件消去
  戻る操作はb、終了はq（戻るための選択行は表示しません）
  検索中もPod一覧を維持し、選択画面は診断開始時に消えます。

対象・API:
  -n, --namespace NAME          Namespace検索を固定
      --context NAME            kubeconfig context
      --kubeconfig FILE         kubeconfigファイル
      --timeout SEC             API要求タイムアウト
      --workers N               並列取得数 1〜16
      --qps N / --burst N       client-goのAPI流量
      --page-size N             List APIページサイズ

このモードの追加診断:
      --tail N                  コンテナログ表示行数
      --log-signatures FILE     追加ログシグネチャ
      --log-signature-lines N   ログ解析行数
      --events-limit N          Event表示数
      --restart-threshold N     再起動警告閾値
      --connect                 Probe/TCP接続確認
      --connect-port PORT       ローカル先頭ポート
      --connect-path PATH       /で始まるHTTPパス上書き
      --debug                   診断後にdebugメニュー
      --debug-image IMAGE       debug用image
      --debug-profile NAME      kubectl debug profile
      --baseline FILE           承認済み所見INI

共通:
      --config FILE / --no-config
      --cmd / --no-cmd / --no-mask / --exit-zero
      --api-requests / --no-api-requests

主な組み合わせ:
  --connect-port / --connect-pathは--connectが必要です。
  --debug-image / --debug-profileは--debugが必要です。
  Pod個別はtext出力専用で、全体専用の--logs / --unusedは使えません。

例:
  %s pod --connect --connect-path /ready

全フラグ: %s advanced --help
`, prog, prog, prog, prog, prog)
	case "list":
		return fmt.Sprintf(`%s list — Pod一覧だけ表示

使い方:
  %s list [対象オプション]
  %s --list [対象オプション]    従来形式も利用可能

利用できるオプション:
  -n, --namespace NAME          対象namespace
      --context NAME            kubeconfig context
      --kubeconfig FILE         kubeconfigファイル
      --timeout SEC             API要求タイムアウト
      --workers N               並列取得数 1〜16
      --qps N / --burst N       client-goのAPI流量
      --page-size N             List APIページサイズ
      --cmd / --no-cmd          各診断項目の確認用kubectlを表示
      --api-requests / --no-api-requests
                                末尾の実API要求を表示／非表示
      --no-mask                 対話端末のtext表示でマスク解除
      --config FILE             INIを明示読込
      --no-config               既定INIを読まない

例:
  %s list -n production

全フラグ: %s advanced --help
`, prog, prog, prog, prog, prog)
	case "triage":
		return fmt.Sprintf(`%s triage — 初動・CI向けの短時間診断

使い方:
  %s triage [オプション]
  %s --triage [オプション]      従来形式も利用可能

利用できる主なオプション:
  -n, --namespace NAME          対象namespace
      --context NAME            kubeconfig context
      --kubeconfig FILE         kubeconfigファイル
      --timeout SEC             API要求タイムアウト
      --workers N               並列取得数 1〜16
      --qps N / --burst N       client-goのAPI流量
      --page-size N             List APIページサイズ
      --events-limit N          Warning Event表示数
      --restart-threshold N     再起動警告閾値
      --node-heartbeat-timeout SEC
  -w, --watch SEC              定期再診断
      --output FORMAT           text/json/sarif/junit/mermaid/dot
      --output-file FILE        構造化レポート保存先
      --save-snapshot FILE / --diff FILE
      --baseline FILE
      --fail-on LEVEL / --max-issues N
      --history-db FILE / --webhook-url-env NAME
      --config FILE / --no-config
      --cmd / --no-cmd / --no-mask / --exit-zero
      --api-requests / --no-api-requests

主な組み合わせ:
  構造化--outputと--watchは併用できません。
  --watchでは--exit-zero / --fail-on / --max-issuesを指定しません。
  Webhookは--diff、--history-db、--watchのいずれかが必要です。

簡単な入口:
  %s quick                     textで一度だけ確認
  %s ci                        JSON出力、確定異常で失敗

全フラグ: %s advanced --help
`, prog, prog, prog, prog, prog, prog)
	case "quick":
		return presetHelp(prog, "quick", "短時間のtriageをtextで一度だけ実行", "text / 秘匿情報マスク / 確定異常でexit 1 / 確認コマンド・実API要求非表示")
	case "ci":
		return presetHelp(prog, "ci", "CI向けtriage設定を一語で適用", "JSON / 秘匿情報マスク / 確定異常でexit 1")
	case "deep":
		return presetHelp(prog, "deep", "クラスタ全体をログ・未使用候補込みで診断", "text / --logs / --unused")
	case "config":
		return fmt.Sprintf(`%s config — 対話式設定エディタ

使い方:
  %s config
  %s config --config FILE       指定INIを編集（無ければ新規）
  %s config --no-config         組み込み既定値から新規作成

操作:
  ↑/↓でカテゴリと設定を選び、Enterで編集します。
  bで1つ前へ戻り、qで設定メニューを終了します。
  空Enterは変更なし、- は組み込み既定値へ戻します。
  保存先を省略すると ./k8s-diagnose.ini です。

手編集したINIと同じパーサ・組み合わせ検証を使うため、結果は同一です。
`, prog, prog, prog, prog)
	default:
		return overviewHelp(prog)
	}
}

func presetHelp(prog, name, description, defaults string) string {
	topic := "triage"
	if name == "deep" {
		topic = "all"
	}
	return fmt.Sprintf(`%s %s — %s

使い方:
  %s %s
  %s %s -n production

適用される設定:
  %s

対象・保存先などは追加フラグで上書きできます。詳細なtriage/allオプションは:
  %s %s --help

既定INIを無視する場合:
  %s %s --no-config
`, prog, name, description, prog, name, prog, name, defaults, prog, topic, prog, name)
}

func overviewHelp(prog string) string {
	return fmt.Sprintf(`%s — 説明書を覚えずに使えるKubernetes診断

最初の一歩:
  %s                           対話メニュー（引数なし）

慣れた人向けの合言葉:
  %s quick                     短時間で問題だけ確認
  %s ci                        CI向けJSON＋失敗条件
  %s deep                      ログ・未使用候補を含む全体診断

診断対象を直接選ぶ:
  %s all                       クラスタ全体
  %s pod                       Podを検索・選択して詳しく
  %s list                      Pod一覧だけ
  %s triage                    初動・CI向け診断

設定:
  %s config                    対話式に設定しINIへ保存
  ./k8s-diagnose.ini           存在すれば自動読込
  --config FILE                別のINIを明示読込
  --no-config                  既定INIを読まず実行

詳しいヘルプ:
  %s pod --help                Pod診断に関係する項目だけ
  %s all --help                全体診断に関係する項目だけ
  %s advanced --help           従来の全フラグ一覧

従来形式も継続利用できます:
  %s -a --logs --unused
  %s -s --connect
`, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog)
}
