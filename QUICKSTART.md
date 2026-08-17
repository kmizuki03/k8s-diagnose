# k8s-diagnose クイックスタート

このツールは **Kubernetesクラスタをread-onlyで診断** します。クラスタへの書き込み・変更は一切行いません。

詳細は `README.md`(全17章のリファレンス)にありますが、**まずはこのページだけで動きます。**

---

## 1. これは何をするツールか

- クラスタの状態を取得し、**異常** / **診断不能** / **原因候補** を分けて報告します
- **read-onlyです。** 診断のためにリソースを作成・変更・削除することはありません
  - 例外は明示的に指定したときだけです: `--connect`(port-forward)と `--debug`(kubectl経由の対話デバッグ)
- 出力に含まれる認証情報・トークン・Cookie等は、保存・通知の前にマスクされます

---

## 2. 権限を当てる(RBAC)

雛形は `rbac/` にあります。ツール自身がRBACを適用することはありません。**適用は人がやります。**

まずは全namespaceのread-only診断から始めるのが簡単です。

```bash
kubectl create namespace diagnostics
kubectl create serviceaccount k8s-diagnose -n diagnostics
kubectl apply -f rbac/k8s-diagnose-clusterrole.yaml
kubectl create clusterrolebinding k8s-diagnose-reader \
  --clusterrole=k8s-diagnose-reader \
  --serviceaccount=diagnostics:k8s-diagnose
```

| 用途 | namespace限定 | 全namespace |
|---|---|---|
| read-only診断 | `rbac/k8s-diagnose-role.yaml` | `rbac/k8s-diagnose-clusterrole.yaml` |
| port-forward (`--connect`) | `rbac/k8s-diagnose-connect-role.yaml` | `rbac/k8s-diagnose-connect-clusterrole.yaml` |
| debug (`--debug`) | `rbac/k8s-diagnose-debug-role.yaml` | `rbac/k8s-diagnose-debug-clusterrole.yaml` |

`--connect` / `--debug` を使わないなら、read-onlyの1つだけで十分です。

補足:

- Role版(namespace限定)ではNodeやPV等のcluster-wide情報を取得できず、一部診断のCoverageが下がります
- Secret診断には `get/list secrets` が必要です。値は保存せずキー名へ射影しますが、RBAC上は強い権限です。不要なら該当ルールを削除してください

詳細は `rbac/README.md` を参照してください。

---

## 3. 最初に叩く1コマンド

```bash
./k8s-diagnose --triage
```

これだけです。コンパクトな初動診断が走ります。

対象namespaceを絞る場合:

```bash
./k8s-diagnose --triage -n prod
```

引数なしで起動すると、対話メニューから選べます。

```bash
./k8s-diagnose
```

---

## 4. 次に使うもの

```bash
# 詳細診断（全ルール）
./k8s-diagnose -a -n prod

# CI向け: JSONで保存
./k8s-diagnose --triage --output json --output-file result.json

# ヘルプ
./k8s-diagnose --help
```

終了コードは診断結果に連動します(既定では issue 相当で失敗)。CIに組み込む場合は `--fail-on` を確認してください。

---

## 5. 困ったとき

**まずスナップショットを取ってください。** 状況を再現できる形で共有できます。

```bash
./k8s-diagnose -a --save-cluster-snapshot snapshot.json
```

このファイルは **マスク済み** で、クラスタへのアクセス権を渡さずに調査を依頼できます。再生はこうします。

```bash
./k8s-diagnose -a --load-cluster-snapshot snapshot.json
```

再生時は、保存時と同じ診断モード、namespace、`--unused`の有無を指定してください。取得範囲が異なる場合は、存在しないリソースを誤って異常扱いしないよう実行を拒否します。

報告するときは、次を添えてください。

- `snapshot.json`
- 実行したコマンドと、期待した結果 / 実際の結果
- `./k8s-diagnose --version` の出力

**連絡先: `<配布時にSlackチャンネル名 / 担当者を記入してください>`**

<!-- TODO(配布担当): 上の連絡先を実際の窓口に置き換えてから配布してください。 -->
