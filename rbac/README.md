# Go版 RBAC雛形

通常診断、`--connect`、`--debug`の権限を分離しています。ツール自身がRBACを適用することはありません。

| 用途 | namespace限定 | 全namespace |
|---|---|---|
| read-only診断 | `k8s-diagnose-role.yaml` | `k8s-diagnose-clusterrole.yaml` |
| port-forward | `k8s-diagnose-connect-role.yaml` | `k8s-diagnose-connect-clusterrole.yaml` |
| debug | `k8s-diagnose-debug-role.yaml` | `k8s-diagnose-debug-clusterrole.yaml` |

Role版ではNode、Nodeメトリクス、`kube-node-lease`のLease、Namespace、StorageClass、IngressClass、Webhook、PriorityClass、RuntimeClass、PV、APIService、CRD、`/readyz`等のcluster-wide情報は取得できず、関連ルールのCoverageが低下します。Podメトリクスは指定namespace内だけ取得できます。任意入力が欠けたルールは可能な範囲で部分評価を続けますが、Pending Podの完全な空きリソース計算には全namespaceのPodとNodeが必要なため、完全な解析はClusterRole版を使ってください。

Secret診断には`get/list secrets`が必要です。診断自体はSecret値を保存せずキー名へ射影しますが、RBAC上は値を取得できる強い権限です。不要な場合はSecret規則を削除してください。

生成と整合確認:

```bash
go run ./cmd/rbac --namespace prod --output-dir rbac
go run ./cmd/rbac --namespace default --output-dir rbac --check
```

適用とBinding例:

```bash
kubectl create namespace diagnostics
kubectl create serviceaccount k8s-diagnose -n diagnostics
kubectl apply -f rbac/k8s-diagnose-clusterrole.yaml
kubectl create clusterrolebinding k8s-diagnose-reader \
  --clusterrole=k8s-diagnose-reader \
  --serviceaccount=diagnostics:k8s-diagnose
```

connect/debugのClusterRoleは必要な場合だけ別Bindingしてください。
