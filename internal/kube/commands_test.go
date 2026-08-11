package kube

import (
	"strings"
	"testing"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
)

func TestKubectlCommandsReflectTargetAndNeverUseLimitFlag(t *testing.T) {
	cfg := config.Defaults()
	cfg.Namespace = "production"
	cfg.Context = "staging"
	cfg.Kubeconfig = "/tmp/cluster config"
	statuses := map[string]FetchStatus{
		"pods": {}, "all_pods": {}, "nodes": {}, "pod_metrics": {}, "readyz": {},
	}
	commands := KubectlCommandsForKeys(cfg, statuses, "pods", "all_pods", "nodes", "pod_metrics", "readyz")
	joined := make([]string, len(commands))
	for index, command := range commands {
		joined[index] = strings.Join(command, " ")
		if strings.Contains(joined[index], "--limit") {
			t.Fatalf("kubectlが受理しない--limitを生成した: %s", joined[index])
		}
		if !strings.Contains(joined[index], "--context staging") || !strings.Contains(joined[index], "--kubeconfig /tmp/cluster config") {
			t.Fatalf("対象context/kubeconfigが欠落した: %s", joined[index])
		}
	}
	all := strings.Join(joined, "\n")
	for _, expected := range []string{
		"get pods -n production",
		"get pods -A",
		"get nodes --chunk-size=500 -o json",
		"--raw=/apis/metrics.k8s.io/v1beta1/namespaces/production/pods",
		"--raw=/readyz?verbose",
	} {
		if !strings.Contains(all, expected) {
			t.Fatalf("等価コマンドに%qがない:\n%s", expected, all)
		}
	}
}

func TestKubectlCommandsDeduplicateClusterWidePodCollection(t *testing.T) {
	cfg := config.Defaults()
	statuses := map[string]FetchStatus{"pods": {}, "all_pods": {}}
	commands := KubectlCommandsForKeys(cfg, statuses, "pods", "all_pods")
	count := 0
	for _, command := range commands {
		if strings.Contains(strings.Join(command, " "), "get pods -A --chunk-size") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("同じcluster-wide Podコマンドが%d回生成された: %#v", count, commands)
	}
}

func TestKubectlCommandsForKeysOnlyReturnsCommandsForThatDiagnosticItem(t *testing.T) {
	cfg := config.Defaults()
	statuses := map[string]FetchStatus{"pods": {}, "nodes": {}, "events": {}}
	commands := KubectlCommandsForKeys(cfg, statuses, "events")
	joined := make([]string, len(commands))
	for index, command := range commands {
		joined[index] = strings.Join(command, " ")
	}
	all := strings.Join(joined, "\n")
	if !strings.Contains(all, "get events -A") {
		t.Fatalf("指定したEventの確認コマンドがない: %q", all)
	}
	for _, unwanted := range []string{"get pods", "get nodes", "__k8s_diagnose_preflight__"} {
		if strings.Contains(all, unwanted) {
			t.Fatalf("別の診断項目のコマンド%qが混入した: %q", unwanted, all)
		}
	}
}
