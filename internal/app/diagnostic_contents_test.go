package app

import (
	"strings"
	"testing"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/console"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	"github.com/kmizuki03/k8s-diagnose/internal/rules"
)

func TestDiagnosticItemsAssociateRuleResultAndItemSpecificCommands(t *testing.T) {
	cfg := config.Defaults()
	cfg.Namespace = "prod"
	runner := &Runner{Config: cfg, Registry: rules.Builtins()}
	snapshot := kube.NewSnapshot()
	for _, key := range []string{"services", "endpoint_slices", "pod_metrics"} {
		snapshot.Statuses[key] = kube.FetchStatus{Available: key != "pod_metrics"}
	}
	state := model.NewState()
	state.AddCheck(model.Check{ID: "services", Section: "Service", Description: "Service診断", Available: true})
	state.AddCheck(model.Check{ID: "services/optional/endpoint_slices", Section: "Service", Description: "重複する元の説明", Available: true})
	state.AddCheck(model.Check{ID: "pod-metrics", Section: "メトリクス", Description: "Pod使用量", Available: false, Reason: "pod_metrics=対象が見つかりません"})
	finding := model.NewFinding(model.Issue, "K8S.SERVICE.TEST", "Service", "Service/prod/api", "Invalid", "port", "ServiceのtargetPortを解決できません", 100)
	finding.RuleID = "services"
	state.Add(finding)

	items := runner.diagnosticItems(snapshot, state)
	service := diagnosticItemByID(t, items, "services")
	if len(service.Findings) != 1 || service.Findings[0].Code != finding.Code {
		t.Fatalf("Service所見が診断項目へ対応付かない: %#v", service.Findings)
	}
	serviceCommands := strings.Join(service.Commands, "\n")
	if !strings.Contains(serviceCommands, "get services -n prod") || strings.Contains(serviceCommands, "endpointslices") {
		t.Fatalf("親ルールのコマンドがrequired入力だけに限定されていない: %q", serviceCommands)
	}

	optional := diagnosticItemByID(t, items, "services/optional/endpoint_slices")
	if !optional.Supplemental || optional.Check.Description != "追加情報としてEndpointSlice一覧を取得" || len(optional.Findings) != 0 {
		t.Fatalf("任意取得項目の表示情報が不正: %#v", optional)
	}
	if commands := strings.Join(optional.Commands, "\n"); !strings.Contains(commands, "get endpointslices.discovery.k8s.io -n prod") || strings.Contains(commands, "get services") {
		t.Fatalf("任意取得のコマンドが対象APIだけに限定されていない: %q", commands)
	}

	metrics := diagnosticItemByID(t, items, "pod-metrics")
	if metrics.Check.Reason != "Podメトリクスを取得できません。原因: 対象が見つかりません" {
		t.Fatalf("内部取得キーが利用者向け理由へ変換されない: %q", metrics.Check.Reason)
	}
	if commands := strings.Join(metrics.Commands, "\n"); !strings.Contains(commands, "--raw=/apis/metrics.k8s.io/v1beta1/namespaces/prod/pods") {
		t.Fatalf("取得不能項目の確認コマンドがない: %q", commands)
	}
}

func TestDiagnosticItemsSeparateCurrentAndPreviousLogResultsAndCommands(t *testing.T) {
	cfg := config.Defaults()
	runner := &Runner{Config: cfg, kubectlCmds: [][]string{
		kube.KubectlCommand(cfg, "logs", "api", "-n", "prod", "-c", "app", "--tail=100"),
		kube.KubectlCommand(cfg, "logs", "api", "-n", "prod", "-c", "app", "--tail=100", "--previous"),
	}}
	state := model.NewState()
	state.AddCheck(model.Check{ID: "logs/prod/api/current", Section: "ログ", Description: "現在ログ", Available: true})
	state.AddCheck(model.Check{ID: "logs/prod/api/previous", Section: "ログ", Description: "前回ログ", Available: true})
	current := model.NewFinding(model.Warning, "K8S.LOG.OOM", "ログ", "Pod/prod/api", "oom", "current/app/oom", "現在ログでOOMを検出", 85)
	current.RuleID = "logs"
	previous := model.NewFinding(model.Warning, "K8S.LOG.GO_PANIC", "ログ", "Pod/prod/api", "panic", "previous/app/panic", "前回ログでpanicを検出", 85)
	previous.RuleID = "logs"
	state.Add(current)
	state.Add(previous)

	items := runner.diagnosticItems(kube.NewSnapshot(), state)
	currentItem := diagnosticItemByID(t, items, "logs/prod/api/current")
	previousItem := diagnosticItemByID(t, items, "logs/prod/api/previous")
	if len(currentItem.Findings) != 1 || currentItem.Findings[0].Code != current.Code || len(previousItem.Findings) != 1 || previousItem.Findings[0].Code != previous.Code {
		t.Fatalf("current/previousのログ所見が混在した: current=%#v previous=%#v", currentItem.Findings, previousItem.Findings)
	}
	currentCommands, previousCommands := strings.Join(currentItem.Commands, "\n"), strings.Join(previousItem.Commands, "\n")
	if strings.Contains(currentCommands, "--previous") || !strings.Contains(previousCommands, "--previous") {
		t.Fatalf("current/previousのログコマンドが混在した: current=%q previous=%q", currentCommands, previousCommands)
	}
}

func diagnosticItemByID(t *testing.T, items []console.DiagnosticItem, id string) console.DiagnosticItem {
	t.Helper()
	for _, item := range items {
		if item.Check.ID == id {
			return item
		}
	}
	t.Fatalf("診断項目 %q がない: %#v", id, items)
	return console.DiagnosticItem{}
}
