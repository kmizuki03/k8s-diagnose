package app

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/kmizuki03/k8s-diagnose/internal/connect"
	"github.com/kmizuki03/k8s-diagnose/internal/console"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	corev1 "k8s.io/api/core/v1"
)

func (runner *Runner) runConnect(ctx context.Context, pod *corev1.Pod, services []corev1.Service, state *model.State) ([]connect.Result, bool, error) {
	checker := &connect.Checker{Clients: runner.Clients, Config: runner.Config}
	results, findings := checker.Check(ctx, pod, services)
	for _, result := range results {
		if result.LocalPort < 1 || result.Target.RemotePort < 1 {
			continue
		}
		runner.kubectlCmds = append(runner.kubectlCmds, kube.KubectlCommand(
			runner.Config, "port-forward", "pod/"+pod.Name,
			fmt.Sprintf("%d:%d", result.LocalPort, result.Target.RemotePort), "-n", pod.Namespace,
		))
	}
	for _, finding := range findings {
		state.Add(finding)
	}
	return results, true, nil
}

func (runner *Runner) renderConnectResults(results []connect.Result) {
	runner.Console.Section("Probe/接続確認結果")
	runner.renderPendingKubectlCommands()
	type totals struct{ tested, succeeded, failed, unavailable, warned int }
	groups := map[string]*totals{"pod": {}, "service": {}}
	for _, group := range []string{"pod", "service"} {
		heading := "Pod直接"
		if group == "service" {
			heading = "Service指定Pod"
		}
		runner.Console.Write("\n  ■ " + heading)
		found := false
		for _, result := range results {
			if result.Target.Group != group {
				continue
			}
			found = true
			total := groups[group]
			mark, color := "?", runner.Console.C.Yellow
			switch {
			case result.Target.Invalid:
				mark, color = "✘", runner.Console.C.Red
				total.failed++
			case !result.Target.Active && result.Target.Unavailable:
				total.unavailable++
			case !result.Target.Active:
			case !result.Tested:
				total.unavailable++
			case result.Successful && result.Warned:
				mark, color = "▲", runner.Console.C.Yellow
				total.tested, total.succeeded, total.warned = total.tested+1, total.succeeded+1, total.warned+1
			case result.Successful:
				mark, color = "✔", runner.Console.C.Green
				total.tested, total.succeeded = total.tested+1, total.succeeded+1
			default:
				mark, color = "▲", runner.Console.C.Yellow
				total.tested, total.failed = total.tested+1, total.failed+1
			}
			label := result.Target.Label
			if result.Target.ProbeType != "" {
				label = result.Target.ProbeType
			}
			label = console.MaskSecrets(label, runner.Config.Mask)
			detail := console.Snip(console.MaskSecrets(result.Detail, runner.Config.Mask), 300)
			path := console.MaskSecrets(result.Target.Path, runner.Config.Mask)
			port := strconv.Itoa(result.Target.RemotePort)
			if result.Target.RemotePort == 0 && result.Target.PortName != "" {
				port = result.Target.PortName
			}
			runner.Console.Write(fmt.Sprintf("    %s%s %-16s %s :%s%s -> %s%s", color, mark, label, strings.ToUpper(result.Target.Protocol), port, path, detail, runner.Console.C.Reset))
			if result.Body != "" && (result.Warned || !result.Successful) {
				body := console.Snip(console.MaskSecrets(result.Body, runner.Config.Mask), 300)
				runner.Console.Write(fmt.Sprintf("      HTTP本文: %s", body))
			}
		}
		if !found {
			runner.Console.Write("    （対象なし・未実施）")
		}
	}
	pod, service := groups["pod"], groups["service"]
	runner.Console.Write()
	switch {
	case pod.failed == 0 && pod.unavailable == 0 && pod.succeeded > 0 && service.failed == 0 && service.unavailable == 0 && service.succeeded > 0:
		if pod.warned+service.warned > 0 {
			runner.Console.Write("  ▲ Pod直接・Service指定Podの両方で接続できましたが、HTTP応答または再現条件に注意が必要です")
		} else {
			runner.Console.Write("  → Pod直接・Service指定Podの両方で、単発の接続確認に成功しました")
		}
	case pod.failed == 0 && pod.succeeded > 0 && service.tested == 0 && service.unavailable == 0:
		runner.Console.Write("  → Pod直接の接続確認には成功しました。Service指定Podは対象がないため未実施です")
	case service.failed == 0 && service.succeeded > 0 && pod.tested == 0 && pod.unavailable == 0:
		runner.Console.Write("  → Service指定Podの接続確認には成功しました。Pod直接はポートを推定できないため未実施です")
	case pod.failed > 0 || service.failed > 0:
		runner.Console.Write("  ▲ 失敗した接続確認があります。kubeletの連続判定と現在のPod状態も併せて確認してください")
	case pod.unavailable+service.unavailable > 0:
		runner.Console.Write("  ? 接続確認の一部を実施できませんでした")
	default:
		runner.Console.Write("  → 接続確認の対象がないため、テストは実施されませんでした")
	}
}
