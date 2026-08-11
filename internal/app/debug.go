package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/kmizuki03/k8s-diagnose/internal/console"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/redact"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (runner *Runner) debugPod(ctx context.Context, pod *corev1.Pod) error {
	current, err := runner.refreshPodTarget(ctx, pod)
	if err != nil {
		return err
	}
	pod = current
	kubectl, err := exec.LookPath("kubectl")
	if err != nil {
		return errors.New("--debug に必要な kubectl が PATH に見つかりません")
	}
	base := []string{}
	if runner.Config.Kubeconfig != "" {
		base = append(base, "--kubeconfig", runner.Config.Kubeconfig)
	}
	if runner.Config.Context != "" {
		base = append(base, "--context", runner.Config.Context)
	}
	// kubectl is resolved by exec.LookPath and all arguments are passed as an
	// argv slice without a shell. Config validation constrains profile/image and
	// Kubernetes validates resource names.
	helpCommand := exec.CommandContext(ctx, kubectl, append(base, "debug", "--help")...) // #nosec G204 -- intentional argv-only kubectl integration.
	helpOutput, helpErr := helpCommand.CombinedOutput()
	if helpErr != nil || !strings.Contains(string(helpOutput), "--image") {
		return errors.New("この環境の kubectl は debug コマンドをサポートしていません")
	}
	runner.Console.Section(fmt.Sprintf("kubectl debug: %s/%s", pod.Namespace, pod.Name))
	runner.Console.Write("  1) Ephemeral Containerを追加 (Running Pod向け)")
	runner.Console.Write("  2) デバッグ用コピーPodを作成")
	runner.Console.Write("  3) 実行しない")
	fmt.Fprint(runner.Streams.Out, "選択 [1-3]: ")
	choice, readErr := runner.reader.ReadString('\n')
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return fmt.Errorf("debugメニューの選択を読み取れませんでした: %w", readErr)
	}
	choice = strings.TrimSpace(choice)
	if choice == "" || choice == "3" {
		runner.Console.Write("debugは実行しません")
		return nil
	}
	canI := func(verb, resource string) (bool, error) {
		args := append(append([]string{}, base...), "auth", "can-i", verb, resource, "-n", pod.Namespace)
		command := exec.CommandContext(ctx, kubectl, args...) // #nosec G204 -- argv-only kubectl auth check; no shell expansion.
		output, err := command.CombinedOutput()
		return interpretCanIResult(output, err)
	}
	debugArgs := append(append([]string{}, base...), "debug", pod.Name, "-n", pod.Namespace, "-it", "--image="+runner.Config.DebugImage)
	switch choice {
	case "1":
		if pod.Status.Phase != corev1.PodRunning {
			return fmt.Errorf("Podの状態（phase）が %s のため、Ephemeral Containerを追加できません", pod.Status.Phase)
		}
		allowed, err := canI("update", "pods/ephemeralcontainers")
		if err != nil {
			return err
		}
		if !allowed {
			return errors.New("pods/ephemeralcontainersを更新する権限がありません")
		}
		if len(pod.Spec.Containers) > 0 && strings.Contains(string(helpOutput), "--target") {
			debugArgs = append(debugArgs, "--target="+pod.Spec.Containers[0].Name)
		}
	case "2":
		allowed, err := canI("create", "pods")
		if err != nil {
			return err
		}
		if !allowed {
			return errors.New("Podを作成する権限がありません")
		}
		copyName := fmt.Sprintf("%s-debug-%s", pod.Name, time.Now().Format("150405"))
		if len(copyName) > 63 {
			copyName = strings.TrimRight(copyName[:63], "-")
		}
		debugArgs = append(debugArgs, "--copy-to="+copyName)
		if strings.Contains(string(helpOutput), "--share-processes") {
			debugArgs = append(debugArgs, "--share-processes")
		}
		if strings.Contains(string(helpOutput), "--same-node") {
			debugArgs = append(debugArgs, "--same-node")
		}
		runner.Console.Write(fmt.Sprintf("  終了後の削除: kubectl delete pod %s -n %s", copyName, pod.Namespace))
	default:
		return errors.New("選択は1〜3で指定してください")
	}
	if strings.Contains(string(helpOutput), "--profile") {
		debugArgs = append(debugArgs, "--profile="+runner.Config.DebugProfile)
	}
	debugArgs = append(debugArgs, "--", "sh")
	runner.Console.Command(shellDisplay(append([]string{kubectl}, debugArgs...)))
	runner.Console.Write("\n注意: kubectl debugはクラスタを変更します。")
	fmt.Fprint(runner.Streams.Out, "実行するにはYESと入力: ")
	answer, readErr := runner.reader.ReadString('\n')
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return fmt.Errorf("debug実行の確認入力を読み取れませんでした: %w", readErr)
	}
	if strings.TrimSpace(answer) != "YES" {
		runner.Console.Write("debugをキャンセルしました")
		return nil
	}
	current, err = runner.refreshPodTarget(ctx, pod)
	if err != nil {
		return err
	}
	if choice == "1" && current.Status.Phase != corev1.PodRunning {
		return fmt.Errorf("Podの状態（phase）が %s に変化したため、Ephemeral Containerを追加できません", current.Status.Phase)
	}
	command := exec.CommandContext(ctx, kubectl, debugArgs...) // #nosec G204 -- confirmed argv-only kubectl debug execution.
	command.Stdin, command.Stdout, command.Stderr = runner.Streams.In, runner.Streams.Out, runner.Streams.Err
	if err := command.Run(); err != nil {
		return fmt.Errorf("kubectl debugが失敗しました: %w", err)
	}
	return nil
}

func interpretCanIResult(output []byte, commandErr error) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(string(output))) {
	case "yes":
		return true, nil
	case "no":
		return false, nil
	}
	if commandErr != nil {
		return false, fmt.Errorf("kubectl auth can-i の実行に失敗しました: %s", console.Snip(redact.MaskSecrets(string(output)), 300))
	}
	return false, fmt.Errorf("kubectl auth can-i が解釈できない応答を返しました: %s", console.Snip(redact.MaskSecrets(string(output)), 300))
}

func (runner *Runner) refreshPodTarget(ctx context.Context, selected *corev1.Pod) (*corev1.Pod, error) {
	current, err := runner.Clients.Kube.CoreV1().Pods(selected.Namespace).Get(ctx, selected.Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("対象Pod %s/%s の現在の状態を確認できませんでした。原因: %s", selected.Namespace, selected.Name, kube.ErrorReason(err))
	}
	if selected.UID != "" && current.UID != "" && selected.UID != current.UID {
		return nil, fmt.Errorf("対象Pod %s/%s は再作成されています。debugを中止して再度選択してください", selected.Namespace, selected.Name)
	}
	return current, nil
}
