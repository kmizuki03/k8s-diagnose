// Package app orchestrates collection, analysis, rendering and interactive modes.
package app

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kmizuki03/k8s-diagnose/internal/baseline"
	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/connect"
	"github.com/kmizuki03/k8s-diagnose/internal/console"
	"github.com/kmizuki03/k8s-diagnose/internal/history"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	"github.com/kmizuki03/k8s-diagnose/internal/notify"
	"github.com/kmizuki03/k8s-diagnose/internal/redact"
	"github.com/kmizuki03/k8s-diagnose/internal/report"
	"github.com/kmizuki03/k8s-diagnose/internal/rules"
	"golang.org/x/term"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Streams struct {
	In  io.Reader
	Out io.Writer
	Err io.Writer
}

type Runner struct {
	Config      config.Config
	Streams     Streams
	Clients     *kube.Clients
	Console     *console.Console
	Registry    *rules.Registry
	Baseline    baseline.Baseline
	Previous    report.Document
	LogAnalyzer *rules.LogAnalyzer
	WebhookURL  string
	History     *history.Analysis
	watchRuns   []report.Document
	reader      *bufio.Reader
	logBlocks   []logBlock
	trace       *bytes.Buffer
}

type logBlock struct {
	Title string
	Lines []string
}

func printError(stream io.Writer, err error) {
	if err == nil {
		return
	}
	fmt.Fprintln(stream, "エラー:", redact.MaskSecrets(err.Error()))
}

func printErrorMessage(stream io.Writer, message string) {
	fmt.Fprintln(stream, "エラー:", redact.MaskSecrets(message))
}

func Run(ctx context.Context, cfg config.Config, streams Streams) int {
	if streams.In == nil {
		streams.In = os.Stdin
	}
	if streams.Out == nil {
		streams.Out = os.Stdout
	}
	if streams.Err == nil {
		streams.Err = os.Stderr
	}
	var err error
	cfg, err = enforceInteractiveMaskPolicy(cfg, streams.Out)
	if err != nil {
		printError(streams.Err, err)
		return 1
	}
	loadedBaseline, err := baseline.Load(cfg.BaselineFile)
	if err != nil {
		printError(streams.Err, err)
		return 1
	}
	var previous report.Document
	if cfg.DiffFrom != "" {
		previous, err = report.Load(cfg.DiffFrom)
		if err != nil {
			printError(streams.Err, err)
			return 1
		}
	}
	if cfg.HistoryDB != "" {
		if err := history.Validate(ctx, cfg.HistoryDB); err != nil {
			printError(streams.Err, err)
			return 1
		}
	}
	webhookURL := ""
	if cfg.WebhookURLEnv != "" {
		webhookURL, err = notify.ResolveURL(cfg.WebhookURLEnv)
		if err != nil {
			printError(streams.Err, err)
			return 1
		}
	}
	logAnalyzer, err := rules.NewLogAnalyzer(cfg.LogSignatures, cfg.LogSignatureLines)
	if err != nil {
		printError(streams.Err, err)
		return 1
	}
	clients, err := kube.NewClients(cfg)
	if err != nil {
		printError(streams.Err, err)
		return 1
	}
	var trace *bytes.Buffer
	if cfg.ShowCmd && cfg.Output == "text" {
		trace = &bytes.Buffer{}
		clients.SetTraceWriter(trace)
	}
	if err := clients.Preflight(ctx); err != nil {
		printError(streams.Err, err)
		return 1
	}
	consoleOut := streams.Out
	if cfg.Output != "text" {
		consoleOut = io.Discard
	}
	runner := &Runner{
		Config: cfg, Streams: streams, Clients: clients,
		Console: console.New(cfg, consoleOut, streams.Err), Registry: rules.Builtins(),
		Baseline: loadedBaseline, Previous: previous, LogAnalyzer: logAnalyzer,
		WebhookURL: webhookURL,
		reader:     bufio.NewReader(streams.In),
		trace:      trace,
	}
	if cfg.Watch > 0 {
		return runner.watch(ctx)
	}
	return runner.once(ctx)
}

func enforceInteractiveMaskPolicy(cfg config.Config, output io.Writer) (config.Config, error) {
	if cfg.Mask {
		return cfg, nil
	}
	file, ok := output.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) { // #nosec G115 -- canonical x/term descriptor conversion.
		return cfg, errors.New("--no-maskは対話端末へのtext出力でのみ使用できます")
	}
	return cfg, nil
}

func (runner *Runner) once(ctx context.Context) int {
	switch runner.Config.Mode {
	case "list":
		return runner.list(ctx)
	case "select":
		return runner.selectPod(ctx)
	default:
		state, snapshot, err := runner.diagnose(ctx, nil)
		if ctx.Err() != nil {
			return 0
		}
		if err != nil {
			printError(runner.Streams.Err, err)
			return 1
		}
		document, difference, payload, err := runner.prepare(ctx, state, snapshot)
		if err != nil {
			printError(runner.Streams.Err, err)
			return 1
		}
		if runner.Config.Output == "text" {
			runner.renderText(snapshot, state)
		}
		if err := runner.finish(ctx, document, difference, payload); err != nil {
			printError(runner.Streams.Err, err)
			return 1
		}
		if runner.Config.Debug {
			selected, quit, err := runner.promptPod(snapshot.Pods)
			if err != nil {
				printError(runner.Streams.Err, err)
				return 1
			}
			if !quit && selected != nil {
				if err := runner.debugPod(ctx, selected); err != nil {
					printError(runner.Streams.Err, err)
					return 1
				}
			}
		}
		if runner.Config.ExitZero || !state.ShouldFail(runner.Config.FailOn, runner.Config.MaxIssues) {
			return 0
		}
		return 1
	}
}

func (runner *Runner) diagnose(ctx context.Context, selected *corev1.Pod) (*model.State, *kube.Snapshot, error) {
	runner.logBlocks = nil
	keys := runner.Registry.RequiredKeys(runner.Config.Mode)
	if runner.Config.Mode == "select" {
		for _, key := range []string{"deployments", "statefulsets", "daemonsets", "replicasets", "jobs", "endpoint_slices", "services", "ingresses"} {
			keys[key] = true
		}
	}
	if runner.Config.ShowUnused {
		for _, key := range []string{"pods", "configmaps", "secrets", "pvcs", "serviceaccounts", "ingresses", "deployments", "statefulsets", "daemonsets", "replicasets", "jobs", "cronjobs"} {
			keys[key] = true
		}
	}
	collector := &kube.Collector{Clients: runner.Clients, Config: runner.Config, Only: keys}
	snapshot := collector.Collect(ctx)
	if selected != nil {
		if status := snapshot.Status("pods"); !status.Available {
			return nil, snapshot, fmt.Errorf("選択したPodを診断直前に再取得できません (%s)", status.Reason)
		}
		fresh, err := resolveSelectedPod(snapshot.Pods, selected)
		if err != nil {
			return nil, snapshot, err
		}
		copySnapshot := *snapshot
		copySnapshot.Pods = []corev1.Pod{*fresh}
		snapshot = &copySnapshot
	}
	state := model.NewState()
	runner.Registry.Run(ctx, snapshot, runner.Config, state)
	if runner.Config.ShowUnused {
		addUnusedDiagnostics(snapshot, state, runner.Config.Namespace == "")
	}
	if selected != nil || runner.Config.ShowLogs {
		runner.collectLogs(ctx, snapshot, state, selected != nil)
	}
	runner.correlateAndApplyBaseline(snapshot, state)
	return state, snapshot, nil
}

func (runner *Runner) correlateAndApplyBaseline(snapshot *kube.Snapshot, state *model.State) {
	state.Sort()
	rules.Correlate(snapshot, state)
	if runner.Baseline.Path == "" {
		return
	}
	baseline.Apply(state, runner.Baseline, rules.BaselineWorkloadResolver(snapshot))
	state.Sort()
	rules.Correlate(snapshot, state)
}

func (runner *Runner) applyBaselineToLateFindings(snapshot *kube.Snapshot, state *model.State) {
	if runner.Baseline.Path != "" {
		baseline.Apply(state, runner.Baseline, rules.BaselineWorkloadResolver(snapshot))
	}
	state.Sort()
}

func addUnusedDiagnostics(snapshot *kube.Snapshot, state *model.State, excludeSystemNamespaces bool) {
	collections := []struct {
		key, description string
	}{
		{"pods", "Pod参照"}, {"deployments", "Deployment template参照"},
		{"statefulsets", "StatefulSet template参照"}, {"daemonsets", "DaemonSet template参照"},
		{"replicasets", "ReplicaSet template参照"}, {"jobs", "Job template参照"},
		{"cronjobs", "CronJob template参照"}, {"ingresses", "Ingress TLS参照"},
		{"configmaps", "ConfigMap候補"}, {"secrets", "Secret候補"},
		{"pvcs", "PVC候補"}, {"serviceaccounts", "ServiceAccount候補・参照"},
	}
	unavailable := []string{}
	for _, collection := range collections {
		status := snapshot.Status(collection.key)
		state.AddCheck(model.Check{
			ID: "unused/" + collection.key, Section: "未使用候補",
			Description: "未使用リソース診断: " + collection.description,
			Available:   status.Available, Reason: status.Reason,
		})
		if !status.Available {
			unavailable = append(unavailable, collection.key)
		}
	}
	if len(unavailable) > 0 {
		finding := model.NewFinding(
			model.Unavailable, "K8S.UNUSED.PARTIAL_UNAVAILABLE", "未使用候補", "Rule/unused",
			"FetchUnavailable", "collections", fmt.Sprintf("未使用リソース診断は取得できた範囲だけで実施しました (取得不能: %s)", strings.Join(unavailable, ", ")), 100,
		)
		finding.RuleID = "unused"
		state.Add(finding)
	}
	for _, finding := range rules.UnusedFindings(snapshot, excludeSystemNamespaces) {
		finding.RuleID = "unused"
		state.Add(finding)
	}
}

// resolveSelectedPod prevents the interactive selection screen from pinning a
// stale Pod object while the subsequent diagnostics collect a fresh snapshot.
// A Pod recreated under the same name is a different target and must be
// selected again instead of being diagnosed silently.
func resolveSelectedPod(pods []corev1.Pod, selected *corev1.Pod) (*corev1.Pod, error) {
	for i := range pods {
		pod := &pods[i]
		if pod.Namespace != selected.Namespace || pod.Name != selected.Name {
			continue
		}
		if selected.UID != "" && pod.UID != "" && selected.UID != pod.UID {
			return nil, fmt.Errorf("選択したPod %s/%s は再作成されています。再度選択してください", selected.Namespace, selected.Name)
		}
		return pod.DeepCopy(), nil
	}
	return nil, fmt.Errorf("選択したPod %s/%s は再取得時に存在しません。再度選択してください", selected.Namespace, selected.Name)
}

func (runner *Runner) renderText(snapshot *kube.Snapshot, state *model.State) {
	runner.Console.Header(runner.Clients.Context)
	runner.renderTrace()
	if runner.Config.Mode == "all" {
		runner.Console.Chapter("Pod一覧")
		runner.Console.PodTable([]string{"NAMESPACE", "NAME", "READY", "STATUS", "RESTARTS", "AGE", "NODE"}, podRows(snapshot.Pods))
		runner.renderMetrics(snapshot, state)
	}
	runner.renderEvents(snapshot.Events, "")
	runner.renderLogs()
	runner.Console.RootCauseReport(state.RootCauses)
	if runner.History != nil {
		runner.renderHistory(*runner.History)
	}
	runner.Console.Summary(state)
}

func (runner *Runner) list(ctx context.Context) int {
	collector := &kube.Collector{Clients: runner.Clients, Config: runner.Config, Only: map[string]bool{"pods": true}}
	snapshot := collector.Collect(ctx)
	status := snapshot.Status("pods")
	if !status.Available {
		printErrorMessage(runner.Streams.Err, fmt.Sprintf("Pod一覧を取得できません (%s)", status.Reason))
		return 1
	}
	runner.Console.Header(runner.Clients.Context)
	runner.renderTrace()
	runner.Console.Chapter("Pod一覧")
	runner.Console.PodTable([]string{"NAMESPACE", "NAME", "READY", "STATUS", "RESTARTS", "AGE", "NODE"}, podRows(snapshot.Pods))
	counts := podPhaseCounts(snapshot.Pods)
	runner.Console.Write(fmt.Sprintf("\nPod: 合計 %d / Running %d / Pending %d / Succeeded %d / Failed %d / Unknown %d",
		len(snapshot.Pods), counts["Running"], counts["Pending"], counts["Succeeded"], counts["Failed"], counts["Unknown"]))
	return 0
}

func podPhaseCounts(pods []corev1.Pod) map[string]int {
	counts := map[string]int{}
	for i := range pods {
		phase := string(pods[i].Status.Phase)
		if phase == "" {
			phase = "Unknown"
		}
		counts[phase]++
	}
	return counts
}

func (runner *Runner) selectPod(ctx context.Context) int {
	collector := &kube.Collector{Clients: runner.Clients, Config: runner.Config, Only: map[string]bool{"pods": true}}
	snapshot := collector.Collect(ctx)
	status := snapshot.Status("pods")
	if !status.Available {
		printErrorMessage(runner.Streams.Err, fmt.Sprintf("Pod一覧を取得できません (%s)", status.Reason))
		return 1
	}
	selected, quit, err := runner.promptPod(snapshot.Pods)
	if err != nil {
		printError(runner.Streams.Err, err)
		return 1
	}
	if quit || selected == nil {
		return 0
	}
	state, selectedSnapshot, err := runner.diagnose(ctx, selected)
	if ctx.Err() != nil {
		return 0
	}
	if err != nil {
		printError(runner.Streams.Err, err)
		return 1
	}
	selected = &selectedSnapshot.Pods[0]
	if runner.Config.Output == "text" {
		runner.Console.Header(runner.Clients.Context)
		runner.renderTrace()
		runner.Console.Chapter("Pod個別診断: " + selected.Namespace + "/" + selected.Name)
		runner.Console.PodTable([]string{"NAMESPACE", "NAME", "READY", "STATUS", "RESTARTS", "AGE", "NODE"}, podRows([]corev1.Pod{*selected}))
		runner.renderEvents(selectedSnapshot.Events, selected.Name)
		runner.renderLogs()
		if runner.Config.Connect {
			results, ran, err := runner.runConnect(ctx, selected, selectedSnapshot.Services, state)
			if err != nil {
				printError(runner.Streams.Err, err)
				return 1
			}
			if ran {
				runner.correlateAndApplyBaseline(selectedSnapshot, state)
				runner.renderConnectResults(results)
				runner.renderTrace()
			}
		}
		runner.Console.RootCauseReport(state.RootCauses)
		runner.Console.Summary(state)
	}
	if runner.Config.Debug {
		if err := runner.debugPod(ctx, selected); err != nil {
			printError(runner.Streams.Err, err)
			return 1
		}
	}
	if runner.Config.ExitZero || len(state.BySeverity(model.Issue, true)) == 0 {
		return 0
	}
	return 1
}

func (runner *Runner) renderEvents(events []corev1.Event, podName string) {
	type timedEvent struct {
		event corev1.Event
		when  time.Time
	}
	values := []timedEvent{}
	for i := range events {
		event := events[i]
		if event.Type != corev1.EventTypeWarning {
			continue
		}
		if podName != "" && !(event.InvolvedObject.Kind == "Pod" && event.InvolvedObject.Name == podName) {
			continue
		}
		when := latestEventTime(&event)
		values = append(values, timedEvent{event: event, when: when})
	}
	sort.SliceStable(values, func(i, j int) bool { return values[i].when.After(values[j].when) })
	if len(values) > runner.Config.EventsLimit {
		values = values[:runner.Config.EventsLimit]
	}
	if len(values) == 0 {
		return
	}
	runner.Console.Chapter(fmt.Sprintf("Warning Event (最新%d件)", len(values)))
	rows := make([]console.TableRow, 0, len(values))
	for _, value := range values {
		event := value.event
		rows = append(rows, console.TableRow{Cells: []string{
			event.Namespace, event.InvolvedObject.Kind + "/" + event.InvolvedObject.Name,
			event.Reason, ageText(value.when), console.Snip(console.MaskSecrets(strings.Join(strings.Fields(event.Message), " "), runner.Config.Mask), 120),
		}, Status: "Warning"})
	}
	runner.Console.Table([]string{"NAMESPACE", "OBJECT", "REASON", "AGE", "MESSAGE"}, rows, true)
}

func latestEventTime(event *corev1.Event) time.Time {
	latest := event.CreationTimestamp.Time
	for _, candidate := range []time.Time{event.FirstTimestamp.Time, event.LastTimestamp.Time, event.EventTime.Time} {
		if candidate.After(latest) {
			latest = candidate
		}
	}
	if event.Series != nil && event.Series.LastObservedTime.Time.After(latest) {
		latest = event.Series.LastObservedTime.Time
	}
	return latest
}

func (runner *Runner) promptPod(pods []corev1.Pod) (*corev1.Pod, bool, error) {
	reader := runner.reader
	if reader == nil {
		reader = bufio.NewReader(runner.Streams.In)
		runner.reader = reader
	}
	candidates := append([]corev1.Pod{}, pods...)
	for {
		runner.Console.Header(runner.Clients.Context)
		runner.renderTrace()
		runner.Console.Chapter("Pod選択")
		runner.Console.PodTable([]string{"#", "NAMESPACE", "NAME", "READY", "STATUS"}, compactPodRows(candidates))
		fmt.Fprint(runner.Streams.Out, "\nPod名または namespace/Pod名の一部 (番号、qで終了): ")
		line, err := reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, false, err
		}
		line = strings.TrimSpace(line)
		if line == "q" || line == "Q" || line == "" && errors.Is(err, io.EOF) {
			return nil, true, nil
		}
		if number, parseErr := strconv.Atoi(line); parseErr == nil {
			if number >= 1 && number <= len(candidates) {
				return candidates[number-1].DeepCopy(), false, nil
			}
			fmt.Fprintln(runner.Streams.Out, "無効な番号です")
			continue
		}
		query := strings.ToLower(strings.TrimPrefix(line, "/"))
		filtered := []corev1.Pod{}
		for i := range pods {
			value := strings.ToLower(pods[i].Namespace + "/" + pods[i].Name)
			matched := true
			for _, word := range strings.Fields(query) {
				if !strings.Contains(value, word) {
					matched = false
					break
				}
			}
			if matched {
				filtered = append(filtered, pods[i])
			}
		}
		if len(filtered) == 0 {
			fmt.Fprintln(runner.Streams.Out, "一致するPodがありません")
			continue
		}
		if len(filtered) == 1 {
			return filtered[0].DeepCopy(), false, nil
		}
		candidates = filtered
	}
}

func (runner *Runner) renderTrace() {
	if runner.trace == nil || runner.trace.Len() == 0 {
		return
	}
	runner.Console.Section("実行したKubernetes API要求")
	for _, line := range strings.Split(strings.TrimRight(runner.trace.String(), "\n"), "\n") {
		runner.Console.Write(line)
	}
	runner.trace.Reset()
}

func (runner *Runner) debugPod(ctx context.Context, pod *corev1.Pod) error {
	current, err := runner.refreshPodTarget(ctx, pod)
	if err != nil {
		return err
	}
	pod = current
	kubectl, err := exec.LookPath("kubectl")
	if err != nil {
		return errors.New("--debugに必要なkubectlがPATHにありません")
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
		return errors.New("このkubectlはdebugをサポートしていません")
	}
	runner.Console.Section(fmt.Sprintf("kubectl debug: %s/%s", pod.Namespace, pod.Name))
	runner.Console.Write("  1) Ephemeral Containerを追加 (Running Pod向け)")
	runner.Console.Write("  2) デバッグ用コピーPodを作成")
	runner.Console.Write("  3) 実行しない")
	fmt.Fprint(runner.Streams.Out, "選択 [1-3]: ")
	choice, readErr := runner.reader.ReadString('\n')
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return fmt.Errorf("debug選択を読み取れません: %w", readErr)
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
			return fmt.Errorf("Pod phase=%s のためEphemeral Containerは追加できません", pod.Status.Phase)
		}
		allowed, err := canI("update", "pods/ephemeralcontainers")
		if err != nil {
			return err
		}
		if !allowed {
			return errors.New("pods/ephemeralcontainersのupdate権限がありません")
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
			return errors.New("Podのcreate権限がありません")
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
		return fmt.Errorf("debug確認を読み取れません: %w", readErr)
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
		return fmt.Errorf("Pod phase=%s に変化したためEphemeral Containerを追加できません", current.Status.Phase)
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
		// kubectl intentionally exits non-zero for a valid authorization denial.
		return false, nil
	}
	if commandErr != nil {
		return false, fmt.Errorf("kubectl auth can-iに失敗しました: %s", console.Snip(redact.MaskSecrets(string(output)), 300))
	}
	return false, fmt.Errorf("kubectl auth can-iが解釈できない応答を返しました: %s", console.Snip(redact.MaskSecrets(string(output)), 300))
}

func (runner *Runner) refreshPodTarget(ctx context.Context, selected *corev1.Pod) (*corev1.Pod, error) {
	current, err := runner.Clients.Kube.CoreV1().Pods(selected.Namespace).Get(ctx, selected.Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("対象Pod %s/%sを再確認できません (%s)", selected.Namespace, selected.Name, kube.ErrorReason(err))
	}
	if selected.UID != "" && current.UID != "" && selected.UID != current.UID {
		return nil, fmt.Errorf("対象Pod %s/%s は再作成されています。debugを中止して再度選択してください", selected.Namespace, selected.Name)
	}
	return current, nil
}

func shellDisplay(args []string) string {
	quoted := make([]string, len(args))
	for index, value := range args {
		if value != "" && !strings.ContainsAny(value, " \t\n'\"\\$`;&|<>()[]{}*?!") {
			quoted[index] = value
		} else {
			quoted[index] = "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
		}
	}
	return strings.Join(quoted, " ")
}

func (runner *Runner) collectLogs(ctx context.Context, snapshot *kube.Snapshot, state *model.State, selected bool) {
	referenceTime := snapshot.ServerTime
	if referenceTime.IsZero() {
		referenceTime = time.Now()
	}
	for i := range snapshot.Pods {
		pod := &snapshot.Pods[i]
		if !selected && isHealthyPod(pod, runner.Config, referenceTime) {
			continue
		}
		for _, previous := range []bool{false, true} {
			text, failures := runner.podLogs(ctx, pod, previous)
			source := "current"
			if previous {
				source = "previous"
			}
			checkID := "logs/" + pod.Namespace + "/" + pod.Name + "/" + source
			state.AddCheck(model.Check{ID: checkID, Section: "ログ", Description: fmt.Sprintf("Pod %s/%sの%sログ", pod.Namespace, pod.Name, source), Available: len(failures) == 0, Reason: strings.Join(failures, "; ")})
			if len(failures) > 0 {
				finding := model.NewFinding(model.Unavailable, "K8S.LOG.FETCH_UNAVAILABLE", "ログ", "Pod/"+pod.Namespace+"/"+pod.Name, "LogFetchFailed", source, fmt.Sprintf("Pod %s/%sの%sログを完全に取得できません", pod.Namespace, pod.Name, source), 100, model.Evidence{Kind: "api", Key: "errors", Value: strings.Join(failures, "; ")})
				finding.RuleID = "logs"
				state.Add(finding)
			}
			if text == "" {
				continue
			}
			for _, finding := range runner.LogAnalyzer.Analyze(pod.Namespace, pod.Name, source, text) {
				finding.RuleID = "logs"
				state.Add(finding)
			}
			lines := tailLines(newestBytes(text, 512*1024), runner.Config.Tail)
			for index := range lines {
				lines[index] = console.MaskSecrets(lines[index], runner.Config.Mask)
			}
			runner.logBlocks = append(runner.logBlocks, logBlock{Title: fmt.Sprintf("ログ %s/%s (%s)", pod.Namespace, pod.Name, source), Lines: lines})
		}
	}
}

func (runner *Runner) renderLogs() {
	for _, block := range runner.logBlocks {
		runner.Console.Section(block.Title)
		for _, line := range block.Lines {
			runner.Console.Write(line)
		}
	}
}

func (runner *Runner) runConnect(ctx context.Context, pod *corev1.Pod, services []corev1.Service, state *model.State) ([]connect.Result, bool, error) {
	runner.Console.Section("接続確認 (client-go port-forward)")
	runner.Console.Write("注意: トンネルを作成し、Pod直接とService指定Podを単発確認します。")
	fmt.Fprint(runner.Streams.Out, "実行するにはYESと入力: ")
	answer, err := runner.reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false, fmt.Errorf("接続確認の確認入力を読めません: %w", err)
	}
	if strings.TrimSpace(answer) != "YES" {
		runner.Console.Write("接続確認は実行しません")
		return nil, false, nil
	}
	checker := &connect.Checker{Clients: runner.Clients, Config: runner.Config}
	results, findings := checker.Check(ctx, pod, services)
	for _, finding := range findings {
		state.Add(finding)
	}
	return results, true, nil
}

func (runner *Runner) podLogs(ctx context.Context, pod *corev1.Pod, previous bool) (string, []string) {
	tail := int64(max(runner.Config.Tail, runner.Config.LogSignatureLines))
	names := []string{}
	for _, container := range pod.Spec.InitContainers {
		names = append(names, container.Name)
	}
	for _, container := range pod.Spec.Containers {
		names = append(names, container.Name)
	}
	for _, container := range pod.Spec.EphemeralContainers {
		names = append(names, container.Name)
	}
	var output strings.Builder
	failures := []string{}
	for _, name := range names {
		data, err := runner.Clients.Kube.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &corev1.PodLogOptions{Container: name, Previous: previous, TailLines: &tail}).DoRaw(ctx)
		if err != nil {
			lower := strings.ToLower(err.Error())
			if previous && (strings.Contains(lower, "previous terminated container") || strings.Contains(lower, "not found")) {
				continue
			}
			failures = append(failures, name+": "+kube.ErrorReason(err))
			continue
		}
		fmt.Fprintf(&output, "=== %s ===\n%s\n", name, data)
	}
	return newestBytes(output.String(), 512*1024), failures
}

func (runner *Runner) renderConnectResults(results []connect.Result) {
	runner.Console.Section("Probe/接続確認結果")
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
			runner.Console.Write("    (対象なし・未実施)")
		}
	}
	pod, service := groups["pod"], groups["service"]
	runner.Console.Write()
	switch {
	case pod.failed == 0 && pod.unavailable == 0 && pod.succeeded > 0 && service.failed == 0 && service.unavailable == 0 && service.succeeded > 0:
		if pod.warned+service.warned > 0 {
			runner.Console.Write("  ▲ Pod直接・Service指定Podとも単発接続成立、HTTP応答または再現条件に注意あり")
		} else {
			runner.Console.Write("  → Pod直接・Service指定Podとも単発接続確認成功")
		}
	case pod.failed == 0 && pod.succeeded > 0 && service.tested == 0 && service.unavailable == 0:
		runner.Console.Write("  → Pod直接は接続成立、Service指定Podは対象なしのため未実施")
	case service.failed == 0 && service.succeeded > 0 && pod.tested == 0 && pod.unavailable == 0:
		runner.Console.Write("  → Service指定Podは接続成立、Pod直接はポート推定不可のため未実施")
	case pod.failed > 0 || service.failed > 0:
		runner.Console.Write("  ▲ 単発接続に失敗があります。kubeletの連続判定と現在のPod状態を合わせて確認してください")
	case pod.unavailable+service.unavailable > 0:
		runner.Console.Write("  ? 接続確認の一部を実施できませんでした")
	default:
		runner.Console.Write("  → 接続テストは実施されませんでした")
	}
}

func (runner *Runner) prepare(ctx context.Context, state *model.State, snapshot *kube.Snapshot) (report.Document, map[string]any, map[string]any, error) {
	runner.History = nil
	draft := report.Build(state, runner.Config, runner.Clients.Context)
	historyRecords := []report.Document{}
	if runner.Config.HistoryDB != "" {
		var err error
		historyRecords, err = history.Load(ctx, runner.Config.HistoryDB, draft, max(1, runner.Config.HistoryWindow-1))
		if err != nil {
			return nil, nil, nil, err
		}
		analysis := history.Analyze(historyRecords, draft, runner.Config.HistoryWindow, runner.Config.FlapThreshold, runner.Config.RestartGrowth)
		history.AddFindings(state, analysis)
		runner.applyBaselineToLateFindings(snapshot, state)
		runner.History = &analysis
	}
	document := report.Build(state, runner.Config, runner.Clients.Context)
	if runner.History != nil {
		document["history_analysis"] = report.Sanitize(*runner.History)
	}
	var difference map[string]any
	var err error
	switch {
	case runner.Previous != nil:
		difference = report.Compare(runner.Previous, document)
		difference, _ = report.Sanitize(difference).(map[string]any)
		document["diff"] = difference
	case len(historyRecords) > 0:
		difference, err = report.CompareHistory(historyRecords, document)
	case len(runner.watchRuns) > 0:
		difference, err = report.CompareHistory(runner.watchRuns, document)
	}
	if difference != nil {
		difference, _ = report.Sanitize(difference).(map[string]any)
	}
	if err != nil {
		return nil, nil, nil, err
	}
	var payload map[string]any
	if runner.WebhookURL != "" && difference != nil {
		payload = notify.BuildPayload(difference, document)
	}
	return document, difference, payload, nil
}

func (runner *Runner) finish(ctx context.Context, document report.Document, difference, payload map[string]any) error {
	if runner.Previous != nil && difference != nil && runner.Config.Output == "text" {
		fmt.Fprintln(runner.Streams.Out, "\n"+report.DiffText(difference))
	}
	jsonData, err := report.JSON(document)
	if err != nil {
		return err
	}
	if runner.Config.HistoryDB != "" {
		if _, err := history.Append(ctx, runner.Config.HistoryDB, document, runner.Config.HistoryRetain, runner.Config.Watch > 0); err != nil {
			return err
		}
	}
	if runner.Config.SaveSnapshot != "" {
		if err := report.WriteAtomic(runner.Config.SaveSnapshot, jsonData); err != nil {
			return err
		}
	}
	if runner.Config.Output != "text" {
		data, err := report.Render(runner.Config.Output, document)
		if err != nil {
			return err
		}
		if runner.Config.OutputFile != "" {
			if err := report.WriteAtomic(runner.Config.OutputFile, data); err != nil {
				return err
			}
		} else if _, err = runner.Streams.Out.Write(data); err != nil {
			return err
		}
	}
	if runner.WebhookURL != "" {
		switch {
		case difference == nil:
			runner.Console.Write("\n  Webhook通知: 比較基準がない初回実行のため送信しません")
		case payload == nil:
			runner.Console.Write("\n  Webhook通知: 新規・悪化した確定異常はありません")
		default:
			if err := notify.Send(ctx, runner.WebhookURL, payload, time.Duration(runner.Config.WebhookTimeout)*time.Second, runner.Config.WebhookFormat); err != nil {
				return err
			}
			runner.Console.Write("\n  Webhook通知: 新規・悪化した確定異常を送信しました")
		}
	}
	runner.watchRuns = append(runner.watchRuns, document)
	if limit := max(1, runner.Config.HistoryWindow-1); len(runner.watchRuns) > limit {
		runner.watchRuns = runner.watchRuns[len(runner.watchRuns)-limit:]
	}
	return nil
}

func (runner *Runner) renderHistory(analysis history.Analysis) {
	runner.Console.Section("履歴トレンド")
	if len(analysis.Trends) == 0 {
		runner.Console.Write(fmt.Sprintf("直近%d回ではフラッピング・継続的な再起動増加を検出しませんでした", analysis.Samples))
	} else {
		for _, trend := range analysis.Trends {
			runner.Console.Write("  ▲ " + console.MaskSecrets(trend.Message, runner.Config.Mask))
		}
		runner.Console.Write(fmt.Sprintf("  (%d 件 / 分析サンプル %d)", len(analysis.Trends), analysis.Samples))
	}
	if analysis.UnknownEvaluations > 0 {
		runner.Console.Write(fmt.Sprintf("  取得不能によるunknown %d件は正常・異常の遷移判定から除外しました", analysis.UnknownEvaluations))
	}
}

func (runner *Runner) watch(ctx context.Context) int {
	first := true
	for {
		if !first {
			fmt.Fprintln(runner.Streams.Out, "\n"+strings.Repeat("=", 68)+"\n")
		}
		first = false
		state, snapshot, err := runner.diagnose(ctx, nil)
		if ctx.Err() != nil {
			return 0
		}
		if err != nil {
			printError(runner.Streams.Err, err)
			return 1
		}
		document, difference, payload, err := runner.prepare(ctx, state, snapshot)
		if err != nil {
			printError(runner.Streams.Err, err)
			return 1
		}
		runner.renderText(snapshot, state)
		if err := runner.finish(ctx, document, difference, payload); err != nil {
			printError(runner.Streams.Err, err)
			return 1
		}
		fmt.Fprintf(runner.Streams.Out, "\n次回診断まで %d 秒 (Ctrl-Cで終了)\n", runner.Config.Watch)
		timer := time.NewTimer(time.Duration(runner.Config.Watch) * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return 0
		case <-timer.C:
		}
	}
}

func podRows(pods []corev1.Pod) []console.TableRow {
	values := append([]corev1.Pod{}, pods...)
	sort.Slice(values, func(i, j int) bool {
		return values[i].Namespace+"/"+values[i].Name < values[j].Namespace+"/"+values[j].Name
	})
	result := make([]console.TableRow, 0, len(values))
	for i := range values {
		pod := &values[i]
		ready, total := readyRatio(pod)
		restarts := int32(0)
		for _, status := range append(append([]corev1.ContainerStatus{}, pod.Status.InitContainerStatuses...), pod.Status.ContainerStatuses...) {
			restarts += status.RestartCount
		}
		result = append(result, console.TableRow{Cells: []string{pod.Namespace, pod.Name, fmt.Sprintf("%d/%d", ready, total), podStatus(pod), fmt.Sprint(restarts), ageText(pod.CreationTimestamp.Time), valueOr(pod.Spec.NodeName, "<none>")}, Status: podStatus(pod)})
	}
	return result
}

func compactPodRows(pods []corev1.Pod) []console.TableRow {
	rows := podRows(pods)
	result := make([]console.TableRow, 0, len(rows))
	for index, row := range rows {
		result = append(result, console.TableRow{Cells: append([]string{fmt.Sprintf("%d", index+1)}, row.Cells[:4]...), Status: row.Status})
	}
	return result
}

func readyRatio(pod *corev1.Pod) (int, int) {
	ready, total := 0, 0
	for _, container := range pod.Spec.InitContainers {
		if container.RestartPolicy == nil || *container.RestartPolicy != corev1.ContainerRestartPolicyAlways {
			continue
		}
		total++
		for _, status := range pod.Status.InitContainerStatuses {
			if status.Name == container.Name && status.Ready {
				ready++
				break
			}
		}
	}
	for _, container := range pod.Spec.Containers {
		total++
		for _, status := range pod.Status.ContainerStatuses {
			if status.Name == container.Name && status.Ready {
				ready++
				break
			}
		}
	}
	return ready, total
}

func podStatus(pod *corev1.Pod) string {
	if pod.DeletionTimestamp != nil {
		return "Terminating"
	}
	statuses := append(append([]corev1.ContainerStatus{}, pod.Status.InitContainerStatuses...), pod.Status.ContainerStatuses...)
	for _, status := range statuses {
		if status.State.Waiting != nil && status.State.Waiting.Reason != "" {
			return status.State.Waiting.Reason
		}
		if status.State.Terminated != nil && status.State.Terminated.Reason != "" && status.State.Terminated.Reason != "Completed" {
			return status.State.Terminated.Reason
		}
	}
	if pod.Status.Reason != "" {
		return pod.Status.Reason
	}
	if pod.Status.Phase != "" {
		return string(pod.Status.Phase)
	}
	return "Unknown"
}

func isHealthyPod(pod *corev1.Pod, cfg config.Config, now time.Time) bool {
	if pod.DeletionTimestamp != nil {
		return false
	}
	if pod.Status.Phase == corev1.PodSucceeded {
		return true
	}
	if pod.Status.Phase != corev1.PodRunning {
		return false
	}
	ready := false
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady {
			ready = condition.Status == corev1.ConditionTrue
		}
		if condition.Type == corev1.DisruptionTarget && condition.Status == corev1.ConditionTrue || condition.Type == corev1.PodReadyToStartContainers && condition.Status == corev1.ConditionFalse {
			return false
		}
	}
	if !ready {
		return false
	}
	statuses := append([]corev1.ContainerStatus{}, pod.Status.InitContainerStatuses...)
	statuses = append(statuses, pod.Status.ContainerStatuses...)
	for _, status := range statuses {
		if status.State.Waiting != nil && status.State.Waiting.Reason != "" {
			return false
		}
		if status.State.Terminated != nil && status.State.Terminated.Reason != "" && status.State.Terminated.Reason != "Completed" {
			return false
		}
		terminated := status.LastTerminationState.Terminated
		if terminated == nil || terminated.FinishedAt.IsZero() {
			continue
		}
		age := now.Sub(terminated.FinishedAt.Time)
		recent := age <= 24*time.Hour
		if recent && (terminated.Reason == "OOMKilled" || int64(status.RestartCount) >= int64(cfg.RestartThreshold)) {
			return false
		}
	}
	return true
}

func ageText(created time.Time) string {
	duration := time.Since(created)
	if duration < time.Minute {
		return fmt.Sprintf("%ds", max(0, int(duration.Seconds())))
	}
	if duration < time.Hour {
		return fmt.Sprintf("%dm", int(duration.Minutes()))
	}
	if duration < 24*time.Hour {
		return fmt.Sprintf("%dh", int(duration.Hours()))
	}
	return fmt.Sprintf("%dd", int(duration.Hours()/24))
}

func newestBytes(value string, maximum int) string {
	data := []byte(value)
	if len(data) <= maximum {
		return value
	}
	data = data[len(data)-maximum:]
	for len(data) > 0 && data[0]&0xc0 == 0x80 {
		data = data[1:]
	}
	return string(data)
}

func tailLines(value string, count int) []string {
	lines := strings.Split(strings.TrimRight(value, "\n"), "\n")
	if len(lines) > count {
		lines = lines[len(lines)-count:]
	}
	return lines
}

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
