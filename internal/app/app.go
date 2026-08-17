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
	"strings"
	"time"

	"github.com/kmizuki03/k8s-diagnose/internal/baseline"
	"github.com/kmizuki03/k8s-diagnose/internal/config"
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
	// ReplaySnapshot is the already-validated input loaded from
	// --load-cluster-snapshot. Keeping it here prevents interactive select mode
	// from falling through to a live Collector whose clients are intentionally
	// nil in offline mode.
	ReplaySnapshot *kube.Snapshot
	watchRuns      []report.Document
	reader         *bufio.Reader
	logBlocks      []logBlock
	trace          *bytes.Buffer
	kubectlCmds    [][]string
}

type logBlock struct {
	Title   string
	Lines   []string
	Command []string
}

type containerLog struct {
	Container string
	Text      string
	Command   []string
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
	var trace *bytes.Buffer
	var clients *kube.Clients
	var replaySnapshot *kube.Snapshot
	if cfg.LoadClusterSnapshot != "" {
		// Replaying a saved snapshot must work without any cluster access at
		// all: whoever received the file is helping precisely because they
		// cannot reach the reporter's cluster. Skip client construction and
		// preflight, and label the run so reports never imply a live context.
		file, err := kube.LoadClusterSnapshotFile(cfg.LoadClusterSnapshot)
		if err != nil {
			printError(streams.Err, err)
			return 1
		}
		if err := file.ValidateReplayScope(cfg.Namespace, cfg.Mode, cfg.ShowUnused); err != nil {
			printError(streams.Err, err)
			return 1
		}
		clients = kube.OfflineClients(cfg)
		if contextName := strings.TrimSpace(file.Scope.Context); contextName != "" {
			clients.Context = contextName + "（保存済みクラスタ状態）"
		}
		replaySnapshot = file.Snapshot
	} else {
		live, err := kube.NewClients(cfg)
		if err != nil {
			printError(streams.Err, err)
			return 1
		}
		clients = live
		if cfg.ShowAPIRequests && cfg.Output == "text" {
			trace = &bytes.Buffer{}
			clients.SetTraceWriter(trace)
		}
		if err := clients.Preflight(ctx); err != nil {
			printError(streams.Err, err)
			return 1
		}
	}
	consoleOut := streams.Out
	if cfg.Output != "text" {
		consoleOut = io.Discard
	}
	runner := &Runner{
		Config: cfg, Streams: streams, Clients: clients,
		Console: console.New(cfg, consoleOut, streams.Err), Registry: rules.Builtins(),
		Baseline: loadedBaseline, Previous: previous, LogAnalyzer: logAnalyzer,
		WebhookURL: webhookURL, ReplaySnapshot: replaySnapshot,
		reader: bufio.NewReader(streams.In),
		trace:  trace,
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
		return cfg, errors.New("--no-mask は、対話端末へのテキスト出力でのみ使用できます")
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
				if errors.Is(err, errPodSelectionInterrupted) {
					return 130
				}
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
	runner.kubectlCmds = nil
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
	snapshot, err := runner.snapshotForKeys(ctx, keys)
	if err != nil {
		return nil, nil, err
	}
	if path := runner.Config.SaveClusterSnapshot; path != "" {
		scope := kube.ClusterSnapshotScope{
			Context: runner.Clients.Context, Namespace: runner.Config.Namespace, Mode: runner.Config.Mode,
			Unused: runner.Config.ShowUnused,
		}
		if err := kube.SaveClusterSnapshot(path, config.Version, scope, snapshot); err != nil {
			return nil, snapshot, err
		}
	}
	if selected != nil {
		if status := snapshot.Status("pods"); !status.Available {
			return nil, snapshot, fmt.Errorf("選択したPodを診断直前に再取得できません。原因: %s", status.Reason)
		}
		fresh, err := resolveSelectedPod(snapshot.Pods, selected)
		if err != nil {
			return nil, snapshot, err
		}
		snapshot = scopeSnapshotToSelectedPod(snapshot, fresh)
	}
	state := model.NewState()
	runner.Registry.Run(ctx, snapshot, runner.Config, state)
	if runner.Config.ShowUnused {
		addUnusedDiagnostics(snapshot, state, runner.Config.Namespace == "")
	}
	if selected != nil || runner.Config.ShowLogs {
		if runner.ReplaySnapshot != nil || runner.Config.LoadClusterSnapshot != "" {
			runner.addReplayLogUnavailable(snapshot, state, selected != nil)
		} else {
			runner.collectLogs(ctx, snapshot, state, selected != nil)
		}
	}
	runner.correlateAndApplyBaseline(snapshot, state)
	if selected != nil && len(snapshot.Pods) == 1 {
		state.SetScopedScore(calculatePodScore(&snapshot.Pods[0], state, snapshot))
	}
	return state, snapshot, nil
}

// snapshotForKeys selects exactly one input source. A replay never falls back
// to Kubernetes API access; this is especially important in select mode,
// where the first Pod-list screen previously created a Collector with nil
// offline clients and could panic before showing the saved Pods.
func (runner *Runner) snapshotForKeys(ctx context.Context, keys map[string]bool) (*kube.Snapshot, error) {
	if runner.ReplaySnapshot != nil {
		return runner.ReplaySnapshot, nil
	}
	if path := runner.Config.LoadClusterSnapshot; path != "" {
		file, err := kube.LoadClusterSnapshotFile(path)
		if err != nil {
			return nil, err
		}
		if err := file.ValidateReplayScope(runner.Config.Namespace, runner.Config.Mode, runner.Config.ShowUnused); err != nil {
			return nil, err
		}
		runner.ReplaySnapshot = file.Snapshot
		return runner.ReplaySnapshot, nil
	}
	collector := &kube.Collector{Clients: runner.Clients, Config: runner.Config, Only: keys}
	return collector.Collect(ctx), nil
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
			"FetchUnavailable", "collections", fmt.Sprintf("必要なリソースの一部を取得できなかったため、未使用リソース診断は取得できた範囲で実施しました（取得できなかった項目: %s）", strings.Join(unavailable, ", ")), 100,
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

func (runner *Runner) list(ctx context.Context) int {
	collector := &kube.Collector{Clients: runner.Clients, Config: runner.Config, Only: map[string]bool{"pods": true}}
	snapshot := collector.Collect(ctx)
	status := snapshot.Status("pods")
	if !status.Available {
		printErrorMessage(runner.Streams.Err, fmt.Sprintf("Pod一覧を取得できませんでした。原因: %s", status.Reason))
		return 1
	}
	runner.Console.Header(runner.Clients.Context)
	runner.Console.Chapter("Pod一覧")
	runner.renderCommandsForKeys(snapshot, "pods")
	runner.Console.PodTable([]string{"NAMESPACE", "NAME", "READY", "STATUS", "RESTARTS", "AGE", "NODE"}, podRows(snapshot.Pods))
	counts := podPhaseCounts(snapshot.Pods)
	runner.Console.Write(fmt.Sprintf("\nPod: 合計 %d / Running %d / Pending %d / Succeeded %d / Failed %d / Unknown %d",
		len(snapshot.Pods), counts["Running"], counts["Pending"], counts["Succeeded"], counts["Failed"], counts["Unknown"]))
	runner.renderTrace()
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
	snapshot, err := runner.snapshotForKeys(ctx, map[string]bool{"pods": true})
	if err != nil {
		printError(runner.Streams.Err, err)
		return 1
	}
	status := snapshot.Status("pods")
	if !status.Available {
		printErrorMessage(runner.Streams.Err, fmt.Sprintf("Pod一覧を取得できませんでした。原因: %s", status.Reason))
		return 1
	}
	selected, quit, err := runner.promptPod(snapshot.Pods)
	if err != nil {
		if errors.Is(err, errPodSelectionInterrupted) {
			return 130
		}
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
		runner.Console.Chapter("Pod個別診断: " + selected.Namespace + "/" + selected.Name)
		runner.renderCommandGroup(runner.commandsForResource("Pod/" + selected.Namespace + "/" + selected.Name))
		runner.Console.PodTable([]string{"NAMESPACE", "NAME", "READY", "STATUS", "RESTARTS", "AGE", "NODE"}, podRows([]corev1.Pod{*selected}))
		runner.Console.DiagnosticContents(runner.diagnosticItems(selectedSnapshot, state))
		runner.renderEvents(selectedSnapshot, selectedSnapshot.Events, selected.Name)
		runner.renderLogs()
		if runner.Config.Connect {
			results, ran, err := runner.runConnect(ctx, selected, selectedSnapshot.Services, state)
			if err != nil {
				printError(runner.Streams.Err, err)
				return 1
			}
			if ran {
				runner.correlateAndApplyBaseline(selectedSnapshot, state)
				state.SetScopedScore(calculatePodScore(selected, state, selectedSnapshot))
				runner.renderConnectResults(results)
				runner.probeManually(ctx, selected, results)
			}
		}
		runner.Console.RootCauseReport(state.RootCauses)
		runner.Console.Summary(state, func(finding model.Finding) {
			runner.renderCommandsForFinding(selectedSnapshot, finding)
		})
		runner.renderTrace()
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
