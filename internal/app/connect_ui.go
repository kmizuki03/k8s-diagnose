package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

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
		// Reproduction commands exist to hand an investigation back to the
		// operator, so they are printed for the checks that give them something
		// to investigate. Emitting three lines for every target buries the two
		// that matter: on a Pod with several ports the block grew longer than
		// the results it was supposed to support.
		if !needsReproduction(result) {
			continue
		}
		// kubectl also accepts service/NAME, and unlike the Pod-pinned form it
		// makes kubectl resolve the selector, the endpoints and the service
		// port → targetPort mapping before forwarding. That is the part this
		// check cannot cover on its own, so the command is offered even for a
		// shared result: it is an alternative to run, not a duplicate line.
		if name := result.Target.ServiceName; name != "" && result.Target.ServicePort > 0 {
			runner.kubectlCmds = append(runner.kubectlCmds, kube.KubectlCommand(
				runner.Config, "port-forward", "service/"+name,
				fmt.Sprintf("%d:%d", result.LocalPort, result.Target.ServicePort), "-n", pod.Namespace,
			))
		}
		// A shared result reused an earlier target's tunnel, so printing its
		// Pod-pinned command again would list the same port-forward twice with
		// no way to tell the two lines apart.
		if result.Shared {
			continue
		}
		runner.kubectlCmds = append(runner.kubectlCmds, kube.KubectlCommand(
			runner.Config, "port-forward", "pod/"+pod.Name,
			fmt.Sprintf("%d:%d", result.LocalPort, result.Target.RemotePort), "-n", pod.Namespace,
		))
		// The port-forward alone only opens the tunnel. Pairing it with the
		// request the checker actually sent is what makes the pair runnable:
		// otherwise the scheme, path and probe headers have to be reassembled
		// from the manifest by hand.
		if command, ok := connect.CurlCommand(result); ok {
			runner.kubectlCmds = append(runner.kubectlCmds, command)
		}
	}
	for _, finding := range findings {
		state.Add(finding)
	}
	return results, true, nil
}

// probeManually lets the operator aim the same check at a port and path of
// their choosing.
//
// The automatic targets only cover what the manifest declares, and an
// investigation rarely ends there: the port worth poking at is often an admin
// or metrics endpoint nothing references, and the path is whatever the
// application actually serves. Printing a curl to run afterwards leaves the
// operator to set up their own tunnel; doing it here reuses the one this tool
// already knows how to open.
func (runner *Runner) probeManually(ctx context.Context, pod *corev1.Pod, results []connect.Result) {
	if !runner.Config.Connect || runner.Config.Output != "text" || !InteractiveTerminal(runner.Streams) {
		return
	}
	checker := &connect.Checker{Clients: runner.Clients, Config: runner.Config}
	local := connect.NextLocalPort(results)
	runner.Console.Section("ポートとパスを指定して確認")
	runner.Console.Write("  例: 9000（TCP接続のみ） / 8080/healthz / http://localhost:8080/secure / https://8443/metrics")
	runner.Console.Write("  空欄のままEnterで終了します。")
	for {
		if ctx.Err() != nil {
			return
		}
		fmt.Fprint(runner.Streams.Out, "  確認先: ")
		line, err := runner.reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			printErrorMessage(runner.Streams.Err, "確認先を読み取れませんでした: "+err.Error())
			return
		}
		input := strings.TrimSpace(line)
		if input == "" {
			return
		}
		target, parseErr := connect.ManualTarget(input)
		if parseErr != nil {
			printErrorMessage(runner.Streams.Err, parseErr.Error())
			if errors.Is(err, io.EOF) {
				return
			}
			continue
		}
		result, checkErr := checker.CheckTarget(ctx, pod, target, local)
		local++
		if checkErr != nil {
			printErrorMessage(runner.Streams.Err, "確認を実施できませんでした: "+checkErr.Error())
		} else {
			runner.renderManualResult(result)
		}
		if errors.Is(err, io.EOF) {
			return
		}
	}
}

func (runner *Runner) renderManualResult(result connect.Result) {
	mark, color := "▲", runner.Console.C.Yellow
	if result.Successful {
		mark, color = "✔", runner.Console.C.Green
	}
	detail := console.Snip(console.MaskSecrets(result.Detail, runner.Config.Mask), 300)
	runner.Console.Write(fmt.Sprintf("    %s%s %s -> %s%s", color, mark,
		console.MaskSecrets(result.Target.Label, runner.Config.Mask), detail, runner.Console.C.Reset))
	// Whoever typed a URL here was reaching for curl -i, so the response line and
	// headers are shown rather than a summary of them: which handler answered,
	// where a redirect points, what the cache and auth headers say are exactly
	// what an operator is looking at when they poke an endpoint by hand.
	if result.Proto != "" {
		runner.Console.Write(fmt.Sprintf("      %s %d %s", result.Proto, result.StatusCode, http.StatusText(result.StatusCode)))
	}
	for _, name := range sortedHeaderNames(result.Header) {
		for _, value := range result.Header.Values(name) {
			line := console.Snip(console.MaskSecrets(name+": "+value, runner.Config.Mask), 200)
			runner.Console.Write("      " + line)
		}
	}
	// A manual check is an explicit request to look at an endpoint, so the
	// answer is shown whether or not the status code was a success. "200 with
	// an error page" and "200 with the expected payload" are the same line
	// without it.
	runner.renderResponseBody(result, manualBodyRunes, manualBodyLines)
}

const (
	manualBodyRunes = 2000
	manualBodyLines = 30
	// A failing automatic check gets the same room as a manual one, because the
	// body is usually where the reason is. A passing one gets a single line: it
	// only has to show that something real answered.
	autoBodyRunes   = 1200
	autoBodyLines   = 20
	previewBodyRune = 120
)

// renderResponseBody prints what the application itself answered, preserving
// the line structure. console.Snip collapses whitespace, which is right for a
// one-line summary and wrong for a payload someone is trying to read.
func (runner *Runner) renderResponseBody(result connect.Result, runeLimit, lineLimit int) {
	if result.Body == "" {
		if result.BodyBytes > 0 {
			runner.Console.Write(fmt.Sprintf("      （本文 %dバイト）", result.BodyBytes))
		}
		return
	}
	if !printableResponseBody(result) {
		runner.Console.Write(fmt.Sprintf("      （本文 %dバイト・%s のため表示しません）", result.BodyBytes, responseMediaType(result)))
		return
	}
	body, clipped := clipResponseBody(console.MaskSecrets(result.Body, runner.Config.Mask), runeLimit, lineLimit)
	if strings.TrimSpace(body) == "" {
		runner.Console.Write(fmt.Sprintf("      （本文 %dバイト）", result.BodyBytes))
		return
	}
	runner.Console.Write(fmt.Sprintf("      ── 応答本文（%dバイト） ──", result.BodyBytes))
	for _, line := range strings.Split(body, "\n") {
		runner.Console.Write("      " + line)
	}
	if clipped {
		runner.Console.Write("      …（以降は省略）")
	}
}

// printableResponseBody keeps a binary payload out of the terminal. The reader
// wants to know an image came back, not to have its bytes typed at them.
func printableResponseBody(result connect.Result) bool {
	if !utf8.ValidString(result.Body) || strings.ContainsRune(result.Body, 0) {
		return false
	}
	media := responseMediaType(result)
	for _, prefix := range []string{"image/", "audio/", "video/", "font/"} {
		if strings.HasPrefix(media, prefix) {
			return false
		}
	}
	switch media {
	case "application/octet-stream", "application/zip", "application/gzip", "application/pdf", "application/x-protobuf":
		return false
	}
	return true
}

func responseMediaType(result connect.Result) string {
	media, _, _ := strings.Cut(result.ContentType, ";")
	media = strings.ToLower(strings.TrimSpace(media))
	if media == "" {
		return "内容種別不明"
	}
	return media
}

func clipResponseBody(body string, runeLimit, lineLimit int) (string, bool) {
	clipped := false
	if utf8.RuneCountInString(body) > runeLimit {
		body, clipped = string([]rune(body)[:runeLimit]), true
	}
	lines := strings.Split(strings.TrimRight(body, "\n"), "\n")
	if len(lines) > lineLimit {
		lines, clipped = lines[:lineLimit], true
	}
	return strings.Join(lines, "\n"), clipped
}

// sortedHeaderNames keeps the header block stable across runs; Go's header map
// is unordered and the wire order is not preserved anyway.
func sortedHeaderNames(header http.Header) []string {
	names := make([]string, 0, len(header))
	for name := range header {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// needsReproduction reports whether a result leaves the operator with something
// to look into. A check that plainly succeeded does not.
func needsReproduction(result connect.Result) bool {
	if !result.Target.Active {
		return false
	}
	return !result.Tested || !result.Successful || result.Warned
}

func (runner *Runner) renderConnectResults(results []connect.Result) {
	runner.Console.Section("Probe/接続確認結果")
	runner.renderPendingKubectlCommands()
	type totals struct{ tested, succeeded, failed, unavailable, warned int }
	groups := map[string]*totals{"pod": {}, "service": {}}
	for _, group := range []string{"pod", "service"} {
		runner.Console.Write("\n  ■ " + connect.GroupLabel(group))
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
			switch {
			case result.Body == "":
			case result.Warned || !result.Successful:
				// The body is usually where the reason is, so a check that did
				// not plainly pass gets it in full.
				runner.renderResponseBody(result, autoBodyRunes, autoBodyLines)
			case printableResponseBody(result):
				// A passing check gets one line. "200 with the expected payload"
				// and "200 with an error page" are otherwise the same row, and a
				// full dump per target is what made this section unreadable.
				runner.Console.Write("      応答本文: " + console.Snip(console.MaskSecrets(result.Body, runner.Config.Mask), previewBodyRune))
			}
		}
		if !found {
			runner.Console.Write("    （対象なし・未実施）")
		}
	}
	pod, service := groups["pod"], groups["service"]
	runner.Console.Write()
	podLabel, serviceLabel := connect.GroupLabel("pod"), connect.GroupLabel("service")
	switch {
	case pod.failed == 0 && pod.unavailable == 0 && pod.succeeded > 0 && service.failed == 0 && service.unavailable == 0 && service.succeeded > 0:
		if pod.warned+service.warned > 0 {
			runner.Console.Write(fmt.Sprintf("  ▲ %s・%sの両方でPodに接続できましたが、HTTP応答または再現条件に注意が必要です", podLabel, serviceLabel))
		} else {
			runner.Console.Write(fmt.Sprintf("  → %s・%sの両方で、Podへの単発接続に成功しました", podLabel, serviceLabel))
		}
	case pod.failed == 0 && pod.succeeded > 0 && service.tested == 0 && service.unavailable == 0:
		runner.Console.Write(fmt.Sprintf("  → %sの接続確認には成功しました。%sは対象がないため未実施です", podLabel, serviceLabel))
	case service.failed == 0 && service.succeeded > 0 && pod.tested == 0 && pod.unavailable == 0:
		runner.Console.Write(fmt.Sprintf("  → %sの接続確認には成功しました。%sはポートを推定できないため未実施です", serviceLabel, podLabel))
	case pod.failed > 0 || service.failed > 0:
		runner.Console.Write("  ▲ 失敗した接続確認があります。kubeletの連続判定と現在のPod状態も併せて確認してください")
	case pod.unavailable+service.unavailable > 0:
		runner.Console.Write("  ? 接続確認の一部を実施できませんでした")
	default:
		runner.Console.Write("  → 接続確認の対象がないため、テストは実施されませんでした")
	}
	// Without this the reader can take a row of green checks under the Service
	// heading as proof that the Service works. port-forward always tunnels
	// straight to the Pod, so nothing here exercises the ClusterIP, kube-proxy
	// or the EndpointSlice path; what is verified is only that a container
	// answers on the port the Service forwards to.
	if service.tested > 0 {
		runner.Console.Write("    ※ 接続確認はport-forwardでPodへ直接つなぐため、ClusterIP経由の経路（kube-proxy・Endpoint）は検証していません")
		runner.Console.Write(fmt.Sprintf("       %sで確認しているのは、Serviceが転送先に指定したポートでコンテナが応答するかどうかです", serviceLabel))
	}
	reproducible := 0
	for _, result := range results {
		if needsReproduction(result) {
			reproducible++
		}
	}
	if reproducible == 0 && pod.tested+service.tested > 0 && runner.Config.ShowCmd {
		runner.Console.Write("    ※ 再現用のport-forward / curlは、確認できなかった対象にのみ表示します")
	}
}
