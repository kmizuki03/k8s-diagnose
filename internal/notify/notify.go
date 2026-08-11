// Package notify sends state-change notifications. Webhook delivery is kept
// separate from report/history persistence so an external outage never erases
// diagnosis evidence.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kmizuki03/k8s-diagnose/internal/jsonutil"
	"github.com/kmizuki03/k8s-diagnose/internal/report"
)

const Schema = "k8s-diagnose/webhook/v1"

func ResolveURL(environmentName string) (string, error) {
	value := strings.TrimSpace(os.Getenv(environmentName))
	if value == "" {
		return "", fmt.Errorf("Webhook URLを保持する環境変数 %s が未設定または空です", environmentName)
	}
	for _, character := range value {
		if character <= 0x20 || character == 0x7f {
			return "", errors.New("Webhook URLに空白または制御文字は指定できません")
		}
	}
	if strings.Contains(value, "#") {
		return "", errors.New("Webhook URLにはフラグメント（#以降）を指定できません")
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Hostname() == "" {
		return "", errors.New("Webhook URLは、ホスト名を含む https:// URLで指定してください")
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return "", errors.New("Webhook URLにはユーザー情報（例: user:password@host）を指定できません")
	}
	// URL.Port validates bracket/port syntax while still allowing an omitted port.
	if port := parsed.Port(); port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return "", errors.New("Webhook URLのポート番号は1以上65535以下で指定してください")
		}
	}
	return value, nil
}

func BuildPayload(difference map[string]any, current report.Document) map[string]any {
	newIssues := []any{}
	for _, finding := range jsonutil.Objects(difference["new"]) {
		if jsonutil.String(finding["severity"]) == "issue" && !jsonutil.Bool(finding["acknowledged"]) {
			newIssues = append(newIssues, finding)
		}
	}
	worsened := []any{}
	for _, pair := range jsonutil.Objects(difference["worsened"]) {
		after, _ := pair["after"].(map[string]any)
		if jsonutil.String(after["severity"]) == "issue" && !jsonutil.Bool(after["acknowledged"]) {
			worsened = append(worsened, pair)
		}
	}
	if len(newIssues) == 0 && len(worsened) == 0 {
		return nil
	}
	newRoots := []any{}
	rootDifference, _ := difference["root_causes"].(map[string]any)
	for _, root := range jsonutil.Objects(rootDifference["new"]) {
		cause, _ := root["cause"].(map[string]any)
		if jsonutil.String(root["classification"]) == "root_cause" && !jsonutil.Bool(cause["acknowledged"]) {
			newRoots = append(newRoots, root)
		}
	}
	target, _ := current["target"].(map[string]any)
	lines := []string{
		"[k8s-diagnose] 新規または悪化した確定異常を検出",
		fmt.Sprintf("context=%s namespace=%s", fallback(jsonutil.String(target["context"]), "-"), fallback(jsonutil.String(target["scope"]), "-")),
		fmt.Sprintf("新規異常=%d 悪化=%d 新規根本原因=%d", len(newIssues), len(worsened), len(newRoots)),
	}
	messages := []string{}
	for _, item := range newIssues {
		finding, _ := item.(map[string]any)
		messages = append(messages, jsonutil.String(finding["message"]))
	}
	for _, item := range worsened {
		pair, _ := item.(map[string]any)
		after, _ := pair["after"].(map[string]any)
		messages = append(messages, jsonutil.String(after["message"]))
	}
	for index, message := range messages {
		if index >= 8 {
			break
		}
		if len([]rune(message)) > 300 {
			message = string([]rune(message)[:300])
		}
		if message != "" {
			lines = append(lines, "• "+message)
		}
	}
	if len(messages) > 8 {
		lines = append(lines, fmt.Sprintf("• ほか %d件", len(messages)-8))
	}
	text := strings.Join(lines, "\n")
	if len([]rune(text)) > 3500 {
		text = string([]rune(text)[:3500])
	}
	return map[string]any{
		"schema": Schema, "event_id": current["generated_at"], "text": text,
		"target": target, "summary": current["summary"],
		"difference_counts": difference["counts"], "new_issues": newIssues,
		"worsened_to_issue": worsened, "new_root_causes": newRoots,
	}
}

func Send(ctx context.Context, webhookURL string, payload map[string]any, timeout time.Duration, format string) error {
	var outgoing any = payload
	switch format {
	case "slack":
		outgoing = map[string]any{"text": jsonutil.String(payload["text"])}
	case "generic":
	default:
		return fmt.Errorf("未対応のWebhook形式です: %s", format)
	}
	body, err := json.Marshal(report.Sanitize(outgoing))
	if err != nil {
		return fmt.Errorf("Webhookの送信データを生成できません: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return errors.New("Webhookへの送信要求を作成できません")
	}
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	request.Header.Set("User-Agent", "k8s-diagnose")
	client := &http.Client{
		Timeout: timeout,
		// A webhook URL is a single configured trust boundary. Never allow a 3xx
		// response to silently move credentials/payload to a second endpoint.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	// ResolveURL accepts only an operator-configured HTTPS URL, forbids
	// userinfo/control characters and redirects, while intentionally allowing
	// private corporate webhook endpoints.
	response, err := client.Do(request) // #nosec G704 -- validated operator trust boundary; private endpoints are supported by design.
	if err != nil {
		return errors.New("Webhookへ接続できません")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("Webhookの送信先がHTTP %dを返しました", response.StatusCode)
	}
	return nil
}

func fallback(value, defaultValue string) string {
	if value == "" || value == "<nil>" {
		return defaultValue
	}
	return value
}
