package notify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kmizuki03/k8s-diagnose/internal/report"
)

func TestResolveURLFailsClosed(t *testing.T) {
	const name = "K8S_DIAGNOSE_TEST_WEBHOOK"
	t.Cleanup(func() { os.Unsetenv(name) })
	for _, value := range []string{"", "http://example.com/hook", "https://user:pass@example.com/hook", "https://example.com/hook#fragment", "https://example.com/a b", "https://example.com:0/hook", "https://example.com:65536/hook"} {
		if err := os.Setenv(name, value); err != nil {
			t.Fatal(err)
		}
		if _, err := ResolveURL(name); err == nil {
			t.Fatalf("不正URLを受理した: %q", value)
		}
	}
	os.Setenv(name, "https://example.com/hook")
	if got, err := ResolveURL(name); err != nil || got == "" {
		t.Fatalf("有効URLを拒否: %q %v", got, err)
	}
}

func TestBuildPayloadOnlyForNewOrWorsenedIssues(t *testing.T) {
	issue := map[string]any{"id": "id", "severity": "issue", "message": "broken", "acknowledged": false}
	diff := map[string]any{"new": []any{issue}, "worsened": []any{}, "counts": map[string]any{"new": 1}, "root_causes": map[string]any{"new": []any{}}}
	doc := report.Document{"generated_at": "now", "target": map[string]any{"context": "test", "scope": "ns"}, "summary": map[string]any{}}
	payload := BuildPayload(diff, doc)
	if payload == nil || !strings.Contains(payload["text"].(string), "broken") {
		t.Fatalf("通知payloadが不正: %#v", payload)
	}
	diff["new"] = []any{}
	if payload := BuildPayload(diff, doc); payload != nil {
		t.Fatalf("新規issueなしで通知した: %#v", payload)
	}
}

func TestSendDoesNotFollowRedirect(t *testing.T) {
	var destinationHits atomic.Int32
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		destinationHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer destination.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, destination.URL, http.StatusFound)
	}))
	defer source.Close()
	previousTransport := http.DefaultTransport
	http.DefaultTransport = source.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = previousTransport })
	err := Send(context.Background(), source.URL, map[string]any{"text": "test"}, time.Second, "generic")
	if err == nil || !strings.Contains(err.Error(), "HTTP 302") {
		t.Fatalf("redirectをエラーにしていない: %v", err)
	}
	if destinationHits.Load() != 0 {
		t.Fatal("Webhookのredirect先へpayloadを送信した")
	}
}
