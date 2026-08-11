package kube

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubefake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (function roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestClassifyStructuredAPIErrors(t *testing.T) {
	resource := schema.GroupResource{Group: "", Resource: "pods"}
	tests := []struct {
		err  error
		want ErrorStatus
	}{
		{apierrors.NewNotFound(resource, "x"), StatusNotFound},
		{apierrors.NewForbidden(resource, "x", errors.New("denied")), StatusForbidden},
		{apierrors.NewUnauthorized("denied"), StatusUnauthorized},
		{apierrors.NewServiceUnavailable("down"), StatusUnavailable},
		{apierrors.NewTimeoutError("slow", 1), StatusTimeout},
		{apierrors.NewInvalid(schema.GroupKind{Group: "apps", Kind: "Deployment"}, "x", nil), StatusInvalid},
		{context.DeadlineExceeded, StatusTimeout},
	}
	for _, test := range tests {
		if got := ClassifyError(test.err); got != test.want {
			t.Errorf("ClassifyError(%T)=%s, want %s", test.err, got, test.want)
		}
	}
	_ = metav1.NamespaceAll
}

func TestHTTPStatusCodeUsesStructuredAPIError(t *testing.T) {
	err := apierrors.NewInternalError(errors.New("health failed"))
	if code := HTTPStatusCode(err); code != 500 {
		t.Fatalf("HTTP status=%d, want 500", code)
	}
	if code := HTTPStatusCode(context.DeadlineExceeded); code != 0 {
		t.Fatalf("非HTTPエラーにstatus=%dを付与した", code)
	}
}

func TestErrorReasonMasksCredentials(t *testing.T) {
	reason := ErrorReason(errors.New(`admission denied: {"password":"hunter2"} DB_TOKEN=token-value`))
	if strings.Contains(reason, "hunter2") || strings.Contains(reason, "token-value") {
		t.Fatalf("APIエラーから秘密が漏れた: %s", reason)
	}
}

func TestErrorReasonUsesNaturalUserFacingLabels(t *testing.T) {
	resource := schema.GroupResource{Resource: "pods"}
	reason := ErrorReason(apierrors.NewForbidden(resource, "api", errors.New("denied")))
	if !strings.Contains(reason, "アクセス権限がありません") || strings.Contains(reason, "RBAC Forbidden") {
		t.Fatalf("権限エラーの案内が不自然: %q", reason)
	}
	reason = ErrorReason(context.DeadlineExceeded)
	if !strings.Contains(reason, "タイムアウトしました") {
		t.Fatalf("タイムアウトの案内が不自然: %q", reason)
	}
}

func TestErrorReasonTruncatesWithoutBreakingUTF8(t *testing.T) {
	reason := ErrorReason(errors.New(strings.Repeat("障", 400)))
	if !utf8.ValidString(reason) || !strings.HasSuffix(reason, "…") {
		t.Fatalf("APIエラーの切り詰めでUTF-8が壊れた: %q", reason)
	}
}

func TestWarningRecorderDrainsPerSnapshot(t *testing.T) {
	recorder := &warningRecorder{}
	recorder.HandleWarningHeader(299, "agent", "deprecated API")
	recorder.HandleWarningHeader(299, "agent", "deprecated API")
	if values := recorder.Drain(); len(values) != 1 || values[0] != "deprecated API" {
		t.Fatalf("Warningの重複排除またはDrainが不正: %#v", values)
	}
	if values := recorder.Drain(); len(values) != 0 {
		t.Fatalf("過去のWarningが次回snapshotへ残った: %#v", values)
	}
}

func TestBeginCollectionResetsServerTime(t *testing.T) {
	tracer := &requestTracer{}
	tracer.recordServerTime(time.Now().UTC().Format(http.TimeFormat))
	clients := &Clients{trace: tracer}
	if clients.ServerTime().IsZero() {
		t.Fatal("テスト前提のServerTimeを記録できない")
	}
	clients.BeginCollection()
	if !clients.ServerTime().IsZero() {
		t.Fatalf("前回snapshotのServerTimeが残った: %s", clients.ServerTime())
	}
}

func TestRequestTracerPreservesExistingTransportWrapper(t *testing.T) {
	config := &rest.Config{}
	existingCalled := false
	config.Wrap(func(next http.RoundTripper) http.RoundTripper {
		return roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			existingCalled = true
			return next.RoundTrip(request)
		})
	})
	var trace bytes.Buffer
	tracer := &requestTracer{writer: &trace}
	addRequestTracer(config, tracer)

	base := roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody, Request: request}, nil
	})
	request := httptest.NewRequest(http.MethodGet, "https://cluster.example/api/v1/pods", nil)
	if _, err := config.WrapTransport(base).RoundTrip(request); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if !existingCalled {
		t.Fatal("既存のWrapTransportが失われた")
	}
	if !strings.Contains(trace.String(), "GET /api/v1/pods") {
		t.Fatalf("API traceが記録されない: %q", trace.String())
	}
}

func TestListSecretsProjectsTLSKeyPairErrorWithoutRetainingPrivateKey(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "tls", Namespace: "ns"}, Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{corev1.TLSCertKey: []byte("invalid certificate"), corev1.TLSPrivateKeyKey: []byte("private-key-material")},
	}
	collector := &Collector{Clients: &Clients{Kube: kubefake.NewSimpleClientset(secret)}, Config: config.Defaults()}
	values, err := collector.listSecrets(context.Background(), "ns")
	if err != nil || len(values) != 1 {
		t.Fatalf("Secret projection: len=%d err=%v", len(values), err)
	}
	projection := values[0]
	if projection.TLSKeyPairError == "" || !strings.Contains(string(projection.TLSCert), "invalid certificate") {
		t.Fatalf("TLS key pair検証結果が保持されない: %#v", projection)
	}
	if _, exists := projection.Keys[corev1.TLSPrivateKeyKey]; !exists {
		t.Fatal("tls.keyのキー名まで失われた")
	}
}
