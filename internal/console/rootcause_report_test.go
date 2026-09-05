package console

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
)

func TestRootCauseReportExplainsUncertaintyAndNextChecks(t *testing.T) {
	var output bytes.Buffer
	c := New(config.Defaults(), &output, &output)
	finding := model.NewFinding(model.Warning, "K8S.LOG.NAME_RESOLUTION", "ログ", "Pod/ns/api", "DNS", "dns", "名前解決失敗の記録", 65)
	root := model.NewRootCause(finding, 65, []model.Evidence{
		{Kind: "assessment", Key: "classification", Value: "現在の状態との照合が必要です"},
	}, []model.Impact{{Kind: "Service", Resource: "Service/ns/api", Path: []string{"Pod/ns/api", "Service/ns/api"}}}, nil, []string{"Eventとログを照合する"}, nil, nil)
	c.RootCauseReport([]model.RootCause{root})
	for _, want := range []string{"確定原因は見つかっていません", "原因候補", "分類理由: 現在の状態との照合が必要です", "次に確認すること", "関連する異常と依存経路"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("説明 %q がない: %q", want, output.String())
		}
	}
	if strings.Contains(output.String(), "◆ 修正候補") {
		t.Fatal("候補を確定済みの修正として表示した")
	}
}

func TestRootCauseReportWrapsLongEvidenceWithoutLeakingSecrets(t *testing.T) {
	var output bytes.Buffer
	c := New(config.Defaults(), &output, &output)
	c.width = 56
	finding := model.NewFinding(model.Issue, "K8S.TEST", "test", "Pod/ns/api", "failure", "failure", "異常", 100)
	root := model.NewRootCause(finding, 85, []model.Evidence{{Kind: "assessment", Key: "classification", Value: strings.Repeat("確認が必要です。", 12) + " password=evidence-secret"}}, nil, nil, nil, nil, nil)
	c.RootCauseReport([]model.RootCause{root})
	_, detail, ok := strings.Cut(output.String(), "検出理由・根拠\n")
	if !ok {
		t.Fatal("根拠が表示されていない")
	}
	for _, line := range strings.Split(detail, "\n") {
		if DisplayWidth(line) > 56 {
			t.Fatalf("根拠が端末幅を超えた: %q", line)
		}
	}
	if strings.Contains(output.String(), "evidence-secret") {
		t.Fatal("根拠から秘密が漏れた")
	}
}
