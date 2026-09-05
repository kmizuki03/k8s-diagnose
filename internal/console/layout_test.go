package console

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
)

func TestHeaderKeepsLongAndMultilineValuesInsideFrame(t *testing.T) {
	for _, width := range []int{56, 68, 100} {
		var output bytes.Buffer
		cfg := config.Defaults()
		cfg.Namespace = strings.Repeat("namespace-", 10)
		c := New(cfg, &output, &output)
		c.width = width
		c.Header(strings.Repeat("本番-cluster-", 12) + "\n\tpassword=header-secret")
		lines := strings.Split(strings.TrimSpace(output.String()), "\n")
		if len(lines) != 7 {
			t.Fatalf("ヘッダーの高さが変わった: %q", output.String())
		}
		for _, line := range lines {
			if DisplayWidth(line) != DisplayWidth(lines[0]) || DisplayWidth(line) > width {
				t.Fatalf("枠が揃わない: width=%d line=%q", width, line)
			}
		}
		if strings.Contains(output.String(), "header-secret") {
			t.Fatal("ヘッダーから秘密が漏れた")
		}
	}
}

func TestTablesFitWidthAndPreserveLongValues(t *testing.T) {
	for _, podTable := range []bool{false, true} {
		for _, width := range []int{32, 56, 80, 120} {
			var output bytes.Buffer
			c := New(config.Defaults(), &output, &output)
			c.width = width
			headers := []string{"NAMESPACE", "NAME", "READY", "STATUS", "RESTARTS", "AGE", "NODE"}
			name := strings.Repeat("api-", 20) + "tail"
			cells := []string{"production", name, "0/1", "CrashLoopBackOff", "12", "3d", "worker-1"}
			original := append([]string{}, cells...)
			rows := []TableRow{{Cells: cells, Status: "CrashLoopBackOff"}}
			if podTable {
				c.PodTable(headers, rows)
			} else {
				c.Table(headers, rows, true)
			}
			for _, line := range strings.Split(output.String(), "\n") {
				if DisplayWidth(line) > width {
					t.Fatalf("表が端末幅を超えた: pod=%v width=%d line=%q", podTable, width, line)
				}
			}
			// Wrapped identifiers must retain every character in their original order.
			if !strings.Contains(strings.Join(strings.Fields(output.String()), ""), name) {
				t.Fatalf("長いPod名が欠落した: %q", output.String())
			}
			if !reflect.DeepEqual(cells, original) {
				t.Fatal("表示処理が入力を変更した")
			}
		}
	}
}

func TestTableUsesExplicitStatusForColor(t *testing.T) {
	var output bytes.Buffer
	c := New(config.Defaults(), &output, &output)
	c.C = Palette{Red: "RED", Yellow: "YELLOW", Green: "GREEN", Reset: "RESET"}
	c.Table([]string{"NAME"}, []TableRow{{Cells: []string{"error-collector"}, Status: "Running"}}, true)
	if !strings.Contains(output.String(), "GREENerror-collector") {
		t.Fatalf("正常行がリソース名で異常色になった: %q", output.String())
	}
	output.Reset()
	c.Table([]string{"MESSAGE"}, []TableRow{{Cells: []string{"BackOff"}, Status: "Warning"}}, true)
	if !strings.Contains(output.String(), "YELLOWBackOff") {
		t.Fatalf("Warning行が警告色にならない: %q", output.String())
	}
}

func TestTableNormalizesWhitespaceAfterMasking(t *testing.T) {
	var output bytes.Buffer
	c := New(config.Defaults(), &output, &output)
	c.Table([]string{"MESSAGE"}, []TableRow{{Cells: []string{"開始\t完了\npassword=table-secret"}}}, false)
	if got := output.String(); strings.Contains(got, "table-secret") || strings.Contains(got, "\t") ||
		!strings.Contains(got, "開始 完了 password=<masked>") {
		t.Fatalf("改行・タブ・秘密の処理が不正: %q", got)
	}
	output.Reset()
	c.Header("password=header-secret")
	if got := output.String(); strings.Contains(got, "header-secret") || !strings.Contains(got, "password=<masked>") {
		t.Fatalf("ヘッダーのマスクが不正: %q", got)
	}
}
