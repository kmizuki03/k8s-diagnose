package rules

import (
	"bytes"
	"testing"
)

func FuzzLoadLogAnalyzer(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(""),
		[]byte("[settings]\ndisabled = permission_denied\n"),
		[]byte("[signature.database]\npattern = connection refused\ntitle = DB connection\nseverity = candidate\nmin_count = 2\n"),
		[]byte("[signature.invalid]\npattern = (\ntitle = invalid\n"),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 2*1024*1024 {
			t.Skip()
		}
		analyzer, err := loadLogAnalyzer(bytes.NewReader(data), 200)
		if err == nil && analyzer == nil {
			t.Fatal("成功時にnil analyzerを返した")
		}
	})
}
