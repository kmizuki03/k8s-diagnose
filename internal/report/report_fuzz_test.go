package report

import (
	"bytes"
	"testing"
)

func FuzzDecodeDocument(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{"schema":"k8s-diagnose/report/v1","findings":[],"root_causes":[]}`),
		[]byte(`{"schema":"old"}`),
		[]byte(`{"schema":"k8s-diagnose/report/v1"} trailing`),
		[]byte(`null`),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4*1024*1024 {
			t.Skip()
		}
		document, err := decodeDocument(bytes.NewReader(data))
		if err == nil && document["schema"] != Schema {
			t.Fatalf("対応外schemaを受理した: %#v", document["schema"])
		}
	})
}
