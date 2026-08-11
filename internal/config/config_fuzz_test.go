package config

import (
	"bytes"
	"testing"
)

func FuzzLoadINI(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(""),
		[]byte("[target]\nnamespace = production\n"),
		[]byte("[diagnosis]\nmode = triage\nworkers = 4\n"),
		[]byte("[unknown]\nvalue = secret\n"),
		[]byte("[target]\nnamespace = one\nnamespace = two\n"),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 2*1024*1024 {
			t.Skip()
		}
		cfg := Defaults()
		_ = loadINI(bytes.NewReader(data), &cfg)
	})
}
