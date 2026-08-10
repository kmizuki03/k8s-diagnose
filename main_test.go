package main

import "testing"

func TestInterruptedExitCodeMatchesDocumentedContract(t *testing.T) {
	tests := []struct {
		name                  string
		code                  int
		interrupted           bool
		watch, expectedResult int
	}{
		{"normal success", 0, false, 0, 0},
		{"normal failure", 1, false, 0, 1},
		{"interrupt replaces success", 0, true, 0, 130},
		{"interrupt replaces request failure", 1, true, 0, 130},
		{"watch interrupt is clean", 1, true, 10, 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := interruptedExitCode(test.code, test.interrupted, test.watch); got != test.expectedResult {
				t.Fatalf("exit code=%d, want %d", got, test.expectedResult)
			}
		})
	}
}
