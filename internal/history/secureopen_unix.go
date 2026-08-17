//go:build !windows

package history

import (
	"os"
	"syscall"
)

// openExistingNoFollow opens an already-existing history database without
// following a final-component symlink. On a shared host (a bastion where the
// database path lives under a world-writable directory) an attacker could plant
// a symlink at the expected path; O_NOFOLLOW makes the open fail with ELOOP
// instead, so we never chmod or write through someone else's file. All
// subsequent permission and type checks run against this file descriptor
// (fstat/fchmod), closing the time-of-check/time-of-use window a path-based
// os.Stat + os.Chmod would leave open.
func openExistingNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW, 0) // #nosec G304 -- --history-db explicitly selects this path; O_NOFOLLOW rejects a planted final-component symlink.
}
