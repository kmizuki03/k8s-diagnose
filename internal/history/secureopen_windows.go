//go:build windows

package history

import "os"

// openExistingNoFollow opens an already-existing history database. Windows lacks
// O_NOFOLLOW; creating symlinks there requires elevated privilege and the
// shared-bastion threat model that motivates the Unix guard does not apply, so
// a plain read/write open is used. Permission and type checks still run against
// the returned descriptor rather than the path.
func openExistingNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR, 0)
}
