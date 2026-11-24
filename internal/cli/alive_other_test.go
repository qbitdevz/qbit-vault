//go:build !windows

package cli

import "syscall"

// processAlive reports whether the process with this pid is still running.
func processAlive(pid int) bool { return syscall.Kill(pid, 0) == nil }
