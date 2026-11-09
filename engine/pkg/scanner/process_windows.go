//go:build windows

package scanner

import "os/exec"

// applyProcessGroup is a no-op on Windows.
//
// Windows has no process groups in the POSIX sense; the equivalent is a Job
// Object, which needs `CreateJobObject`/`AssignProcessToJobObject` and its own
// permission handling. Guessing at that from a Unix implementation would be a
// claim without a measurement, and the leak this guards against is measured on
// the platform this project runs on: 17 orphaned `python3` processes, the
// oldest twelve hours old, after `code` templates were killed on their batch
// deadline.
//
// So the cancellation stays `Process.Kill()` here — the direct child only, which
// is what `exec.CommandContext` does by default and what this file does not make
// worse — and the limitation is stated rather than papered over.
func applyProcessGroup(command *exec.Cmd) {
	_ = command
}
