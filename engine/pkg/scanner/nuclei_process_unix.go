//go:build !windows

package scanner

import (
	"os/exec"
	"syscall"
)

// applyProcessGroup puts the binary in its own process group and makes
// cancellation kill that whole group instead of the binary alone.
//
// Why the group, measured rather than assumed. nuclei does not run a `code`
// template inside itself: it writes the document's script to a temp file and
// executes it with `sh`, `python3`, `powershell` or whatever the template asks
// for, so every such template is a *grandchild* of the process we start.
// `exec.CommandContext`'s own cancellation is `Process.Kill()`, which reaches
// the direct child only.
//
// The consequence is visible without instrumentation. After a batch of `code`
// templates was killed on its deadline, this machine carried 17 `python3`
// processes with no parent — `ppid=1` — the oldest alive for twelve hours,
// each one blocked in a `recv()` that would never return, and each one holding
// the memory it had already taken:
//
//	PID      ELAPSED   COMMAND
//	828865   12:07:17   /usr/bin/python3 /tmp/nuclei-tmp-.../949657734
//	1391297   7:18:38   /usr/bin/python3 /tmp/nuclei-tmp-.../3846069837
//	(17 in total, none of them children of any running nuclei)
//
// A scan that is stopped is therefore not stopped: its work keeps running,
// invisible, and a long session accumulates one orphan per timed-out template.
// The group is the mechanism the operating system already offers for exactly
// this, and it costs one `setpgid`.
//
// The group is only killed on the cancellation path. A batch that finishes on
// its own is never signalled, so a template that is legitimately still writing
// when the deadline expires — the case this exists for — loses nothing that was
// already reported.
func applyProcessGroup(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		if command.Process == nil {
			return nil
		}
		// The negated pid addresses the group, which the child leads. ESRCH
		// means the group is already gone, which is the outcome we wanted and
		// not a failure of the cancellation.
		if err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL); err != nil &&
			err != syscall.ESRCH {
			return err
		}
		return nil
	}
}
