//go:build unix

package scanner

import (
	"fmt"
	"os"
	"syscall"
)

// pauseSupported reports that a running binary can be frozen on this platform.
func pauseSupported() bool { return true }

// stopProcess freezes the binary. Every thread is suspended, so the scan keeps
// its place exactly: open connections, pending requests and the reported
// counters are all still there when it is continued.
func stopProcess(process *os.Process) error {
	if process == nil {
		return ErrNotPausable
	}
	if err := process.Signal(syscall.SIGSTOP); err != nil {
		return fmt.Errorf("could not pause the scan: %w", err)
	}
	return nil
}

// continueProcess returns a frozen binary to the state it was paused in.
func continueProcess(process *os.Process) error {
	if process == nil {
		return ErrNotPausable
	}
	if err := process.Signal(syscall.SIGCONT); err != nil {
		return fmt.Errorf("could not resume the scan: %w", err)
	}
	return nil
}
