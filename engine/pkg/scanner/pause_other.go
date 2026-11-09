//go:build !unix

package scanner

import "os"

// pauseSupported reports that a running binary cannot be frozen here, so a run
// that is pausable has to be given a request timeout a pause cannot exhaust.
func pauseSupported() bool { return false }

// stopProcess reports that this platform cannot suspend a running binary.
// The job is left running rather than being reported as paused.
func stopProcess(*os.Process) error {
	return ErrPauseUnsupported
}

// continueProcess is a no-op: without a pause there is nothing to continue.
func continueProcess(*os.Process) error {
	return nil
}
