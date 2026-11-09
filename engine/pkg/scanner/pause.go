package scanner

import (
	"errors"
	"fmt"
	"os"
)

// jobActive reports whether a phase still accepts control requests.
func jobActive(phase string) bool {
	return phase == JobQueued || phase == JobRunning || phase == JobPaused
}

// ErrPauseUnsupported is reported when the platform cannot stop a process.
var ErrPauseUnsupported = errors.New("pausing a scan is not supported on this platform")

// ErrNotPausable is reported when there is nothing running to pause.
var ErrNotPausable = errors.New("the scan is not running yet")

// ErrNotPaused is reported when a resume is requested for a running scan.
var ErrNotPaused = errors.New("the scan is not paused")

// PauseNucleiJob stops a running scan without losing its place. Nuclei has no
// pause flag, so the binary is stopped with a supervisor signal: it keeps every
// request, connection and counter it had, and continues from exactly that point
// when the job is resumed.
func PauseNucleiJob(id string) error {
	job, ok := nucleiJobs.get(id)
	if !ok {
		return fmt.Errorf("job %q is unknown or already collected", id)
	}
	job.mutex.Lock()
	defer job.mutex.Unlock()
	if job.paused {
		return nil
	}
	if job.progress.Phase != JobRunning {
		return ErrNotPausable
	}
	if job.process == nil {
		return ErrNotPausable
	}
	if err := stopProcess(job.process); err != nil {
		return err
	}
	job.paused = true
	job.progress.Phase = JobPaused
	return nil
}

// ResumeNucleiJob continues a paused scan.
func ResumeNucleiJob(id string) error {
	job, ok := nucleiJobs.get(id)
	if !ok {
		return fmt.Errorf("job %q is unknown or already collected", id)
	}
	job.mutex.Lock()
	defer job.mutex.Unlock()
	if !job.paused {
		return ErrNotPaused
	}
	if err := continueProcess(job.process); err != nil {
		return err
	}
	job.paused = false
	job.progress.Phase = JobRunning
	return nil
}

// resumeLocked continues a paused process. It is used when the run is being
// cancelled, because a stopped process would otherwise never see the
// cancellation. The caller must hold the job mutex.
func (j *NucleiJob) resumeLocked() {
	if !j.paused {
		return
	}
	if j.process != nil {
		// The run is over, so a failure here only means the process is already
		// gone, which is the outcome cancellation wanted anyway.
		_ = continueProcess(j.process)
	}
	j.paused = false
}

// watchProcess stores the running binary so it can be paused and resumed.
func (j *NucleiJob) watchProcess(process *os.Process) {
	j.mutex.Lock()
	// A run cancelled before the binary started has nothing left to control.
	if j.progress.Phase == JobQueued && j.process == nil {
		j.process = process
		j.progress.Phase = JobRunning
	} else if j.paused {
		// The job was paused in the instant between start and this call, so the
		// new process has to be stopped immediately.
		_ = stopProcess(process)
	}
	j.mutex.Unlock()
}
