//go:build !windows

package scanner

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Зупинений скан має бути зупинений.
//
// `code`-шаблон — це не код у процесі nuclei: nuclei пише скрипт у temp-файл і
// запускає його через `sh`/`python3`/`powershell`, тобто це **онук** процесу,
// який ми стартували. `exec.CommandContext` за замовчуванням вбиває лише пряму
// дитину, тому зупинений скан лишається виконуватись.
//
// Виміряно на цій машині: 17 `python3` без батька (`ppid=1`), найстаріший
// жив 12 годин, після батчів, вбитих на власному дедлайні.

func alive(pid int) bool {
	if err := syscall.Kill(pid, 0); err != nil {
		return false
	}
	// A killed child that has not been reaped yet is still a zombie, and a
	// zombie is not what this test is about. Read the state to tell them apart.
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	fields := strings.Fields(string(raw))
	if len(fields) > 2 && fields[2] == "Z" {
		return false
	}
	return true
}

// The assertion is about the grandchild, because that is what leaked.
func TestCancellingABatchKillsTheTemplatesItStarted(t *testing.T) {
	dir := t.TempDir()
	// Rebuild inside a known directory so the pid file path is predictable.
	pidFile := dir + "/grandchild.pid"
	script := dir + "/child.sh"
	if err := os.WriteFile(script, []byte("#!/bin/sh\nsleep 300 &\necho $! > "+pidFile+"\nwait\n"), 0o700); err != nil {
		t.Fatalf("write script: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	command := exec.CommandContext(ctx, "/bin/sh", script)
	applyProcessGroup(command)
	command.WaitDelay = 2 * time.Second
	if err := command.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	waitDone := make(chan struct{})
	go func() { _ = command.Wait(); close(waitDone) }()

	pid := 0
	for range 40 {
		raw, err := os.ReadFile(pidFile)
		if err == nil {
			if parsed, convErr := strconv.Atoi(strings.TrimSpace(string(raw))); convErr == nil {
				pid = parsed
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if pid == 0 {
		cancel()
		t.Fatal("the grandchild never recorded its pid")
	}
	if !alive(pid) {
		cancel()
		t.Fatalf("the grandchild was never running, so nothing was proven")
	}

	cancel()
	select {
	case <-waitDone:
	case <-time.After(10 * time.Second):
		t.Fatal("Wait did not return after cancellation")
	}

	deadline := time.Now().Add(5 * time.Second)
	for alive(pid) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if alive(pid) {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		t.Fatalf("pid %d outlived the cancellation: a template's work survived the scan", pid)
	}
}

// `sleep 300` is what a code template that waits does; without the group it is
// still running when the batch is declared finished. The plain path is measured
// in the same test so the two are comparable rather than asserted in prose.
func TestWithoutTheGroupTheGrandchildOutlivesCancellation(t *testing.T) {
	if testing.Short() {
		t.Skip("the demonstration waits on a real process")
	}
	dir := t.TempDir()
	pidFile := dir + "/grandchild.pid"
	script := dir + "/child.sh"
	if err := os.WriteFile(script, []byte("#!/bin/sh\nsleep 300 &\necho $! > "+pidFile+"\nwait\n"), 0o700); err != nil {
		t.Fatalf("write script: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	// No applyProcessGroup: this is `exec.CommandContext` on its own, which is
	// what the code looked like before the fix.
	command := exec.CommandContext(ctx, "/bin/sh", script)
	command.WaitDelay = 2 * time.Second
	if err := command.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	waitDone := make(chan struct{})
	go func() { _ = command.Wait(); close(waitDone) }()

	pid := 0
	for range 40 {
		raw, err := os.ReadFile(pidFile)
		if err == nil {
			if parsed, convErr := strconv.Atoi(strings.TrimSpace(string(raw))); convErr == nil {
				pid = parsed
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if pid == 0 {
		cancel()
		t.Fatal("the grandchild never recorded its pid")
	}

	cancel()
	<-waitDone
	// One second is far longer than a SIGKILL needs. If the grandchild is still
	// here, it is because nothing signalled it — which is the defect.
	time.Sleep(time.Second)
	if !alive(pid) {
		t.Skip("the grandchild died on its own on this kernel; the mechanism differs")
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
	t.Logf("pid %d survived the direct child's cancellation — this is the leak", pid)
}
