package main

import (
	"context"
	"testing"
	"time"
)

func TestOSINTTimeoutHelperAppliesDeadlineAndRespectsCancellation(t *testing.T) {
	ctx, cancel := osintWithRequestTimeout(context.Background())
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatalf("expected osintWithRequestTimeout to attach a deadline")
	}
	remaining := time.Until(deadline)
	if remaining <= 0 || remaining > defaultOSINTRequestTimeout+time.Second {
		t.Fatalf("unexpected remaining timeout: %v", remaining)
	}

	parentCtx, parentCancel := context.WithCancel(context.Background())
	parentCancel()
	childCtx, childCancel := osintWithRequestTimeout(parentCtx)
	defer childCancel()
	if childCtx.Err() == nil {
		t.Fatalf("expected cancelled parent context to propagate immediately")
	}
}
