package main

import (
	"sync/atomic"
	"testing"
	"time"
)

// The job ids used to be `time.Now().Unix() << 20`: predictable to the second,
// so any local process could enumerate the range and read or delete another run.
// The base is now drawn from the OS CSPRNG once per process.

func TestSequenceBasesAreUnpredictable(t *testing.T) {
	seen := map[uint64]bool{}
	for i := 0; i < 16; i++ {
		base := randomSequenceBase()
		if seen[base] {
			t.Fatalf("randomSequenceBase repeated a value within 16 draws: %d", base)
		}
		seen[base] = true
	}
}

func TestSequenceBaseKeepsCounterRoomAndFitsJavaScript(t *testing.T) {
	// The low 20 bits are the per-process counter room; the value must stay a
	// JavaScript safe integer or the browser loses precision on the round trip.
	const maxSafeJSInteger = uint64(1<<53 - 1)
	for i := 0; i < 64; i++ {
		base := randomSequenceBase()
		if base&0xFFFFF != 0 {
			t.Fatalf("base %d does not reserve the low 20 bits for the counter", base)
		}
		if base > maxSafeJSInteger {
			t.Fatalf("base %d exceeds the JavaScript safe-integer range", base)
		}
	}
}

func TestSequencesStayMonotonicWithinAProcess(t *testing.T) {
	s := &server{}
	s.attackSequence = randomSequenceBase()
	first := atomic.AddUint64(&s.attackSequence, 1)
	second := atomic.AddUint64(&s.attackSequence, 1)
	if second != first+1 {
		t.Fatalf("counter is not monotonic: %d then %d", first, second)
	}
}

func TestSequenceBasesAreNotTimeDerived(t *testing.T) {
	// A time-derived base always has the current Unix second in the high bits.
	// If ten consecutive draws all decode to "now", the CSPRNG is not in the loop
	// and the test is proving nothing.
	matches := 0
	for i := 0; i < 10; i++ {
		if randomSequenceBase()>>20 == uint64(time.Now().Unix()) {
			matches++
		}
	}
	if matches == 10 {
		t.Fatal("ten consecutive bases all decode to the current second: not random")
	}
}
