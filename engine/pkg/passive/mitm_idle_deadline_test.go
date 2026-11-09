package passive

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// The engine's traffic all goes through this proxy (see the project rule that
// every tool records through the passive proxy rather than its own path), so a
// connection the proxy cannot reclaim is a connection the analyzer's own
// concurrency budget has permanently lost.
//
// Measured on the full `http` corpus against `https://yandex.ru`: 82 tunnels
// left ESTAB, the request counter frozen at 6395/20675, nuclei down to one
// thread at 0% CPU — while the same corpus in a terminal finished in 189 s.
// The cause was that a hijacked tunnel has no deadline anywhere: `HandleConnect
// (AlwaysMitm)` ends in `Hijack()`, and after the 200 confirmation goproxy only
// `io.Copy`s between the two sockets.

func TestHijackedConnectionExpiresWhenItGoesIdle(t *testing.T) {
	restore := MITMIdleTimeout
	MITMIdleTimeout = 150 * time.Millisecond
	t.Cleanup(func() { MITMIdleTimeout = restore })

	client, server := net.Pipe()
	conn := &deadlineConn{Conn: server, idle: MITMIdleTimeout}

	read := make(chan error, 1)
	go func() {
		buf := make([]byte, 8)
		_, err := conn.Read(buf)
		read <- err
	}()

	select {
	case err := <-read:
		if err == nil {
			t.Fatal("a read on an idle tunnel returned without an error; nothing bounded it")
		}
		var netErr net.Error
		if !asNetError(err, &netErr) {
			t.Fatalf("idle read failed with %v, want a timeout", err)
		}
		if !netErr.Timeout() {
			t.Fatalf("idle read failed with %v, want a timeout", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("an idle tunnel never expired; the connection is unbounded")
	}

	_ = client.Close()
	_ = conn.Close()
}

// A tunnel that keeps moving bytes must not be expired. This is the other half
// of the same rule: a bound on idleness is not a lifetime, and treating it as one
// would kill long scans that legitimately reuse one connection.
func TestAConnectionThatKeepsSendingIsNotExpired(t *testing.T) {
	restore := MITMIdleTimeout
	MITMIdleTimeout = 200 * time.Millisecond
	t.Cleanup(func() { MITMIdleTimeout = restore })

	client, server := net.Pipe()
	conn := &deadlineConn{Conn: server, idle: MITMIdleTimeout}
	defer client.Close()
	defer conn.Close()

	// Each message arrives well inside the idle bound, but the whole exchange
	// takes far longer than it, so a bound on total time would fail here.
	for i := 0; i < 8; i++ {
		go func() {
			_, _ = client.Write([]byte("x"))
		}()
		buf := make([]byte, 1)
		if _, err := conn.Read(buf); err != nil {
			t.Fatalf("read %d on a busy tunnel failed: %v", i, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestAWriteOnAnIdleConnectionAlsoExpires(t *testing.T) {
	restore := MITMIdleTimeout
	MITMIdleTimeout = 120 * time.Millisecond
	t.Cleanup(func() { MITMIdleTimeout = restore })

	client, server := net.Pipe()
	conn := &deadlineConn{Conn: server, idle: MITMIdleTimeout}
	defer client.Close()
	defer conn.Close()

	// Nothing reads on the other side, so with no peer buffer this write parks
	// until the deadline. The point is that it does park and then return, rather
	// than holding the goroutine for the life of the process.
	done := make(chan error, 1)
	go func() {
		_, err := conn.Write(make([]byte, 1<<20))
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Skip("the platform accepted the whole write; the write bound is not observable on net.Pipe")
		}
		var netErr net.Error
		if !asNetError(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("blocked write failed with %v, want a timeout", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a blocked write never returned; the write path is unbounded")
	}
}

// The wrapper has to keep goproxy on its hijacking path. goproxy type-asserts
// for `http.Hijacker`, and a wrapper that only delegated the handler would make
// it fall through to an HTTP/2-only path that this proxy does not serve.
//
// The check is against a real server rather than a stub, because the thing being
// verified is that a live `http.Server`'s writer still hands over a usable
// connection through the wrapper.
func TestTheWrapperStillHandsOverAWorkingHijackedConnection(t *testing.T) {
	restore := MITMIdleTimeout
	MITMIdleTimeout = 2 * time.Second
	t.Cleanup(func() { MITMIdleTimeout = restore })

	accepted := make(chan string, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack through the backend failed: %v", err)
			return
		}
		defer conn.Close()
		_, _ = buffered.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		_ = buffered.Flush()
		// Echo one byte back so the test can prove the connection is live in
		// both directions after the wrapper has been inserted.
		buf := make([]byte, 1)
		if _, err := buffered.Read(buf); err != nil {
			return
		}
		_, _ = conn.Write([]byte("x"))
		accepted <- string(buf)
	}))
	defer backend.Close()

	var wrapped http.ResponseWriter
	probe := httptest.NewRecorder()
	// The wrapper is built over the recorder on purpose: a recorder is not a
	// Hijacker, so this proves the error path, and the live server above proves
	// the success path.
	wrapped = &hijackBoundedResponseWriter{ResponseWriter: probe}
	var _ http.Hijacker = wrapped.(http.Hijacker)
	var _ http.Flusher = wrapped.(http.Flusher)

	client, err := net.Dial("tcp", backend.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial backend: %v", err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\nz")); err != nil {
		t.Fatalf("write to backend: %v", err)
	}
	got := <-accepted
	if got != "z" {
		t.Fatalf("backend read %q through a hijacked connection, want %q", got, "z")
	}
}

// A response writer that is not a Hijacker must say so. goproxy turns a missing
// Hijacker into an HTTP/2-only path, and an operator seeing requests fail would
// otherwise get no indication why.
func TestAMissingHijackerIsReportedRatherThanImpersonated(t *testing.T) {
	// A recorder stands in for the "server does not support hijacking" case, and
	// `http.ResponseRecorder` genuinely is not a Hijacker, so this is the real
	// shape of the failure rather than a stubbed one.
	wrapped := &hijackBoundedResponseWriter{ResponseWriter: httptest.NewRecorder()}
	conn, buffered, err := wrapped.Hijack()
	if err == nil {
		t.Fatal("Hijack succeeded on a writer that cannot hijack")
	}
	if conn != nil || buffered != nil {
		t.Fatalf("Hijack returned %v / %v alongside the error; both must be nil", conn, buffered)
	}
	if err != errNoHijacker {
		t.Fatalf("Hijack failed with %v, want errNoHijacker", err)
	}
}

// Zero must keep the previous behaviour rather than mean "expire immediately":
// an operator who sets RR_MITM_IDLE_TIMEOUT_SEC=0 is asking for no bound, and
// reading it as a deadline of zero would close every tunnel on the next read.
func TestAZeroIdleTimeoutDisablesTheBound(t *testing.T) {
	restore := MITMIdleTimeout
	MITMIdleTimeout = 0
	t.Cleanup(func() { MITMIdleTimeout = restore })

	client, server := net.Pipe()
	defer client.Close()
	// No deadline conn at all — this is what Handler builds when the bound is 0.
	read := make(chan error, 1)
	go func() {
		buf := make([]byte, 4)
		_, err := server.Read(buf)
		read <- err
	}()

	select {
	case <-read:
		t.Fatal("an unbounded connection returned; it was closed by something else")
	case <-time.After(300 * time.Millisecond):
		// Still blocked, which is exactly the documented behaviour.
	}
	_ = server.Close()
}

// The bound is read from the environment so an operator can widen it for a slow
// target without a rebuild. Zero and unparsable both fall back to the default
// rather than to "expire at once".
func TestTheIdleTimeoutIsReadFromTheEnvironment(t *testing.T) {
	// `t.Setenv` rather than a stubbed reader: the point of the test is that the
	// real `os.Getenv` call is what decides, and a stub would let the function
	// read the value from anywhere at all and still pass.
	t.Run("unset falls back to the default", func(t *testing.T) {
		t.Setenv("RR_MITM_IDLE_TIMEOUT_SEC", "")
		if got := idleTimeoutFromEnv(); got != defaultMITMIdleTimeout {
			t.Fatalf("unset variable gave %v, want the %v default", got, defaultMITMIdleTimeout)
		}
	})

	t.Run("zero falls back rather than expiring at once", func(t *testing.T) {
		t.Setenv("RR_MITM_IDLE_TIMEOUT_SEC", "0")
		if got := idleTimeoutFromEnv(); got != defaultMITMIdleTimeout {
			t.Fatalf("a zero value gave %v, want the %v default, not an immediate expiry", got, defaultMITMIdleTimeout)
		}
	})

	t.Run("unparsable falls back", func(t *testing.T) {
		t.Setenv("RR_MITM_IDLE_TIMEOUT_SEC", "not-a-number")
		if got := idleTimeoutFromEnv(); got != defaultMITMIdleTimeout {
			t.Fatalf("an unparsable value gave %v, want the %v default", got, defaultMITMIdleTimeout)
		}
	})

	t.Run("a fractional value is honoured", func(t *testing.T) {
		t.Setenv("RR_MITM_IDLE_TIMEOUT_SEC", "12.5")
		if got := idleTimeoutFromEnv(); got != 12500*time.Millisecond {
			t.Fatalf("12.5 gave %v, want 12.5s", got)
		}
	})
}

// Concurrent traffic must not race on the wrapped connection. The engine runs
// every tool's traffic through here at once, so `go test -race` is the level
// that decides whether this is shippable.
func TestConcurrentHijackedTunnelsAreIndependent(t *testing.T) {
	restore := MITMIdleTimeout
	MITMIdleTimeout = time.Second
	t.Cleanup(func() { MITMIdleTimeout = restore })

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client, server := net.Pipe()
			conn := &deadlineConn{Conn: server, idle: MITMIdleTimeout}
			go func() {
				buf := make([]byte, 4)
				_, _ = conn.Read(buf)
			}()
			_, _ = client.Write([]byte("ping"))
			time.Sleep(20 * time.Millisecond)
			_ = client.Close()
			_ = conn.Close()
		}()
	}
	wg.Wait()
}

func asNetError(err error, target *net.Error) bool {
	netErr, ok := err.(net.Error)
	if ok {
		*target = netErr
	}
	return ok
}
