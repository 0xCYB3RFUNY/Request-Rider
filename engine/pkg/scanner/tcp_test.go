package scanner

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// `tcp:` — 289 шаблонів корпусу. Тести нижче відкривають **справжній сокет** на
// loopback: мок транспорту погодився б із діалером, який нічого не надсилає, а
// протокол усякий разом у цьому й полягає.

// tcpFixture answers one banner and then whatever it is sent, so a template that
// writes `EHLO` and reads the reply is exercised end to end.
func tcpFixture(t *testing.T, banner string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte(banner))
				_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
				reader := bufio.NewReader(c)
				for {
					line, readErr := reader.ReadString('\n')
					if line != "" {
						_, _ = c.Write([]byte("250-" + strings.TrimSpace(line) + "\r\n"))
					}
					if readErr != nil {
						return
					}
				}
			}(connection)
		}
	}()
	return "tcp://" + listener.Addr().String()
}

// tcpDocument writes one block against the fixture's address.
//
// It emits `host:` and `port:` only: the caller supplies `inputs:` and the
// `matchers:` section, because writing a default `inputs:` here produced a second
// `inputs:` key and every such document failed with «mapping key "inputs" already
// defined» — a fault in the fixture, reported as a fault in the runner.
func tcpDocument(address, rest string) string {
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(address, "tcp://"))
	return "id: tcp-probe\ninfo: {name: tcp probe, severity: info}\ntcp:\n" +
		"  - host:\n      - \"" + host + "\"\n    port: " + port + "\n" + rest
}

// Мутація: прибрати надсилання `data:`.
func TestATcpBlockReadsTheBannerAndMatchesOnIt(t *testing.T) {
	address := tcpFixture(t, "220 testserver ESMTP\r\n")
	document := tcpDocument(address,
		"    inputs:\n      - read: 256\n"+
			"    matchers:\n      - type: word\n        part: body\n        words:\n          - ESMTP\n")
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document,
		"http://"+strings.TrimPrefix(address, "tcp://"), transport)

	if run.Reason != "" {
		t.Fatalf("a tcp block reading a banner was refused: %s", run.Reason)
	}
	if !run.Matched {
		t.Fatalf("the banner matched its word matcher and the block did not match: %q", run.Reason)
	}
	if transport.count() != 0 {
		t.Fatalf("a `tcp:` block sent %d HTTP request(s); it dials a socket", transport.count())
	}
}

// Мутація: не надсилати `data:` і не читати відповідь на нього.
func TestATcpBlockWritesItsDataAndReadsTheReply(t *testing.T) {
	address := tcpFixture(t, "220 testserver ESMTP\r\n")
	document := tcpDocument(address,
		"    inputs:\n      - data: \"EHLO probe\\r\\n\"\n        read: 256\n"+
			"    matchers:\n      - type: word\n        part: body\n        words:\n          - EHLO\n")
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document,
		"http://"+strings.TrimPrefix(address, "tcp://"), transport)

	if run.Reason != "" {
		t.Fatalf("a tcp block that writes and reads was refused: %s", run.Reason)
	}
	if !run.Matched {
		t.Fatalf("the service echoed the command and the block did not match: %q / %q",
			run.Reason, run.Response)
	}
}

// `{{Hostname}}` — спосіб, яким 253 із 289 шаблонів пишуть хост: це хост цілі
// оператора, а не ім'я для пошуку. Мутація: не підставляти `{{Hostname}}`.
func TestTheHostnamePlaceholderMeansTheTargetsOwnHost(t *testing.T) {
	address := tcpFixture(t, "220 testserver ESMTP\r\n")
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(address, "tcp://"))
	document := "id: tcp-hostname\ninfo: {name: tcp hostname, severity: info}\ntcp:\n" +
		"  - host:\n      - \"{{Hostname}}\"\n    port: " + port + "\n" +
		"    inputs:\n      - read: 256\n" +
		"    matchers:\n      - type: word\n        part: body\n        words:\n          - ESMTP\n"
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document, "http://"+host+"/", transport)

	if !run.Matched {
		t.Fatalf("`{{Hostname}}` did not reach the target's own host: %q / %q", run.Reason, run.Response)
	}
}

// Іменований крок: 32 шаблони читають `ehlo`, `help`, `info` замість `raw`.
func TestANamedReadStepIsReadableAsAPart(t *testing.T) {
	address := tcpFixture(t, "220 testserver ESMTP\r\n")
	document := tcpDocument(address,
		"    inputs:\n      - read: 256\n"+
			"    matchers:\n      - type: word\n        part: step1\n        words:\n          - ESMTP\n")
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document,
		"http://"+strings.TrimPrefix(address, "tcp://"), transport)

	if !run.Matched {
		t.Fatalf("a named read step was not readable as a part: %q / %q", run.Reason, run.Response)
	}
}

// Сокет, до якого ніхто не слухає, — це відмова з назвою, а не негативний
// результат: перевірка не відбулася.
func TestATcpBlockThatCannotConnectIsRefusedByName(t *testing.T) {
	document := "id: tcp-dead\ninfo: {name: tcp dead port, severity: info}\ntcp:\n" +
		"  - host:\n      - \"127.0.0.1\"\n    port: 1\n" +
		"    inputs:\n      - read: 16\n" +
		"    matchers:\n      - type: word\n        part: body\n        words:\n          - anything\n"
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document, "http://127.0.0.1/", transport)

	if run.Matched {
		t.Fatal("a tcp block whose connection failed reported a finding")
	}
	if !run.Skipped {
		t.Fatalf("a refused connection was reported as a check that ran: %+v", run)
	}
	if !strings.Contains(run.Reason, "cannot connect") {
		t.Fatalf("the refusal does not say the connection failed: %q", run.Reason)
	}
}

// Ціль не URL — у `tcp:`-шаблона немає хост�� для набору.
func TestATcpTemplateWithoutAnAbsoluteTargetIsRefused(t *testing.T) {
	address := tcpFixture(t, "220 testserver ESMTP\r\n")
	document := tcpDocument(address,
		"    matchers:\n      - type: word\n        part: body\n        words:\n          - ESMTP\n")
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document, "not-a-url", transport)

	if !strings.Contains(run.Reason, "absolute URL") {
		t.Fatalf("a tcp template without a URL target was not refused by name: %q", run.Reason)
	}
}

// Доказ у звіті: без нього вердикт про розмову не є доказом.
func TestTheTranscriptIsKeptAsEvidence(t *testing.T) {
	address := tcpFixture(t, "220 testserver ESMTP\r\n")
	document := tcpDocument(address,
		"    inputs:\n      - data: \"EHLO probe\\r\\n\"\n        read: 256\n"+
			"    matchers:\n      - type: word\n        part: body\n        words:\n          - ESMTP\n")
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document,
		"http://"+strings.TrimPrefix(address, "tcp://"), transport)

	if !strings.Contains(run.Request, "EHLO") {
		t.Fatalf("the evidence does not show what was written: %q", run.Request)
	}
	if !strings.Contains(run.Response, "220 testserver") {
		t.Fatalf("the evidence does not show what came back: %q", run.Response)
	}
	// The bytes that went on the wire, not the template's spelling of them: a
	// transcript that repeats `\r\n` would read as four bytes on the wire that
	// were never sent.
	if !strings.Contains(run.Request, "EHLO probe\r\n") {
		t.Fatalf("the transcript shows the template's spelling rather than the bytes sent: %q", run.Request)
	}
}

// Блок, який поговорив із ціллю і нічого не знайшов, — це негатив, а не відмова.
//
// Різниця не академічна: `Skipped` у UI, у фільтрі й в експорті читається як
// «Не запускався», тому рядок, який насправді відпрацював, але названий `skipped`,
// бреше про те, що перевірка відбулася. Nuclei для того самого шаблону пише
// `"matcher-status": false`, тобто «запустився, не збіглося» — і наш рядок
// суперечив бінарнику, з якого сам і прийшов.
//
// Тест відкриває справжній сокет і просить про слово, якого там немає: розмова
// відбувається, відповідь приходить, matcher не спрацьовує.
func TestATcpBlockThatRanAndFoundNothingIsANegativeNotARefusal(t *testing.T) {
	address := tcpFixture(t, "220 testserver ESMTP\r\n")
	document := tcpDocument(address,
		"    inputs:\n      - read: 256\n"+
			"    matchers:\n      - type: word\n        part: body\n        words:\n          - this-word-is-absent\n")
	transport := &countingTransport{inner: http.DefaultTransport}

	run := RunTemplateLocally(context.Background(), document,
		"http://"+strings.TrimPrefix(address, "tcp://"), transport)

	if run.Matched {
		t.Fatal("a block whose word is absent from the banner reported a finding")
	}
	if run.Skipped {
		t.Fatalf("a block that read the banner was reported as not run: %+v", run)
	}
	if run.Reason != "" {
		t.Fatalf("a real negative needs no reason, and one was invented: %q", run.Reason)
	}
	// Негатив доводиться розмовою, а не її відсутністю: інакше «нічого не знайшов»
	// і «нічого не робив» виглядали б однаково.
	if !strings.Contains(run.Response, "220 testserver") {
		t.Fatalf("the run kept no evidence that the conversation happened: %q", run.Response)
	}
}
